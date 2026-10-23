// Package aws is the broker adapter for AWS: every credential is an STS
// AssumeRole session that lives at least 900 s (default broker.aws_session_ttl),
// carries SourceIdentity=<agent> and a session policy allowing exactly the
// one decided service:Action on the decided resource. Fortik's own long-lived
// keys come from the "aws" integration (secret store) and never leave the
// process. STS sessions cannot be recalled, so revocation attaches an inline
// deny-by-issue-time policy to the role.
package aws

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"

	"fortik/internal/access"
	"fortik/internal/broker"
	"fortik/internal/integrations"
)

// System is the broker system and the integration key.
const System = "aws"

const (
	minTTL  = 900 * time.Second // STS minimum
	maxTTL  = 12 * time.Hour    // STS maximum (the role's own maximum may be lower)
	callTTL = 15 * time.Second  // per AWS API call
)

// Adapter implements broker.Adapter for AWS.
type Adapter struct {
	src        integrations.Source
	defaultTTL time.Duration
	log        *slog.Logger

	// HTTPClient is used for every AWS call (nil = SDK default).
	HTTPClient *http.Client
	// RevokeSkew moves the revocation cut-off past "now" so sessions minted
	// during clock skew between Fortik and AWS are also denied (default 1m).
	RevokeSkew time.Duration
	Now        func() time.Time

	revokeMu sync.Mutex // serialises read-modify-write of the revocation policy
}

var (
	_ broker.Adapter      = (*Adapter)(nil)
	_ integrations.Tester = (*Tester)(nil)
)

// New builds the adapter. defaultTTL is config.BrokerConfig.AWSSessionTTL
// (raised to the 900 s STS minimum when shorter).
func New(src integrations.Source, defaultTTL time.Duration, log *slog.Logger) *Adapter {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Adapter{src: src, defaultTTL: defaultTTL, log: log, RevokeSkew: time.Minute}
}

func (a *Adapter) System() string { return System }

func (a *Adapter) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

// settings are the "aws" integration's config and secrets.
type settings struct {
	region, roleARN, roleName  string
	stsEndpoint, iamEndpoint   string
	accessKeyID, secretKey, ex string
}

var (
	roleARNPattern = regexp.MustCompile(`^arn:aws[a-z-]*:iam::[0-9]{12}:role/(?:[\w+=,.@-]+/)*([\w+=,.@-]{1,64})$`)
	regionPattern  = regexp.MustCompile(`^[a-z]{2}(?:-[a-z]+)+-[0-9]{1,2}$`)
	servicePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
	actionPattern  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]{0,127}$`)
)

// parseSettings validates a resolved integration. Problems with the
// operator's settings are reported as integrations.ErrInvalid (never with
// secret values).
func parseSettings(r integrations.Resolved) (settings, error) {
	str := func(k string) string {
		v, _ := r.ConfigMap[k].(string)
		return strings.TrimSpace(v)
	}
	s := settings{
		region:      str("region"),
		roleARN:     str("role_arn"),
		stsEndpoint: str("sts_endpoint"),
		iamEndpoint: str("iam_endpoint"),
		accessKeyID: r.Secrets["access_key_id"],
		secretKey:   r.Secrets["secret_access_key"],
		ex:          r.Secrets["external_id"],
	}
	if !regionPattern.MatchString(s.region) {
		return s, fmt.Errorf("%w: aws region is missing or invalid", integrations.ErrInvalid)
	}
	m := roleARNPattern.FindStringSubmatch(s.roleARN)
	if m == nil {
		return s, fmt.Errorf("%w: aws role_arn must be arn:aws:iam::<account>:role/<name>", integrations.ErrInvalid)
	}
	s.roleName = m[1]
	if s.accessKeyID == "" || s.secretKey == "" {
		return s, fmt.Errorf("%w: aws access_key_id and secret_access_key are required", integrations.ErrNotConfigured)
	}
	for k, v := range map[string]string{"sts_endpoint": s.stsEndpoint, "iam_endpoint": s.iamEndpoint} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			return s, fmt.Errorf("%w: aws %s must be an http(s) URL", integrations.ErrInvalid, k)
		}
	}
	return s, nil
}

func (a *Adapter) settings(ctx context.Context) (settings, error) {
	r, err := a.src.Get(ctx, System)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return settings{}, fmt.Errorf("%w: aws", broker.ErrNotConfigured)
	}
	if err != nil {
		return settings{}, fmt.Errorf("aws integration: %w", err)
	}
	s, err := parseSettings(r)
	if errors.Is(err, integrations.ErrNotConfigured) {
		return s, fmt.Errorf("%w: %v", broker.ErrNotConfigured, err)
	}
	return s, err
}

// stsClient builds an STS client from explicit settings only: no ambient
// environment, shared config or instance-role credentials are ever used.
func stsClient(s settings, creds awssdk.CredentialsProvider, hc *http.Client) *sts.Client {
	o := sts.Options{Region: s.region, Credentials: creds, RetryMaxAttempts: 2}
	if s.stsEndpoint != "" {
		o.BaseEndpoint = awssdk.String(s.stsEndpoint)
	}
	if hc != nil {
		o.HTTPClient = hc
	}
	return sts.New(o)
}

func iamClient(s settings, hc *http.Client) *iam.Client {
	// IAM is global; its signing region is us-east-1 in the commercial
	// partition and the configured region elsewhere (GovCloud, China).
	region := "us-east-1"
	if strings.HasPrefix(s.region, "us-gov-") || strings.HasPrefix(s.region, "cn-") {
		region = s.region
	}
	o := iam.Options{Region: region, Credentials: staticCreds(s), RetryMaxAttempts: 2}
	if s.iamEndpoint != "" {
		o.BaseEndpoint = awssdk.String(s.iamEndpoint)
	}
	if hc != nil {
		o.HTTPClient = hc
	}
	return iam.New(o)
}

func staticCreds(s settings) awssdk.CredentialsProvider {
	return credentials.NewStaticCredentialsProvider(s.accessKeyID, s.secretKey, "")
}

// --- identities --------------------------------------------------------------

var (
	identityUnsafe = regexp.MustCompile(`[^A-Za-z0-9_.@-]`)
	identityPlain  = regexp.MustCompile(`^[A-Za-z0-9_.@-]{2,64}$`)
)

// SourceIdentity maps an agent id to an STS SourceIdentity (2-64 chars of
// [A-Za-z0-9_+=,.@-]). Ids already of the form [A-Za-z0-9_.@-]{2,64} are
// used unchanged; any other id is sanitised and gets "=" plus a hash of the
// original id. Plain identities never contain '=' and hashed ones always do,
// so the mapping is injective (up to the hash) and distinct agents never
// share an identity. Deterministic: revocation computes the same value.
func SourceIdentity(agentID string) string {
	if identityPlain.MatchString(agentID) {
		return agentID
	}
	clean := identityUnsafe.ReplaceAllString(agentID, "_")
	if len(clean) > 55 {
		clean = clean[:55]
	}
	return clean + "=" + shortHash(agentID)
}

// sessionName is fortik-<identity>-<random>, at most 64 characters.
func sessionName(agentID string) string {
	id := SourceIdentity(agentID)
	if len(id) > 47 {
		id = id[:47]
	}
	return "fortik-" + id + "-" + randomHex(4)
}

// RevokePolicyName is the single inline role policy holding every agent
// revocation (one statement per revoked identity; IAM caps a role's inline
// policies at 10,240 characters in total, so one policy per agent would
// exhaust the quota).
const RevokePolicyName = "fortik-revoke"

// maxRevokePolicyLen bounds the revocation document, leaving room in the
// role's 10,240-character inline-policy budget for other policies.
const maxRevokePolicyLen = 8192

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go 1.24+)
	return hex.EncodeToString(b)
}

// --- policies ------------------------------------------------------------------

type policyDoc struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

type statement struct {
	Sid       string                    `json:"Sid"`
	Effect    string                    `json:"Effect"`
	Action    string                    `json:"Action"`
	Resource  string                    `json:"Resource"`
	Condition map[string]map[string]any `json:"Condition,omitempty"`
}

func marshalPolicy(st statement) string {
	b, _ := json.Marshal(policyDoc{Version: "2012-10-17", Statement: []statement{st}})
	return string(b)
}

// SessionPolicy allows exactly service:Action on resource (restricted to
// region when one was requested). A session's permissions are the
// intersection of the role's policies and this document.
func SessionPolicy(service, actionName, resource, region string) string {
	st := statement{Sid: "FortikExactAction", Effect: "Allow", Action: service + ":" + actionName, Resource: resource}
	if region != "" {
		st.Condition = map[string]map[string]any{"StringEquals": {"aws:RequestedRegion": region}}
	}
	return marshalPolicy(st)
}

// RevokePolicy is the revocation document for identities (SourceIdentity ->
// cut-off): it denies everything to each identity's sessions issued before
// its cut-off. One statement per identity, sorted. If the document would
// exceed maxRevokePolicyLen, all identities are folded into one statement
// with the latest cut-off (fails closed: may over-revoke, never under-revokes).
func RevokePolicy(identities map[string]time.Time) string {
	ids := make([]string, 0, len(identities))
	var latest time.Time
	for id, c := range identities {
		ids = append(ids, id)
		if c.After(latest) {
			latest = c
		}
	}
	sort.Strings(ids)
	stmts := make([]statement, 0, len(ids))
	for _, id := range ids {
		stmts = append(stmts, revokeStatement("FortikRevoke"+shortHash(id), id, identities[id]))
	}
	b, _ := json.Marshal(policyDoc{Version: "2012-10-17", Statement: stmts})
	if len(b) <= maxRevokePolicyLen || len(ids) == 0 {
		return string(b)
	}
	list := make([]any, len(ids))
	for i, id := range ids {
		list[i] = id
	}
	st := revokeStatement("FortikRevokeMerged", "", latest)
	st.Condition["StringEquals"]["aws:SourceIdentity"] = list
	b, _ = json.Marshal(policyDoc{Version: "2012-10-17", Statement: []statement{st}})
	return string(b)
}

func revokeStatement(sid, identity string, cutoff time.Time) statement {
	return statement{Sid: sid, Effect: "Deny", Action: "*", Resource: "*",
		Condition: map[string]map[string]any{
			"StringEquals": {"aws:SourceIdentity": identity},
			"DateLessThan": {"aws:TokenIssueTime": cutoff.UTC().Format(time.RFC3339)},
		}}
}

// parseRevokePolicy reads the identities and cut-offs from an existing
// revocation document (as IAM returns it, possibly URL-encoded). Any
// statement it cannot understand is an error: dropping a revocation is
// never acceptable.
func parseRevokePolicy(doc string) (map[string]time.Time, error) {
	if d, err := url.QueryUnescape(doc); err == nil {
		doc = d
	}
	var pd struct {
		Statement []struct {
			Condition map[string]map[string]any `json:"Condition"`
		} `json:"Statement"`
	}
	if err := json.Unmarshal([]byte(doc), &pd); err != nil {
		return nil, fmt.Errorf("existing %s policy is not valid JSON", RevokePolicyName)
	}
	out := map[string]time.Time{}
	for _, st := range pd.Statement {
		ts, _ := st.Condition["DateLessThan"]["aws:TokenIssueTime"].(string)
		cutoff, err := time.Parse(time.RFC3339, ts)
		if err != nil {
			return nil, fmt.Errorf("existing %s policy has a statement without a valid aws:TokenIssueTime", RevokePolicyName)
		}
		var ids []string
		switch v := st.Condition["StringEquals"]["aws:SourceIdentity"].(type) {
		case string:
			ids = []string{v}
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					ids = append(ids, s)
				}
			}
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("existing %s policy has a statement without aws:SourceIdentity", RevokePolicyName)
		}
		for _, id := range ids {
			if cutoff.After(out[id]) {
				out[id] = cutoff.UTC()
			}
		}
	}
	return out, nil
}

// testPolicy is the read-only session policy used by the connection test.
var testPolicy = marshalPolicy(statement{Sid: "FortikConnectionTest", Effect: "Allow", Action: "sts:GetCallerIdentity", Resource: "*"})

// --- Mint ----------------------------------------------------------------------

func (a *Adapter) duration(ttl time.Duration) time.Duration {
	if ttl <= 0 {
		ttl = a.defaultTTL
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	ttl = ttl.Round(time.Second)
	return min(max(ttl, minTTL), maxTTL)
}

// Mint assumes the integration's role for one decided action. The scope is
// re-checked against the access profile it carries (defence in depth).
func (a *Adapter) Mint(ctx context.Context, agentID string, scope map[string]any, ttl time.Duration) (broker.Credential, error) {
	str := func(k string) string { v, _ := scope[k].(string); return v }
	service, actionName, resource, region := str("service"), str("action"), str("resource"), str("region")
	switch {
	case !servicePattern.MatchString(service), !actionPattern.MatchString(actionName):
		return broker.Credential{}, fmt.Errorf("%w: scope needs one service and one action name", broker.ErrScopeDenied)
	case resource == "" || (resource != "*" && !strings.HasPrefix(resource, "arn:")) || strings.ContainsAny(resource, "\x00\"\\\n\r\t "):
		return broker.Credential{}, fmt.Errorf("%w: scope resource must be an ARN or *", broker.ErrScopeDenied)
	case region != "" && !regionPattern.MatchString(region):
		return broker.Credential{}, fmt.Errorf("%w: scope region is invalid", broker.ErrScopeDenied)
	}
	if la := strings.ToLower(actionName); service == "sts" && la != "getcalleridentity" && la != "getaccesskeyinfo" {
		// A session allowed to call sts:AssumeRole* / GetFederationToken /
		// GetSessionToken / TagSession... can mint credentials that the
		// session policy does not narrow: never broker those.
		return broker.Credential{}, fmt.Errorf("%w: sts:%s would yield a credential outside Fortik's session policy", broker.ErrScopeDenied, actionName)
	}
	prof, err := broker.ProfileFromScope(System, scope)
	if err != nil {
		return broker.Credential{}, err
	}
	p, ok := prof.(access.AWSProfile)
	if !ok {
		return broker.Credential{}, fmt.Errorf("%w: not an aws profile", broker.ErrScopeDenied)
	}
	if err := broker.CheckAWSProfile(p, service, actionName); err != nil {
		return broker.Credential{}, err
	}

	s, err := a.settings(ctx)
	if err != nil {
		return broker.Credential{}, err
	}
	dur := a.duration(ttl)
	policy := SessionPolicy(service, actionName, resource, region)
	identity := SourceIdentity(agentID)
	session := sessionName(agentID)
	in := &sts.AssumeRoleInput{
		RoleArn:         awssdk.String(s.roleARN),
		RoleSessionName: awssdk.String(session),
		DurationSeconds: awssdk.Int32(int32(dur / time.Second)),
		Policy:          awssdk.String(policy),
		SourceIdentity:  awssdk.String(identity),
	}
	if s.ex != "" {
		in.ExternalId = awssdk.String(s.ex)
	}
	cctx, cancel := context.WithTimeout(ctx, callTTL)
	defer cancel()
	out, err := stsClient(s, staticCreds(s), a.HTTPClient).AssumeRole(cctx, in)
	if err != nil {
		return broker.Credential{}, fmt.Errorf("sts AssumeRole: %s", summarize(err))
	}
	c := out.Credentials
	if c == nil || c.AccessKeyId == nil || c.SecretAccessKey == nil || c.SessionToken == nil {
		return broker.Credential{}, errors.New("sts AssumeRole returned no credentials")
	}
	exp := a.now().Add(dur)
	if c.Expiration != nil {
		exp = c.Expiration.UTC()
	}
	return broker.Credential{
		System:    System,
		ExpiresAt: exp,
		Scope: map[string]any{
			"iam_action":               service + ":" + actionName,
			"resource":                 resource,
			"region":                   region,
			"role_arn":                 s.roleARN,
			"session_name":             session,
			"source_identity":          identity,
			"duration_seconds":         int(dur / time.Second),
			"session_policy":           policy,
			broker.ScopeProfileVersion: scope[broker.ScopeProfileVersion],
		},
		Secret: map[string]string{
			"access_key_id":     *c.AccessKeyId,
			"secret_access_key": *c.SecretAccessKey,
			"session_token":     *c.SessionToken,
		},
	}, nil
}

// --- RevokeAgent ---------------------------------------------------------------

// RevokeAgent adds (or moves forward) this agent's statement in the single
// inline role policy fortik-revoke, denying every action to sessions with the
// agent's SourceIdentity issued before now (+RevokeSkew). Entries whose
// cut-off is older than the STS maximum session duration are pruned: every
// session they could deny has already expired.
func (a *Adapter) RevokeAgent(ctx context.Context, agentID string) (string, error) {
	s, err := a.settings(ctx)
	if err != nil {
		return "", err
	}
	skew := a.RevokeSkew
	if skew < 0 {
		skew = 0
	}
	now := a.now()
	cutoff := now.Add(skew).Truncate(time.Second)
	identity := SourceIdentity(agentID)

	a.revokeMu.Lock()
	defer a.revokeMu.Unlock()
	cctx, cancel := context.WithTimeout(ctx, 2*callTTL)
	defer cancel()
	client := iamClient(s, a.HTTPClient)
	entries := map[string]time.Time{}
	got, err := client.GetRolePolicy(cctx, &iam.GetRolePolicyInput{RoleName: awssdk.String(s.roleName), PolicyName: awssdk.String(RevokePolicyName)})
	var nse *iamtypes.NoSuchEntityException
	switch {
	case errors.As(err, &nse):
	case err != nil:
		return "", fmt.Errorf("iam GetRolePolicy: %s", summarize(err))
	case got.PolicyDocument != nil:
		if entries, err = parseRevokePolicy(*got.PolicyDocument); err != nil {
			return "", err
		}
	}
	for id, c := range entries {
		if c.Before(now.Add(-maxTTL)) {
			delete(entries, id)
		}
	}
	if cutoff.After(entries[identity]) {
		entries[identity] = cutoff
	}
	_, err = client.PutRolePolicy(cctx, &iam.PutRolePolicyInput{
		RoleName:       awssdk.String(s.roleName),
		PolicyName:     awssdk.String(RevokePolicyName),
		PolicyDocument: awssdk.String(RevokePolicy(entries)),
	})
	if err != nil {
		return "", fmt.Errorf("iam PutRolePolicy: %s", summarize(err))
	}
	return fmt.Sprintf("aws: STS session tokens are not recallable; updated deny-by-issue-time inline policy %s on role %s "+
		"(Deny * for aws:SourceIdentity=%s with aws:TokenIssueTime before %s); sessions issued earlier are refused by AWS",
		RevokePolicyName, s.roleName, identity, entries[identity].Format(time.RFC3339)), nil
}

// --- connection test -------------------------------------------------------------

// Tester is the "aws" integrations.Tester: AssumeRole with a read-only
// session policy (and a SourceIdentity, as Mint uses), then
// GetCallerIdentity with the session.
type Tester struct {
	HTTPClient *http.Client
}

func NewTester() *Tester { return &Tester{} }

func (t *Tester) System() string { return System }

func (t *Tester) Test(ctx context.Context, r integrations.Resolved) error {
	s, err := parseSettings(r)
	if err != nil {
		return err
	}
	in := &sts.AssumeRoleInput{
		RoleArn:         awssdk.String(s.roleARN),
		RoleSessionName: awssdk.String("fortik-connection-test-" + randomHex(4)),
		DurationSeconds: awssdk.Int32(int32(minTTL / time.Second)),
		Policy:          awssdk.String(testPolicy),
		SourceIdentity:  awssdk.String("fortik-connection-test"),
	}
	if s.ex != "" {
		in.ExternalId = awssdk.String(s.ex)
	}
	out, err := stsClient(s, staticCreds(s), t.HTTPClient).AssumeRole(ctx, in)
	if err != nil {
		return fmt.Errorf("sts AssumeRole on %s failed: %s", s.roleARN, summarize(err))
	}
	c := out.Credentials
	if c == nil || c.AccessKeyId == nil || c.SecretAccessKey == nil || c.SessionToken == nil {
		return errors.New("sts AssumeRole returned no credentials")
	}
	session := credentials.NewStaticCredentialsProvider(*c.AccessKeyId, *c.SecretAccessKey, *c.SessionToken)
	if _, err := stsClient(s, session, t.HTTPClient).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{}); err != nil {
		return fmt.Errorf("sts GetCallerIdentity with the assumed role failed: %s", summarize(err))
	}
	return nil
}

// summarize reduces an SDK error to its API code and message (no request
// signatures, headers or credentials).
func summarize(err error) string {
	var apiErr smithy.APIError
	if errors.As(err, &apiErr) {
		msg := strings.Join(strings.Fields(apiErr.ErrorMessage()), " ")
		if len(msg) > 300 {
			msg = msg[:300] + "..."
		}
		return apiErr.ErrorCode() + ": " + msg
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return "request failed: " + urlErr.Err.Error()
	}
	return "request failed"
}
