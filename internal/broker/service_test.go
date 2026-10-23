package broker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/broker"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
	"fortik/internal/testutil"
)

const secretMarker = "SECRET-VALUE-NEVER-STORED"

// fakeAdapter is a test double for a system adapter: it records Mint calls
// and returns a credential carrying a recognisable secret.
type fakeAdapter struct {
	system    string
	mu        sync.Mutex
	mints     []map[string]any
	ttls      []time.Duration
	mintErr   error
	lifetime  time.Duration
	revokeErr error
	revoked   []string
	reduced   bool
}

func (f *fakeAdapter) System() string { return f.system }

func (f *fakeAdapter) Mint(_ context.Context, agentID string, scope map[string]any, ttl time.Duration) (broker.Credential, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mints = append(f.mints, scope)
	f.ttls = append(f.ttls, ttl)
	if f.mintErr != nil {
		return broker.Credential{}, f.mintErr
	}
	life := f.lifetime
	if life == 0 {
		life = 15 * time.Minute
	}
	desc := map[string]any{broker.ScopeProfile: scope[broker.ScopeProfile], "agent": agentID}
	for _, k := range []string{"iam_action", "resource", "repos", "permissions"} {
		if v, ok := scope[k]; ok {
			desc[k] = v
		}
	}
	return broker.Credential{ExpiresAt: time.Now().Add(life), Scope: desc, Secret: map[string]string{"token": secretMarker}}, nil
}

func (f *fakeAdapter) RevokeAgent(_ context.Context, agentID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, agentID)
	if f.revokeErr != nil {
		return "", f.revokeErr
	}
	return f.system + ": revoked for real (fake)", nil
}

func (f *fakeAdapter) SupportsReducedForm(map[string]any) bool { return f.reduced }

type fixture struct {
	pool   *pgxpool.Pool
	d      *diary.Diary
	ctl    *control.Store
	acc    *access.PGStore
	dec    *decide.Service
	aws    *fakeAdapter
	github *fakeAdapter
	svc    *broker.Service
}

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, id := range []string{"claude_code_01", "ops_agent:02"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: id, Type: "test", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	acc := access.NewPGStore(pool, d)
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc}
	f := &fixture{pool: pool, d: d, ctl: ctl, acc: acc, dec: dec,
		aws: &fakeAdapter{system: "aws"}, github: &fakeAdapter{system: "github"}}
	f.svc = broker.New(dec, pool, d, acc, map[string]broker.Adapter{"aws": f.aws, "github": f.github}, log)
	return f
}

func (f *fixture) profile(t *testing.T, agent, system, p string) {
	t.Helper()
	if _, err := f.acc.Put(context.Background(), agent, system, json.RawMessage(p), "user:sec@acme.com", "test"); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// diaryData returns the data of every event of type, oldest first.
func (f *fixture) diaryData(t *testing.T, eventType string) []map[string]any {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, eventType)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			t.Fatal(err)
		}
		var b struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b.Data)
	}
	return out
}

func awsReq(agent, svc, act, resource string) broker.IssueRequest {
	return broker.IssueRequest{AgentID: agent, InstanceID: "inst-1", System: "aws",
		AWS: &broker.AWSRequest{Service: svc, Action: act, Resource: resource, Region: "eu-west-1"}}
}

func refusal(t *testing.T, err error) *broker.Refusal {
	t.Helper()
	var r *broker.Refusal
	if !errors.As(err, &r) {
		t.Fatalf("want *Refusal, got %v", err)
	}
	return r
}

func TestIssueRefusedWithoutProfile(t *testing.T) {
	f := setup(t)
	_, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "arn:aws:s3:::reports/q3.csv"))
	r := refusal(t, err)
	if r.Outcome.Result.RuleID != "POL-020" || r.Outcome.Result.Decision != policy.Deny || r.Outcome.Action.ActionID == "" {
		t.Fatalf("got %+v", r.Outcome.Result)
	}
	if len(f.aws.mints) != 0 {
		t.Fatal("adapter minted despite refusal")
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances`); n != 0 {
		t.Fatalf("issuances: %d", n)
	}
	// The decision and the refusal are both recorded.
	if n := f.count(t, `SELECT count(*) FROM actions WHERE action_id = $1 AND system = 'aws' AND verb = 'READ'`, r.Outcome.Action.ActionID); n != 1 {
		t.Fatal("action not recorded")
	}
	ev := f.diaryData(t, broker.EventRefused)
	if len(ev) != 1 || ev[0]["action_id"] != r.Outcome.Action.ActionID || ev[0]["rule_id"] != "POL-020" || ev[0]["stage"] != "decision" ||
		ev[0]["instance_id"] != "inst-1" {
		t.Fatalf("refused event: %v", ev)
	}
}

func TestIssueAWSAllowedRecordsWithoutSecret(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_write","services":["s3"],"denied_actions":["s3:delete*"]}`)
	f.svc.TTL["aws"] = 20 * time.Minute
	cred, err := f.svc.Issue(ctx, awsReq("claude_code_01", "s3", "GetObject", "arn:aws:s3:::reports/q3.csv"))
	if err != nil {
		t.Fatal(err)
	}
	if cred.IssuanceID == "" || cred.ActionID == "" || cred.System != "aws" || cred.Secret["token"] != secretMarker {
		t.Fatalf("credential %+v", cred)
	}
	if _, leaked := cred.Scope[broker.ScopeProfile]; leaked {
		t.Fatal("access profile left in the returned scope")
	}
	// The adapter got the decided scope plus the profile to re-check.
	if len(f.aws.mints) != 1 || f.aws.ttls[0] != 20*time.Minute {
		t.Fatalf("mints %v ttls %v", f.aws.mints, f.aws.ttls)
	}
	s := f.aws.mints[0]
	if s["service"] != "s3" || s["action"] != "GetObject" || s["iam_action"] != "s3:GetObject" || s["resource"] != "arn:aws:s3:::reports/q3.csv" ||
		s["region"] != "eu-west-1" || s[broker.ScopeProfileVersion] != 1 {
		t.Fatalf("scope %v", s)
	}
	if !strings.Contains(string(s[broker.ScopeProfile].(json.RawMessage)), `"read_write"`) {
		t.Fatalf("scope profile %v", s[broker.ScopeProfile])
	}
	// The decided Action carried the broker's target.
	var target string
	if err := f.pool.QueryRow(ctx, `SELECT target::text FROM actions WHERE action_id = $1 AND decision = 'allow' AND source = 'app_gateway' AND instance_id = 'inst-1'`,
		cred.ActionID).Scan(&target); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"iam_action": "s3:GetObject"`, `"credential_request": true`, `"region": "eu-west-1"`} {
		if !strings.Contains(target, want) {
			t.Fatalf("target %s lacks %s", target, want)
		}
	}
	// One issuance row and one credential.issued event, neither with the secret.
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE issuance_id = $1 AND action_id = $2 AND agent_id = 'claude_code_01'
		AND instance_id = 'inst-1' AND system = 'aws' AND revoked_at IS NULL AND expires_at > now()`, cred.IssuanceID, cred.ActionID); n != 1 {
		t.Fatal("issuance row missing")
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE scope_json::text LIKE '%'||$1||'%' OR scope_json ? 'access_profile'`, secretMarker); n != 0 {
		t.Fatal("secret or profile stored in scope_json")
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE body_json LIKE '%'||$1||'%'`, secretMarker); n != 0 {
		t.Fatal("secret written to the Diary")
	}
	ev := f.diaryData(t, broker.EventIssued)
	if len(ev) != 1 || ev[0]["issuance_id"] != cred.IssuanceID || ev[0]["action_id"] != cred.ActionID || ev[0]["system"] != "aws" || ev[0]["expires_at"] == "" {
		t.Fatalf("issued event %v", ev)
	}
	if sc := ev[0]["scope"].(map[string]any); sc["iam_action"] != "s3:GetObject" {
		t.Fatalf("event scope %v", sc)
	}
	if res, err := f.d.VerifyChain(ctx); err != nil || !res.OK {
		t.Fatalf("diary chain %+v %v", res, err)
	}
}

func TestIssueAWSRefusedByProfileRules(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"],"denied_actions":["s3:getobjectacl"]}`)
	cases := []struct {
		svc, act, rule string
	}{
		{"s3", "PutObject", "POL-021"},
		{"ec2", "DescribeInstances", "POL-025"},
		{"s3", "GetObjectAcl", "POL-025"},
	}
	for _, c := range cases {
		_, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", c.svc, c.act, "*"))
		if r := refusal(t, err); r.Outcome.Result.RuleID != c.rule {
			t.Errorf("%s:%s: got %s (%s)", c.svc, c.act, r.Outcome.Result.RuleID, r.Outcome.Result.Reason)
		}
	}
	if len(f.aws.mints) != 0 {
		t.Fatal("minted")
	}
}

func TestIssueAWSRedActionHeldNotIssued(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_write","services":["ec2"]}`)
	_, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "ec2", "TerminateInstances", "arn:aws:ec2:eu-west-1:123456789012:instance/i-1"))
	r := refusal(t, err)
	if r.Outcome.Result.RuleID != "POL-402" || r.Outcome.Result.Decision != policy.Hold || !r.Outcome.Held {
		t.Fatalf("got %+v", r.Outcome)
	}
}

func TestIssueNotConfigured(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	svc := broker.New(f.dec, f.pool, f.d, f.acc, nil, nil)
	_, err := svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*"))
	var nc *broker.NotConfiguredError
	if !errors.As(err, &nc) || !errors.Is(err, broker.ErrNotConfigured) || nc.System != "aws" || nc.ActionID == "" {
		t.Fatalf("got %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM actions WHERE action_id = $1 AND decision = 'allow'`, nc.ActionID); n != 1 {
		t.Fatal("decision not recorded before not-configured")
	}
	ev := f.diaryData(t, broker.EventRefused)
	if len(ev) != 1 || ev[0]["stage"] != "not_configured" {
		t.Fatalf("refused events %v", ev)
	}
	// An adapter that reports its integration missing maps the same way.
	f.aws.mintErr = broker.ErrNotConfigured
	if _, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*")); !errors.As(err, &nc) {
		t.Fatalf("adapter not configured: %v", err)
	}
}

func TestIssueInvalidAndUnsupported(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.svc.Issue(ctx, broker.IssueRequest{AgentID: "claude_code_01", System: "postgres"}); !errors.Is(err, broker.ErrUnsupported) {
		t.Fatalf("postgres: %v", err)
	}
	bad := []broker.IssueRequest{
		{System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: "*"}},
		{AgentID: "claude_code_01", System: "gmail"},
		{AgentID: "claude_code_01", System: "aws"},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "Get*", Resource: "*"}},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "S3", Action: "GetObject", Resource: "*"}},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: "bucket"}},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: `arn:aws:s3:::a" , "Resource":"*`}},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: "*", Region: "mars"}},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: "*", EstCostUSD: -1}},
		{AgentID: "claude_code_01", System: "aws", AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: "*"}, GitHub: &broker.GHRequest{}},
		{AgentID: "claude_code_01", System: "github"},
		{AgentID: "claude_code_01", System: "github", GitHub: &broker.GHRequest{Repos: []string{"acme/api"}}},
		{AgentID: "claude_code_01", System: "github", GitHub: &broker.GHRequest{Permissions: map[string]string{"contents": "read"}}},
		{AgentID: "claude_code_01", System: "github", GitHub: &broker.GHRequest{Repos: []string{"nope"}, Permissions: map[string]string{"contents": "read"}}},
		{AgentID: "claude_code_01", System: "github", GitHub: &broker.GHRequest{Repos: []string{"acme/api"}, Permissions: map[string]string{"contents": "admin"}}},
	}
	for i, req := range bad {
		if _, err := f.svc.Issue(ctx, req); !errors.Is(err, broker.ErrInvalidRequest) {
			t.Errorf("case %d: want ErrInvalidRequest, got %v", i, err)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM actions`); n != 0 {
		t.Fatalf("invalid requests reached Decide: %d", n)
	}
}

func TestIssueGitHubDirectToken(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	req := broker.IssueRequest{AgentID: "claude_code_01", System: "github", GitHub: &broker.GHRequest{
		Repos: []string{"Acme/API"}, Permissions: map[string]string{"contents": "read", "pull_requests": "write"}}}
	f.profile(t, "claude_code_01", "github", `{"repos":["acme/api"],"permissions":{"contents":"write","pull_requests":"write"},"allow_direct_token":false}`)
	r := refusal(t, func() error { _, err := f.svc.Issue(ctx, req); return err }())
	if r.Outcome.Result.RuleID != "POL-024" || !strings.Contains(r.Outcome.Result.Reason, "allow_direct_token") {
		t.Fatalf("got %+v", r.Outcome.Result)
	}
	f.profile(t, "claude_code_01", "github", `{"repos":["acme/api","acme/web"],"permissions":{"contents":"write","pull_requests":"write"},"allow_direct_token":true}`)
	cred, err := f.svc.Issue(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	s := f.github.mints[0]
	if strings.Join(s["repos"].([]string), ",") != "acme/api" || s["permissions"].(map[string]string)["pull_requests"] != "write" ||
		s["permissions"].(map[string]string)["contents"] != "read" || s[broker.ScopeProfileVersion] != 2 {
		t.Fatalf("scope %v", s)
	}
	if n := f.count(t, `SELECT count(*) FROM actions WHERE action_id = $1 AND verb = 'WRITE' AND target->>'operation' = 'credential'`, cred.ActionID); n != 1 {
		t.Fatal("github action verb/target")
	}
	// A read-only request is decided as READ.
	req.GitHub.Permissions = map[string]string{"contents": "read"}
	cred, err = f.svc.Issue(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM actions WHERE action_id = $1 AND verb = 'READ'`, cred.ActionID); n != 1 {
		t.Fatal("read-only github request not READ")
	}
	// Beyond the profile: refused by policy.
	req.GitHub.Repos = []string{"acme/infra"}
	if r := refusal(t, func() error { _, err := f.svc.Issue(ctx, req); return err }()); r.Outcome.Result.RuleID != "POL-024" {
		t.Fatalf("other repo: %+v", r.Outcome.Result)
	}
}

// The adapter's own re-check (or a profile change between decision and
// mint) refuses with BROKER-SCOPE, recorded.
func TestIssueAdapterScopeDenied(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	f.aws.mintErr = &wrapErr{broker.ErrScopeDenied}
	_, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*"))
	r := refusal(t, err)
	if r.Outcome.Result.RuleID != broker.RuleBrokerScope || r.Outcome.Result.Decision != policy.Deny {
		t.Fatalf("got %+v", r.Outcome.Result)
	}
	ev := f.diaryData(t, broker.EventRefused)
	if len(ev) != 1 || ev[0]["rule_id"] != broker.RuleBrokerScope || ev[0]["stage"] != "profile" {
		t.Fatalf("events %v", ev)
	}
}

type wrapErr struct{ inner error }

func (w *wrapErr) Error() string { return "adapter re-check: " + w.inner.Error() }
func (w *wrapErr) Unwrap() error { return w.inner }

func TestIssueMintFailuresNeverReturnCredential(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	f.aws.mintErr = errors.New("AccessDenied: not authorized to perform sts:AssumeRole")
	if _, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*")); !errors.Is(err, broker.ErrMintFailed) {
		t.Fatalf("upstream failure: %v", err)
	}
	f.aws.mintErr = nil
	f.aws.lifetime = 24 * time.Hour
	if _, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*")); !errors.Is(err, broker.ErrMintFailed) {
		t.Fatalf("long-lived credential accepted: %v", err)
	}
	f.aws.lifetime = -time.Minute
	if _, err := f.svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*")); !errors.Is(err, broker.ErrMintFailed) {
		t.Fatalf("expired credential accepted: %v", err)
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances`); n != 0 {
		t.Fatalf("issuances: %d", n)
	}
	if ev := f.diaryData(t, broker.EventRefused); len(ev) != 3 || ev[0]["stage"] != "mint" {
		t.Fatalf("events %v", ev)
	}
}

// A profile narrowed after an issuance applies to the very next one.
func TestNextIssuanceReflectsProfileChange(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_write","services":["s3"]}`)
	if _, err := f.svc.Issue(ctx, awsReq("claude_code_01", "s3", "PutObject", "*")); err != nil {
		t.Fatal(err)
	}
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	if r := refusal(t, func() error { _, err := f.svc.Issue(ctx, awsReq("claude_code_01", "s3", "PutObject", "*")); return err }()); r.Outcome.Result.RuleID != "POL-021" {
		t.Fatalf("got %+v", r.Outcome.Result)
	}
}

// stubDecider returns a fixed outcome (the real bundle has no allow_reduced
// path for credentials) and records the action like Decide would.
type stubDecider struct {
	pool       *pgxpool.Pool
	res        policy.Result
	failClosed bool
}

func (s *stubDecider) Decide(ctx context.Context, a action.Action) (decide.Outcome, error) {
	a.Normalize(time.Now())
	_, err := s.pool.Exec(ctx, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, source, target, payload_summary, decision_json, ts)
		VALUES ($1, $2, $3, $4, 'h', $5, $6, $7, $8, $9, '{}', '{}', '{}', now())`,
		a.ActionID, a.AgentID, a.System, string(a.Verb), string(s.res.Class), string(s.res.Decision), s.res.RuleID, s.res.Reason, a.Source)
	return decide.Outcome{Action: a, Result: s.res, FailClosed: s.failClosed}, err
}

// A fail-closed outcome that still allows a green read (the allowlist)
// never yields a credential.
func TestFailClosedAllowNeverMints(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_write","services":["s3"]}`)
	stub := &stubDecider{pool: f.pool, failClosed: true,
		res: policy.Result{Class: policy.Green, Decision: policy.Allow, RuleID: "FAIL-CLOSED", Reason: "store unavailable; green read allowlisted"}}
	svc := broker.New(stub, f.pool, f.d, f.acc, map[string]broker.Adapter{"aws": f.aws}, nil)
	_, err := svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "GetObject", "*"))
	r := refusal(t, err)
	if r.Outcome.Result.Decision != policy.Deny || !strings.Contains(r.Outcome.Result.Reason, "fail-closed") {
		t.Fatalf("got %+v", r.Outcome.Result)
	}
	if len(f.aws.mints) != 0 {
		t.Fatal("minted on a fail-closed outcome")
	}
}

func TestAllowReducedRefusedUnlessAdapterSupportsIt(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_write","services":["s3"]}`)
	stub := &stubDecider{pool: f.pool, res: policy.Result{Class: policy.Yellow, Decision: policy.AllowReduced, RuleID: "POL-999",
		Reason: "test reduced", ReducedForm: map[string]any{"delay_send_seconds": 60}}}
	svc := broker.New(stub, f.pool, f.d, f.acc, map[string]broker.Adapter{"aws": f.aws}, nil)
	_, err := svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "PutObject", "*"))
	r := refusal(t, err)
	if r.Outcome.Result.Decision != policy.AllowReduced || !strings.Contains(r.Outcome.Result.Reason, "no reduced form is meaningful") {
		t.Fatalf("got %+v", r.Outcome.Result)
	}
	if len(f.aws.mints) != 0 {
		t.Fatal("minted under allow_reduced")
	}
	f.aws.reduced = true
	if _, err := svc.Issue(context.Background(), awsReq("claude_code_01", "s3", "PutObject", "*")); err != nil {
		t.Fatalf("adapter supporting the reduced form: %v", err)
	}
}

func TestRecordIssuance(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	c := broker.Credential{System: "gmail", ExpiresAt: time.Now().Add(time.Hour), Scope: map[string]any{"scopes": []string{"gmail.send"}},
		Secret: map[string]string{"access_token": secretMarker}}
	if err := f.svc.RecordIssuance(ctx, c, "claude_code_01", ""); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE system = 'gmail' AND action_id IS NULL AND instance_id IS NULL`); n != 1 {
		t.Fatal("row missing")
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE body_json LIKE '%'||$1||'%'`, secretMarker); n != 0 {
		t.Fatal("secret in Diary")
	}
	if ev := f.diaryData(t, broker.EventIssued); len(ev) != 1 || ev[0]["system"] != "gmail" {
		t.Fatalf("events %v", ev)
	}
	for _, bad := range []broker.Credential{{System: "gmail"}, {System: "gmail", ExpiresAt: time.Now().Add(-time.Second)},
		{System: "gmail", ExpiresAt: time.Now().Add(48 * time.Hour)}, {ExpiresAt: time.Now().Add(time.Hour)}} {
		if err := f.svc.RecordIssuance(ctx, bad, "claude_code_01", ""); !errors.Is(err, broker.ErrInvalidRequest) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if err := f.svc.RecordIssuance(ctx, c, "", ""); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Errorf("no agent: %v", err)
	}
}

func TestRevokeAll(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	if _, err := f.svc.Issue(ctx, awsReq("claude_code_01", "s3", "GetObject", "*")); err != nil {
		t.Fatal(err)
	}
	// A GitHub issuance recorded in-process, and a Google one with no adapter here.
	for _, sys := range []string{"github", "gmail"} {
		if err := f.svc.RecordIssuance(ctx, broker.Credential{System: sys, ExpiresAt: time.Now().Add(time.Hour), Secret: map[string]string{"t": "x"}}, "claude_code_01", ""); err != nil {
			t.Fatal(err)
		}
	}
	// Another agent's credential is untouched.
	if err := f.svc.RecordIssuance(ctx, broker.Credential{System: "aws", ExpiresAt: time.Now().Add(time.Hour)}, "ops_agent:02", ""); err != nil {
		t.Fatal(err)
	}
	f.github.revokeErr = errors.New("github said 502\nretry later")
	got, err := f.svc.RevokeAll(ctx, "claude_code_01", "user:sec@acme.com", "quarantined after swarm alert")
	if err == nil || !strings.Contains(err.Error(), "github") {
		t.Fatalf("want joined github error, got %v", err)
	}
	if got["aws"] != "aws: revoked for real (fake)" || !strings.HasPrefix(got["github"], "revocation FAILED: github said 502 retry later") ||
		!strings.Contains(got["gmail"], "no revocation adapter registered") {
		t.Fatalf("results %v", got)
	}
	if len(f.aws.revoked) != 1 || f.aws.revoked[0] != "claude_code_01" {
		t.Fatalf("aws revoke calls %v", f.aws.revoked)
	}
	// Only the system whose revocation succeeded is marked revoked.
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE agent_id = 'claude_code_01' AND system = 'aws'
		AND revoked_at IS NOT NULL AND revoke_method = 'aws: revoked for real (fake)'`); n != 1 {
		t.Fatal("aws issuance not marked")
	}
	if n := f.count(t, `SELECT count(*) FROM credential_issuances WHERE revoked_at IS NOT NULL`); n != 1 {
		t.Fatalf("marked %d issuances, want only the aws one", n)
	}
	ev := f.diaryData(t, broker.EventRevoked)
	if len(ev) != 3 {
		t.Fatalf("revoked events %v", ev)
	}
	bySys := map[string]map[string]any{}
	for _, e := range ev {
		bySys[e["system"].(string)] = e
	}
	if bySys["aws"]["succeeded"] != true || bySys["aws"]["issuances_marked"] != float64(1) || bySys["aws"]["reason"] != "quarantined after swarm alert" {
		t.Fatalf("aws event %v", bySys["aws"])
	}
	if bySys["github"]["succeeded"] != false || bySys["gmail"]["succeeded"] != false {
		t.Fatalf("events %v", bySys)
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type = 'credential.revoked' AND actor = 'user:sec@acme.com'`); n != 3 {
		t.Fatal("actor not recorded")
	}
	if _, err := f.svc.RevokeAll(ctx, "", "user:x", "r"); !errors.Is(err, broker.ErrInvalidRequest) {
		t.Fatalf("no agent: %v", err)
	}
}

// An unconfigured system with no live credentials has honestly nothing to
// revoke; with live credentials recorded it is still a failed revocation.
func TestRevokeAllUnconfiguredSystem(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.aws.revokeErr = fmt.Errorf("%w: aws", broker.ErrNotConfigured)
	got, err := f.svc.RevokeAll(ctx, "claude_code_01", "user:sec@acme.com", "suspended")
	if err != nil || !strings.Contains(got["aws"], "nothing to revoke") {
		t.Fatalf("no issuances: %v %v", got, err)
	}
	if err := f.svc.RecordIssuance(ctx, broker.Credential{System: "aws", ExpiresAt: time.Now().Add(time.Hour)}, "claude_code_01", ""); err != nil {
		t.Fatal(err)
	}
	got, err = f.svc.RevokeAll(ctx, "claude_code_01", "user:sec@acme.com", "suspended")
	if err == nil || !strings.HasPrefix(got["aws"], "revocation FAILED") {
		t.Fatalf("live issuance on an unconfigured system must fail: %v %v", got, err)
	}
}
