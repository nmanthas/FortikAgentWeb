package aws_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"fortik/internal/access"
	"fortik/internal/broker"
	brokeraws "fortik/internal/broker/aws"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/testutil"
)

var fixedNow = time.Date(2026, 10, 8, 12, 30, 45, 0, time.UTC)

func newAdapter(t *testing.T, src integrations.Source) *brokeraws.Adapter {
	t.Helper()
	a := brokeraws.New(src, 15*time.Minute, slog.New(slog.NewTextHandler(io.Discard, nil)))
	a.Now = func() time.Time { return fixedNow }
	return a
}

func scope(profile, service, act, resource, region string) map[string]any {
	return map[string]any{
		"service": service, "action": act, "iam_action": service + ":" + act, "resource": resource, "region": region,
		broker.ScopeProfile: json.RawMessage(profile), broker.ScopeProfileVersion: 4,
	}
}

const rwS3 = `{"mode":"read_write","services":["s3","ec2"],"denied_actions":["s3:delete*","iam:*"]}`

func TestMintAssumesRoleWithExactSessionPolicy(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, map[string]string{"external_id": "ext-123"})})
	cred, err := a.Mint(context.Background(), "claude_code_01", scope(rwS3, "s3", "GetObject", "arn:aws:s3:::reports/q3.csv", "eu-west-1"), 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := fake.all()
	if len(calls) != 1 || calls[0].Action != "AssumeRole" {
		t.Fatalf("calls %+v", calls)
	}
	f := calls[0].Form
	wantPolicy := `{"Version":"2012-10-17","Statement":[{"Sid":"FortikExactAction","Effect":"Allow","Action":"s3:GetObject",` +
		`"Resource":"arn:aws:s3:::reports/q3.csv","Condition":{"StringEquals":{"aws:RequestedRegion":"eu-west-1"}}}]}`
	if got := f.Get("Policy"); got != wantPolicy {
		t.Fatalf("session policy\n got %s\nwant %s", got, wantPolicy)
	}
	if f.Get("SourceIdentity") != "claude_code_01" || f.Get("DurationSeconds") != "900" || f.Get("RoleArn") != roleARN || f.Get("ExternalId") != "ext-123" {
		t.Fatalf("form %v", f)
	}
	if !regexp.MustCompile(`^fortik-claude_code_01-[0-9a-f]{8}$`).MatchString(f.Get("RoleSessionName")) {
		t.Fatalf("session name %q", f.Get("RoleSessionName"))
	}
	if calls[0].AccessKey != fortikKey {
		t.Fatalf("signed with %q", calls[0].AccessKey)
	}
	if cred.System != "aws" || cred.Secret["access_key_id"] != fakeSessionKey || cred.Secret["secret_access_key"] != fakeSessionSecret ||
		cred.Secret["session_token"] != fakeSessionToken || len(cred.Secret) != 3 {
		t.Fatalf("secret %v", cred.Secret)
	}
	if d := time.Until(cred.ExpiresAt); d < 14*time.Minute || d > 16*time.Minute {
		t.Fatalf("expires in %s", d)
	}
	sc := cred.Scope
	if sc["iam_action"] != "s3:GetObject" || sc["source_identity"] != "claude_code_01" || sc["duration_seconds"] != 900 ||
		sc["session_policy"] != wantPolicy || sc["role_arn"] != roleARN || sc[broker.ScopeProfileVersion] != 4 {
		t.Fatalf("scope %v", sc)
	}
	// Fortik's own long-lived key never appears in what the agent receives.
	b, _ := json.Marshal(cred)
	if strings.Contains(string(b), fortikSecret) || strings.Contains(string(b), fortikKey) {
		t.Fatal("Fortik's credentials leaked into the issued credential")
	}
}

func TestMintWithoutRegionHasNoCondition(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	if _, err := a.Mint(context.Background(), "claude_code_01", scope(rwS3, "ec2", "DescribeInstances", "*", ""), 0); err != nil {
		t.Fatal(err)
	}
	f := fake.all()[0].Form
	if f.Get("Policy") != `{"Version":"2012-10-17","Statement":[{"Sid":"FortikExactAction","Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}` {
		t.Fatalf("policy %s", f.Get("Policy"))
	}
	if _, set := f["ExternalId"]; set {
		t.Fatal("ExternalId sent although not configured")
	}
}

func TestMintDuration(t *testing.T) {
	cases := []struct {
		def, ttl time.Duration
		want     string
	}{
		{15 * time.Minute, 0, "900"},
		{30 * time.Minute, 0, "1800"},
		{0, 0, "900"},
		{15 * time.Minute, 5 * time.Minute, "900"},
		{15 * time.Minute, 2 * time.Hour, "7200"},
		{15 * time.Minute, 48 * time.Hour, "43200"},
		{time.Minute, 0, "900"},
	}
	for _, c := range cases {
		fake := newFakeAWS(t)
		a := brokeraws.New(&fakeSource{r: resolved(fake.srv.URL, nil)}, c.def, nil)
		if _, err := a.Mint(context.Background(), "claude_code_01", scope(rwS3, "s3", "GetObject", "*", ""), c.ttl); err != nil {
			t.Fatal(err)
		}
		if got := fake.all()[0].Form.Get("DurationSeconds"); got != c.want {
			t.Errorf("default %s ttl %s: DurationSeconds %s want %s", c.def, c.ttl, got, c.want)
		}
	}
}

// Defence in depth: the adapter refuses anything its profile forbids and
// never calls STS for it.
func TestMintRefusesWhatTheProfileForbids(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	cases := []map[string]any{
		scope(`{"mode":"read_only","services":["s3"]}`, "s3", "PutObject", "*", ""),
		scope(`{"mode":"none","services":["s3"]}`, "s3", "GetObject", "*", ""),
		scope(rwS3, "dynamodb", "GetItem", "*", ""),
		scope(rwS3, "s3", "DeleteObject", "*", ""),
		scope(`{"mode":"read_write","services":["s3"],"denied_actions":["*"]}`, "s3", "GetObject", "*", ""),
		scope(`{"mode":"bogus","services":["s3"]}`, "s3", "GetObject", "*", ""),
		{"service": "s3", "action": "GetObject", "resource": "*"}, // no profile
		scope(rwS3, "s3", "Get*", "*", ""),
		scope(rwS3, "s3", "GetObject", "bucket-name", ""),
		scope(rwS3, "s3", "GetObject", `arn:aws:s3:::x","Resource":"*`, ""),
		scope(rwS3, "s3", "GetObject", "*", "moon-1"),
	}
	for i, sc := range cases {
		if _, err := a.Mint(context.Background(), "claude_code_01", sc, 0); !errors.Is(err, broker.ErrScopeDenied) {
			t.Errorf("case %d: want ErrScopeDenied, got %v", i, err)
		}
	}
	if n := len(fake.all()); n != 0 {
		t.Fatalf("STS called %d times for forbidden scopes", n)
	}
}

func TestMintNotConfigured(t *testing.T) {
	sc := scope(rwS3, "s3", "GetObject", "*", "")
	a := newAdapter(t, &fakeSource{})
	if _, err := a.Mint(context.Background(), "claude_code_01", sc, 0); !errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("absent integration: %v", err)
	}
	r := resolved("http://127.0.0.1:1", nil)
	delete(r.Secrets, "secret_access_key")
	if _, err := newAdapter(t, &fakeSource{r: r}).Mint(context.Background(), "claude_code_01", sc, 0); !errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("missing secret: %v", err)
	}
	r = resolved("http://127.0.0.1:1", nil)
	r.ConfigMap["role_arn"] = "arn:aws:iam::123:user/bob"
	_, err := newAdapter(t, &fakeSource{r: r}).Mint(context.Background(), "claude_code_01", sc, 0)
	if !errors.Is(err, integrations.ErrInvalid) || errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("bad role arn: %v", err)
	}
	r = resolved("ftp://example", nil)
	if _, err := newAdapter(t, &fakeSource{r: r}).Mint(context.Background(), "claude_code_01", sc, 0); !errors.Is(err, integrations.ErrInvalid) {
		t.Fatalf("bad endpoint: %v", err)
	}
}

func TestMintUpstreamErrorIsSummarisedWithoutSecrets(t *testing.T) {
	fake := newFakeAWS(t)
	fake.failWith = "AccessDenied"
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	_, err := a.Mint(context.Background(), "claude_code_01", scope(rwS3, "s3", "GetObject", "*", ""), 0)
	if err == nil || !strings.Contains(err.Error(), "AccessDenied: User is not authorized") {
		t.Fatalf("got %v", err)
	}
	if errors.Is(err, broker.ErrScopeDenied) || errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("upstream failure misclassified: %v", err)
	}
	if strings.Contains(err.Error(), fortikSecret) || strings.Contains(err.Error(), fortikKey) {
		t.Fatal("error leaks credentials")
	}
}

func TestRevokeAgentAttachesDenyByIssueTime(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	desc, err := a.RevokeAgent(context.Background(), "claude_code_01")
	if err != nil {
		t.Fatal(err)
	}
	calls := fake.all()
	if len(calls) != 2 || calls[0].Action != "GetRolePolicy" || calls[1].Action != "PutRolePolicy" || calls[1].AccessKey != fortikKey {
		t.Fatalf("calls %+v", calls)
	}
	f := calls[1].Form
	sid := "FortikRevoke" + fmt.Sprintf("%x", sha256.Sum256([]byte("claude_code_01")))[:8]
	wantDoc := `{"Version":"2012-10-17","Statement":[{"Sid":"` + sid + `","Effect":"Deny","Action":"*","Resource":"*",` +
		`"Condition":{"DateLessThan":{"aws:TokenIssueTime":"2026-10-08T12:31:45Z"},"StringEquals":{"aws:SourceIdentity":"claude_code_01"}}}]}`
	if f.Get("RoleName") != "fortik-agents" || f.Get("PolicyName") != brokeraws.RevokePolicyName || f.Get("PolicyDocument") != wantDoc {
		t.Fatalf("form %v\nwant doc %s", f, wantDoc)
	}
	for _, want := range []string{"not recallable", "deny-by-issue-time", brokeraws.RevokePolicyName, "fortik-agents", "aws:SourceIdentity=claude_code_01", "2026-10-08T12:31:45Z"} {
		if !strings.Contains(desc, want) {
			t.Fatalf("description %q lacks %q", desc, want)
		}
	}
	// A later revocation moves the cut-off forward, never back.
	a.Now = func() time.Time { return fixedNow.Add(time.Hour) }
	if _, err := a.RevokeAgent(context.Background(), "claude_code_01"); err != nil {
		t.Fatal(err)
	}
	if doc := fake.all()[3].Form.Get("PolicyDocument"); !strings.Contains(doc, `"aws:TokenIssueTime":"2026-10-08T13:31:45Z"`) || strings.Count(doc, "FortikRevoke") != 1 {
		t.Fatalf("doc %s", doc)
	}
	fake.failWith = "AccessDenied"
	if _, err := a.RevokeAgent(context.Background(), "claude_code_01"); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("failure: %v", err)
	}
	if _, err := newAdapter(t, &fakeSource{}).RevokeAgent(context.Background(), "claude_code_01"); !errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}

// Regression: revocations share one bounded inline policy (IAM caps a role's
// inline policies at 10,240 characters), keep every agent revoked within the
// STS maximum session lifetime, and prune expired entries.
func TestRevokeManyAgentsStaysWithinIAMLimit(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	ctx := context.Background()
	names := map[string]bool{}
	for i := range 200 {
		if _, err := a.RevokeAgent(ctx, fmt.Sprintf("agent_%03d", i)); err != nil {
			t.Fatal(err)
		}
	}
	var last string
	for _, c := range fake.all() {
		if c.Action == "PutRolePolicy" {
			names[c.Form.Get("PolicyName")] = true
			last = c.Form.Get("PolicyDocument")
			if len(last) > 10240 {
				t.Fatalf("revocation policy %d chars exceeds the IAM inline limit", len(last))
			}
		}
	}
	if len(names) != 1 {
		t.Fatalf("inline policies %v", names)
	}
	for i := range 200 {
		if !strings.Contains(last, fmt.Sprintf(`"agent_%03d"`, i)) {
			t.Fatalf("agent_%03d no longer revoked", i)
		}
	}
	// 13 h later every earlier entry has expired and is pruned.
	a.Now = func() time.Time { return fixedNow.Add(13 * time.Hour) }
	if _, err := a.RevokeAgent(ctx, "late"); err != nil {
		t.Fatal(err)
	}
	calls := fake.all()
	doc := calls[len(calls)-1].Form.Get("PolicyDocument")
	if strings.Contains(doc, "agent_") || !strings.Contains(doc, `"late"`) {
		t.Fatalf("not pruned: %s", doc)
	}
}

func TestMintRefusesSTSCredentialActions(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	prof := `{"mode":"read_write","services":["sts"]}`
	for _, act := range []string{"AssumeRole", "assumerole", "AssumeRoleWithWebIdentity", "GetFederationToken", "GetSessionToken", "TagSession", "SetSourceIdentity"} {
		if _, err := a.Mint(context.Background(), "claude_code_01", scope(prof, "sts", act, "*", ""), 0); !errors.Is(err, broker.ErrScopeDenied) {
			t.Errorf("sts:%s: %v", act, err)
		}
	}
	if len(fake.all()) != 0 {
		t.Fatal("AWS was called")
	}
}

func TestSourceIdentity(t *testing.T) {
	cases := map[string]string{
		"claude_code_01": "claude_code_01",
		"a.b@c-d":        "a.b@c-d",
	}
	for in, want := range cases {
		if got := brokeraws.SourceIdentity(in); got != want {
			t.Errorf("%q: %q want %q", in, got, want)
		}
	}
	valid := regexp.MustCompile(`^[A-Za-z0-9_+=,.@-]{2,64}$`)
	for _, in := range []string{"ops:agent", "x", strings.Repeat("a", 64), strings.Repeat("b", 65), strings.Repeat("c:", 64), "a:b", "a_b"} {
		got := brokeraws.SourceIdentity(in)
		if !valid.MatchString(got) {
			t.Errorf("%q -> %q is not a valid SourceIdentity", in, got)
		}
		if got != brokeraws.SourceIdentity(in) {
			t.Errorf("%q not deterministic", in)
		}
	}
	// Distinct agents never collapse to one identity, including an id that
	// spells out another id's hashed form.
	if h := brokeraws.SourceIdentity("a:b"); brokeraws.SourceIdentity(h) == h {
		t.Fatalf("literal id %q maps to the same identity as a:b", h)
	}
	if brokeraws.SourceIdentity("a:b") == brokeraws.SourceIdentity("a_b") {
		t.Fatal("a:b and a_b share an identity")
	}
}

func TestSessionNameFitsForLongIDs(t *testing.T) {
	fake := newFakeAWS(t)
	a := newAdapter(t, &fakeSource{r: resolved(fake.srv.URL, nil)})
	long := "agent:" + strings.Repeat("x", 100)
	if _, err := a.Mint(context.Background(), long, scope(rwS3, "s3", "GetObject", "*", ""), 0); err != nil {
		t.Fatal(err)
	}
	f := fake.all()[0].Form
	if n := len(f.Get("RoleSessionName")); n > 64 || !regexp.MustCompile(`^[\w+=,.@-]+$`).MatchString(f.Get("RoleSessionName")) {
		t.Fatalf("session name %q (%d)", f.Get("RoleSessionName"), n)
	}
	if f.Get("SourceIdentity") != brokeraws.SourceIdentity(long) || len(f.Get("SourceIdentity")) > 64 {
		t.Fatalf("source identity %q", f.Get("SourceIdentity"))
	}
}

func TestTester(t *testing.T) {
	fake := newFakeAWS(t)
	tester := brokeraws.NewTester()
	if tester.System() != "aws" {
		t.Fatal(tester.System())
	}
	if err := tester.Test(context.Background(), *resolved(fake.srv.URL, nil)); err != nil {
		t.Fatal(err)
	}
	calls := fake.all()
	if len(calls) != 2 || calls[0].Action != "AssumeRole" || calls[1].Action != "GetCallerIdentity" {
		t.Fatalf("calls %+v", calls)
	}
	if calls[0].Form.Get("Policy") != `{"Version":"2012-10-17","Statement":[{"Sid":"FortikConnectionTest","Effect":"Allow","Action":"sts:GetCallerIdentity","Resource":"*"}]}` ||
		calls[0].Form.Get("SourceIdentity") != "fortik-connection-test" || calls[0].Form.Get("DurationSeconds") != "900" || calls[0].AccessKey != fortikKey {
		t.Fatalf("assume role %+v", calls[0])
	}
	// The identity check runs with the assumed session, not Fortik's keys.
	if calls[1].AccessKey != fakeSessionKey || calls[1].SecurityToken != fakeSessionToken {
		t.Fatalf("caller identity signed with %q token %q", calls[1].AccessKey, calls[1].SecurityToken)
	}
	fake.failWith = "AccessDenied"
	err := tester.Test(context.Background(), *resolved(fake.srv.URL, nil))
	if err == nil || !strings.Contains(err.Error(), "AccessDenied") || strings.Contains(err.Error(), fortikSecret) {
		t.Fatalf("failure: %v", err)
	}
	r := resolved(fake.srv.URL, nil)
	r.ConfigMap["region"] = ""
	if err := tester.Test(context.Background(), *r); !errors.Is(err, integrations.ErrInvalid) {
		t.Fatalf("missing region: %v", err)
	}
}

// End to end through the broker: real decide.Service, real policy bundle,
// real Postgres, AWS faked. The issued credential is recorded without any
// secret, and RevokeAll attaches the deny policy and marks the issuance.
func TestBrokerIssueAndRevokeThroughAWSAdapter(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, file, _, _ := runtime.Caller(0)
	eng, err := policy.NewEngine(ctx, filepath.Join(filepath.Dir(file), "..", "..", "..", "policies"), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	if _, err := ctl.Register(ctx, control.Agent{AgentID: "claude_code_01", Type: "test", Sponsor: "jane@acme.com"}, "test"); err != nil {
		t.Fatal(err)
	}
	acc := access.NewPGStore(pool, d)
	if _, err := acc.Put(ctx, "claude_code_01", "aws", json.RawMessage(`{"mode":"read_only","services":["s3"]}`), "user:sec@acme.com", "s3 reads"); err != nil {
		t.Fatal(err)
	}
	fake := newFakeAWS(t)
	adapter := brokeraws.New(&fakeSource{r: resolved(fake.srv.URL, nil)}, 15*time.Minute, log)
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc}
	svc := broker.New(dec, pool, d, acc, map[string]broker.Adapter{"aws": adapter}, log)

	cred, err := svc.Issue(ctx, broker.IssueRequest{AgentID: "claude_code_01", System: "aws",
		AWS: &broker.AWSRequest{Service: "s3", Action: "GetObject", Resource: "arn:aws:s3:::reports/*", Region: "eu-west-1"}})
	if err != nil {
		t.Fatal(err)
	}
	if cred.Secret["session_token"] != fakeSessionToken {
		t.Fatalf("credential %+v", cred)
	}
	// A write is refused by policy before STS is ever called.
	_, err = svc.Issue(ctx, broker.IssueRequest{AgentID: "claude_code_01", System: "aws",
		AWS: &broker.AWSRequest{Service: "s3", Action: "PutObject", Resource: "arn:aws:s3:::reports/x"}})
	var ref *broker.Refusal
	if !errors.As(err, &ref) || ref.Outcome.Result.RuleID != "POL-021" {
		t.Fatalf("write: %v", err)
	}
	if n := len(fake.all()); n != 1 {
		t.Fatalf("STS calls %d", n)
	}
	var leaks int
	if err := pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM diary WHERE body_json LIKE '%'||$1||'%' OR body_json LIKE '%'||$2||'%' OR body_json LIKE '%'||$3||'%')
		+ (SELECT count(*) FROM credential_issuances WHERE scope_json::text LIKE '%'||$1||'%' OR scope_json::text LIKE '%'||$2||'%')`,
		fakeSessionSecret, fakeSessionToken, fortikSecret).Scan(&leaks); err != nil || leaks != 0 {
		t.Fatalf("secret material stored (%d) %v", leaks, err)
	}

	got, err := svc.RevokeAll(ctx, "claude_code_01", "user:sec@acme.com", "quarantined")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got["aws"], "not recallable") {
		t.Fatalf("revocation %v", got)
	}
	calls := fake.all()
	if last := calls[len(calls)-1]; last.Action != "PutRolePolicy" || !strings.Contains(last.Form.Get("PolicyDocument"), `"aws:SourceIdentity":"claude_code_01"`) {
		t.Fatalf("revoke call %+v", last)
	}
	var method string
	if err := pool.QueryRow(ctx, `SELECT revoke_method FROM credential_issuances WHERE issuance_id = $1 AND revoked_at IS NOT NULL`, cred.IssuanceID).Scan(&method); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(method, "deny-by-issue-time") {
		t.Fatalf("revoke_method %q", method)
	}
}
