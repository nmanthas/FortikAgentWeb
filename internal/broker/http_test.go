package broker_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fortik/internal/authz"
	"fortik/internal/broker"
)

func issueServer(t *testing.T, b broker.Broker, who *authz.Principal) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	broker.NewHandler(b, nil).Register(mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if who != nil {
			r = r.WithContext(authz.With(r.Context(), *who))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func post(t *testing.T, srv *httptest.Server, body string) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Post(srv.URL+"/v1/credentials/issue", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

const s3Get = `{"system":"aws","aws":{"service":"s3","action":"GetObject","resource":"arn:aws:s3:::reports/q3.csv","region":"eu-west-1"}}`

func TestIssueHandler(t *testing.T) {
	f := setup(t)
	agent := &authz.Principal{Kind: authz.KindAgent, Name: "claude_code_01", InstanceID: "inst-9", AuthMethod: "agent_token"}

	// 403 fortik_refused with the action id (no profile yet).
	resp, body := post(t, issueServer(t, f.svc, agent), s3Get)
	if resp.StatusCode != 403 {
		t.Fatalf("status %d %v", resp.StatusCode, body)
	}
	e := body["error"].(map[string]any)
	if e["code"] != "fortik_refused" || e["decision"] != "deny" || e["class"] != "green" || e["rule_id"] != "POL-020" ||
		e["held"] != false || e["action_id"] == "" || resp.Header.Get("X-Fortik-Action-Id") != e["action_id"] || e["reason"] == "" {
		t.Fatalf("refusal body %v headers %v", e, resp.Header)
	}
	// The agent identity came from the principal, never the body.
	if n := f.count(t, `SELECT count(*) FROM actions WHERE action_id = $1 AND agent_id = 'claude_code_01' AND instance_id = 'inst-9'`, e["action_id"]); n != 1 {
		t.Fatal("action not attributed to the authenticated agent")
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type = 'action.decided' AND actor = 'agent:claude_code_01'`); n != 1 {
		t.Fatal("decision actor is not the authenticated agent")
	}

	// 200 with the credential once the profile allows it.
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	resp, body = post(t, issueServer(t, f.svc, agent), s3Get)
	if resp.StatusCode != 200 || body["issuance_id"] == "" || body["system"] != "aws" || body["secret"].(map[string]any)["token"] != secretMarker ||
		resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status %d %v", resp.StatusCode, body)
	}

	// 503 integration_not_configured.
	bare := broker.New(f.dec, f.pool, f.d, f.acc, nil, nil)
	resp, body = post(t, issueServer(t, bare, agent), s3Get)
	e, _ = body["error"].(map[string]any)
	if resp.StatusCode != 503 || e["code"] != "integration_not_configured" || e["system"] != "aws" || resp.Header.Get("X-Fortik-Action-Id") == "" {
		t.Fatalf("status %d %v", resp.StatusCode, body)
	}

	// 400s: unknown fields (including attempts to name another agent), bad shapes, postgres.
	for _, b := range []string{
		`{"system":"aws","agent_id":"finance_agent_07","aws":{"service":"s3","action":"GetObject","resource":"*"}}`,
		`{"system":"aws","aws":{"service":"s3","action":"GetObject","resource":"*","extra":1}}`,
		`{"system":"aws"}`,
		`{"system":"postgres"}`,
		`not json`,
		s3Get + `{}`,
	} {
		if resp, body := post(t, issueServer(t, f.svc, agent), b); resp.StatusCode != 400 {
			t.Errorf("%s: status %d %v", b, resp.StatusCode, body)
		}
	}
}

func TestIssueHandlerRequiresAgentPrincipal(t *testing.T) {
	f := setup(t)
	if resp, _ := post(t, issueServer(t, f.svc, nil), s3Get); resp.StatusCode != 401 {
		t.Fatalf("anonymous: %d", resp.StatusCode)
	}
	for _, p := range []authz.Principal{
		{Kind: authz.KindUser, Email: "jane@acme.com", Name: "claude_code_01", Roles: map[string]bool{authz.RoleAdmin: true}},
		{Kind: authz.KindToken, Name: "claude_code_01", Roles: map[string]bool{authz.RoleAdmin: true}},
		{Kind: authz.KindAgent},
	} {
		if resp, _ := post(t, issueServer(t, f.svc, &p), s3Get); resp.StatusCode != 403 {
			t.Fatalf("%+v: %d", p, resp.StatusCode)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM actions`); n != 0 {
		t.Fatalf("non-agent callers reached Decide: %d", n)
	}
}

func TestIssueHandlerMintFailureIs502WithoutDetails(t *testing.T) {
	f := setup(t)
	f.profile(t, "claude_code_01", "aws", `{"mode":"read_only","services":["s3"]}`)
	f.aws.mintErr = &wrapErr{inner: http.ErrHandlerTimeout}
	agent := &authz.Principal{Kind: authz.KindAgent, Name: "claude_code_01"}
	resp, body := post(t, issueServer(t, f.svc, agent), s3Get)
	if resp.StatusCode != 502 || body["error"] != "credential issuance failed upstream" {
		t.Fatalf("status %d %v", resp.StatusCode, body)
	}
}
