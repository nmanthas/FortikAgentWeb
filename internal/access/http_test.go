package access_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fortik/internal/access"
	"fortik/internal/authz"
)

var (
	security = authz.Principal{Kind: authz.KindUser, Email: "sec@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	auditor  = authz.Principal{Kind: authz.KindUser, Email: "audit@acme.com", Roles: map[string]bool{authz.RoleAuditor: true}}
	owner    = authz.Principal{Kind: authz.KindUser, Email: "jane@acme.com"} // sponsor of claude_code_01 (case-insensitive)
	stranger = authz.Principal{Kind: authz.KindUser, Email: "eve@acme.com"}
	admin    = authz.Principal{Kind: authz.KindToken, Name: "ops", Roles: map[string]bool{authz.RoleAdmin: true}}
	// A service token whose name equals the sponsor email is not an owner.
	tokenNamedOwner = authz.Principal{Kind: authz.KindToken, Name: "jane@acme.com", Email: "jane@acme.com"}
)

type api struct {
	t   *testing.T
	f   fixture
	srv *httptest.Server
	who *authz.Principal
}

func newAPI(t *testing.T) *api {
	f := setup(t)
	a := &api{t: t, f: f}
	mux := http.NewServeMux()
	access.NewHandler(f.store, f.pool, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.who != nil {
			r = r.WithContext(authz.With(r.Context(), *a.who))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(a.srv.Close)
	return a
}

func (a *api) do(p *authz.Principal, method, path, body string) (int, map[string]any) {
	a.t.Helper()
	a.who = p
	req, _ := http.NewRequest(method, a.srv.URL+path, strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		a.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

const pgPath = "/v1/agents/claude_code_01/access/postgres"

func TestAccessAPIAuthorization(t *testing.T) {
	a := newAPI(t)
	broad := `{"profile":{"upstreams":{"acme_prod":"read_write","acme_staging":"read_write"}},"reason":"onboarding"}`

	if code, _ := a.do(nil, "GET", "/v1/agents/claude_code_01/access", ""); code != 401 {
		t.Fatalf("anonymous GET: %d", code)
	}
	if code, _ := a.do(&stranger, "GET", "/v1/agents/claude_code_01/access", ""); code != 403 {
		t.Fatalf("stranger GET: %d", code)
	}
	for _, p := range []*authz.Principal{&auditor, &owner, &security, &admin} {
		code, body := a.do(p, "GET", "/v1/agents/claude_code_01/access", "")
		if code != 200 {
			t.Fatalf("%s GET: %d %v", p.Actor(), code, body)
		}
		profiles := body["profiles"].([]any)
		if len(profiles) != len(access.Systems) {
			t.Fatalf("profiles: %v", profiles)
		}
		first := profiles[0].(map[string]any)
		if first["system"] != "gmail" || first["version"] != float64(0) || first["profile"] != nil {
			t.Fatalf("empty profile view: %v", first)
		}
	}
	// Writes: auditors, strangers and look-alike tokens may not; security may widen.
	for _, p := range []*authz.Principal{&auditor, &stranger, &tokenNamedOwner} {
		if code, _ := a.do(p, "PUT", pgPath, broad); code != 403 {
			t.Fatalf("%s PUT: %d", p.Actor(), code)
		}
	}
	// The owner may not widen from nothing.
	code, body := a.do(&owner, "PUT", pgPath, broad)
	if code != 403 || !strings.Contains(body["error"].(string), "widening requires the security role") {
		t.Fatalf("owner widen: %d %v", code, body)
	}
	code, body = a.do(&security, "PUT", pgPath, broad)
	if code != 200 || body["version"] != float64(1) || body["changed_by"] != "user:sec@acme.com" {
		t.Fatalf("security PUT: %d %v", code, body)
	}
	// The owner may narrow...
	code, body = a.do(&owner, "PUT", pgPath, `{"profile":{"upstreams":{"acme_prod":"read_only"}},"reason":"prod reads only"}`)
	if code != 200 || body["version"] != float64(2) || body["changed_by"] != "user:jane@acme.com" {
		t.Fatalf("owner narrow: %d %v", code, body)
	}
	// ...but not widen back, nor revert to the broader version.
	if code, _ := a.do(&owner, "PUT", pgPath, broad); code != 403 {
		t.Fatalf("owner re-widen: %d", code)
	}
	if code, _ := a.do(&owner, "POST", pgPath+"/revert", `{"version":1,"reason":"undo"}`); code != 403 {
		t.Fatalf("owner widening revert: %d", code)
	}
	// Security may revert; then the owner may revert to the narrower one.
	if code, body := a.do(&security, "POST", pgPath+"/revert", `{"version":1,"reason":"restore"}`); code != 200 || body["version"] != float64(3) {
		t.Fatalf("security revert: %d %v", code, body)
	}
	if code, body := a.do(&owner, "POST", pgPath+"/revert", `{"version":2,"reason":"narrow again"}`); code != 200 || body["version"] != float64(4) {
		t.Fatalf("owner narrowing revert: %d %v", code, body)
	}
	// Owner of one agent is not the owner of another.
	if code, _ := a.do(&owner, "PUT", "/v1/agents/finance_agent_07/access/postgres", `{"profile":{"upstreams":{}},"reason":"x"}`); code != 403 {
		t.Fatalf("owner of other agent: %d", code)
	}
	// History is visible to readers, newest first.
	code, body = a.do(&auditor, "GET", pgPath+"/history?limit=10", "")
	if code != 200 {
		t.Fatalf("history: %d", code)
	}
	vs := body["versions"].([]any)
	if len(vs) != 4 || vs[0].(map[string]any)["version"] != float64(4) {
		t.Fatalf("history versions: %v", vs)
	}
	if code, _ := a.do(&stranger, "GET", pgPath+"/history", ""); code != 403 {
		t.Fatalf("stranger history: %d", code)
	}
	// Every change is in the Diary.
	if n := count(t, a.f, `SELECT count(*) FROM diary WHERE event_type = 'access.changed'`); n != 4 {
		t.Fatalf("access.changed events: %d", n)
	}
}

func TestAccessAPIValidation(t *testing.T) {
	a := newAPI(t)
	cases := []struct {
		method, path, body string
		want               int
	}{
		{"PUT", pgPath, `{"profile":{"upstreams":{"x":"admin"}},"reason":"r"}`, 400},
		{"PUT", pgPath, `{"profile":{"upstreams":{}},"reason":"r","agent_id":"other"}`, 400},
		{"PUT", pgPath, `{"profile":{"upstreams":{}}}`, 400},
		{"PUT", pgPath, `{"reason":"r"}`, 400},
		{"PUT", pgPath, `{"profile":null,"reason":"r"}`, 400},
		{"PUT", pgPath, `{"profile":{"upstreams":{}},"reason":"r"} trailing`, 400},
		{"PUT", "/v1/agents/claude_code_01/access/shell", `{"profile":{},"reason":"r"}`, 404},
		{"PUT", "/v1/agents/ghost/access/postgres", `{"profile":{"upstreams":{}},"reason":"r"}`, 404},
		{"POST", pgPath + "/revert", `{"version":5,"reason":"r"}`, 404},
		{"POST", pgPath + "/revert", `{"version":"1","reason":"r"}`, 400},
		{"GET", "/v1/agents/ghost/access", ``, 404},
		{"GET", pgPath + "/history?limit=-1", ``, 400},
		{"GET", "/v1/agents/claude_code_01/access/shell/history", ``, 404},
	}
	for _, c := range cases {
		if code, body := a.do(&security, c.method, c.path, c.body); code != c.want {
			t.Errorf("%s %s %s: got %d want %d (%v)", c.method, c.path, c.body, code, c.want, body)
		}
	}
	// Non-privileged callers learn nothing about agents that do not exist.
	if code, _ := a.do(&stranger, "GET", "/v1/agents/ghost/access", ""); code != 403 {
		t.Fatalf("stranger on missing agent: %d", code)
	}
	if n := count(t, a.f, `SELECT count(*) FROM access_profiles`); n != 0 {
		t.Fatalf("rows written by invalid requests: %d", n)
	}
}
