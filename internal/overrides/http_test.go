package overrides

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fortik/internal/authz"
)

var (
	pSec     = authz.Principal{Kind: authz.KindUser, Name: "Sec", Email: "sec@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	pJane    = authz.Principal{Kind: authz.KindUser, Name: "Jane", Email: janeEmail, Roles: map[string]bool{}}
	pBob     = authz.Principal{Kind: authz.KindUser, Name: "Bob", Email: "bob@acme.com", Roles: map[string]bool{}}
	pAuditor = authz.Principal{Kind: authz.KindUser, Name: "Aud", Email: "aud@acme.com", Roles: map[string]bool{authz.RoleAuditor: true}}
	pAgent   = authz.Principal{Kind: authz.KindAgent, Name: "code_agent_12", Roles: map[string]bool{}}
)

type apiClient struct {
	t   *testing.T
	srv *httptest.Server
}

// newAPI serves the handler behind a stand-in for the API's auth
// middleware: the X-Test-Principal header picks the authenticated caller.
func newAPI(t *testing.T, f *fixture) *apiClient {
	t.Helper()
	mux := http.NewServeMux()
	NewHandler(f.store, nil).Register(mux)
	byName := map[string]authz.Principal{"sec": pSec, "jane": pJane, "bob": pBob, "auditor": pAuditor, "agent": pAgent}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p, ok := byName[r.Header.Get("X-Test-Principal")]; ok {
			r = r.WithContext(authz.With(r.Context(), p))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return &apiClient{t: t, srv: srv}
}

func (c *apiClient) do(who, method, path, body string) (int, map[string]any) {
	c.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, c.srv.URL+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("X-Test-Principal", who)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *apiClient) create(who, body string) (int, map[string]any) {
	return c.do(who, http.MethodPost, "/v1/overrides", body)
}

const ghCreate = `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":1800,"reason":"incident 42"}`

func TestHTTPCreateAuthorization(t *testing.T) {
	f := setup(t)
	c := newAPI(t, f)

	code, body := c.create("sec", ghCreate)
	if code != http.StatusCreated || body["status"] != "active" || body["created_by"] != "user:sec@acme.com" {
		t.Fatalf("security create: %d %v", code, body)
	}
	rr, _ := body["revoke_result"].(map[string]any)
	if gh, _ := rr["github"].(map[string]any); gh["code_agent_12"] == nil {
		t.Fatalf("revoke_result %v", body["revoke_result"])
	}

	// Owner on their own agent (sponsor match is case-insensitive).
	if code, body := c.create("jane", strings.Replace(ghCreate, `"github"`, `"drive"`, 1)); code != http.StatusCreated || body["created_by"] != "user:"+janeEmail {
		t.Fatalf("owner create: %d %v", code, body)
	}
	// Owner on someone else's agent, and on an agent that does not exist:
	// the same 403 (no enumeration).
	other := strings.Replace(ghCreate, "code_agent_12", "finance_agent_07", 1)
	if code, _ := c.create("jane", other); code != http.StatusForbidden {
		t.Fatalf("non-owner: %d", code)
	}
	code1, b1 := c.create("jane", strings.Replace(ghCreate, "code_agent_12", "ghost_agent", 1))
	code2, b2 := c.create("jane", other)
	if code1 != http.StatusForbidden || b1["error"] != b2["error"] || code2 != code1 {
		t.Fatalf("enumeration: %d %v / %d %v", code1, b1, code2, b2)
	}
	if code, _ := c.create("sec", strings.Replace(ghCreate, "code_agent_12", "ghost_agent", 1)); code != http.StatusNotFound {
		t.Fatalf("security unknown agent: %d", code)
	}
	team := `{"scope":"team","scope_id":"platform","system":"github","mode":"read_only","until_released":true,"reason":"freeze"}`
	if code, body := c.create("jane", team); code != http.StatusForbidden || body["error"] != msgTeamSecurity {
		t.Fatalf("owner team: %d %v", code, body)
	}
	if code, body := c.create("sec", team); code != http.StatusCreated || body["expires_at"] != nil {
		t.Fatalf("security team: %d %v", code, body)
	}
	if code, _ := c.create("auditor", ghCreate); code != http.StatusForbidden {
		t.Fatalf("auditor create: %d", code)
	}
	if code, _ := c.create("agent", ghCreate); code != http.StatusForbidden {
		t.Fatalf("agent create: %d", code)
	}
	if code, _ := c.create("", ghCreate); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	if n := f.count(t, `SELECT count(*) FROM access_overrides`); n != 3 {
		t.Fatalf("%d overrides stored", n)
	}
}

func TestHTTPCreateValidation(t *testing.T) {
	f := setup(t)
	c := newAPI(t, f)
	bad := map[string]string{
		"unknown field":     `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":1800,"reason":"r","extra":1}`,
		"trailing":          ghCreate + `{}`,
		"not json":          `scope=agent`,
		"no reason":         `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":1800}`,
		"blank reason":      `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":1800,"reason":"   "}`,
		"under 1m":          `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":59,"reason":"r"}`,
		"over 30d":          `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":2592001,"reason":"r"}`,
		"negative":          `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":-5,"reason":"r"}`,
		"overflow":          `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":9223372036854775807,"reason":"r"}`,
		"both":              `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":600,"until_released":true,"reason":"r"}`,
		"neither":           `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","reason":"r"}`,
		"bad mode":          `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"off","duration_seconds":600,"reason":"r"}`,
		"bad system":        `{"scope":"agent","scope_id":"code_agent_12","system":"slack","mode":"suspended","duration_seconds":600,"reason":"r"}`,
		"string duration":   `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":"600","reason":"r"}`,
		"fractional":        `{"scope":"agent","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":60.5,"reason":"r"}`,
		"bad scope":         `{"scope":"org","scope_id":"code_agent_12","system":"github","mode":"suspended","duration_seconds":600,"reason":"r"}`,
		"empty body object": `{}`,
	}
	for name, body := range bad {
		t.Run(name, func(t *testing.T) {
			if code, out := c.create("sec", body); code != http.StatusBadRequest {
				t.Fatalf("%d %v", code, out)
			}
		})
	}
	// Bounds are inclusive; scope defaults to agent.
	for _, secs := range []string{"60", "2592000"} {
		body := `{"scope_id":"code_agent_12","system":"github","mode":"read_only","duration_seconds":` + secs + `,"reason":"r"}`
		if code, out := c.create("sec", body); code != http.StatusCreated || out["scope"] != "agent" {
			t.Fatalf("%s: %d %v", secs, code, out)
		}
	}
}

func TestHTTPReleaseExtendPermanent(t *testing.T) {
	f := setup(t)
	c := newAPI(t, f)
	_, secOv := c.create("sec", ghCreate)
	secID := secOv["override_id"].(string)
	_, janeOv := c.create("jane", strings.Replace(ghCreate, `"github"`, `"drive"`, 1))
	janeID := janeOv["override_id"].(string)

	// An owner may tighten someone else's override on their agent...
	if code, out := c.do("jane", "POST", "/v1/overrides/"+secID+"/extend", `{"duration_seconds":600}`); code != http.StatusOK || out["status"] != "active" {
		t.Fatalf("owner extend: %d %v", code, out)
	}
	// ...but not lift it.
	if code, out := c.do("jane", "POST", "/v1/overrides/"+secID+"/release", ""); code != http.StatusForbidden || out["error"] != msgReleaseOwn {
		t.Fatalf("owner release of security's override: %d %v", code, out)
	}
	if code, _ := c.do("bob", "POST", "/v1/overrides/"+secID+"/extend", `{"duration_seconds":600}`); code != http.StatusForbidden {
		t.Fatalf("non-owner extend: %d", code)
	}
	if code, _ := c.do("bob", "POST", "/v1/overrides/ovr_01HZZZZZZZZZZZZZZZZZZZZZZZ/release", ""); code != http.StatusForbidden {
		t.Fatalf("non-owner unknown id: %d", code)
	}
	if code, _ := c.do("sec", "POST", "/v1/overrides/ovr_01HZZZZZZZZZZZZZZZZZZZZZZZ/release", ""); code != http.StatusNotFound {
		t.Fatalf("security unknown id: %d", code)
	}
	if code, _ := c.do("sec", "POST", "/v1/overrides/"+secID+"/extend", `{}`); code != http.StatusBadRequest {
		t.Fatalf("extend without duration: %d", code)
	}
	if code, _ := c.do("sec", "POST", "/v1/overrides/"+secID+"/extend", `{"duration_seconds":30}`); code != http.StatusBadRequest {
		t.Fatalf("extend under 1m: %d", code)
	}
	if code, _ := c.do("sec", "POST", "/v1/overrides/"+secID+"/release", `{"reason":"x","bogus":1}`); code != http.StatusBadRequest {
		t.Fatalf("strict body on release: %d", code)
	}
	// The owner releases their own override (empty body allowed).
	if code, out := c.do("jane", "POST", "/v1/overrides/"+janeID+"/release", ""); code != http.StatusOK || out["status"] != "released" {
		t.Fatalf("owner release own: %d %v", code, out)
	}
	if code, _ := c.do("jane", "POST", "/v1/overrides/"+janeID+"/release", ""); code != http.StatusConflict {
		t.Fatalf("release twice: %d", code)
	}
	if code, out := c.do("jane", "POST", "/v1/overrides/"+secID+"/permanent", `{"reason":"keep it"}`); code != http.StatusOK || out["expires_at"] != nil {
		t.Fatalf("owner permanent: %d %v", code, out)
	}
	if code, _ := c.do("sec", "POST", "/v1/overrides/"+secID+"/permanent", ""); code != http.StatusConflict {
		t.Fatalf("permanent twice: %d", code)
	}
	if code, out := c.do("sec", "POST", "/v1/overrides/"+secID+"/release", `{"reason":"resolved"}`); code != http.StatusOK || out["status"] != "released" {
		t.Fatalf("security release: %d %v", code, out)
	}
}

func TestHTTPList(t *testing.T) {
	f := setup(t)
	c := newAPI(t, f)
	c.create("sec", ghCreate)
	c.create("sec", `{"scope":"team","scope_id":"platform","system":"drive","mode":"read_only","until_released":true,"reason":"freeze"}`)
	c.create("sec", strings.Replace(ghCreate, "code_agent_12", "finance_agent_07", 1))

	count := func(out map[string]any) int { l, _ := out["overrides"].([]any); return len(l) }
	if code, out := c.do("auditor", "GET", "/v1/overrides", ""); code != http.StatusOK || count(out) != 3 {
		t.Fatalf("auditor: %d %v", code, out)
	}
	if code, out := c.do("jane", "GET", "/v1/overrides?agent_id=code_agent_13", ""); code != http.StatusOK || count(out) != 1 {
		t.Fatalf("owner, team override via member: %d %v", code, out)
	}
	if code, out := c.do("jane", "GET", "/v1/overrides?agent_id=code_agent_12&status=active", ""); code != http.StatusOK || count(out) != 2 {
		t.Fatalf("owner own agent: %d %v", code, out)
	}
	if code, _ := c.do("jane", "GET", "/v1/overrides", ""); code != http.StatusForbidden {
		t.Fatalf("owner without agent_id: %d", code)
	}
	if code, _ := c.do("jane", "GET", "/v1/overrides?agent_id=finance_agent_07", ""); code != http.StatusForbidden {
		t.Fatalf("owner other agent: %d", code)
	}
	if code, _ := c.do("agent", "GET", "/v1/overrides?agent_id=code_agent_12", ""); code != http.StatusForbidden {
		t.Fatalf("agent principal: %d", code)
	}
	if code, _ := c.do("sec", "GET", "/v1/overrides?status=bogus", ""); code != http.StatusBadRequest {
		t.Fatalf("bad status: %d", code)
	}
	if code, _ := c.do("sec", "GET", "/v1/overrides?limit=0", ""); code != http.StatusBadRequest {
		t.Fatalf("bad limit: %d", code)
	}
	if code, out := c.do("sec", "GET", "/v1/overrides?limit=1", ""); code != http.StatusOK || count(out) != 1 {
		t.Fatalf("limit: %d %v", code, out)
	}

	_, out := c.do("sec", "GET", "/v1/overrides?agent_id=finance_agent_07", "")
	finID := out["overrides"].([]any)[0].(map[string]any)["override_id"].(string)
	_, out = c.do("sec", "GET", "/v1/overrides?agent_id=code_agent_12", "")
	var janeAgentOv string
	for _, o := range out["overrides"].([]any) {
		if m := o.(map[string]any); m["scope"] == "agent" {
			janeAgentOv = m["override_id"].(string)
		}
	}
	if code, _ := c.do("jane", "GET", "/v1/overrides/"+janeAgentOv, ""); code != http.StatusOK {
		t.Fatalf("owner get own: %d", code)
	}
	if code, _ := c.do("jane", "GET", "/v1/overrides/"+finID, ""); code != http.StatusForbidden {
		t.Fatalf("owner get other: %d", code)
	}
	if code, _ := c.do("auditor", "GET", "/v1/overrides/"+finID, ""); code != http.StatusOK {
		t.Fatalf("auditor get: %d", code)
	}
	if code, _ := c.do("auditor", "GET", "/v1/overrides/ovr_01HZZZZZZZZZZZZZZZZZZZZZZZ", ""); code != http.StatusNotFound {
		t.Fatalf("auditor unknown: %d", code)
	}
	if code, _ := c.do("jane", "GET", "/v1/overrides/ovr_01HZZZZZZZZZZZZZZZZZZZZZZZ", ""); code != http.StatusForbidden {
		t.Fatalf("owner unknown: %d", code)
	}
}
