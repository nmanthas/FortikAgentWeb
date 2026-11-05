package nsquickstart

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"fortik/internal/integrations"
	"fortik/internal/mcpclient/mcpfake"
	"fortik/internal/secrets"
)

const aiKey = "netsuite_mcp:acme"

// oauthFixture is a fixture with a netsuite_mcp connection in front of the
// LOCAL FAKE NetSuite OAuth + MCP server.
type oauthFixture struct {
	*fixture
	mcp *mcpfake.Server
	oa  *mcpfake.OAuthServer
	ns  *httptest.Server
}

func newOAuthFixture(t *testing.T) *oauthFixture {
	t.Helper()
	f := newFixture(t, loopback())
	f.svc.SetSecrets(f.sec)
	mcp := &mcpfake.Server{Token: "nobody-yet"}
	oa := &mcpfake.OAuthServer{MCP: mcp, ClientID: "fortik-public-client", RedirectURI: f.api + CallbackPath}
	ns := httptest.NewServer(oa)
	t.Cleanup(ns.Close)
	o := &oauthFixture{fixture: f, mcp: mcp, oa: oa, ns: ns}
	o.configureAI(nil)
	return o
}

func (o *oauthFixture) configureAI(extra map[string]any) {
	o.t.Helper()
	cfg := map[string]any{"account_id": "1234567", "client_id": o.oa.ClientID, "redirect_uri": o.oa.RedirectURI, "api_base": o.ns.URL}
	for k, v := range extra {
		cfg[k] = v
	}
	if code, out := o.do("PUT", "/v1/integrations/"+aiKey, "security", map[string]any{"config": cfg}); code != 200 {
		o.t.Fatalf("configure: %d %v", code, out)
	}
}

func (o *oauthFixture) statusOf(key string) View {
	o.t.Helper()
	v, err := o.svc.Status(context.Background(), key)
	if err != nil {
		o.t.Fatal(err)
	}
	return v
}

var noFollow = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func location(t *testing.T, req *http.Request) *url.URL {
	t.Helper()
	resp, err := noFollow.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("%s %s: HTTP %d, want 302", req.Method, req.URL.Path, resp.StatusCode)
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// start asks Fortik for the authorize URL and lets the fake NetSuite consent:
// it returns Fortik's callback URL with code and state.
func (o *oauthFixture) start() *url.URL {
	o.t.Helper()
	code, out := o.do("POST", "/v1/integrations/"+aiKey+"/oauth/start", "security", nil)
	if code != 200 {
		o.t.Fatalf("start: %d %v", code, out)
	}
	au, _ := out["authorize_url"].(string)
	if !strings.HasPrefix(au, o.ns.URL+authorizePath+"?") {
		o.t.Fatalf("authorize_url %q", au)
	}
	req, _ := http.NewRequest("GET", au, nil)
	return location(o.t, req)
}

// callback delivers the code to Fortik in the console session and returns
// the console redirect's query.
func (o *oauthFixture) callback(cb *url.URL) url.Values {
	o.t.Helper()
	req, _ := http.NewRequest("GET", o.api+cb.Path+"?"+cb.RawQuery, nil)
	req.Header.Set("X-Test-Roles", "security")
	u := location(o.t, req)
	if u.Path != "/integrations" {
		o.t.Fatalf("callback redirected to %s", u)
	}
	return u.Query()
}

func (o *oauthFixture) authorize() {
	o.t.Helper()
	if q := o.callback(o.start()); q.Get("oauth_ok") != "1" || q.Get("oauth") != aiKey {
		o.t.Fatalf("authorization failed: %v", q)
	}
}

// expireAccess makes the stored access token due for refresh.
func (o *oauthFixture) expireAccess() *oauthTokens {
	o.t.Helper()
	ctx := context.Background()
	tk, err := o.svc.loadTokens(ctx, aiKey)
	if err != nil || tk == nil {
		o.t.Fatalf("tokens: %v %v", tk, err)
	}
	tk.AccessExpiresAt = time.Now().Add(-time.Minute)
	if err := o.svc.saveTokens(ctx, aiKey, tk); err != nil {
		o.t.Fatal(err)
	}
	return tk
}

// noOAuthTokenAnywhere fails if an issued token reached Postgres or an output.
func (o *oauthFixture) noOAuthTokenAnywhere(outputs ...any) {
	o.t.Helper()
	var s string
	if err := o.pool.QueryRow(context.Background(), `
		SELECT COALESCE((SELECT string_agg(i::text, E'\n') FROM integrations i), '') ||
		       COALESCE((SELECT string_agg(m::text, E'\n') FROM mcp_connections m), '') ||
		       COALESCE((SELECT string_agg(d::text, E'\n') FROM diary d), '')`).Scan(&s); err != nil {
		o.t.Fatal(err)
	}
	for _, out := range outputs {
		s += fmtAny(out)
	}
	for _, p := range []string{"fake-access-", "fake-refresh-", "code-"} {
		if strings.Contains(s, p) {
			o.t.Fatalf("an OAuth value (%s…) leaked into the database, Diary or API output", p)
		}
	}
}

func fmtAny(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestOAuthAuthorizationRequiredBeforeConsent(t *testing.T) {
	o := newOAuthFixture(t)
	v := o.statusOf(aiKey)
	if v.Integration != integrations.SystemNetSuiteMCP || v.IntegrationID != "netsuite:acme" || v.Transport != integrations.TransportMCP ||
		v.OAuth == nil || v.OAuth.Authorized || v.State != StateAuthRequired || v.Token.Set {
		t.Fatalf("%+v", v)
	}
	if v.Endpoint != o.ns.URL+"/services/mcp/v1/all" {
		t.Fatalf("endpoint %q", v.Endpoint)
	}
	code, _ := o.do("POST", "/v1/integrations/"+aiKey+"/test", "security", nil)
	if code != 200 {
		t.Fatalf("test: %d", code)
	}
	if v := o.statusOf(aiKey); v.State != StateAuthRequired {
		t.Fatalf("state %q, want %q (%s)", v.State, StateAuthRequired, v.Detail)
	}
	// Nothing reached the MCP server without a token.
	if len(o.mcp.Calls()) != 0 {
		t.Fatalf("MCP server contacted before authorization: %v", o.mcp.Calls())
	}
	// A QuickStart (PAT) connection has no OAuth.
	if code, _ := o.do("POST", "/v1/integrations/netsuite_quickstart/oauth/start", "security", nil); code != 404 && code != 400 {
		t.Fatalf("oauth/start on QuickStart: %d", code)
	}
}

func TestOAuthAuthorizeConnectRefreshRevoke(t *testing.T) {
	o := newOAuthFixture(t)
	ctx := context.Background()
	cb := o.start()
	q := o.oa.LastAuthorize()
	if q.Get("code_challenge_method") != "S256" || q.Get("prompt") != "consent" || q.Get("scope") != "mcp" || len(q.Get("state")) < 22 {
		t.Fatalf("authorize request %v", q)
	}
	if r := o.callback(cb); r.Get("oauth_ok") != "1" {
		t.Fatalf("callback: %v", r)
	}
	v := o.statusOf(aiKey)
	if v.State != StateConnected || v.OAuth == nil || !v.OAuth.Authorized || v.OAuth.AuthorizedBy == "" || len(v.Tools) == 0 {
		t.Fatalf("after authorization: %+v", v)
	}
	if v.MappedTools != 0 {
		t.Fatalf("AI Connector tools must be unmapped until mapped from evidence, got %d", v.MappedTools)
	}
	// The state is one-time: replaying the callback fails.
	if r := o.callback(cb); r.Get("oauth_error") == "" {
		t.Fatalf("replayed callback accepted: %v", r)
	}
	o.noOAuthTokenAnywhere(v)
	if len(o.events(EventOAuthStarted)) != 1 || len(o.events(EventOAuthAuthorized)) != 1 {
		t.Fatal("oauth Diary events missing")
	}

	// Refresh: the refresh token is one-time use and is rotated.
	old := o.expireAccess()
	if code, out := o.do("POST", "/v1/integrations/"+aiKey+"/test", "security", nil); code != 200 {
		t.Fatalf("test: %d %v", code, out)
	}
	tk, _ := o.svc.loadTokens(ctx, aiKey)
	if o.oa.Issued() != 2 || tk.RefreshToken == old.RefreshToken || tk.RefreshedAt.IsZero() || o.statusOf(aiKey).State != StateConnected {
		t.Fatalf("refresh: issued=%d rotated=%v", o.oa.Issued(), tk.RefreshToken != old.RefreshToken)
	}

	// Disconnect revokes the grant with NetSuite and deletes the tokens.
	code, out := o.do("DELETE", "/v1/integrations/"+aiKey, "security", nil)
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	notes, _ := out["notes"].([]any)
	if len(notes) != 1 || !strings.Contains(notes[0].(string), "confirmed the revocation") {
		t.Fatalf("notes %v", notes)
	}
	if rv := o.oa.Revoked(); len(rv) != 1 || rv[0] != tk.RefreshToken {
		t.Fatalf("revoked %d tokens", len(rv))
	}
	if _, err := o.sec.Get(ctx, integrations.SecretName(aiKey, tokenSecretName)); !errors.Is(err, secrets.ErrNotFound) {
		t.Fatalf("tokens survived disconnect: %v", err)
	}
	if ev := o.events(EventOAuthRevoked); len(ev) != 1 || ev[0]["revoked"] != true {
		t.Fatalf("revoked events %v", ev)
	}
}

func TestOAuthRefreshRefusedNeedsReauthorization(t *testing.T) {
	o := newOAuthFixture(t)
	o.authorize()
	o.oa.RefuseRefresh = true
	o.expireAccess()
	o.do("POST", "/v1/integrations/"+aiKey+"/test", "security", nil)
	v := o.statusOf(aiKey)
	if v.State != StateAuthFailed || !strings.Contains(v.Detail, "authorize Fortik again") {
		t.Fatalf("state %q detail %q", v.State, v.Detail)
	}
	if len(o.events(EventOAuthRefreshed)) != 1 {
		t.Fatal("refresh failure not in the Diary")
	}
}

func TestOAuthPKCEAndStateBinding(t *testing.T) {
	o := newOAuthFixture(t)
	first, second := o.start(), o.start()
	// The code of the first authorization with the state (and verifier) of
	// the second: the PKCE check at the token endpoint refuses it.
	mixed := *second
	qs := second.Query()
	qs.Set("code", first.Query().Get("code"))
	mixed.RawQuery = qs.Encode()
	if r := o.callback(&mixed); r.Get("oauth_error") == "" {
		t.Fatalf("code accepted with another authorization's verifier: %v", r)
	}
	if o.oa.Issued() != 0 {
		t.Fatal("tokens issued without a matching verifier")
	}
	// An unknown state.
	bad := *first
	qb := first.Query()
	qb.Set("state", strings.Repeat("x", 30))
	bad.RawQuery = qb.Encode()
	if r := o.callback(&bad); !strings.Contains(r.Get("oauth_error"), "unknown or already used") {
		t.Fatalf("unknown state: %v", r)
	}
	// NetSuite refused (the user declined consent).
	declined, _ := url.Parse(CallbackPath + "?error=access_denied&error_description=declined&state=" + first.Query().Get("state"))
	if r := o.callback(declined); !strings.Contains(r.Get("oauth_error"), "access_denied") {
		t.Fatalf("declined: %v", r)
	}
	// Its pending authorization is gone: the first code no longer completes.
	if r := o.callback(first); r.Get("oauth_error") == "" {
		t.Fatalf("declined authorization completed: %v", r)
	}
	// Only the security role may start or complete an authorization.
	if code, _ := o.do("POST", "/v1/integrations/"+aiKey+"/oauth/start", "auditor", nil); code != 403 {
		t.Fatalf("auditor started an authorization: %d", code)
	}
}

func TestOAuthSettingsChangeDuringAuthorization(t *testing.T) {
	o := newOAuthFixture(t)
	cb := o.start()
	o.configureAI(map[string]any{"scope": "mcp rest_webservices"})
	if r := o.callback(cb); !strings.Contains(r.Get("oauth_error"), "settings changed") {
		t.Fatalf("authorization completed against changed settings: %v", r)
	}
	// Tokens issued for another client are not used.
	o.authorize()
	o.configureAI(map[string]any{"client_id": "another-client"})
	if v := o.statusOf(aiKey); v.OAuth == nil || v.OAuth.Authorized || !v.OAuth.Stale {
		t.Fatalf("stale authorization shown as valid: %+v", v.OAuth)
	}
	// The connection cannot be moved to another account: integration
	// netsuite:acme is account 1234567 (policies name it).
	code, out := o.do("PUT", "/v1/integrations/"+aiKey, "security", map[string]any{"config": map[string]any{
		"account_id": "7654321", "client_id": o.oa.ClientID, "redirect_uri": o.oa.RedirectURI, "api_base": o.ns.URL}})
	if code != 400 || !strings.Contains(out["error"].(string), "same account") {
		t.Fatalf("account change: %d %v", code, out)
	}
}

func TestOAuthRevokeFailureIsReported(t *testing.T) {
	o := newOAuthFixture(t)
	o.authorize()
	o.oa.RevokeStatus = http.StatusServiceUnavailable
	code, out := o.do("DELETE", "/v1/integrations/"+aiKey, "security", nil)
	if code != 200 {
		t.Fatalf("delete: %d %v", code, out)
	}
	notes, _ := out["notes"].([]any)
	if len(notes) != 1 || !strings.Contains(notes[0].(string), "NOT confirmed revoked") {
		t.Fatalf("notes %v", notes)
	}
}

func TestOAuthManagedSecretNotSettable(t *testing.T) {
	o := newOAuthFixture(t)
	code, _ := o.do("PUT", "/v1/integrations/"+aiKey, "security", map[string]any{
		"config":  map[string]any{"account_id": "1234567", "client_id": o.oa.ClientID, "redirect_uri": o.oa.RedirectURI, "api_base": o.ns.URL},
		"secrets": map[string]any{"oauth_tokens": `{"access_token":"x"}`},
	})
	if code != 400 {
		t.Fatalf("managed secret accepted from the API: %d", code)
	}
}
