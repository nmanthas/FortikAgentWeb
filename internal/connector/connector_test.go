package connector_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/config"
	"fortik/internal/connector"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

var bg = context.Background()

// fakeGoogle is a LOCAL FAKE of Google's OAuth token and revoke endpoints and
// of the Admin SDK Reports API token activities. It is not Google.
type fakeGoogle struct {
	srv      *httptest.Server
	mu       sync.Mutex
	codes    map[string]bool  // upstream code -> unused
	refresh  map[string]bool  // live upstream refresh tokens
	revoked  []string         // refresh tokens revoked
	issued   int              // access tokens issued
	reports  []map[string]any // Reports API items
	clientID string
}

func newFakeGoogle(t *testing.T) *fakeGoogle {
	f := &fakeGoogle{codes: map[string]bool{}, refresh: map[string]bool{}, clientID: "fortik-upstream.apps.googleusercontent.com"}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGoogle) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_ = r.ParseForm()
	json := func(code int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		_ = jsonEnc(w, v)
	}
	switch r.URL.Path {
	case "/token":
		if r.PostForm.Get("client_id") != f.clientID || r.PostForm.Get("client_secret") != "upstream-secret" {
			json(401, map[string]string{"error": "invalid_client"})
			return
		}
		switch r.PostForm.Get("grant_type") {
		case "authorization_code":
			if !f.codes[r.PostForm.Get("code")] {
				json(400, map[string]string{"error": "invalid_grant"})
				return
			}
			f.codes[r.PostForm.Get("code")] = false
			rt := fmt.Sprintf("1//upstream-refresh-%d", len(f.refresh)+1)
			f.refresh[rt] = true
			f.issued++
			json(200, map[string]any{"access_token": fmt.Sprintf("ya29.access-%d", f.issued), "refresh_token": rt, "expires_in": 3599, "token_type": "Bearer"})
		case "refresh_token":
			if !f.refresh[r.PostForm.Get("refresh_token")] {
				json(400, map[string]string{"error": "invalid_grant"})
				return
			}
			f.issued++
			json(200, map[string]any{"access_token": fmt.Sprintf("ya29.access-%d", f.issued), "expires_in": 3599, "token_type": "Bearer"})
		}
	case "/revoke":
		tok := r.PostForm.Get("token")
		f.revoked = append(f.revoked, tok)
		delete(f.refresh, tok)
		json(200, map[string]any{})
	case "/admin/reports/v1/activity/users/all/applications/token":
		if r.Header.Get("Authorization") != "Bearer admin-token" {
			json(401, map[string]any{})
			return
		}
		json(200, map[string]any{"items": f.reports})
	default:
		json(404, map[string]any{})
	}
}

func jsonEnc(w io.Writer, v any) error { return json.NewEncoder(w).Encode(v) }

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

type env struct {
	pool *pgxpool.Pool
	svc  *connector.Service
	ctl  *control.Store
	d    *diary.Diary
	sec  secrets.Store
	up   *fakeGoogle
}

func setup(t *testing.T) env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(bg, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log}
	sec, err := secrets.NewEncFile(t.TempDir(), make([]byte, secrets.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	up := newFakeGoogle(t)
	g, err := connector.NewUpstream(connector.UpstreamGoogle, config.ConnectorUpstreamConfig{ClientID: up.clientID, AuthURL: up.srv.URL + "/auth",
		TokenURL: up.srv.URL + "/token", RevokeURL: up.srv.URL + "/revoke", APIBaseURL: up.srv.URL}, "upstream-secret")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := connector.New(pool, d, dec, ctl, sec, map[string]*connector.Upstream{connector.UpstreamGoogle: g}, "https://fortik.test", log)
	if err != nil {
		t.Fatal(err)
	}
	return env{pool: pool, svc: svc, ctl: ctl, d: d, sec: sec, up: up}
}

const (
	gmailRead = "https://www.googleapis.com/auth/gmail.readonly"
	driveRead = "https://www.googleapis.com/auth/drive.readonly"
)

func (e env) register(t *testing.T) connector.Registered {
	t.Helper()
	reg, err := e.svc.Register(bg, connector.RegisterRequest{AgentID: "copilot_chatgpt", Name: "ChatGPT workspace connector", Sponsor: "it@acme.test",
		Team: "IT", Vendor: "chatgpt", Upstream: connector.UpstreamGoogle, RedirectURIs: []string{"https://chat.example/connector/callback"},
		Scopes: []string{gmailRead, driveRead}, Reason: "pilot"}, "user:sec@acme.test")
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

// connect runs the browser flow and the code exchange; it returns the Fortik
// refresh token and the access token the copilot got.
func (e env) connect(t *testing.T, reg connector.Registered, upCode string, replay bool) (string, string) {
	t.Helper()
	verifier := strings.Repeat("v", 50)
	sum := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {reg.Connector.ClientID}, "redirect_uri": {"https://chat.example/connector/callback"}, "response_type": {"code"},
		"state": {"client-state-1"}, "scope": {gmailRead + " https://www.googleapis.com/auth/gmail.send"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"}}
	to, oe := e.svc.Authorize(bg, q)
	if oe != nil {
		t.Fatalf("authorize: %v", oe)
	}
	u, _ := url.Parse(to)
	if !strings.HasPrefix(to, e.up.srv.URL+"/auth?") || u.Query().Get("client_id") != e.up.clientID ||
		u.Query().Get("scope") != gmailRead || u.Query().Get("redirect_uri") != "https://fortik.test/oauth/callback" {
		t.Fatalf("upstream consent URL (scopes must be narrowed to the registration): %s", to)
	}
	e.up.mu.Lock()
	e.up.codes[upCode] = true
	e.up.mu.Unlock()
	back, oe := e.svc.Callback(bg, url.Values{"state": {u.Query().Get("state")}, "code": {upCode}}, "browser:test")
	if oe != nil {
		t.Fatalf("callback: %v", oe)
	}
	b, _ := url.Parse(back)
	if b.Host != "chat.example" || b.Query().Get("state") != "client-state-1" || b.Query().Get("code") == "" {
		t.Fatalf("client redirect: %s", back)
	}
	tok, oe := e.svc.Token(bg, reg.Connector.ClientID, reg.ClientSecret, url.Values{"grant_type": {"authorization_code"},
		"code": {b.Query().Get("code")}, "redirect_uri": {"https://chat.example/connector/callback"}, "code_verifier": {verifier}})
	if oe != nil {
		t.Fatalf("token: %v", oe)
	}
	if !strings.HasPrefix(tok.AccessToken, "ya29.access-") || !strings.HasPrefix(tok.RefreshToken, "frt_") || tok.Scope != gmailRead {
		t.Fatalf("token response: %+v", tok)
	}
	if !replay {
		return tok.RefreshToken, tok.AccessToken
	}
	// A replayed code is refused (and the grant it made is revoked).
	if _, oe := e.svc.Token(bg, reg.Connector.ClientID, reg.ClientSecret, url.Values{"grant_type": {"authorization_code"},
		"code": {b.Query().Get("code")}, "redirect_uri": {"https://chat.example/connector/callback"}, "code_verifier": {verifier}}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("replayed code: %v", oe)
	}
	return tok.RefreshToken, tok.AccessToken
}

func (e env) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(bg, q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e env) refresh(clientID, secret, rt string) (connector.TokenResponse, *connector.OAuthError) {
	return e.svc.Token(bg, clientID, secret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}})
}

// The copilot gets short-lived upstream tokens only through Fortik; Fortik
// decides each one; secrets never reach Postgres.
func TestConnectorFlowAndSecrets(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	if !strings.HasPrefix(reg.ClientSecret, "fcs_") || reg.TokenURL != "https://fortik.test/oauth/token" {
		t.Fatalf("registration: %+v", reg)
	}
	st, _ := e.ctl.Get(bg, "copilot_chatgpt")
	if !st.Registered || st.Type != "copilot" {
		t.Fatalf("copilot agent: %+v", st)
	}
	// The first connection's code is replayed (refused, grant revoked); a second one is used below.
	e.connect(t, reg, "up-code-1", true)
	rt, _ := e.connect(t, reg, "up-code-2", false)
	if e.count(t, `SELECT count(*) FROM connectors WHERE client_secret_sha256 = $1 OR client_secret_sha256 = $2`, reg.ClientSecret, "") != 0 {
		t.Fatal("client secret stored in clear")
	}
	var dump string
	if err := e.pool.QueryRow(bg, `SELECT string_agg(row_to_json(g)::text, ' ') FROM connector_grants g`).Scan(&dump); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(dump, "upstream-refresh") || strings.Contains(dump, rt) || strings.Contains(dump, "ya29") {
		t.Fatalf("a token is stored in Postgres: %s", dump)
	}
	if e.count(t, `SELECT count(*) FROM actions WHERE system = 'connector' AND verb = 'READ' AND decision = 'allow' AND agent_id = 'copilot_chatgpt'`) < 2 {
		t.Fatal("token issues were not decided and recorded")
	}

	// Refresh rotates the Fortik token; the old one presented again is theft:
	// the grant is revoked, upstream too.
	t2, oe := e.refresh(reg.Connector.ClientID, reg.ClientSecret, rt)
	if oe != nil || t2.RefreshToken == rt {
		t.Fatalf("refresh: %+v %v", t2, oe)
	}
	if _, oe := e.refresh(reg.Connector.ClientID, reg.ClientSecret, rt); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("reused refresh token: %v", oe)
	}
	if _, oe := e.refresh(reg.Connector.ClientID, reg.ClientSecret, t2.RefreshToken); oe == nil {
		t.Fatal("the grant survived a refresh-token reuse")
	}
	e.up.mu.Lock()
	revoked := len(e.up.revoked)
	e.up.mu.Unlock()
	if revoked < 2 { // the replayed-code grant and the reused-refresh grant
		t.Fatalf("upstream revocations: %d", revoked)
	}
	if _, oe := e.svc.Token(bg, reg.Connector.ClientID, "fcs_wrong", url.Values{"grant_type": {"refresh_token"}, "refresh_token": {t2.RefreshToken}}); oe == nil || oe.Code != "invalid_client" {
		t.Fatalf("wrong client secret: %v", oe)
	}
	if rep, err := e.d.VerifyChain(bg); err != nil || !rep.OK {
		t.Fatalf("chain: %+v %v", rep, err)
	}
}

// "Their access stops when Fortik stops issuing": a kill refuses the next
// refresh (a Fortik decision) and revoking the agent ends the upstream grant.
func TestConnectorKillStopsAccess(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	e.connect(t, reg, "up-code-1", true)
	rt, _ := e.connect(t, reg, "up-code-2", false)
	if _, err := e.ctl.SetLevel(bg, "copilot_chatgpt", control.Killed, "copilot exfiltrating mail", "user:sec@acme.test"); err != nil {
		t.Fatal(err)
	}
	if _, oe := e.refresh(reg.Connector.ClientID, reg.ClientSecret, rt); oe == nil || oe.Code != "invalid_grant" || !strings.Contains(oe.Desc, "POL-010") {
		t.Fatalf("refresh after kill: %v", oe)
	}
	desc, err := e.svc.RevokeAgent(bg, "copilot_chatgpt")
	if err != nil || !strings.Contains(desc, "upstream grant revoked") {
		t.Fatalf("revoke agent: %q %v", desc, err)
	}
	if e.count(t, `SELECT count(*) FROM connector_grants WHERE agent_id = 'copilot_chatgpt' AND status = 'active'`) != 0 {
		t.Fatal("active grants after revocation")
	}
	e.up.mu.Lock()
	live := len(e.up.refresh)
	e.up.mu.Unlock()
	if live != 0 {
		t.Fatalf("upstream still has %d live grants", live)
	}
}

// READ_ONLY: a read-only connector still works; disabling a connector stops it.
func TestConnectorReadOnlyAndDisable(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	e.connect(t, reg, "up-code-1", true)
	rt, _ := e.connect(t, reg, "up-code-2", false)
	if _, err := e.ctl.SetLevel(bg, "copilot_chatgpt", control.ReadOnly, "review", "user:sec@acme.test"); err != nil {
		t.Fatal(err)
	}
	t2, oe := e.refresh(reg.Connector.ClientID, reg.ClientSecret, rt)
	if oe != nil {
		t.Fatalf("read-only scopes at READ_ONLY: %v", oe)
	}
	res, err := e.svc.Disable(bg, reg.Connector.ConnectorID, "vendor offboarded", "user:sec@acme.test")
	if err != nil || len(res) != 1 {
		t.Fatalf("disable: %v %v", res, err)
	}
	if _, oe := e.refresh(reg.Connector.ClientID, reg.ClientSecret, t2.RefreshToken); oe == nil || oe.Code != "invalid_client" {
		t.Fatalf("refresh after disable: %v", oe)
	}
	if _, oe := e.svc.Authorize(bg, url.Values{"client_id": {reg.Connector.ClientID}, "response_type": {"code"}}); oe == nil {
		t.Fatal("authorize after disable")
	}
}

// Requests that cannot be trusted are refused without redirecting.
func TestConnectorAuthorizeValidation(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	if _, oe := e.svc.Authorize(bg, url.Values{"client_id": {reg.Connector.ClientID}, "response_type": {"code"},
		"redirect_uri": {"https://attacker.example/cb"}}); oe == nil || oe.Redirect != "" {
		t.Fatalf("unregistered redirect_uri: %+v", oe)
	}
	if _, oe := e.svc.Authorize(bg, url.Values{"client_id": {reg.Connector.ClientID}, "response_type": {"code"},
		"scope": {"https://www.googleapis.com/auth/gmail.send"}}); oe == nil || oe.Code != "invalid_scope" || oe.Redirect == "" {
		t.Fatalf("scope outside the registration: %+v", oe)
	}
	if _, oe := e.svc.Authorize(bg, url.Values{"client_id": {"nope"}, "response_type": {"code"}}); oe == nil || oe.Code != "unauthorized_client" {
		t.Fatalf("unknown client: %+v", oe)
	}
	if _, err := e.svc.Register(bg, connector.RegisterRequest{AgentID: "x", Sponsor: "a@b.c", Vendor: "chatgpt", Upstream: connector.UpstreamGitHub,
		RedirectURIs: []string{"https://x.example/cb"}, Reason: "r"}, "user:sec"); err == nil {
		t.Fatal("registration for an unconfigured upstream")
	}
	if _, err := e.svc.Register(bg, connector.RegisterRequest{AgentID: "x", Sponsor: "a@b.c", Vendor: "chatgpt", Upstream: connector.UpstreamGoogle,
		RedirectURIs: []string{"http://x.example/cb"}, Scopes: []string{gmailRead}, Reason: "r"}, "user:sec"); err == nil {
		t.Fatal("plain-http redirect accepted")
	}
}

// Vendor audit logs: Fortik's client's events become observed actions
// (once), others are ignored.
func TestConnectorVendorAudit(t *testing.T) {
	e := setup(t)
	e.register(t)
	now := time.Now().UTC()
	e.up.mu.Lock()
	e.up.reports = []map[string]any{
		{"id": map[string]any{"time": now.Format(time.RFC3339), "uniqueQualifier": "q1"}, "actor": map[string]any{"email": "jane@acme.test"},
			"events": []map[string]any{{"name": "request", "parameters": []map[string]any{{"name": "client_id", "value": e.up.clientID},
				{"name": "api_name", "value": "gmail"}, {"name": "method_name", "value": "gmail.users.messages.send"}}}}},
		{"id": map[string]any{"time": now.Format(time.RFC3339), "uniqueQualifier": "q2"}, "actor": map[string]any{"email": "bob@acme.test"},
			"events": []map[string]any{{"name": "request", "parameters": []map[string]any{{"name": "client_id", "value": "someone-else"},
				{"name": "api_name", "value": "drive"}}}}},
	}
	e.up.mu.Unlock()
	up, _ := connector.NewUpstream(connector.UpstreamGoogle, config.ConnectorUpstreamConfig{ClientID: e.up.clientID, APIBaseURL: e.up.srv.URL}, "s")
	f := map[string]connector.AuditFetcher{connector.UpstreamGoogle: connector.GoogleAudit{Up: up, Token: func(context.Context) (string, error) { return "admin-token", nil }}}
	n, err := e.svc.PullAudit(bg, f, now.Add(-time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("pull: %d %v", n, err)
	}
	if e.count(t, `SELECT count(*) FROM actions WHERE source = 'vendor_audit' AND agent_id = 'copilot_chatgpt' AND system = 'gmail' AND verb = 'SEND'`) != 1 {
		t.Fatal("vendor activity not recorded as an observed action")
	}
	if n, err := e.svc.PullAudit(bg, f, now.Add(-time.Hour)); err != nil || n != 0 {
		t.Fatalf("second pull: %d %v", n, err)
	}
}

// The OAuth endpoints over HTTP: client_secret_basic, no-store responses and
// an error page (never a redirect) for an untrusted request.
func TestConnectorHTTP(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	mux := http.NewServeMux()
	connector.NewHandler(e.svc, nil).MountOAuth(muxMounter{mux})
	srv := httptest.NewServer(mux)
	defer srv.Close()
	res, err := http.Get(srv.URL + "/oauth/authorize?client_id=nope&response_type=code")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 || !strings.Contains(string(b), "unauthorized_client") {
		t.Fatalf("bad client: %d %s", res.StatusCode, b)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/oauth/token", strings.NewReader("grant_type=refresh_token&refresh_token=frt_nope"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(reg.Connector.ClientID, reg.ClientSecret)
	res, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 400 || res.Header.Get("Cache-Control") != "no-store" || !strings.Contains(string(b), "invalid_grant") {
		t.Fatalf("token: %d %s %v", res.StatusCode, b, res.Header)
	}
}

type muxMounter struct{ m *http.ServeMux }

func (m muxMounter) Mount(p string, h http.HandlerFunc) { m.m.HandleFunc(p, h) }

// The unauthenticated authorize endpoint is bounded: open authorizations per
// connector are capped, and expired ones are pruned as new ones arrive.
func TestConnectorAuthorizeIsBounded(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	q := url.Values{"client_id": {reg.Connector.ClientID}, "response_type": {"code"}, "scope": {gmailRead}}
	for i := 0; i < 200; i++ {
		if _, oe := e.svc.Authorize(bg, q); oe != nil {
			t.Fatalf("authorize %d: %v", i, oe)
		}
	}
	if _, oe := e.svc.Authorize(bg, q); oe == nil || oe.Code != "temporarily_unavailable" || oe.Redirect == "" {
		t.Fatalf("201st open authorization: %+v", oe)
	}
	if n := e.count(t, `SELECT count(*) FROM connector_pending WHERE connector_id = $1`, reg.Connector.ConnectorID); n != 200 {
		t.Fatalf("%d pending rows", n)
	}
	later := time.Now().Add(11 * time.Minute)
	e.svc.Now = func() time.Time { return later }
	if _, oe := e.svc.Authorize(bg, q); oe != nil {
		t.Fatalf("after expiry: %v", oe)
	}
	if n := e.count(t, `SELECT count(*) FROM connector_pending WHERE connector_id = $1`, reg.Connector.ConnectorID); n != 1 {
		t.Fatalf("expired rows not pruned: %d", n)
	}
}

// RFC 6749 §4.1.3: with one registered redirect URI the client may omit it in
// both the authorize and the token request; a different one is refused.
func TestConnectorRedirectURIMismatchRefused(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	to, oe := e.svc.Authorize(bg, url.Values{"client_id": {reg.Connector.ClientID}, "response_type": {"code"}, "scope": {gmailRead}})
	if oe != nil {
		t.Fatal(oe)
	}
	u, _ := url.Parse(to)
	e.up.mu.Lock()
	e.up.codes["up-omit"] = true
	e.up.mu.Unlock()
	back, oe := e.svc.Callback(bg, url.Values{"state": {u.Query().Get("state")}, "code": {"up-omit"}}, "browser:test")
	if oe != nil {
		t.Fatal(oe)
	}
	b, _ := url.Parse(back)
	code := b.Query().Get("code")
	if _, oe := e.svc.Token(bg, reg.Connector.ClientID, reg.ClientSecret, url.Values{"grant_type": {"authorization_code"}, "code": {code},
		"redirect_uri": {"https://chat.example/other"}}); oe == nil || oe.Code != "invalid_grant" {
		t.Fatalf("mismatched redirect_uri: %+v", oe)
	}
}

func TestConnectorRedirectURIOmittedInTokenRequest(t *testing.T) {
	e := setup(t)
	reg := e.register(t)
	to, oe := e.svc.Authorize(bg, url.Values{"client_id": {reg.Connector.ClientID}, "response_type": {"code"}, "scope": {gmailRead}})
	if oe != nil {
		t.Fatal(oe)
	}
	u, _ := url.Parse(to)
	e.up.mu.Lock()
	e.up.codes["up-omit2"] = true
	e.up.mu.Unlock()
	back, oe := e.svc.Callback(bg, url.Values{"state": {u.Query().Get("state")}, "code": {"up-omit2"}}, "browser:test")
	if oe != nil {
		t.Fatal(oe)
	}
	b, _ := url.Parse(back)
	tok, oe := e.svc.Token(bg, reg.Connector.ClientID, reg.ClientSecret, url.Values{"grant_type": {"authorization_code"}, "code": {b.Query().Get("code")}})
	if oe != nil || tok.AccessToken == "" {
		t.Fatalf("token without redirect_uri: %+v %v", tok, oe)
	}
}
