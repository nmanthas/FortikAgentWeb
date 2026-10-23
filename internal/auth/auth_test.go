package auth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type mapSecrets map[string]string

func (m mapSecrets) Get(_ context.Context, name string) ([]byte, error) {
	v, ok := m[name]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	return []byte(v), nil
}

type harness struct {
	t     *testing.T
	svc   *Service
	srv   *httptest.Server
	pool  *pgxpool.Pool
	diary *diary.Diary
	clock *clock
	idp   *fakeOIDC
}

const clientSecretValue = "s3cret-client-value"

func newHarness(t *testing.T, mutate func(*config.AuthConfig)) *harness {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	idp := newFakeOIDC(t, "fortik-console", clientSecretValue)
	h := &harness{t: t, pool: pool, diary: diary.New(pool), clock: &clock{t: time.Now()}, idp: idp}
	mux := http.NewServeMux()
	h.srv = httptest.NewServer(testMiddleware(h, mux))
	t.Cleanup(h.srv.Close)
	cfg := config.AuthConfig{
		OIDC: config.OIDCConfig{
			Issuer: idp.issuer(), ClientID: "fortik-console", ClientSecretSecret: "oidc_client_secret",
			RedirectURL: h.srv.URL + "/auth/callback", RoleClaim: "groups",
			RoleMap:    map[string][]string{"fortik-security": {"security", "auditor"}, "fortik-readers": {"auditor"}},
			EmailRoles: map[string][]string{"Boss@Example.com": {"admin"}},
		},
		DevLogin: config.DevLoginConfig{Enabled: true, Users: []config.DevLoginUser{
			{Email: "dev@example.com", Name: "Dev", Roles: []string{"security", "auditor"}}}},
		SessionTTL: 12 * time.Hour, SessionIdleTTL: time.Hour,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	svc, err := New(Options{Config: cfg, APIListen: "127.0.0.1:8080", Pool: pool, Diary: h.diary,
		Secrets: mapSecrets{"oidc_client_secret": clientSecretValue}, Now: h.clock.Now,
		Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		t.Fatal(err)
	}
	svc.Routes(mux)
	h.svc = svc
	return h
}

// testMiddleware stands in for the API middleware: resolves the session
// cookie into the principal for /v1/*.
func testMiddleware(h *harness, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			sess, err := h.svc.Authenticate(r.Context(), r)
			if err != nil {
				http.Error(w, err.Error(), http.StatusUnauthorized)
				return
			}
			r = r.WithContext(WithSession(authz.With(r.Context(), sess.Principal()), sess))
		}
		next.ServeHTTP(w, r)
	})
}

func (h *harness) client() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mustGet(t *testing.T, c *http.Client, u string) *http.Response {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

// oidcLogin walks login -> fake IdP authorize -> callback and returns the
// callback response.
func (h *harness) oidcLogin(c *http.Client) *http.Response {
	h.t.Helper()
	resp := mustGet(h.t, c, h.srv.URL+"/auth/login")
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("login: %d", resp.StatusCode)
	}
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	if q := authURL.Query(); q.Get("code_challenge_method") != "S256" || q.Get("nonce") == "" || q.Get("state") == "" {
		h.t.Fatalf("authorize URL lacks PKCE S256/nonce/state: %s", authURL)
	}
	resp = mustGet(h.t, c, authURL.String())
	if resp.StatusCode != http.StatusFound {
		h.t.Fatalf("idp authorize: %d", resp.StatusCode)
	}
	return mustGet(h.t, c, resp.Header.Get("Location"))
}

func (h *harness) me(c *http.Client) (int, map[string]any) {
	h.t.Helper()
	resp, err := c.Get(h.srv.URL + "/v1/me")
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (h *harness) diaryEvents(typ string) []map[string]any {
	h.t.Helper()
	entries, err := h.diary.Query(context.Background(), diary.Filter{Limit: 1000})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range entries {
		if e.EventType != typ {
			continue
		}
		var body map[string]any
		_ = json.Unmarshal(e.Body, &body)
		body["_body_json"] = e.BodyJSON
		out = append(out, body)
	}
	return out
}

func sessionCookie(resp *http.Response) *http.Cookie {
	for _, c := range resp.Cookies() {
		if c.Name == SessionCookie {
			return c
		}
	}
	return nil
}

func TestOIDCLoginSuccess(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.setClaims(map[string]any{"email": "Alice@Example.com", "email_verified": true, "name": "Alice", "groups": []string{"fortik-security", "other"}})
	c := h.client()
	resp := h.oidcLogin(c)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != "/" {
		t.Fatalf("callback: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	ck := sessionCookie(resp)
	if ck == nil || !ck.HttpOnly || ck.SameSite != http.SameSiteStrictMode || ck.Secure {
		t.Fatalf("session cookie flags wrong (loopback => not Secure): %+v", ck)
	}
	if h.idp.lastChallengeMethod != "S256" || h.idp.pkceFailures != 0 {
		t.Fatalf("PKCE not used correctly: method=%s failures=%d", h.idp.lastChallengeMethod, h.idp.pkceFailures)
	}
	code, me := h.me(c)
	if code != 200 || me["email"] != "alice@example.com" || me["name"] != "Alice" || me["auth_method"] != "oidc" || me["csrf"] == "" {
		t.Fatalf("me: %d %v", code, me)
	}
	roles := me["roles"].([]any)
	if len(roles) != 2 || roles[0] != "auditor" || roles[1] != "security" {
		t.Fatalf("roles: %v", roles)
	}
	if me["oidc_enabled"] != true || me["dev_login_enabled"] != true {
		t.Fatalf("flags: %v", me)
	}
	// The DB holds only the sha256 of the id.
	var n int
	_ = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM console_sessions WHERE id_sha256 = $1`, ck.Value).Scan(&n)
	if n != 0 {
		t.Fatal("raw session id stored in the database")
	}
	logins := h.diaryEvents(EventLogin)
	if len(logins) != 1 {
		t.Fatalf("auth.login events: %d", len(logins))
	}
	body := logins[0]["_body_json"].(string)
	if !strings.Contains(body, `"method":"oidc"`) || logins[0]["actor"] != "user:alice@example.com" {
		t.Fatalf("login event: %s", body)
	}
	for _, secret := range []string{ck.Value, me["csrf"].(string), clientSecretValue} {
		if strings.Contains(body, secret) {
			t.Fatal("diary contains a secret value")
		}
	}

	// Email mapping (case-insensitive) grants admin with no group.
	h.idp.setClaims(map[string]any{"email": "boss@example.com", "email_verified": true})
	c2 := h.client()
	if resp := h.oidcLogin(c2); resp.StatusCode != http.StatusFound {
		t.Fatalf("email-mapped login: %d", resp.StatusCode)
	}
	if _, me := h.me(c2); me["roles"].([]any)[0] != "admin" {
		t.Fatalf("email roles: %v", me)
	}
}

func TestOIDCBadStateRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.setClaims(map[string]any{"email": "alice@example.com", "groups": "fortik-security"})
	c := h.client()
	resp := mustGet(t, c, h.srv.URL+"/auth/login")
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	resp = mustGet(t, c, authURL.String())
	cb, _ := url.Parse(resp.Header.Get("Location"))
	q := cb.Query()
	q.Set("state", "attacker-state")
	cb.RawQuery = q.Encode()
	resp = mustGet(t, c, cb.String())
	if resp.StatusCode != http.StatusBadRequest || sessionCookie(resp) != nil && sessionCookie(resp).Value != "" {
		t.Fatalf("bad state must be refused without a session: %d", resp.StatusCode)
	}
	if h.idp.tokenCalls != 0 {
		t.Fatal("code must not be exchanged when state mismatches")
	}
	// No flow cookie at all (e.g. a forged callback link) is refused too.
	resp = mustGet(t, h.client(), h.srv.URL+"/auth/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback without flow cookie: %d", resp.StatusCode)
	}
	fails := h.diaryEvents(EventLoginFailed)
	if len(fails) != 2 || !strings.Contains(fails[0]["_body_json"].(string), "bad_state") {
		t.Fatalf("auth.login_failed: %v", fails)
	}
}

func TestOIDCNonceMismatchRefused(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.setClaims(map[string]any{"email": "alice@example.com", "groups": "fortik-security"})
	h.idp.nonceOverride = "replayed-nonce"
	resp := h.oidcLogin(h.client())
	if resp.StatusCode != http.StatusUnauthorized || sessionCookie(resp) != nil {
		t.Fatalf("nonce mismatch must be refused: %d", resp.StatusCode)
	}
	if f := h.diaryEvents(EventLoginFailed); len(f) != 1 || !strings.Contains(f[0]["_body_json"].(string), "nonce_mismatch") {
		t.Fatalf("diary: %v", f)
	}
}

func TestOIDCUnmappedUserRefusedWithClearPage(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.setClaims(map[string]any{"email": "stranger@example.com", "email_verified": true, "groups": []string{"marketing"}})
	c := h.client()
	resp, err := c.Get(h.srv.URL + "/auth/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp = mustGet(t, c, resp.Header.Get("Location"))
	resp, err = c.Get(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(b), "no Fortik role") || !strings.Contains(string(b), "stranger@example.com") {
		t.Fatalf("unmapped user: %d %s", resp.StatusCode, b)
	}
	if sessionCookie(resp) != nil {
		t.Fatal("no session may be created for an unmapped user")
	}
	if f := h.diaryEvents(EventLoginFailed); len(f) != 1 || !strings.Contains(f[0]["_body_json"].(string), "no_roles") {
		t.Fatalf("diary: %v", f)
	}
	// Unverified email is refused even when mapped.
	h.idp.setClaims(map[string]any{"email": "boss@example.com", "email_verified": false})
	if resp := h.oidcLogin(h.client()); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified email: %d", resp.StatusCode)
	}
}

func TestLogoutRequiresCSRFAndRevokes(t *testing.T) {
	h := newHarness(t, nil)
	h.idp.setClaims(map[string]any{"email": "alice@example.com", "groups": "fortik-readers"})
	c := h.client()
	h.oidcLogin(c)
	_, me := h.me(c)
	csrf := me["csrf"].(string)

	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/logout", nil)
	resp, _ := c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("logout without CSRF: %d", resp.StatusCode)
	}
	req, _ = http.NewRequest("POST", h.srv.URL+"/auth/logout", nil)
	req.Header.Set(CSRFHeader, csrf)
	resp, _ = c.Do(req)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("logout: %d", resp.StatusCode)
	}
	if code, _ := h.me(c); code != 401 {
		t.Fatalf("session must be gone after logout: %d", code)
	}
	var n int
	_ = h.pool.QueryRow(context.Background(), `SELECT count(*) FROM console_sessions`).Scan(&n)
	if n != 0 {
		t.Fatalf("session row remains: %d", n)
	}
	if f := h.diaryEvents(EventLogout); len(f) != 1 || f[0]["actor"] != "user:alice@example.com" {
		t.Fatalf("auth.logout: %v", f)
	}
}

func TestSessionIdleAndAbsoluteExpiry(t *testing.T) {
	h := newHarness(t, nil)
	login := func() *http.Client {
		c := h.client()
		req, _ := http.NewRequest("POST", h.srv.URL+"/auth/dev-login", strings.NewReader(`{"email":"DEV@example.com"}`))
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 200 {
			t.Fatalf("dev login: %d", resp.StatusCode)
		}
		return c
	}
	// Idle: activity within the hour keeps it alive; an idle hour ends it.
	c := login()
	for i := 0; i < 3; i++ {
		h.clock.Add(50 * time.Minute)
		if code, _ := h.me(c); code != 200 {
			t.Fatalf("active session expired early (step %d): %d", i, code)
		}
	}
	h.clock.Add(61 * time.Minute)
	if code, _ := h.me(c); code != 401 {
		t.Fatalf("idle session must expire: %d", code)
	}

	// Absolute: even an always-active session ends after 12h.
	c = login()
	for elapsed := time.Duration(0); elapsed < 12*time.Hour-50*time.Minute; elapsed += 50 * time.Minute {
		h.clock.Add(50 * time.Minute)
		if code, _ := h.me(c); code != 200 {
			t.Fatalf("session expired early at %s: %d", elapsed, code)
		}
	}
	h.clock.Add(55 * time.Minute)
	if code, _ := h.me(c); code != 401 {
		t.Fatalf("session must expire after 12h absolute: %d", code)
	}
}

func TestDevLoginRules(t *testing.T) {
	h := newHarness(t, nil)
	post := func(body, ctype, origin string) *http.Response {
		req, _ := http.NewRequest("POST", h.srv.URL+"/auth/dev-login", strings.NewReader(body))
		if ctype != "" {
			req.Header.Set("Content-Type", ctype)
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := h.client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	if r := post(`{"email":"nobody@example.com"}`, "application/json", ""); r.StatusCode != 403 || sessionCookie(r) != nil {
		t.Fatalf("unknown dev user: %d", r.StatusCode)
	}
	if r := post(`email=dev@example.com`, "application/x-www-form-urlencoded", ""); r.StatusCode != 415 {
		t.Fatalf("form post must be refused: %d", r.StatusCode)
	}
	if r := post(`{"email":"dev@example.com"}`, "application/json", "https://evil.example"); r.StatusCode != 403 {
		t.Fatalf("cross-origin: %d", r.StatusCode)
	}
	if r := post(`{"email":"dev@example.com","roles":["admin"]}`, "application/json", ""); r.StatusCode != 400 {
		t.Fatalf("unknown fields must be rejected: %d", r.StatusCode)
	}
	// DNS rebinding: Host and Origin agree but do not name loopback.
	for _, origin := range []string{"http://rebind.attacker.example:8080", ""} {
		req, _ := http.NewRequest("POST", h.srv.URL+"/auth/dev-login", strings.NewReader(`{"email":"dev@example.com"}`))
		req.Host = "rebind.attacker.example:8080"
		req.Header.Set("Content-Type", "application/json")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := h.client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != 403 || sessionCookie(resp) != nil {
			t.Fatalf("rebound host (origin %q): %d", origin, resp.StatusCode)
		}
	}
	r := post(`{"email":"dev@example.com"}`, "application/json", h.srv.URL)
	if r.StatusCode != 200 || sessionCookie(r) == nil {
		t.Fatalf("dev login: %d", r.StatusCode)
	}
	if f := h.diaryEvents(EventLoginFailed); len(f) != 1 || strings.Contains(f[0]["_body_json"].(string), "nobody@") {
		t.Fatalf("refused dev login must be recorded without the submitted email: %v", f)
	}

	// /auth/config is public and lists the methods.
	resp, _ := http.Get(h.srv.URL + "/auth/config")
	var cfg map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&cfg)
	resp.Body.Close()
	if cfg["dev_login_enabled"] != true || cfg["oidc_enabled"] != true || len(cfg["dev_users"].([]any)) != 1 {
		t.Fatalf("auth config: %v", cfg)
	}

	// A service whose config no longer enables dev login refuses existing
	// dev sessions (same database, e.g. after a restart with a new config).
	off, err := New(Options{Config: config.AuthConfig{SessionTTL: 12 * time.Hour, SessionIdleTTL: time.Hour},
		APIListen: "127.0.0.1:8080", Pool: h.pool, Diary: h.diary, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("GET", "/v1/me", nil)
	req.AddCookie(sessionCookie(r))
	if _, err := h.svc.Authenticate(context.Background(), req); err != nil {
		t.Fatalf("session valid while enabled: %v", err)
	}
	if _, err := off.Authenticate(context.Background(), req); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("dev session must die when dev login is off: %v", err)
	}
}

func TestNewRefusesUnsafeConfig(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	base := func() Options {
		return Options{APIListen: "127.0.0.1:8080", Pool: pool, Diary: d, Secrets: mapSecrets{}}
	}
	cases := map[string]func(*Options){
		"dev login on public listener": func(o *Options) {
			o.APIListen = "0.0.0.0:8080"
			o.Config.DevLogin = config.DevLoginConfig{Enabled: true, Users: []config.DevLoginUser{{Email: "a@b.c", Roles: []string{"auditor"}}}}
		},
		"dev user unknown role": func(o *Options) {
			o.Config.DevLogin = config.DevLoginConfig{Enabled: true, Users: []config.DevLoginUser{{Email: "a@b.c", Roles: []string{"god"}}}}
		},
		"oidc partial": func(o *Options) { o.Config.OIDC = config.OIDCConfig{Issuer: "https://idp"} },
		"oidc no roles": func(o *Options) {
			o.Config.OIDC = config.OIDCConfig{Issuer: "https://idp", ClientID: "x", RedirectURL: "https://f/auth/callback"}
		},
		"oidc unknown role": func(o *Options) {
			o.Config.OIDC = config.OIDCConfig{Issuer: "https://idp", ClientID: "x", RedirectURL: "https://f/auth/callback",
				RoleClaim: "groups", RoleMap: map[string][]string{"g": {"superuser"}}}
		},
	}
	for name, mut := range cases {
		o := base()
		mut(&o)
		if _, err := New(o); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
	// Non-loopback listener => Secure cookies.
	o := base()
	o.APIListen = "10.0.0.5:8080"
	s, err := New(o)
	if err != nil || !s.secure {
		t.Fatalf("non-loopback must set Secure cookies: %v", err)
	}
}

func TestAuthenticateFailsClosedOnStoreError(t *testing.T) {
	h := newHarness(t, nil)
	c := h.client()
	req, _ := http.NewRequest("POST", h.srv.URL+"/auth/dev-login", strings.NewReader(`{"email":"dev@example.com"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := c.Do(req)
	resp.Body.Close()
	ck := sessionCookie(resp)
	h.pool.Close()
	r := httptest.NewRequest("GET", "/v1/me", nil)
	r.AddCookie(ck)
	if _, err := h.svc.Authenticate(context.Background(), r); err == nil || errors.Is(err, ErrNoSession) {
		t.Fatalf("store error must surface as an error, got %v", err)
	}
	r = httptest.NewRequest("GET", "/v1/me", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: "not-base64!!"})
	if _, err := h.svc.Authenticate(context.Background(), r); !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("malformed cookie: %v", err)
	}
}
