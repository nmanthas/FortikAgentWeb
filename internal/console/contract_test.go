//go:build consolecontract

// Consumer-contract test: wires the real API, auth (dev login), access and
// integrations handlers plus the console onto a temporary Fortik database,
// then checks the JSON fields the console reads (web/console/src/api) and
// that the SPA is served next to the API exactly as main.go will mount it.
//
// It depends on other workstreams' packages, so it sits behind a build tag
// to keep `go test ./internal/console` independent of their progress:
//
//	FORTIK_TEST_PG_URL=postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable \
//	  go test -tags consolecontract -race -count=1 ./internal/console
package console_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/api"
	"fortik/internal/auth"
	"fortik/internal/config"
	"fortik/internal/console"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

type client struct {
	t    *testing.T
	base string
	c    *http.Client
	csrf string
}

func (c *client) do(method, path string, body any) (int, http.Header, []byte) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, c.base+path, rd)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet && c.csrf != "" {
		req.Header.Set(auth.CSRFHeader, c.csrf)
	}
	resp, err := c.c.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, raw
}

func (c *client) json(method, path string, body any, want int) map[string]any {
	c.t.Helper()
	code, _, raw := c.do(method, path, body)
	if code != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, code, want, raw)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		c.t.Fatalf("%s %s: not a JSON object: %s", method, path, raw)
	}
	return out
}

func requireKeys(t *testing.T, what string, m map[string]any, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Errorf("%s: missing %q (the console reads it): %v", what, k, m)
		}
	}
}

func first(t *testing.T, what string, m map[string]any, key string) map[string]any {
	t.Helper()
	l, ok := m[key].([]any)
	if !ok || len(l) == 0 {
		t.Fatalf("%s: %q is not a non-empty list: %v", what, key, m)
	}
	o, ok := l[0].(map[string]any)
	if !ok {
		t.Fatalf("%s: %q[0] is not an object", what, key)
	}
	return o
}

// contractEnv is the API server main.go builds, on a temporary database.
type contractEnv struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	ctl    *control.Store
	eng    *policy.Engine
	svc    *decide.Service
	access *access.PGStore
	store  secrets.Store
	log    *slog.Logger
	c      *client
}

// newContractEnv wires the API with sessions, access and integrations, then
// whatever mount adds (Phase 3 handlers), then the console last, as main.go
// should: "/" is the least specific pattern.
func newContractEnv(t *testing.T, mount func(e *contractEnv, srv *api.Server)) *contractEnv {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, file, _, _ := runtime.Caller(0)
	eng, err := policy.NewEngine(ctx, filepath.Join(filepath.Dir(file), "..", "..", "policies"), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	accessStore := access.NewPGStore(pool, d)
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: accessStore}

	key := make([]byte, secrets.MasterKeySize)
	_, _ = rand.Read(key)
	store, err := secrets.NewEncFile(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	sessions, err := auth.New(auth.Options{
		Config: config.AuthConfig{DevLogin: config.DevLoginConfig{Enabled: true, Users: []config.DevLoginUser{
			{Email: "sec@example.com", Roles: []string{"security", "auditor"}},
			// The sponsor of the contract agents, without the security role (Phase 4 owner rules).
			{Email: "owner@example.com", Roles: []string{"auditor"}},
		}}},
		APIListen: "127.0.0.1:8080", Pool: pool, Diary: d, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	e := &contractEnv{pool: pool, diary: d, ctl: ctl, eng: eng, svc: svc, access: accessStore, store: store, log: log}
	srv := api.NewServer(api.Server{Pool: pool, Decider: svc, Diary: d, Policy: eng, Log: log, Sessions: sessions, Secrets: store}, nil)
	srv.Mount(sessions.Routes)
	srv.Mount(access.NewHandler(accessStore, pool, log).Register)
	srv.Mount(integrations.NewHandler(integrations.NewPGStore(pool, d, store), integrations.NewRegistry(), log).Register)
	if mount != nil {
		mount(e, srv)
	}
	srv.Mount(func(mux *http.ServeMux) { mux.Handle("/", console.Handler()) })
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)

	jar, _ := cookiejar.New(nil)
	e.c = &client{t: t, base: hs.URL, c: &http.Client{Jar: jar}}
	return e
}

// login signs in with dev login and installs the CSRF value.
func (e *contractEnv) login() {
	e.c.t.Helper()
	e.c.json(http.MethodPost, "/auth/dev-login", map[string]string{"email": "sec@example.com"}, 200)
	me := e.c.json(http.MethodGet, "/v1/me", nil, 200)
	e.c.csrf, _ = me["csrf"].(string)
}

// loginAs returns a second client with its own session, signed in as email.
func (e *contractEnv) loginAs(t *testing.T, email string) *client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &client{t: t, base: e.c.base, c: &http.Client{Jar: jar}}
	c.json(http.MethodPost, "/auth/dev-login", map[string]string{"email": email}, 200)
	me := c.json(http.MethodGet, "/v1/me", nil, 200)
	c.csrf, _ = me["csrf"].(string)
	return c
}

func TestConsoleContract(t *testing.T) {
	e := newContractEnv(t, nil)
	ctx := context.Background()
	svc, c := e.svc, e.c

	// The SPA loads without a session; API paths do not fall back to it.
	code, hdr, body := c.do(http.MethodGet, "/agents/some-bot", nil)
	if code != 200 || !strings.Contains(string(body), `<div id="root">`) && !strings.Contains(string(body), "console") {
		t.Fatalf("GET /agents/some-bot: %d %s", code, body)
	}
	if hdr.Get("Content-Security-Policy") != console.ContentSecurityPolicy {
		t.Fatalf("CSP missing on SPA: %q", hdr.Get("Content-Security-Policy"))
	}
	if code, _, _ := c.do(http.MethodGet, "/v1/agents", nil); code != http.StatusUnauthorized {
		t.Fatalf("GET /v1/agents without session: %d, want 401", code)
	}

	cfg := c.json(http.MethodGet, "/auth/config", nil, 200)
	requireKeys(t, "/auth/config", cfg, "oidc_enabled", "dev_login_enabled", "dev_users")

	c.json(http.MethodPost, "/auth/dev-login", map[string]string{"email": "sec@example.com"}, 200)
	me := c.json(http.MethodGet, "/v1/me", nil, 200)
	requireKeys(t, "/v1/me", me, "kind", "email", "name", "roles", "auth_method", "csrf", "dev_login_enabled", "oidc_enabled")
	c.csrf, _ = me["csrf"].(string)
	if me["auth_method"] != "dev" || c.csrf == "" {
		t.Fatalf("/v1/me: %v", me)
	}

	// An unknown /v1 route with a session is a JSON 404 from the console
	// handler, never index.html.
	code, hdr, body = c.do(http.MethodGet, "/v1/does-not-exist", nil)
	if code != 404 || !strings.HasPrefix(hdr.Get("Content-Type"), "application/json") {
		t.Fatalf("unknown /v1 route: %d %q %s", code, hdr.Get("Content-Type"), body)
	}

	created := c.json(http.MethodPost, "/v1/agents", map[string]any{"agent_id": "bot", "name": "Bot", "type": "support", "platform": "test",
		"sponsor": "owner@example.com", "business_unit": "Ops", "workspace_user": "bot@example.com", "copy_cap": 1}, 201)
	requireKeys(t, "POST /v1/agents", created, "agent")

	// One decided action so the activity fields are populated.
	if _, err := svc.Decide(ctx, decideInput()); err != nil {
		t.Fatalf("decide: %v", err)
	}

	agents := c.json(http.MethodGet, "/v1/agents", nil, 200)
	requireKeys(t, "/v1/agents[0]", first(t, "/v1/agents", agents, "agents"),
		"agent_id", "name", "type", "platform", "sponsor", "level_name", "actions_today", "worst_class_24h", "systems_24h", "held_pending", "discovered")

	summary := c.json(http.MethodGet, "/v1/stats/summary", nil, 200)
	requireKeys(t, "/v1/stats/summary", summary, "agents_total", "actions_today", "held_pending", "red_today", "agents_not_full", "by_class_today")

	detail := c.json(http.MethodGet, "/v1/agents/bot", nil, 200)
	requireKeys(t, "/v1/agents/bot", detail, "agent", "counts_24h", "held", "access_profiles", "integrations", "token_issued")

	stats := c.json(http.MethodGet, "/v1/agents/bot/stats?hours=24", nil, 200)
	requireKeys(t, "/v1/agents/bot/stats", stats, "hours", "by_class", "by_verb", "hourly")
	requireKeys(t, "stats.hourly[0]", first(t, "stats", stats, "hourly"), "hour", "count", "worst_class")

	actions := c.json(http.MethodGet, "/v1/actions?agent_id=bot&limit=25", nil, 200)
	requireKeys(t, "/v1/actions[0]", first(t, "/v1/actions", actions, "actions"), "action_id", "agent_id", "system", "verb", "class", "decision", "rule_id", "reason", "ts")

	c.json(http.MethodGet, "/v1/held?status=all&limit=1000", nil, 200)

	put := c.json(http.MethodPut, "/v1/agents/bot/access/gmail", map[string]any{
		"profile": map[string]any{"send": "internal_only", "read": true, "max_recipients": 25}, "reason": "contract test"}, 200)
	_ = put
	all := c.json(http.MethodGet, "/v1/agents/bot/access", nil, 200)
	requireKeys(t, "access.profiles[0]", first(t, "access", all, "profiles"), "system", "version", "profile")
	hist := c.json(http.MethodGet, "/v1/agents/bot/access/gmail/history?limit=50", nil, 200)
	requireKeys(t, "history.versions[0]", first(t, "history", hist, "versions"), "system", "version", "profile", "changed_by", "changed_at", "reason")
	c.json(http.MethodPost, "/v1/agents/bot/access/gmail/revert", map[string]any{"version": 1, "reason": "contract test"}, 200)
	if code, _, raw := c.do(http.MethodPut, "/v1/agents/bot/access/gmail", map[string]any{"profile": map[string]any{"send": "everyone"}, "reason": "x"}); code != 400 ||
		!strings.Contains(string(raw), `"error"`) {
		t.Fatalf("invalid profile: %d %s (the console shows {error} bodies)", code, raw)
	}

	lvl := c.json(http.MethodPut, "/v1/agents/bot/level", map[string]any{"level": "READ_ONLY", "reason": "contract test"}, 200)
	requireKeys(t, "PUT level", lvl, "from", "to", "changed")

	tok := c.json(http.MethodPost, "/v1/agents/bot/tokens", map[string]any{}, 201)
	if s, _ := tok["token"].(string); !strings.HasPrefix(s, "agt_") {
		t.Fatalf("token: %v", tok)
	}
	c.json(http.MethodDelete, "/v1/agents/bot/tokens", nil, 200)

	schema := c.json(http.MethodGet, "/v1/integrations/schema", nil, 200)
	s0 := first(t, "schema", schema, "schemas")
	requireKeys(t, "schemas[0]", s0, "system", "title", "multi", "fields")
	requireKeys(t, "schemas[0].fields[0]", first(t, "schema", s0, "fields"), "key", "label", "type", "secret", "required")

	saved := c.json(http.MethodPut, "/v1/integrations/postgres:acme_dev", map[string]any{
		"config":  map[string]any{"host": "127.0.0.1", "port": 5432, "database": "acme", "sslmode": "disable", "environment": "dev", "admin_user": "fortik_admin", "read_role": "acme_read", "write_role": "acme_write"},
		"secrets": map[string]any{"admin_password": "contract-test-password"},
	}, 200)
	requireKeys(t, "PUT integration", saved, "key", "system", "config", "secret_fields", "secrets", "status", "test_available")
	if strings.Contains(mustJSON(saved), "contract-test-password") {
		t.Fatal("integration response contains a secret value")
	}
	list := c.json(http.MethodGet, "/v1/integrations", nil, 200)
	requireKeys(t, "integrations[0]", first(t, "integrations", list, "integrations"), "key", "status", "secrets")
	c.json(http.MethodDelete, "/v1/integrations/postgres:acme_dev", nil, 200)

	c.json(http.MethodPost, "/auth/logout", map[string]any{}, 200)
	if code, _, _ := c.do(http.MethodGet, "/v1/me", nil); code != http.StatusUnauthorized {
		t.Fatalf("/v1/me after logout: %d", code)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// decideInput is a harmless read on Postgres (classified by policy; no
// access profile, so it is denied by POL-020 — any class will do here).
func decideInput() action.Action {
	return action.Action{AgentID: "bot", System: "postgres", Verb: action.VerbRead, Source: action.SourceAPI,
		Target: map[string]any{"statement_type": "SELECT", "environment": "dev", "tables": []string{"public.t"}}}
}
