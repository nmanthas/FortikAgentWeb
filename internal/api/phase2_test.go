package api_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/api"
	"fortik/internal/auth"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/httpx"
	"fortik/internal/secrets"
)

const (
	userSec   = "sec@example.com"   // security + auditor
	userOwner = "owner@example.com" // auditor; sponsor of agent "bot"
	userOther = "other@example.com" // auditor; owns nothing
)

// fakeRevoker records RevokeAll calls (stands in for broker.Service).
type fakeRevoker struct {
	mu    sync.Mutex
	calls []string // "agent|actor|reason"
	fail  error
}

func (f *fakeRevoker) RevokeAll(_ context.Context, agentID, actor, reason string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, agentID+"|"+actor+"|"+reason)
	return map[string]string{"aws": "deny-by-issue-time attached (tokens not recallable)"}, f.fail
}

func (f *fakeRevoker) Calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

type p2env struct {
	env
	rev     *fakeRevoker
	secrets secrets.Store
}

// p2Options lets a test swap the secret store (nil keeps the encfile one).
type p2Options struct {
	secrets   func(t *testing.T) secrets.Store
	noSecrets bool
}

func setupP2(t *testing.T, o p2Options) p2env {
	t.Helper()
	rev := &fakeRevoker{}
	var store secrets.Store
	switch {
	case o.noSecrets:
	case o.secrets != nil:
		store = o.secrets(t)
	default:
		key := make([]byte, secrets.MasterKeySize)
		_, _ = rand.Read(key)
		ef, err := secrets.NewEncFile(t.TempDir(), key)
		if err != nil {
			t.Fatal(err)
		}
		store = ef
	}
	var sessions *auth.Service
	e := setupWith(t, fakeExec{}, setupOpts{
		configure: func(s *api.Server, pool *pgxpool.Pool, d *diary.Diary) {
			svc, err := auth.New(auth.Options{
				Config: config.AuthConfig{DevLogin: config.DevLoginConfig{Enabled: true, Users: []config.DevLoginUser{
					{Email: userSec, Roles: []string{"security", "auditor"}},
					{Email: userOwner, Roles: []string{"auditor"}},
					{Email: userOther, Roles: []string{"auditor"}},
				}}},
				APIListen: "127.0.0.1:8080", Pool: pool, Diary: d,
				Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
			})
			if err != nil {
				t.Fatal(err)
			}
			sessions = svc
			s.Sessions, s.Revoker = svc, rev
			if store != nil {
				s.Secrets = store
			}
		},
		mount: func(s *api.Server) {
			s.Mount(sessions.Routes)
			// A route registered by "another package": it must get the same
			// authentication and CSRF protection as built-in routes.
			s.Mount(func(mux *http.ServeMux) {
				mux.HandleFunc("POST /v1/test/echo", func(w http.ResponseWriter, r *http.Request) {
					p, ok := authz.Require(w, r, authz.RoleAuditor)
					if !ok {
						return
					}
					httpx.WriteJSON(w, 200, map[string]string{"actor": p.Actor()})
				})
			})
		},
	})
	return p2env{env: e, rev: rev, secrets: store}
}

// browser is a console user: a cookie jar plus the session's csrf value.
type browser struct {
	c    *http.Client
	csrf string
}

func (e p2env) login(t *testing.T, email string) *browser {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	b := &browser{c: &http.Client{Jar: jar}}
	req, _ := http.NewRequest("POST", e.srv.URL+"/auth/dev-login", strings.NewReader(`{"email":"`+email+`"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("dev login %s: %d", email, resp.StatusCode)
	}
	code, me := e.do(t, b, "GET", "/v1/me", nil, nil)
	if code != 200 || me["email"] != email || me["csrf"] == "" || me["auth_method"] != "dev" {
		t.Fatalf("/v1/me: %d %v", code, me)
	}
	b.csrf = me["csrf"].(string)
	return b
}

// do sends a request as a browser (cookie) or, when b is nil, with the
// headers given (e.g. a bearer token). Cookie writes carry the CSRF header
// unless headers overrides it.
func (e p2env) do(t *testing.T, b *browser, method, path string, body any, headers map[string]string) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			raw, _ := json.Marshal(body)
			rd = bytes.NewReader(raw)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	c := http.DefaultClient
	if b != nil {
		c = b.c
		if method != "GET" {
			req.Header.Set(auth.CSRFHeader, b.csrf)
		}
	}
	for k, v := range headers {
		if v == "" {
			req.Header.Del(k)
		} else {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func bearer(tok string) map[string]string { return map[string]string{"Authorization": "Bearer " + tok} }

func (e p2env) diaryEvents(t *testing.T, typ string) []diary.Entry {
	t.Helper()
	entries, err := e.diary.Query(context.Background(), diary.Filter{Limit: 10000})
	if err != nil {
		t.Fatal(err)
	}
	var out []diary.Entry
	for _, en := range entries {
		if en.EventType == typ {
			out = append(out, en)
		}
	}
	return out
}

func (e p2env) registerBot(t *testing.T) {
	t.Helper()
	code, out := e.do(t, nil, "POST", "/v1/agents", map[string]any{"agent_id": "bot", "name": "Bot", "sponsor": "Owner@Example.com",
		"workspace_user": "bot@example.com"}, bearer(tokSecurity))
	if code != 201 {
		t.Fatalf("register bot: %d %v", code, out)
	}
}

func TestCookieSessionsAndCSRF(t *testing.T) {
	e := setupP2(t, p2Options{})
	sec := e.login(t, userSec)

	// Cookie GET needs no CSRF.
	if c, _ := e.do(t, sec, "GET", "/v1/agents", nil, nil); c != 200 {
		t.Fatalf("cookie GET: %d", c)
	}
	newAgent := map[string]any{"agent_id": "csrf_bot"}
	// Cookie write without / with a wrong CSRF header is refused.
	if c, _ := e.do(t, sec, "POST", "/v1/agents", newAgent, map[string]string{auth.CSRFHeader: ""}); c != 403 {
		t.Fatalf("cookie POST without CSRF: %d", c)
	}
	if c, _ := e.do(t, sec, "POST", "/v1/agents", newAgent, map[string]string{auth.CSRFHeader: "wrong"}); c != 403 {
		t.Fatalf("cookie POST with wrong CSRF: %d", c)
	}
	if c, out := e.do(t, sec, "POST", "/v1/agents", newAgent, nil); c != 201 {
		t.Fatalf("cookie POST with CSRF: %d %v", c, out)
	}
	// Mounted routes get the same protection and the principal.
	if c, _ := e.do(t, sec, "POST", "/v1/test/echo", "{}", map[string]string{auth.CSRFHeader: ""}); c != 403 {
		t.Fatalf("mounted route without CSRF: %d", c)
	}
	if c, out := e.do(t, sec, "POST", "/v1/test/echo", "{}", nil); c != 200 || out["actor"] != "user:"+userSec {
		t.Fatalf("mounted route: %d %v", c, out)
	}
	// Bearer writes need no CSRF.
	if c, out := e.do(t, nil, "POST", "/v1/agents", map[string]any{"agent_id": "bearer_bot"}, bearer(tokSecurity)); c != 201 {
		t.Fatalf("bearer POST: %d %v", c, out)
	}
	if c, out := e.do(t, nil, "POST", "/v1/test/echo", "{}", bearer(tokAuditor)); c != 200 || out["actor"] != "token:auditor" {
		t.Fatalf("mounted route via bearer: %d %v", c, out)
	}
	// An invalid bearer token is refused even alongside a valid cookie.
	if c, _ := e.do(t, sec, "GET", "/v1/agents", nil, bearer("nope")); c != 401 {
		t.Fatalf("bad bearer + good cookie: %d", c)
	}
	// Roles still apply to session users.
	other := e.login(t, userOther)
	if c, _ := e.do(t, other, "POST", "/v1/agents", map[string]any{"agent_id": "nope"}, nil); c != 403 {
		t.Fatalf("auditor session must not register agents: %d", c)
	}
	// /v1/me for a bearer token, and /auth/config is public.
	if c, me := e.do(t, nil, "GET", "/v1/me", nil, bearer(tokSecurity)); c != 200 || me["kind"] != "token" || me["csrf"] != nil {
		t.Fatalf("/v1/me bearer: %d %v", c, me)
	}
	if c, cfg := e.do(t, nil, "GET", "/auth/config", nil, nil); c != 200 || cfg["dev_login_enabled"] != true || cfg["oidc_enabled"] != false {
		t.Fatalf("/auth/config: %d %v", c, cfg)
	}
	// Logout revokes the session.
	if c, _ := e.do(t, sec, "POST", "/auth/logout", nil, nil); c != 200 {
		t.Fatalf("logout: %d", c)
	}
	if c, _ := e.do(t, sec, "GET", "/v1/agents", nil, nil); c != 401 {
		t.Fatalf("after logout: %d", c)
	}
	if c, _ := e.do(t, nil, "GET", "/v1/agents", nil, map[string]string{"Cookie": auth.SessionCookie + "=garbage"}); c != 401 {
		t.Fatalf("garbage cookie: %d", c)
	}
}

func TestLevelRules(t *testing.T) {
	e := setupP2(t, p2Options{})
	e.registerBot(t)
	owner, other, sec := e.login(t, userOwner), e.login(t, userOther), e.login(t, userSec)
	level := func(b *browser, to, reason string) (int, map[string]any) {
		t.Helper()
		return e.do(t, b, "PUT", "/v1/agents/bot/level", map[string]any{"level": to, "reason": reason}, nil)
	}

	if c, _ := level(owner, "READ_ONLY", ""); c != 400 {
		t.Fatalf("reason required: %d", c)
	}
	if c, _ := level(owner, "LOUD", "x"); c != 400 {
		t.Fatalf("unknown level: %d", c)
	}
	if c, _ := level(other, "READ_ONLY", "not mine"); c != 403 {
		t.Fatalf("non-owner auditor: %d", c)
	}
	if c, _ := e.do(t, nil, "PUT", "/v1/agents/bot/level", map[string]any{"level": "READ_ONLY", "reason": "x"}, bearer(tokAuditor)); c != 403 {
		t.Fatalf("auditor token: %d", c)
	}
	// Owner: step down any amount (below KILLED).
	if c, out := level(owner, "READ_ONLY", "investigating"); c != 200 || out["from"] != "FULL" || out["to"] != "READ_ONLY" || out["changed"] != true {
		t.Fatalf("owner step down: %d %v", c, out)
	}
	// Owner: step up two levels refused, one level allowed.
	if c, _ := level(owner, "FULL", "all good"); c != 403 {
		t.Fatalf("owner two-level step up: %d", c)
	}
	if c, out := level(owner, "SUPERVISED", "looks fine"); c != 200 || out["to"] != "SUPERVISED" {
		t.Fatalf("owner one-level step up: %d %v", c, out)
	}
	// Owner cannot kill.
	if c, _ := level(owner, "KILLED", "stop"); c != 403 {
		t.Fatalf("owner kill: %d", c)
	}
	if len(e.rev.Calls()) != 0 {
		t.Fatalf("revoker called without quarantine/kill: %v", e.rev.Calls())
	}
	// Security kills: revoker is called and its result returned.
	c, out := level(sec, "KILLED", "exfiltration suspected")
	if c != 200 || out["to"] != "KILLED" || out["revocation"] == nil || out["revocation_error"] != "" {
		t.Fatalf("security kill: %d %v", c, out)
	}
	if rv := out["revocation"].(map[string]any); !strings.Contains(rv["aws"].(string), "not recallable") {
		t.Fatalf("revocation result: %v", rv)
	}
	if calls := e.rev.Calls(); len(calls) != 1 || calls[0] != "bot|user:"+userSec+"|exfiltration suspected" {
		t.Fatalf("revoker calls: %v", calls)
	}
	// Leaving KILLED: owner never; security one level only.
	if c, _ := level(owner, "QUARANTINED", "please"); c != 403 {
		t.Fatalf("owner leaving KILLED: %d", c)
	}
	if c, _ := level(sec, "ISOLATED", "two steps"); c != 403 {
		t.Fatalf("security two-level step up: %d", c)
	}
	e.rev.mu.Lock()
	e.rev.fail = errors.New("aws unreachable")
	e.rev.mu.Unlock()
	c, out = level(sec, "QUARANTINED", "contained")
	if c != 200 || out["to"] != "QUARANTINED" || !strings.Contains(out["revocation_error"].(string), "aws unreachable") {
		t.Fatalf("quarantine with revocation error: %d %v", c, out)
	}
	if len(e.rev.Calls()) != 2 {
		t.Fatalf("quarantine must call the revoker: %v", e.rev.Calls())
	}
	// Owner may step up from QUARANTINED by one.
	if c, _ := level(owner, "ISOLATED", "contained, resuming slowly"); c != 200 {
		t.Fatalf("owner step up from QUARANTINED: %d", c)
	}
	// No-op change: 200, not recorded.
	if c, out := level(owner, "ISOLATED", "same"); c != 200 || out["changed"] != false {
		t.Fatalf("no-op: %d %v", c, out)
	}
	if c, _ := e.do(t, sec, "PUT", "/v1/agents/ghost/level", map[string]any{"level": "KILLED", "reason": "x"}, nil); c != 404 {
		t.Fatalf("unknown agent: %d", c)
	}

	evs := e.diaryEvents(t, diary.EventLevelChanged)
	if len(evs) != 5 {
		t.Fatalf("want 5 level changes in the diary, got %d", len(evs))
	}

	if evs[2].Actor != "user:"+userSec || !strings.Contains(evs[2].BodyJSON, "exfiltration suspected") || !strings.Contains(evs[2].BodyJSON, `"to":"KILLED"`) {
		t.Fatalf("kill diary entry: %s %s", evs[2].Actor, evs[2].BodyJSON)
	}
	if evs[0].Actor != "user:"+userOwner || !strings.Contains(evs[0].BodyJSON, `"as_owner":true`) {
		t.Fatalf("owner diary entry: %s %s", evs[0].Actor, evs[0].BodyJSON)
	}
}

func TestAgentTokensEndToEnd(t *testing.T) {
	e := setupP2(t, p2Options{})
	e.registerBot(t)
	ctx := context.Background()

	if c, _ := e.do(t, nil, "POST", "/v1/agents/bot/tokens", nil, bearer(tokAuditor)); c != 403 {
		t.Fatalf("auditor issuing token: %d", c)
	}
	if c, _ := e.do(t, nil, "POST", "/v1/agents/ghost/tokens", nil, bearer(tokSecurity)); c != 404 {
		t.Fatalf("unknown agent: %d", c)
	}
	// Another agent's entry must survive our read-modify-write.
	_ = e.secrets.Put(ctx, "agent_tokens", []byte(`{"other_agent":"`+sha("other-token")+`"}`))

	c, out := e.do(t, nil, "POST", "/v1/agents/bot/tokens", nil, bearer(tokSecurity))
	tok, _ := out["token"].(string)
	if c != 201 || !strings.HasPrefix(tok, api.AgentTokenPrefix) || len(tok) < 40 || out["replaced"] != false {
		t.Fatalf("issue: %d %v", c, out)
	}
	tokens := func() map[string]string {
		raw, err := e.secrets.Get(ctx, "agent_tokens")
		if err != nil {
			t.Fatal(err)
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	m := tokens()
	if m["bot"] != sha(tok) || m["other_agent"] != sha("other-token") {
		t.Fatalf("agent_tokens after issue: %v", m)
	}
	issued := e.diaryEvents(t, api.EventAgentTokenIssued)
	if len(issued) != 1 || strings.Contains(issued[0].BodyJSON, tok) || strings.Contains(issued[0].BodyJSON, sha(tok)) ||
		!strings.Contains(issued[0].BodyJSON, sha(tok)[:12]) || issued[0].Actor != "token:alice" {
		t.Fatalf("token_issued diary entry must hold only a fingerprint prefix: %s", issued[0].BodyJSON)
	}

	// Re-issue (via a console session) replaces the old token.
	sec := e.login(t, userSec)
	c, out = e.do(t, sec, "POST", "/v1/agents/bot/tokens", nil, nil)
	tok2, _ := out["token"].(string)
	if c != 201 || tok2 == tok || out["replaced"] != true {
		t.Fatalf("re-issue: %d %v", c, out)
	}
	if m := tokens(); m["bot"] != sha(tok2) {
		t.Fatalf("re-issue must replace the hash: %v", m)
	}
	// GET agent reports presence only.
	if c, out := e.do(t, nil, "GET", "/v1/agents/bot", nil, bearer(tokAuditor)); c != 200 || out["token_issued"] != true {
		t.Fatalf("token_issued flag: %d %v", c, out["token_issued"])
	}

	// Revoke.
	if c, out := e.do(t, sec, "DELETE", "/v1/agents/bot/tokens", nil, nil); c != 200 || out["revoked"] != true {
		t.Fatalf("revoke: %d %v", c, out)
	}
	if m := tokens(); m["bot"] != "" || m["other_agent"] == "" {
		t.Fatalf("after revoke: %v", m)
	}
	if c, out := e.do(t, sec, "DELETE", "/v1/agents/bot/tokens", nil, nil); c != 200 || out["revoked"] != false {
		t.Fatalf("second revoke: %d %v", c, out)
	}
	if n := len(e.diaryEvents(t, api.EventAgentTokenRevoked)); n != 1 {
		t.Fatalf("want 1 token_revoked event, got %d", n)
	}

	// A corrupt secret is never overwritten.
	_ = e.secrets.Put(ctx, "agent_tokens", []byte(`not json`))
	if c, _ := e.do(t, nil, "POST", "/v1/agents/bot/tokens", nil, bearer(tokSecurity)); c != 500 {
		t.Fatalf("corrupt secret: %d", c)
	}
	if raw, _ := e.secrets.Get(ctx, "agent_tokens"); string(raw) != "not json" {
		t.Fatalf("corrupt secret was overwritten: %q", raw)
	}
}

func TestAgentTokensNeedWritableStore(t *testing.T) {
	ro := setupP2(t, p2Options{secrets: func(t *testing.T) secrets.Store { return secrets.AsStore(secrets.File{Dir: t.TempDir()}) }})
	ro.registerBot(t)
	if c, out := ro.do(t, nil, "POST", "/v1/agents/bot/tokens", nil, bearer(tokSecurity)); c != 503 || !strings.Contains(out["error"].(string), "read-only") {
		t.Fatalf("read-only store: %d %v", c, out)
	}
	none := setupP2(t, p2Options{noSecrets: true})
	none.registerBot(t)
	if c, _ := none.do(t, nil, "POST", "/v1/agents/bot/tokens", nil, bearer(tokSecurity)); c != 503 {
		t.Fatalf("no store: %d", c)
	}
}

func TestAgentRegistryAndConsoleStats(t *testing.T) {
	e := setupP2(t, p2Options{})
	sec := bearer(tokSecurity)
	for _, bad := range []any{
		map[string]any{"agent_id": "bad id!"},
		map[string]any{"agent_id": "x", "sponsor": "not-an-email"},
		map[string]any{"agent_id": "x", "level": 0}, // unknown field
		map[string]any{"agent_id": "x", "copy_cap": -1},
	} {
		if c, _ := e.do(t, nil, "POST", "/v1/agents", bad, sec); c != 400 {
			t.Fatalf("want 400 for %v, got %d", bad, c)
		}
	}
	e.registerBot(t)
	if c, _ := e.do(t, nil, "POST", "/v1/agents", map[string]any{"agent_id": "bot"}, sec); c != 409 {
		t.Fatalf("duplicate: %d", c)
	}
	// PATCH: fields change and are recorded; agent_id/level are not patchable.
	c, out := e.do(t, nil, "PATCH", "/v1/agents/bot", map[string]any{"name": "Bot 2", "copy_cap": 3}, sec)
	if a := out["agent"].(map[string]any); c != 200 || a["name"] != "Bot 2" || a["copy_cap"] != float64(3) || a["owner"] != userOwner {
		t.Fatalf("patch: %d %v", c, out)
	}
	if c, _ := e.do(t, nil, "PATCH", "/v1/agents/bot", map[string]any{"level": 5}, sec); c != 400 {
		t.Fatalf("patch level: %d", c)
	}
	if c, _ := e.do(t, nil, "PATCH", "/v1/agents/ghost", map[string]any{"name": "x"}, sec); c != 404 {
		t.Fatalf("patch unknown: %d", c)
	}
	if evs := e.diaryEvents(t, api.EventAgentUpdated); len(evs) != 1 || !strings.Contains(evs[0].BodyJSON, "Bot 2") {
		t.Fatalf("agent.updated: %v", evs)
	}
	if evs := e.diaryEvents(t, diary.EventAgentRegistered); len(evs) < 1 {
		t.Fatal("agent.registered missing")
	}

	// Activity: one red held action for claude_code_01 (POL-101).
	if c, _ := e.do(t, nil, "POST", "/v1/actions/decide", dropTable, bearer(tokInterceptor)); c != 200 {
		t.Fatalf("decide: %d", c)
	}

	c, sum := e.do(t, nil, "GET", "/v1/stats/summary", nil, bearer(tokAuditor))
	if c != 200 || sum["agents_total"] != float64(2) || sum["actions_today"] != float64(1) || sum["red_today"] != float64(1) ||
		sum["held_pending"] != float64(1) || sum["agents_not_full"] != float64(1) {
		t.Fatalf("summary: %d %v", c, sum)
	}
	if bl := sum["agents_by_level"].(map[string]any); bl["READ_ONLY"] != float64(1) || bl["FULL"] != float64(1) || bl["KILLED"] != float64(0) {
		t.Fatalf("agents_by_level: %v", bl)
	}
	if bc := sum["by_class_today"].(map[string]any); bc["red"] != float64(1) || bc["green"] != float64(0) {
		t.Fatalf("by_class_today: %v", bc)
	}

	c, list := e.do(t, nil, "GET", "/v1/agents", nil, bearer(tokAuditor))
	rows := list["agents"].([]any)
	if c != 200 || len(rows) != 2 {
		t.Fatalf("list: %d %v", c, list)
	}
	byID := map[string]map[string]any{}
	for _, r := range rows {
		byID[r.(map[string]any)["agent_id"].(string)] = r.(map[string]any)
	}
	if a := byID["claude_code_01"]; a["actions_today"] != float64(1) || a["worst_class_24h"] != "red" || a["level_name"] != "READ_ONLY" {
		t.Fatalf("claude row: %v", a)
	}
	if a := byID["bot"]; a["actions_today"] != float64(0) || a["worst_class_24h"] != nil || a["owner"] != userOwner {
		t.Fatalf("bot row: %v", a)
	}

	c, one := e.do(t, nil, "GET", "/v1/agents/claude_code_01", nil, bearer(tokAuditor))
	if c != 200 || one["held_pending"] != float64(1) || one["counts_24h"].(map[string]any)["red"] != float64(1) || one["access_profiles"] == nil {
		t.Fatalf("get agent: %d %v", c, one)
	}
	if c, _ := e.do(t, nil, "GET", "/v1/agents/ghost", nil, bearer(tokAuditor)); c != 404 {
		t.Fatalf("get unknown: %d", c)
	}

	c, st := e.do(t, nil, "GET", "/v1/agents/claude_code_01/stats?hours=24", nil, bearer(tokAuditor))
	if c != 200 || st["by_class"].(map[string]any)["red"] != float64(1) || st["by_verb"].(map[string]any)["DELETE"] != float64(1) ||
		st["by_system"].(map[string]any)["postgres"] != float64(1) {
		t.Fatalf("stats: %d %v", c, st)
	}
	hourly := st["hourly"].([]any)
	if len(hourly) != 24 {
		t.Fatalf("hourly buckets: %d", len(hourly))
	}
	if lastB := hourly[23].(map[string]any); lastB["count"] != float64(1) || lastB["worst_class"] != "red" {
		t.Fatalf("current hour bucket: %v", lastB)
	}
	if c, _ := e.do(t, nil, "GET", "/v1/agents/claude_code_01/stats?hours=0", nil, bearer(tokAuditor)); c != 400 {
		t.Fatalf("hours=0: %d", c)
	}
	if c, _ := e.do(t, nil, "GET", "/v1/stats/summary", nil, bearer(tokInterceptor)); c != 403 {
		t.Fatalf("interceptor summary: %d", c)
	}
}
