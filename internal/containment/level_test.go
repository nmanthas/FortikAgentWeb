package containment_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"fortik/internal/api"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

const (
	tokSecurity = "tok-security-0123456789"
	tokAuditor  = "tok-auditor-0123456789"
)

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

// apiServer is the real API server with the manager as its Revoker and the
// containment routes mounted behind its authentication.
func (e *env) apiServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	tokens, _ := json.Marshal([]map[string]any{
		{"name": "alice", "sha256": sha(tokSecurity), "roles": []string{"security", "auditor"}},
		{"name": "auditor", "sha256": sha(tokAuditor), "roles": []string{"auditor"}},
	})
	if err := os.WriteFile(filepath.Join(dir, "api_tokens"), tokens, 0o600); err != nil {
		t.Fatal(err)
	}
	auth, err := api.NewTokenAuth(context.Background(), secrets.File{Dir: dir}, "api_tokens")
	if err != nil {
		t.Fatal(err)
	}
	signer, err := diary.NewSigner([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	if err != nil {
		t.Fatal(err)
	}
	s := api.NewServer(api.Server{Pool: e.pool, Decider: e.dec, Diary: e.d, Signer: signer, Undo: undo.NewPGStore(e.pool, e.d),
		Policy: e.eng, Log: discard(), Revoker: e.mgr}, auth)
	s.Mount(containment.NewHandler(e.mgr, discard()).Register)
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func httpDo(t *testing.T, srv *httptest.Server, method, path, token, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(method, srv.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// PUT /v1/agents/{id}/level KILLED runs the kill steps exactly once (the
// level is set by the level API, not again by containment); repeats and a
// later containment kill repeat nothing.
func TestLevelAPIKilledRunsKillStepsOnce(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	srv := e.apiServer(t)

	if code, _ := httpDo(t, srv, "POST", "/v1/agents/a1/suspend", "", `{"reason":"x"}`); code != 401 {
		t.Fatalf("unauthenticated containment: %d", code)
	}
	code, body := httpDo(t, srv, "PUT", "/v1/agents/a1/level", tokSecurity, `{"level":"KILLED","reason":"confirmed compromise"}`)
	if code != 200 || body["changed"] != true || body["revocation_error"] != "" {
		t.Fatalf("set KILLED: %d %+v", code, body)
	}
	rev := body["revocation"].(map[string]any)
	if rev["github"] != "installation tokens revoked" || !strings.HasPrefix(rev[containment.ResultKeySteps].(string), "done: ") {
		t.Fatalf("revocation result: %+v", rev)
	}
	if e.rev.count("a1") != 1 || e.q.count("cancel:a1") != 1 {
		t.Fatalf("revoker %v queue %v", e.rev.all(), e.q.all())
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed'`); n != 1 {
		t.Fatalf("level changed %d times", n)
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 410 {
		t.Fatalf("copy after kill: %d", hb.code)
	}
	if e.str(t, `SELECT mode FROM memory_access WHERE agent_id = 'a1'`) != "none" {
		t.Fatal("memory not none")
	}
	ops, err := e.mgr.List(context.Background(), "agent", "a1", 10)
	if err != nil || len(ops) != 1 || ops[0].OpID != rev[containment.ResultKeyOp] {
		t.Fatalf("ops: %v %+v", err, ops)
	}
	wantSteps(t, ops[0], "a1", map[string]string{"set_level": "skipped", "revoke_credentials": "done", "cancel_queue": "done",
		"terminate_db_sessions": "done", "stop_instances": "done", "set_memory_access": "done"})
	if ev := e.diaryData(t, "containment.kill"); len(ev) != 1 {
		t.Fatalf("containment.kill events: %d", len(ev))
	}

	// Repeat KILLED (the level API's retry path) and a containment kill:
	// nothing is repeated, level is never re-set.
	if code, _ := httpDo(t, srv, "PUT", "/v1/agents/a1/level", tokSecurity, `{"level":"KILLED","reason":"retry"}`); code != 200 {
		t.Fatalf("repeat KILLED: %d", code)
	}
	if code, b := httpDo(t, srv, "POST", "/v1/agents/a1/kill", tokSecurity, `{"reason":"belt and braces"}`); code != 200 || b["status"] != "done" {
		t.Fatalf("containment kill after level kill: %d %+v", code, b)
	}
	if e.rev.count("a1") != 1 || e.q.count("cancel:a1") != 1 {
		t.Fatalf("kill steps repeated: revoker %v queue %v", e.rev.all(), e.q.all())
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed'`); n != 1 {
		t.Fatalf("level changed %d times", n)
	}
}

// A containment kill does not go through the level API (no recursion): the
// level is set once by containment, and the revoker is called once.
func TestContainmentKillDoesNotReenterLevelAPI(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	srv := e.apiServer(t)
	code, b := httpDo(t, srv, "POST", "/v1/containment", tokSecurity, `{"op":"kill","target_type":"agent","target_id":"a1","reason":"x"}`)
	if code != 200 || b["status"] != "done" {
		t.Fatalf("kill: %d %+v", code, b)
	}
	if e.rev.count("a1") != 1 || e.count(t, `SELECT count(*) FROM containment_ops`) != 1 {
		t.Fatalf("revoker %v", e.rev.all())
	}
	if e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed'`) != 1 {
		t.Fatal("level not changed exactly once")
	}
}

// QUARANTINED through the level API: revoke, pause queues, pause copies,
// memory staging_only; the agent is not marked suspended.
func TestLevelAPIQuarantined(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	srv := e.apiServer(t)
	code, body := httpDo(t, srv, "PUT", "/v1/agents/a1/level", tokSecurity, `{"level":"QUARANTINED","reason":"review"}`)
	if code != 200 || body["revocation_error"] != "" {
		t.Fatalf("set QUARANTINED: %d %+v", code, body)
	}
	if st := e.state(t, "a1"); st.Level != control.Quarantined || st.Suspended {
		t.Fatalf("state %+v", st)
	}
	if e.rev.count("a1") != 1 || e.q.count("pause:a1") != 1 || e.q.count("cancel:a1") != 0 {
		t.Fatalf("revoker %v queue %v", e.rev.all(), e.q.all())
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 423 {
		t.Fatalf("copy after quarantine: %d %s", hb.code, hb.raw)
	}
	if e.str(t, `SELECT mode FROM memory_access WHERE agent_id = 'a1'`) != "staging_only" {
		t.Fatal("memory not staging_only")
	}
	ev := e.diaryData(t, containment.EventQuarantine)
	if len(ev) != 1 || ev[0]["status"] != "done" || len(ev[0]["steps"].([]any)) != 4 {
		t.Fatalf("quarantine event: %+v", ev)
	}
	if got := e.str(t, `SELECT op || ':' || status FROM containment_ops WHERE target_id = 'a1' AND op = 'quarantine'`); got != "quarantine:done" {
		t.Fatalf("quarantine not in containment history: %q", got)
	}
	e.mustDeny(t, pgRead("a1", ""), "POL-011")

	// Memory already none is never loosened by a quarantine.
	e.agent(t, "a2", "payments", "jane@acme.com", 1)
	opOf(t, e.post(t, security, "/v1/agents/a2/memory/remove", `{"reason":"cut"}`))
	if code, _ := httpDo(t, srv, "PUT", "/v1/agents/a2/level", tokSecurity, `{"level":"QUARANTINED","reason":"review"}`); code != 200 {
		t.Fatal(code)
	}
	if e.str(t, `SELECT mode FROM memory_access WHERE agent_id = 'a2'`) != "none" {
		t.Fatal("quarantine loosened memory none")
	}
	// Lifting the quarantine and resuming releases the copies.
	if code, _ := httpDo(t, srv, "PUT", "/v1/agents/a1/level", tokSecurity, `{"level":"ISOLATED","reason":"cleared"}`); code != 200 {
		t.Fatal(code)
	}
	opOf(t, e.post(t, security, "/v1/agents/a1/resume", `{"reason":"cleared"}`))
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 200 {
		t.Fatalf("copy after resume: %d %s", hb.code, hb.raw)
	}
}
