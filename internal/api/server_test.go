package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/api"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

const (
	tokInterceptor = "tok-interceptor-123"
	tokAuditor     = "tok-auditor-456"
	tokSecurity    = "tok-security-789"
)

func sha(s string) string { h := sha256.Sum256([]byte(s)); return hex.EncodeToString(h[:]) }

type fakeExec struct{ fail error }

func (fakeExec) Kinds() []string { return []string{undo.KindPGRows} }
func (f fakeExec) Undo(context.Context, undo.Handle) (map[string]any, error) {
	if f.fail != nil {
		return nil, f.fail
	}
	return map[string]any{"rows_restored": 2}, nil
}

type env struct {
	srv   *httptest.Server
	store *undo.PGStore
	svc   *decide.Service
	pool  *pgxpool.Pool
	diary *diary.Diary
}

// setupOpts customises the server for Phase 2 tests: configure edits the
// Server before NewServer; mount runs before Handler (s.Mount calls).
type setupOpts struct {
	configure func(s *api.Server, pool *pgxpool.Pool, d *diary.Diary)
	mount     func(s *api.Server)
}

func setup(t *testing.T, ex undo.Executor) env { return setupWith(t, ex, setupOpts{}) }

func setupWith(t *testing.T, ex undo.Executor, o setupOpts) env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, f, _, _ := runtime.Caller(0)
	eng, err := policy.NewEngine(ctx, filepath.Join(filepath.Dir(f), "..", "..", "policies"), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	_, _ = ctl.Register(ctx, control.Agent{AgentID: "claude_code_01"}, "test")
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log}

	dir := t.TempDir()
	tokens, _ := json.Marshal([]map[string]any{
		{"name": "pgproxy", "sha256": sha(tokInterceptor), "roles": []string{"interceptor"}},
		{"name": "auditor", "sha256": sha(tokAuditor), "roles": []string{"auditor"}},
		{"name": "alice", "sha256": sha(tokSecurity), "roles": []string{"security", "auditor"}},
	})
	_ = os.WriteFile(filepath.Join(dir, "api_tokens"), tokens, 0o600)
	auth, err := api.NewTokenAuth(ctx, secrets.File{Dir: dir}, "api_tokens")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := diary.NewSigner([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="))
	us := undo.NewPGStore(pool, d)
	cfg := api.Server{Pool: pool, Decider: svc, Diary: d, Signer: signer, Undo: us,
		Executors: map[string]undo.Executor{undo.KindPGRows: ex}, Policy: eng, Log: log}
	if o.configure != nil {
		o.configure(&cfg, pool, d)
	}
	s := api.NewServer(cfg, auth)
	if o.mount != nil {
		o.mount(s)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return env{srv: srv, store: us, svc: svc, pool: pool, diary: d}
}

func call(t *testing.T, e env, method, path, token string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		if s, ok := body.(string); ok {
			rd = strings.NewReader(s)
		} else {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		}
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

var dropTable = map[string]any{"agent_id": "claude_code_01", "system": "postgres", "verb": "DELETE",
	"target": map[string]any{"statement_type": "DROP_TABLE", "environment": "prod", "tables": []string{"public.orders"}}}

func TestAuthAndRoles(t *testing.T) {
	e := setup(t, fakeExec{})
	if c, _ := call(t, e, "POST", "/v1/actions/decide", "", dropTable); c != 401 {
		t.Fatalf("no token: %d", c)
	}
	if c, _ := call(t, e, "POST", "/v1/actions/decide", "wrong", dropTable); c != 401 {
		t.Fatalf("bad token: %d", c)
	}
	if c, _ := call(t, e, "POST", "/v1/actions/decide", tokAuditor, dropTable); c != 403 {
		t.Fatalf("auditor must not decide: %d", c)
	}
	if c, _ := call(t, e, "GET", "/v1/diary", tokInterceptor, nil); c != 403 {
		t.Fatalf("interceptor must not read diary: %d", c)
	}
	if c, _ := call(t, e, "POST", "/v1/undo/act_x", tokAuditor, map[string]any{"reason": "x"}); c != 403 {
		t.Fatalf("auditor must not undo: %d", c)
	}
	if c, _ := call(t, e, "GET", "/metrics", "", nil); c != 401 {
		t.Fatalf("metrics must require auth: %d", c)
	}
	if c, _ := call(t, e, "GET", "/healthz", "", nil); c != 200 {
		t.Fatalf("healthz: %d", c)
	}
}

func TestDecideEndpointAndExplain(t *testing.T) {
	e := setup(t, fakeExec{})
	c, out := call(t, e, "POST", "/v1/actions/decide", tokInterceptor, dropTable)
	if c != 200 || out["class"] != "red" || out["decision"] != "hold" || out["rule_id"] != "POL-101" || out["level_after"] != "READ_ONLY" {
		t.Fatalf("decide: %d %v", c, out)
	}
	id := out["action_id"].(string)
	c, ex := call(t, e, "GET", "/v1/actions/"+id, tokAuditor, nil)
	if c != 200 || ex["rule_id"] != "POL-101" || ex["held"] == nil {
		t.Fatalf("explain: %d %v", c, ex)
	}
	expl := ex["explanation"].(map[string]any)
	if expl["level_before"] != "FULL" || expl["level_after"] != "READ_ONLY" || expl["policy_version"] == nil {
		t.Fatalf("explanation incomplete: %v", expl)
	}
	c, held := call(t, e, "GET", "/v1/held", tokAuditor, nil)
	if c != 200 || len(held["held"].([]any)) != 1 {
		t.Fatalf("held list: %v", held)
	}
}

func TestDecideRejectsBadInput(t *testing.T) {
	e := setup(t, fakeExec{})
	for _, body := range []any{
		`{"agent_id":"a","system":"postgres","verb":"READ","unexpected":1}`, // unknown field
		`{"agent_id":"a","system":"postgres"`,                               // malformed
		map[string]any{"system": "postgres", "verb": "READ"},                // no agent
		`{"agent_id":"a","system":"postgres","verb":"READ"} {}`,             // trailing data
	} {
		if c, _ := call(t, e, "POST", "/v1/actions/decide", tokInterceptor, body); c != 400 {
			t.Fatalf("want 400 for %v, got %d", body, c)
		}
	}
}

func TestDiaryEndpoints(t *testing.T) {
	e := setup(t, fakeExec{})
	call(t, e, "POST", "/v1/actions/decide", tokInterceptor, dropTable)
	c, v := call(t, e, "GET", "/v1/diary/verify", tokAuditor, nil)
	if c != 200 || v["ok"] != true {
		t.Fatalf("verify: %v", v)
	}
	c, exp := call(t, e, "GET", "/v1/diary/export", tokAuditor, nil)
	if c != 200 || exp["head_root"] == nil || exp["signed"] != true || exp["verification"].(map[string]any)["ok"] != true {
		t.Fatalf("export: %d %v", c, exp)
	}
	c, q := call(t, e, "GET", "/v1/diary?agent_id=claude_code_01", tokAuditor, nil)
	if c != 200 || len(q["entries"].([]any)) < 3 {
		t.Fatalf("query: %v", q)
	}
}

func prepareActive(t *testing.T, e env) string {
	t.Helper()
	out, err := e.svc.Decide(context.Background(), action.Action{AgentID: "claude_code_01", System: "postgres", Verb: "DELETE",
		Target: map[string]any{"statement_type": "DELETE", "environment": "staging", "tables": []string{"public.orders"}, "has_where": false, "where_narrow": false, "undo_preparable": true}})
	if err != nil {
		t.Fatal(err)
	}
	h := undo.Handle{ActionID: out.Action.ActionID, AgentID: "claude_code_01", Kind: undo.KindPGRows, Data: json.RawMessage(`{"table":"orders"}`), ExpiresAt: time.Now().Add(time.Hour)}
	if err := e.store.Prepare(context.Background(), h, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Activate(context.Background(), h.ActionID); err != nil {
		t.Fatal(err)
	}
	return h.ActionID
}

func TestUndoEndpoint(t *testing.T) {
	e := setup(t, fakeExec{})
	id := prepareActive(t, e)
	if c, _ := call(t, e, "POST", "/v1/undo/"+id, tokSecurity, map[string]any{}); c != 400 {
		t.Fatalf("reason required: %d", c)
	}
	c, out := call(t, e, "POST", "/v1/undo/"+id, tokSecurity, map[string]any{"reason": "staging delete was a mistake"})
	if c != 200 || out["status"] != "used" {
		t.Fatalf("undo: %d %v", c, out)
	}
	if c, _ := call(t, e, "POST", "/v1/undo/"+id, tokSecurity, map[string]any{"reason": "again"}); c != 409 {
		t.Fatalf("second undo must conflict: %d", c)
	}
	if c, out := call(t, e, "POST", "/v1/undo/act_never_prepared", tokSecurity, map[string]any{"reason": "x"}); c != 404 || !strings.Contains(out["error"].(string), "NOT undoable") {
		t.Fatalf("unprepared action must say NOT undoable: %d %v", c, out)
	}
}

func TestUndoFailureReleasesHandle(t *testing.T) {
	e := setup(t, fakeExec{fail: errors.New("upstream unreachable")})
	id := prepareActive(t, e)
	if c, _ := call(t, e, "POST", "/v1/undo/"+id, tokSecurity, map[string]any{"reason": "x"}); c != 502 {
		t.Fatalf("failed undo: %d", c)
	}
	h, _ := e.store.Get(context.Background(), id)
	if h.Status != undo.StatusActive || !strings.Contains(h.Error, "upstream unreachable") {
		t.Fatalf("handle must return to active with the error: %+v", h)
	}
}

func TestDecideActorSafeFormAndSource(t *testing.T) {
	e := setup(t, fakeExec{})
	body := map[string]any{"agent_id": "claude_code_01", "system": "postgres", "verb": "DELETE",
		"target": map[string]any{"statement_type": "DROP_TABLE", "environment": "prod", "tables": []string{"public.orders"},
			"safe_form": map[string]any{"kind": "pg_rename", "sql": "DROP TABLE everything"}}}
	c, out := call(t, e, "POST", "/v1/actions/decide", tokInterceptor, body)
	if c != 200 {
		t.Fatalf("decide: %d %v", c, out)
	}
	c, ex := call(t, e, "GET", "/v1/actions/"+out["action_id"].(string), tokAuditor, nil)
	if c != 200 || ex["held"] == nil {
		t.Fatalf("explain: %v", ex)
	}
	if sf := ex["held"].(map[string]any)["safe_form"]; sf != nil {
		t.Fatalf("caller-supplied safe_form must be dropped, got %v", sf)
	}
	_, q := call(t, e, "GET", "/v1/diary?agent_id=claude_code_01", tokAuditor, nil)
	found := false
	for _, en := range q["entries"].([]any) {
		if en.(map[string]any)["event_type"] == "action.decided" && en.(map[string]any)["actor"] == "token:pgproxy" {
			found = true
		}
	}
	if !found {
		t.Fatal("diary actor must be the authenticated token, not the body")
	}
	bad := map[string]any{"agent_id": "a", "system": "postgres", "verb": "READ", "source": "evil-\u0000"}
	if c, _ := call(t, e, "POST", "/v1/actions/decide", tokInterceptor, bad); c != 400 {
		t.Fatalf("unknown source must be rejected: %d", c)
	}
}

func TestUndoListUndoability(t *testing.T) {
	e := setup(t, fakeExec{})
	out, err := e.svc.Decide(context.Background(), action.Action{AgentID: "claude_code_01", System: "postgres", Verb: "DELETE",
		Target: map[string]any{"statement_type": "DELETE", "environment": "staging", "tables": []string{"public.orders"}, "has_where": false, "where_narrow": false, "undo_preparable": true}})
	if err != nil {
		t.Fatal(err)
	}
	h := undo.Handle{ActionID: out.Action.ActionID, AgentID: "claude_code_01", Kind: undo.KindPGRows, ExpiresAt: time.Now().Add(time.Hour),
		Data: json.RawMessage(`{"upstream":"acme_staging","database":"acme","schema":"public","table":"orders","snapshot_schema":"fortik_undo","snapshot_table":"s_1","op":"DELETE","pk_columns":["id"],"rows":335}`)}
	if err := e.store.Prepare(context.Background(), h, "t"); err != nil {
		t.Fatal(err)
	}
	if err := e.store.Activate(context.Background(), h.ActionID); err != nil {
		t.Fatal(err)
	}
	find := func() map[string]any {
		t.Helper()
		c, l := call(t, e, "GET", "/v1/undo", tokAuditor, nil)
		if c != 200 {
			t.Fatalf("list: %d %v", c, l)
		}
		for _, x := range l["undo"].([]any) {
			if m := x.(map[string]any); m["action_id"] == h.ActionID {
				return m
			}
		}
		t.Fatal("handle not listed")
		return nil
	}
	got := find()
	if got["undoable"] != true || got["why_not"] != nil || !strings.Contains(got["description"].(string), "public.orders") || got["kind"] != undo.KindPGRows {
		t.Fatalf("active handle: %v", got)
	}
	if c, _ := call(t, e, "POST", "/v1/undo/"+h.ActionID, tokSecurity, map[string]any{"reason": "mistake"}); c != 200 {
		t.Fatalf("undo: %d", c)
	}
	if got := find(); got["undoable"] != false || got["why_not"] != undo.WhyNotUsed {
		t.Fatalf("used handle: %v", got)
	}
}

func TestDiaryFilterByActionID(t *testing.T) {
	e := setup(t, fakeExec{})
	c, out := call(t, e, "POST", "/v1/actions/decide", tokInterceptor, dropTable)
	if c != 200 {
		t.Fatalf("decide: %d", c)
	}
	id := out["action_id"].(string)
	call(t, e, "POST", "/v1/actions/decide", tokInterceptor, dropTable)
	c, q := call(t, e, "GET", "/v1/diary?action_id="+id, tokAuditor, nil)
	if c != 200 {
		t.Fatalf("query: %d", c)
	}
	entries := q["entries"].([]any)
	if len(entries) == 0 {
		t.Fatal("no entries for the action")
	}
	for _, en := range entries {
		body := en.(map[string]any)["body"].(map[string]any)
		if body["data"].(map[string]any)["action_id"] != id {
			t.Fatalf("entry for another action: %v", body)
		}
	}
}
