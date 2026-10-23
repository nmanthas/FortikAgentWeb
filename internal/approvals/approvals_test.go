package approvals_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/approvals"
	"fortik/internal/authz"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/pgsql"
	"fortik/internal/policy"
	"fortik/internal/testutil"
	"fortik/internal/undo"
	"fortik/internal/undo/pgundo"
)

var bg = context.Background()

var (
	security  = authz.Principal{Kind: authz.KindUser, Email: "sec@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	security2 = authz.Principal{Kind: authz.KindUser, Email: "sec2@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	// SECURITY1 with different case is the same approver as security.
	securityUpper = authz.Principal{Kind: authz.KindUser, Email: "SEC@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	// ownerSec sponsors coder (and analyst) and holds the security role.
	ownerSec = authz.Principal{Kind: authz.KindUser, Email: "Jane@Acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	auditor  = authz.Principal{Kind: authz.KindUser, Email: "audit@acme.com", Roles: map[string]bool{authz.RoleAuditor: true}}
	admin    = authz.Principal{Kind: authz.KindToken, Name: "ops", Roles: map[string]bool{authz.RoleAdmin: true}}
)

const (
	coder   = "claude_code_01"
	analyst = "analyst_02"
	other   = "finance_agent_07"
)

type env struct {
	t     *testing.T
	pool  *pgxpool.Pool
	d     *diary.Diary
	ctl   *control.Store
	undo  *undo.PGStore
	acc   *access.PGStore
	f     *pgrolestest.Fixture
	dec   *decide.Service
	svc   *approvals.Service
	srv   *httptest.Server
	mu    sync.Mutex
	who   *authz.Principal
	quiet *slog.Logger
}

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

func setup(t *testing.T, cfg approvals.Config) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, a := range []control.Agent{
		{AgentID: coder, Type: "coding", Sponsor: "jane@acme.com"},
		{AgentID: analyst, Type: "analytics", Sponsor: "jane@acme.com"},
		{AgentID: other, Type: "finance", Sponsor: "bob@acme.com"},
	} {
		if _, err := ctl.Register(bg, a, "test"); err != nil {
			t.Fatal(err)
		}
	}
	f := pgrolestest.New(t, "acme_prod")
	f.Exec("CREATE TABLE public.orders (id serial PRIMARY KEY, item text NOT NULL, qty int NOT NULL DEFAULT 1)")
	f.Exec("INSERT INTO public.orders (item, qty) SELECT 'item-' || g, g FROM generate_series(1, 50) g")
	f.Exec("CREATE TABLE public.customers (id int PRIMARY KEY, name text)")
	f.Exec("ALTER TABLE public.orders OWNER TO " + f.AdminUser)
	f.Exec("ALTER TABLE public.customers OWNER TO " + f.AdminUser)
	// Renaming a table needs CREATE on its schema (PG 15+ no longer grants it on public).
	f.Exec("GRANT CREATE ON SCHEMA public TO " + f.AdminUser)

	acc := access.NewPGStore(pool, d)
	for _, a := range []string{coder, analyst, other} {
		if _, err := acc.Put(bg, a, "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_write"}}`), "user:sec@acme.com", "test"); err != nil {
			t.Fatal(err)
		}
	}
	eng, err := policy.NewEngine(bg, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	us := undo.NewPGStore(pool, d)
	e := &env{t: t, pool: pool, d: d, ctl: ctl, undo: us, acc: acc, f: f, quiet: log}
	e.dec = &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc,
		Enrichers: []decide.Enricher{approvals.NewGrantEnricher(pool)},
		Observers: []decide.Observer{approvals.NewGrantObserver(d)}}
	e.svc = approvals.New(pool, d, us, f.Source, cfg, log)
	mux := http.NewServeMux()
	approvals.NewHandler(e.svc).Register(mux)
	e.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		e.mu.Lock()
		who := e.who
		e.mu.Unlock()
		if who != nil {
			r = r.WithContext(authz.With(r.Context(), *who))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(e.srv.Close)
	return e
}

// pgAct builds the Action the proxy would build for sql (same classifier,
// same target keys, same safe form).
func (e *env) pgAct(agent, sql string) action.Action {
	e.t.Helper()
	sts, err := pgsql.Classify(sql)
	if err != nil {
		e.t.Fatal(err)
	}
	st := &sts[0]
	target := map[string]any{
		"upstream": e.f.Upstream, "database": e.f.DB, "environment": "prod",
		"statement_type": st.StatementType, "tables": append([]string{}, st.Tables...),
		"schema": st.Schema, "table": st.Table, "has_where": st.HasWhere, "where_narrow": false,
		"undo_preparable": st.SnapshotPreparable(), "dangerous_functions": append([]string{}, st.DangerousFunctions...),
		"protocol": "simple", "statement_count": len(sts), "fingerprint": st.Fingerprint, "normalized_sql": st.Normalized,
		"on_conflict_update": st.OnConflictUpdate, "merge_has_delete": st.MergeHasDelete, "volatile_where": st.VolatileWhere,
	}
	if (st.StatementType == pgsql.TypeDropTable || st.StatementType == pgsql.TypeTruncate) && st.SingleRelation() {
		if q, trash, err := pgsql.SafeRenameSQL(st, time.Now()); err == nil {
			target["safe_form"] = map[string]any{"kind": undo.KindPGRename, "sql": q, "trash_table": trash}
		}
	}
	return action.Action{AgentID: agent, System: action.SystemPostgres, Verb: st.Verb, Target: target, Source: action.SourcePGProxy}
}

// decideCopy decides a fresh copy of a (new action id, same target).
func (e *env) decideCopy(a action.Action) decide.Outcome {
	e.t.Helper()
	b, _ := json.Marshal(a.Target)
	var tgt map[string]any
	_ = json.Unmarshal(b, &tgt)
	a.Target, a.ActionID = tgt, ""
	out, err := e.dec.Decide(bg, a)
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

func (e *env) do(p *authz.Principal, path, body string) (int, map[string]any) {
	e.t.Helper()
	e.mu.Lock()
	e.who = p
	e.mu.Unlock()
	resp, err := http.Post(e.srv.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) count(q string, args ...any) int {
	e.t.Helper()
	var n int
	if err := e.pool.QueryRow(bg, q, args...).Scan(&n); err != nil {
		e.t.Fatal(err)
	}
	return n
}

func (e *env) upCount(q string) int {
	e.t.Helper()
	var n int
	if err := e.f.Super.QueryRow(bg, q).Scan(&n); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return n
}

func (e *env) relExists(name string) bool {
	e.t.Helper()
	var ok bool
	if err := e.f.Super.QueryRow(bg, `SELECT to_regclass($1) IS NOT NULL`, name).Scan(&ok); err != nil {
		e.t.Fatal(err)
	}
	return ok
}

func (e *env) outcome(actionID string) string {
	e.t.Helper()
	var o string
	if err := e.pool.QueryRow(bg, `SELECT outcome FROM held_actions WHERE action_id = $1`, actionID).Scan(&o); err != nil {
		e.t.Fatal(err)
	}
	return o
}

func (e *env) events(typ, actionID string) int {
	return e.count(`SELECT count(*) FROM diary WHERE event_type = $1 AND body_json::jsonb -> 'data' ->> 'action_id' = $2`, typ, actionID)
}

func (e *env) verifyDiary() {
	e.t.Helper()
	rep, err := e.d.VerifyChain(bg)
	if err != nil {
		e.t.Fatal(err)
	}
	if !rep.OK {
		e.t.Fatalf("diary chain broken: %v", rep.Problems)
	}
}

func (e *env) setLevel(agent string, l control.Level) {
	e.t.Helper()
	if _, err := e.ctl.SetLevel(bg, agent, l, "test", "test"); err != nil {
		e.t.Fatal(err)
	}
}

func path(id, verb string) string { return "/v1/held/" + id + "/" + verb }

// The accident gate: DROP TABLE is held red; approving it unchanged is
// refused; approving it with the safe form renames the table to trash (undo
// handle recorded first), and pgundo renames it back.
func TestRedDropApprovedWithSafeFormAndUndone(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(coder, "DROP TABLE orders"))
	if out.Result.Decision != policy.Hold || out.Result.Class != policy.Red || out.Result.RuleID != "POL-101" {
		t.Fatalf("DROP: %+v", out.Result)
	}
	id := out.Action.ActionID

	if code, _ := e.do(nil, path(id, "approve"), `{"reason":"x","use_safe_form":true}`); code != 401 {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := e.do(&auditor, path(id, "approve"), `{"reason":"x","use_safe_form":true}`); code != 403 {
		t.Fatalf("auditor: %d", code)
	}
	code, body := e.do(&security, path(id, "approve"), `{"reason":"looks fine"}`)
	if code != 409 || !strings.Contains(body["error"].(string), "red actions are never run unchanged") {
		t.Fatalf("approve red without safe form: %d %v", code, body)
	}
	code, body = e.do(&ownerSec, path(id, "approve"), `{"reason":"my agent","use_safe_form":true}`)
	if code != 403 || !strings.Contains(body["error"].(string), "sponsor") {
		t.Fatalf("owner self-approval: %d %v", code, body)
	}
	if code, _ := e.do(&security, path(id, "approve"), `{"reason":"x","use_safe_form":true,"sql":"DROP TABLE x"}`); code != 400 {
		t.Fatalf("unknown field accepted: %d", code)
	}
	if code, _ := e.do(&security, path(id, "approve"), `{"reason":"  ","use_safe_form":true}`); code != 400 {
		t.Fatalf("blank reason accepted: %d", code)
	}
	if n := e.count(`SELECT count(*) FROM held_approvals WHERE action_id = $1`, id); n != 0 {
		t.Fatalf("refused attempts recorded %d votes", n)
	}
	if !e.relExists("public.orders") {
		t.Fatal("orders gone before approval")
	}

	code, body = e.do(&security, path(id, "approve"), `{"reason":"cleanup approved, keep it undoable","use_safe_form":true}`)
	if code != 200 || body["outcome"] != "approved" {
		t.Fatalf("approve with safe form: %d %v", code, body)
	}
	sf := body["safe_form"].(map[string]any)
	trash, _ := sf["trash_table"].(string)
	if !strings.HasPrefix(trash, "fortik_trash_orders_") || sf["op"] != "DROP" || sf["undo_kind"] != undo.KindPGRename {
		t.Fatalf("safe form result: %v", sf)
	}
	if e.relExists("public.orders") {
		t.Fatal("orders still exists after the safe form")
	}
	if n := e.upCount(`SELECT count(*) FROM public.` + pgsql.QuoteIdent(trash)); n != 50 {
		t.Fatalf("trash table rows = %d", n)
	}
	h, err := e.undo.Get(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	var hd undo.PGRenameData
	_ = json.Unmarshal(h.Data, &hd)
	if h.Kind != undo.KindPGRename || h.Status != undo.StatusActive || hd.TrashTable != trash || hd.Table != "orders" ||
		hd.Schema != "public" || hd.Upstream != e.f.Upstream || hd.Database != e.f.DB || hd.Op != "DROP" {
		t.Fatalf("undo handle: %+v %+v", h, hd)
	}
	if e.outcome(id) != "approved" {
		t.Fatal("hold not approved")
	}
	for _, ev := range []string{approvals.EventActionApproved, approvals.EventSafeFormExecuted, diary.EventUndoPrepared, diary.EventUndoActivated} {
		if e.events(ev, id) != 1 {
			t.Fatalf("diary %s missing", ev)
		}
	}
	// The undo handle was prepared before the safe form's diary record.
	if e.count(`SELECT count(*) FROM diary p, diary x WHERE p.event_type = 'undo.prepared' AND x.event_type = 'safe_form.executed'
		AND p.body_json::jsonb->'data'->>'action_id' = $1 AND x.body_json::jsonb->'data'->>'action_id' = $1 AND p.seq < x.seq`, id) != 1 {
		t.Fatal("undo handle not recorded before the safe form")
	}
	if code, _ := e.do(&security2, path(id, "approve"), `{"reason":"again","use_safe_form":true}`); code != 409 {
		t.Fatalf("second approval of a decided hold: %d", code)
	}

	// Undo through the real executor (as the API's /v1/undo does).
	ex := pgundo.NewExecutor(config.PGProxyConfig{}, nil, pgundo.WithIntegrations(e.f.Source))
	claimed, err := e.undo.Claim(bg, id, "user:sec@acme.com")
	if err != nil {
		t.Fatal(err)
	}
	res, err := ex.Undo(bg, claimed)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.undo.Complete(bg, id, "user:sec@acme.com", res); err != nil {
		t.Fatal(err)
	}
	if n := e.upCount(`SELECT count(*) FROM public.orders`); n != 50 {
		t.Fatalf("orders after undo = %d", n)
	}
	if e.relExists("public." + pgsql.QuoteIdent(trash)) {
		t.Fatal("trash table still exists after undo")
	}
	e.verifyDiary()
}

// TRUNCATE's safe form renames to trash and recreates an empty copy; undo
// drops the empty copy and restores the rows.
func TestRedTruncateSafeForm(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(coder, "TRUNCATE orders"))
	if out.Result.Decision != policy.Hold || out.Result.Class != policy.Red {
		t.Fatalf("TRUNCATE: %+v", out.Result)
	}
	id := out.Action.ActionID
	code, body := e.do(&admin, path(id, "approve"), `{"reason":"reset test data","use_safe_form":true}`)
	if code != 200 {
		t.Fatalf("approve: %d %v", code, body)
	}
	sf := body["safe_form"].(map[string]any)
	if sf["op"] != "TRUNCATE" || sf["recreated_empty_table"] != true {
		t.Fatalf("safe form: %v", sf)
	}
	if n := e.upCount(`SELECT count(*) FROM public.orders`); n != 0 {
		t.Fatalf("recreated orders has %d rows", n)
	}
	// The recreated table keeps the structure (defaults, PK).
	e.f.Exec(`INSERT INTO public.orders (item) VALUES ('probe')`)
	e.f.Exec(`DELETE FROM public.orders`)
	if n := e.upCount(`SELECT count(*) FROM public.` + pgsql.QuoteIdent(sf["trash_table"].(string))); n != 50 {
		t.Fatalf("trash rows = %d", n)
	}
	ex := pgundo.NewExecutor(config.PGProxyConfig{}, nil, pgundo.WithIntegrations(e.f.Source))
	h, err := e.undo.Claim(bg, id, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ex.Undo(bg, h); err != nil {
		t.Fatal(err)
	}
	if n := e.upCount(`SELECT count(*) FROM public.orders`); n != 50 {
		t.Fatalf("orders after undo = %d", n)
	}
}

// A red hold without a safe form can never be approved, with or without
// use_safe_form.
func TestRedWithoutSafeFormRefused(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(coder, "DROP SCHEMA reporting CASCADE"))
	if out.Result.Decision != policy.Hold || out.Result.Class != policy.Red {
		t.Fatalf("DROP SCHEMA: %+v", out.Result)
	}
	for _, body := range []string{`{"reason":"ok","use_safe_form":true}`, `{"reason":"ok"}`} {
		code, resp := e.do(&security, path(out.Action.ActionID, "approve"), body)
		if code != 409 || !strings.Contains(resp["error"].(string), "red actions are never run unchanged") {
			t.Fatalf("%s: %d %v", body, code, resp)
		}
	}
	if e.outcome(out.Action.ActionID) != "pending" {
		t.Fatal("hold changed")
	}
}

// Stored safe_form SQL is never trusted: the rename is rebuilt from the
// target identifiers (a tampered sql field changes nothing), and identifiers
// are quoted.
func TestSafeFormIgnoresStoredSQLAndQuotes(t *testing.T) {
	e := setup(t, approvals.Config{})
	e.f.Exec(`CREATE TABLE public."Weird ""Name"" ; x" (id int)`)
	e.f.Exec(`INSERT INTO public."Weird ""Name"" ; x" VALUES (1), (2)`)
	e.f.Exec(`ALTER TABLE public."Weird ""Name"" ; x" OWNER TO ` + e.f.AdminUser)
	a := e.pgAct(coder, `DROP TABLE public."Weird ""Name"" ; x"`)
	out := e.decideCopy(a)
	if out.Result.Decision != policy.Hold {
		t.Fatalf("%+v", out.Result)
	}
	id := out.Action.ActionID
	if _, err := e.pool.Exec(bg, `UPDATE held_actions SET safe_form = jsonb_set(safe_form, '{sql}', '"DROP TABLE public.customers"') WHERE action_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	code, body := e.do(&security, path(id, "approve"), `{"reason":"ok","use_safe_form":true}`)
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	if !e.relExists("public.customers") {
		t.Fatal("stored SQL was executed")
	}
	if e.relExists(`public."Weird ""Name"" ; x"`) {
		t.Fatal("quoted table not renamed")
	}
	trash := body["safe_form"].(map[string]any)["trash_table"].(string)
	if n := e.upCount(`SELECT count(*) FROM public.` + pgsql.QuoteIdent(trash)); n != 2 {
		t.Fatalf("trash rows %d", n)
	}
}

// A safe form whose table vanished is refused before any undo handle is
// recorded; the hold stays pending.
func TestSafeFormTableGone(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(coder, "DROP TABLE customers"))
	e.f.Exec(`DROP TABLE public.customers`)
	code, body := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok","use_safe_form":true}`)
	if code != 409 || !strings.Contains(body["error"].(string), "no longer exists") {
		t.Fatalf("%d %v", code, body)
	}
	if _, err := e.undo.Get(bg, out.Action.ActionID); err != undo.ErrNotFound {
		t.Fatalf("undo handle recorded for a safe form that never ran: %v", err)
	}
	if e.outcome(out.Action.ActionID) != "pending" {
		t.Fatal("hold changed")
	}
}

// An unmanaged upstream (no postgres:<name> integration) cannot run a safe form.
func TestSafeFormUnmanagedUpstream(t *testing.T) {
	e := setup(t, approvals.Config{})
	if _, err := e.acc.Put(bg, coder, "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_write","legacy_db":"read_write"}}`), "test", "test"); err != nil {
		t.Fatal(err)
	}
	a := e.pgAct(coder, "DROP TABLE orders")
	a.Target["upstream"] = "legacy_db"
	out := e.decideCopy(a)
	if out.Result.Decision != policy.Hold {
		t.Fatalf("%+v", out.Result)
	}
	code, body := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok","use_safe_form":true}`)
	if code != 409 || !strings.Contains(body["error"].(string), "not a postgres integration") {
		t.Fatalf("%d %v", code, body)
	}
	if !e.relExists("public.orders") {
		t.Fatal("orders renamed")
	}
}

// Yellow: COPY TO STDOUT is held; approval issues a one-time grant bound to
// the agent and action hash; the identical retry runs exactly once.
func TestYellowGrantAllowsIdenticalRetryOnce(t *testing.T) {
	e := setup(t, approvals.Config{GrantTTL: 10 * time.Minute})
	copyOut := e.pgAct(analyst, "COPY orders TO STDOUT")
	out := e.decideCopy(copyOut)
	if out.Result.Decision != policy.Hold || out.Result.Class != policy.Yellow || out.Result.RuleID != "POL-105" {
		t.Fatalf("COPY: %+v", out.Result)
	}
	id := out.Action.ActionID
	if again := e.decideCopy(copyOut); again.Result.Decision != policy.Hold {
		t.Fatalf("retry before approval: %+v", again.Result)
	}
	if code, _ := e.do(&security, path(id, "approve"), `{"reason":"export ok","use_safe_form":true}`); code != 400 {
		t.Fatalf("use_safe_form on yellow: %d", code)
	}
	code, body := e.do(&security, path(id, "approve"), `{"reason":"quarterly export approved"}`)
	if code != 200 || body["outcome"] != "approved" {
		t.Fatalf("approve: %d %v", code, body)
	}
	g := body["grant"].(map[string]any)
	grantID := g["grant_id"].(string)
	if g["agent_id"] != analyst || g["action_hash"] != out.Action.Hash() || g["action_id"] != id {
		t.Fatalf("grant: %v", g)
	}
	exp, _ := time.Parse(time.RFC3339Nano, g["expires_at"].(string))
	if d := time.Until(exp); d < 9*time.Minute || d > 11*time.Minute {
		t.Fatalf("grant ttl: %v", d)
	}
	if e.events(approvals.EventGrantIssued, id) != 1 || e.events(approvals.EventActionApproved, id) != 1 {
		t.Fatal("diary events missing")
	}

	// Bound to the agent and the exact action.
	if o := e.decideCopy(e.pgAct(other, "COPY orders TO STDOUT")); o.Result.Decision != policy.Hold {
		t.Fatalf("other agent used the grant: %+v", o.Result)
	}
	if o := e.decideCopy(e.pgAct(analyst, "COPY customers TO STDOUT")); o.Result.Decision != policy.Hold {
		t.Fatalf("different action used the grant: %+v", o.Result)
	}

	first := e.decideCopy(copyOut)
	if first.Result.Decision != policy.Allow || first.Result.GrantID != grantID || !strings.Contains(first.Result.Reason, grantID) {
		t.Fatalf("identical retry: %+v", first.Result)
	}
	var usedBy string
	if err := e.pool.QueryRow(bg, `SELECT used_by_action FROM approval_grants WHERE grant_id = $1 AND used_at IS NOT NULL`, grantID).Scan(&usedBy); err != nil || usedBy != first.Action.ActionID {
		t.Fatalf("grant not consumed by the retry: %v %q", err, usedBy)
	}
	if e.count(`SELECT count(*) FROM diary WHERE event_type = 'grant.used' AND body_json::jsonb->'data'->>'used_by_action' = $1`, first.Action.ActionID) != 1 {
		t.Fatal("grant.used not in diary")
	}
	second := e.decideCopy(copyOut)
	if second.Result.Decision != policy.Hold || second.Result.GrantID != "" {
		t.Fatalf("second retry: %+v", second.Result)
	}
	e.verifyDiary()
}

// A grant never releases a red action, even when one matches its hash.
func TestGrantNeverReleasesRed(t *testing.T) {
	e := setup(t, approvals.Config{})
	drop := e.pgAct(coder, "DROP TABLE orders")
	out := e.decideCopy(drop)
	if out.Result.Decision != policy.Hold {
		t.Fatalf("%+v", out.Result)
	}
	if _, err := e.pool.Exec(bg, `INSERT INTO approval_grants (grant_id, action_id, agent_id, action_hash, approved_by, reason, expires_at)
		VALUES ('grt_forged', $1, $2, $3, 'test', 'test', now() + interval '10 minutes')`, out.Action.ActionID, coder, out.Action.Hash()); err != nil {
		t.Fatal(err)
	}
	e.setLevel(coder, control.Full) // POL-101 stepped it down to READ_ONLY
	again := e.decideCopy(drop)
	if again.Result.Decision != policy.Hold || again.Result.Class != policy.Red || again.Result.GrantID != "" {
		t.Fatalf("red with matching grant: %+v", again.Result)
	}
	if e.count(`SELECT count(*) FROM approval_grants WHERE grant_id = 'grt_forged' AND used_at IS NULL`) != 1 {
		t.Fatal("grant consumed by a red action")
	}
}

// A gate that refuses the retry leaves the grant unused (the observer only
// consumes on allow).
//
// decide.rego currently still emits grant_id when a gate denies a granted
// yellow; policy.Engine rejects that result, so the decision fails closed
// (FAIL-CLOSED) rather than naming the gate's rule. Either way it is a deny
// and the grant survives; see the contract change request in the D6 report.
func TestGatedRetryDoesNotConsumeGrant(t *testing.T) {
	e := setup(t, approvals.Config{})
	copyOut := e.pgAct(analyst, "COPY orders TO STDOUT")
	out := e.decideCopy(copyOut)
	if code, body := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok"}`); code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	e.setLevel(analyst, control.ReadOnly)
	o := e.decideCopy(copyOut)
	t.Logf("gated granted retry: decision=%s rule=%s fail_closed=%v", o.Result.Decision, o.Result.RuleID, o.FailClosed)
	if o.Result.Decision != policy.Deny || o.Result.GrantID != "" ||
		(o.Result.RuleID != "POL-013" && o.Result.RuleID != decide.RuleFailClosed) {
		t.Fatalf("read-only retry: %+v", o.Result)
	}
	if e.count(`SELECT count(*) FROM approval_grants WHERE agent_id = $1 AND used_at IS NULL`, analyst) != 1 {
		t.Fatal("gated retry consumed the grant")
	}
	e.setLevel(analyst, control.Full)
	if o := e.decideCopy(copyOut); o.Result.Decision != policy.Allow {
		t.Fatalf("retry after level restored: %+v", o.Result)
	}
}

// An expired grant is ignored.
func TestExpiredGrantIgnored(t *testing.T) {
	e := setup(t, approvals.Config{})
	copyOut := e.pgAct(analyst, "COPY orders TO STDOUT")
	out := e.decideCopy(copyOut)
	if code, _ := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok"}`); code != 200 {
		t.Fatal(code)
	}
	if _, err := e.pool.Exec(bg, `UPDATE approval_grants SET expires_at = now() - interval '1 second'`); err != nil {
		t.Fatal(err)
	}
	if o := e.decideCopy(copyOut); o.Result.Decision != policy.Hold {
		t.Fatalf("expired grant used: %+v", o.Result)
	}
}

// Concurrent identical retries: exactly one consumes the grant and runs.
func TestConcurrentGrantConsumeOnlyOne(t *testing.T) {
	e := setup(t, approvals.Config{})
	copyOut := e.pgAct(analyst, "COPY orders TO STDOUT")
	out := e.decideCopy(copyOut)
	if code, _ := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok"}`); code != 200 {
		t.Fatal(code)
	}
	const n = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	results := make([]decide.Outcome, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b, _ := json.Marshal(copyOut.Target)
			var tgt map[string]any
			_ = json.Unmarshal(b, &tgt)
			a := copyOut
			a.Target = tgt
			<-start
			results[i], errs[i] = e.dec.Decide(bg, a)
		}(i)
	}
	close(start)
	wg.Wait()
	allowed := 0
	var winner string
	for i, r := range results {
		if errs[i] != nil {
			t.Fatal(errs[i])
		}
		switch r.Result.Decision {
		case policy.Allow:
			allowed++
			winner = r.Action.ActionID
		case policy.Hold, policy.Deny:
		default:
			t.Fatalf("unexpected decision %+v", r.Result)
		}
	}
	if allowed != 1 {
		t.Fatalf("%d concurrent retries were allowed, want exactly 1", allowed)
	}
	var usedBy string
	if err := e.pool.QueryRow(bg, `SELECT used_by_action FROM approval_grants WHERE agent_id = $1`, analyst).Scan(&usedBy); err != nil || usedBy != winner {
		t.Fatalf("grant used by %q, winner %q (%v)", usedBy, winner, err)
	}
	if c := e.count(`SELECT count(*) FROM actions WHERE agent_id = $1 AND decision = 'allow'`, analyst); c != 1 {
		t.Fatalf("%d allow decisions recorded", c)
	}
	e.verifyDiary()
}

// The observer alone: consuming a grant twice fails the second decision.
func TestObserverRefusesConsumedGrant(t *testing.T) {
	e := setup(t, approvals.Config{})
	copyOut := e.pgAct(analyst, "COPY orders TO STDOUT")
	out := e.decideCopy(copyOut)
	if code, _ := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok"}`); code != 200 {
		t.Fatal(code)
	}
	var grantID string
	if err := e.pool.QueryRow(bg, `SELECT grant_id FROM approval_grants`).Scan(&grantID); err != nil {
		t.Fatal(err)
	}
	obs := approvals.NewGrantObserver(e.d)
	o := &decide.Outcome{Action: out.Action, Result: policy.Result{Decision: policy.Allow, GrantID: grantID}}
	o.Action.ActionID = out.Action.ActionID
	tx, err := e.pool.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := obs.AfterDecide(bg, tx, o, policy.Input{}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	tx, err = e.pool.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(bg) //nolint:errcheck
	if err := obs.AfterDecide(bg, tx, o, policy.Input{}); err == nil || !strings.Contains(err.Error(), "already used") {
		t.Fatalf("second consume: %v", err)
	}
}

// The enricher fails the decision closed when grants cannot be read.
func TestGrantEnricherFailsClosed(t *testing.T) {
	e := setup(t, approvals.Config{})
	if _, err := e.pool.Exec(bg, `ALTER TABLE approval_grants RENAME TO approval_grants_gone`); err != nil {
		t.Fatal(err)
	}
	o := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	if !o.FailClosed || o.Result.Decision != policy.Deny || o.Result.RuleID != decide.RuleFailClosed {
		t.Fatalf("%+v", o)
	}
}

// Deny: one deny denies; the hold cannot be approved afterwards and the
// retry is held again (no grant).
func TestDeny(t *testing.T) {
	e := setup(t, approvals.Config{})
	copyOut := e.pgAct(analyst, "COPY orders TO STDOUT")
	out := e.decideCopy(copyOut)
	id := out.Action.ActionID
	if code, _ := e.do(&ownerSec, path(id, "deny"), `{"reason":"no"}`); code != 403 {
		t.Fatalf("owner deny: %d", code)
	}
	if code, _ := e.do(&auditor, path(id, "deny"), `{"reason":"no"}`); code != 403 {
		t.Fatalf("auditor deny: %d", code)
	}
	if code, _ := e.do(&security, path(id, "deny"), `{}`); code != 400 {
		t.Fatalf("deny without reason: %d", code)
	}
	if code, _ := e.do(&security, path("act_does_not_exist", "deny"), `{"reason":"no"}`); code != 404 {
		t.Fatalf("unknown hold: %d", code)
	}
	code, body := e.do(&security, path(id, "deny"), `{"reason":"customer data must not leave"}`)
	if code != 200 || body["outcome"] != "denied" || body["decided_by"] != "user:sec@acme.com" {
		t.Fatalf("deny: %d %v", code, body)
	}
	if e.outcome(id) != "denied" || e.events(approvals.EventActionDenied, id) != 1 {
		t.Fatal("deny not recorded")
	}
	if e.count(`SELECT count(*) FROM held_approvals WHERE action_id = $1 AND decision = 'deny'`, id) != 1 {
		t.Fatal("deny vote not recorded")
	}
	if code, _ := e.do(&security2, path(id, "approve"), `{"reason":"override"}`); code != 409 {
		t.Fatalf("approve after deny: %d", code)
	}
	if code, _ := e.do(&security2, path(id, "deny"), `{"reason":"again"}`); code != 409 {
		t.Fatalf("deny after deny: %d", code)
	}
	if o := e.decideCopy(copyOut); o.Result.Decision != policy.Hold {
		t.Fatalf("retry after deny: %+v", o.Result)
	}
	if e.count(`SELECT count(*) FROM approval_grants`) != 0 {
		t.Fatal("deny issued a grant")
	}
	e.verifyDiary()
}

// approvals_required = 2: the hold is approved only by two distinct approvers.
func TestTwoApproversRequired(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	id := out.Action.ActionID
	if _, err := e.pool.Exec(bg, `UPDATE held_actions SET approvals_required = 2 WHERE action_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	code, body := e.do(&security, path(id, "approve"), `{"reason":"first"}`)
	if code != 202 || body["outcome"] != "pending" || body["approvals"] != float64(1) || body["approvals_required"] != float64(2) {
		t.Fatalf("first vote: %d %v", code, body)
	}
	if e.count(`SELECT count(*) FROM approval_grants`) != 0 || e.outcome(id) != "pending" {
		t.Fatal("one vote approved the hold")
	}
	if code, _ := e.do(&securityUpper, path(id, "approve"), `{"reason":"same person"}`); code != 409 {
		t.Fatalf("same approver twice: %d", code)
	}
	code, body = e.do(&security2, path(id, "approve"), `{"reason":"second"}`)
	if code != 200 || body["outcome"] != "approved" || body["grant"] == nil {
		t.Fatalf("second vote: %d %v", code, body)
	}
	if e.events(approvals.EventApprovalVote, id) != 1 || e.events(approvals.EventActionApproved, id) != 1 {
		t.Fatal("vote events")
	}
}

// A red hold needing two approvers runs its safe form only on the second vote.
func TestRedTwoApproversExecutesOnce(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(coder, "DROP TABLE orders"))
	id := out.Action.ActionID
	if _, err := e.pool.Exec(bg, `UPDATE held_actions SET approvals_required = 2 WHERE action_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(&security, path(id, "approve"), `{"reason":"first","use_safe_form":true}`); code != 202 {
		t.Fatalf("first: %d", code)
	}
	if !e.relExists("public.orders") {
		t.Fatal("safe form ran on the first of two votes")
	}
	if code, body := e.do(&security2, path(id, "approve"), `{"reason":"second","use_safe_form":true}`); code != 200 {
		t.Fatalf("second: %d %v", code, body)
	}
	if e.relExists("public.orders") {
		t.Fatal("safe form did not run")
	}
}

// Owner approval is allowed only when configured.
func TestOwnerApprovalWhenAllowed(t *testing.T) {
	e := setup(t, approvals.Config{AllowOwnerApproval: true})
	out := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	code, body := e.do(&ownerSec, path(out.Action.ActionID, "approve"), `{"reason":"mine"}`)
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	var asOwner bool
	if err := e.pool.QueryRow(bg, `SELECT (body_json::jsonb->'data'->>'as_owner')::boolean FROM diary WHERE event_type = 'action.approved'`).Scan(&asOwner); err != nil || !asOwner {
		t.Fatalf("as_owner not recorded: %v", err)
	}
}

// A quarantined agent's holds cannot be approved (they can be denied).
func TestFrozenAgentCannotBeApproved(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	e.setLevel(analyst, control.Quarantined)
	if code, _ := e.do(&security, path(out.Action.ActionID, "approve"), `{"reason":"ok"}`); code != 409 {
		t.Fatalf("approve for quarantined agent: %d", code)
	}
	if code, _ := e.do(&security, path(out.Action.ActionID, "deny"), `{"reason":"frozen"}`); code != 200 {
		t.Fatalf("deny: %d", code)
	}
}

// Expiry: an expired hold cannot be decided; the worker marks it expired.
func TestExpiryWorker(t *testing.T) {
	e := setup(t, approvals.Config{})
	expired := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	fresh := e.decideCopy(e.pgAct(analyst, "COPY customers TO STDOUT"))
	if _, err := e.pool.Exec(bg, `UPDATE held_actions SET expires_at = now() - interval '1 second' WHERE action_id = $1`, expired.Action.ActionID); err != nil {
		t.Fatal(err)
	}
	code, body := e.do(&security, path(expired.Action.ActionID, "approve"), `{"reason":"late"}`)
	if code != 409 || !strings.Contains(body["error"].(string), "expired") {
		t.Fatalf("approve expired: %d %v", code, body)
	}
	if code, _ := e.do(&security, path(expired.Action.ActionID, "deny"), `{"reason":"late"}`); code != 409 {
		t.Fatalf("deny expired: %d", code)
	}
	w := e.svc.ExpiryWorker(time.Hour)
	n, err := w.Sweep(bg)
	if err != nil || n != 1 {
		t.Fatalf("sweep: %d %v", n, err)
	}
	if e.outcome(expired.Action.ActionID) != "expired" || e.outcome(fresh.Action.ActionID) != "pending" {
		t.Fatal("wrong holds expired")
	}
	if e.events(approvals.EventHoldExpired, expired.Action.ActionID) != 1 {
		t.Fatal("expiry not in diary")
	}
	if n, err := w.Sweep(bg); err != nil || n != 0 {
		t.Fatalf("second sweep: %d %v", n, err)
	}

	// Run sweeps on its own and stops with its context.
	if _, err := e.pool.Exec(bg, `UPDATE held_actions SET expires_at = now() - interval '1 second' WHERE action_id = $1`, fresh.Action.ActionID); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { e.svc.ExpiryWorker(10 * time.Millisecond).Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for e.outcome(fresh.Action.ActionID) != "expired" {
		if time.Now().After(deadline) {
			t.Fatal("worker did not expire the hold")
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker did not stop")
	}
	e.verifyDiary()
}

// Concurrent approvals of the same red hold: the safe form runs once.
func TestConcurrentRedApprovalsRunOnce(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(coder, "DROP TABLE orders"))
	id := out.Action.ActionID
	var wg sync.WaitGroup
	codes := make([]int, 2)
	start := make(chan struct{})
	for i, p := range []authz.Principal{security, security2} {
		wg.Add(1)
		go func(i int, p authz.Principal) {
			defer wg.Done()
			<-start
			_, err := e.svc.Approve(bg, p, id, approvals.ApproveRequest{Reason: "go", UseSafeForm: true})
			if err == nil {
				codes[i] = 200
			} else {
				codes[i] = 409
			}
		}(i, p)
	}
	close(start)
	wg.Wait()
	if codes[0]+codes[1] != 609 {
		t.Fatalf("codes %v", codes)
	}
	if e.count(`SELECT count(*) FROM diary WHERE event_type = 'safe_form.executed'`) != 1 {
		t.Fatal("safe form executed more than once")
	}
}

// Regression (Phase 3 demo): a table the AGENT created belongs to its
// per-agent role, not to the integration admin. The admin was granted SET
// (not INHERIT) on that role, so the approved safe form and its undo act as
// the owner for one transaction.
func TestSafeFormOnAgentCreatedTable(t *testing.T) {
	e := setup(t, approvals.Config{})
	e.f.Exec("GRANT CREATE ON SCHEMA public TO " + e.f.WriteRole)
	maker := e.f.Agent("maker", "read_write", true)
	sess, err := e.f.Manager(time.Minute).Session(bg, maker, "", e.f.Upstream)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := e.f.Login(sess.User, sess.Password)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Exec(bg, "CREATE TABLE public.agent_made (id int); INSERT INTO public.agent_made VALUES (1),(2)").Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close(bg)

	out := e.decideCopy(e.pgAct(coder, "DROP TABLE agent_made"))
	if out.Result.Decision != policy.Hold {
		t.Fatalf("DROP: %+v", out.Result)
	}
	id := out.Action.ActionID
	code, body := e.do(&security, path(id, "approve"), `{"reason":"cleanup","use_safe_form":true}`)
	if code != 200 {
		t.Fatalf("approve safe form on agent-created table: %d %v", code, body)
	}
	trash := body["safe_form"].(map[string]any)["trash_table"].(string)
	if e.relExists("public.agent_made") || e.upCount(`SELECT count(*) FROM public.`+pgsql.QuoteIdent(trash)) != 2 {
		t.Fatal("table not renamed with its rows")
	}
	h, err := e.undo.Get(bg, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.undo.Activate(bg, id); err != nil && h.Status != undo.StatusActive {
		t.Fatalf("activate: %v (status %s)", err, h.Status)
	}
	h, _ = e.undo.Claim(bg, id, "user:sec")
	ex := pgundo.NewExecutor(config.PGProxyConfig{}, nil, pgundo.WithIntegrations(e.f.Source))
	if _, err := ex.Undo(bg, h); err != nil {
		t.Fatalf("undo rename of an agent-owned table: %v", err)
	}
	if !e.relExists("public.agent_made") {
		t.Fatal("undo did not restore agent_made")
	}
}

// reassignSponsor mirrors PATCH /v1/agents/{id}: update the row and record
// the agent.updated Diary event in one transaction.
func (e *env) reassignSponsor(agent, to string) {
	e.t.Helper()
	tx, err := e.pool.Begin(bg)
	if err != nil {
		e.t.Fatal(err)
	}
	defer tx.Rollback(bg)
	var old string
	if err := tx.QueryRow(bg, `SELECT sponsor FROM agents WHERE agent_id = $1 FOR UPDATE`, agent).Scan(&old); err != nil {
		e.t.Fatal(err)
	}
	if _, err := tx.Exec(bg, `UPDATE agents SET sponsor = $2 WHERE agent_id = $1`, agent, to); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.d.AppendTx(bg, tx, diary.Event{AgentID: agent, EventType: "agent.updated", Actor: "user:jane@acme.com",
		Data: map[string]any{"changes": map[string]any{"sponsor": map[string]any{"old": old, "new": to}}}}); err != nil {
		e.t.Fatal(err)
	}
	if err := tx.Commit(bg); err != nil {
		e.t.Fatal(err)
	}
}

// Reassigning the sponsor while a hold is pending does not let the former
// sponsor decide it, and the newly assigned sponsor is refused as well.
func TestSponsorReassignmentDoesNotBypassOwnerRule(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	id := out.Action.ActionID
	e.reassignSponsor(analyst, "sec2@acme.com")
	code, body := e.do(&ownerSec, path(id, "approve"), `{"reason":"not mine any more"}`)
	if code != 403 || !strings.Contains(body["error"].(string), "sponsor") {
		t.Fatalf("former sponsor approved after reassignment: %d %v", code, body)
	}
	if code, _ := e.do(&ownerSec, path(id, "deny"), `{"reason":"no"}`); code != 403 {
		t.Fatalf("former sponsor denied after reassignment: %d", code)
	}
	e.reassignSponsor(analyst, "jane@acme.com")
	if code, _ := e.do(&security2, path(id, "approve"), `{"reason":"was sponsor"}`); code != 403 {
		t.Fatalf("interim sponsor approved: %d", code)
	}
	if code, body := e.do(&security, path(id, "approve"), `{"reason":"independent"}`); code != 200 {
		t.Fatalf("independent approver: %d %v", code, body)
	}
}

// Denying is always possible: an approver who voted to approve may change
// their mind and deny; the approve vote is withdrawn.
func TestApproverMayWithdrawApprovalByDenying(t *testing.T) {
	e := setup(t, approvals.Config{})
	out := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
	id := out.Action.ActionID
	if _, err := e.pool.Exec(bg, `UPDATE held_actions SET approvals_required = 2 WHERE action_id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if code, _ := e.do(&security, path(id, "approve"), `{"reason":"first"}`); code != 202 {
		t.Fatalf("first vote: %d", code)
	}
	code, body := e.do(&security, path(id, "deny"), `{"reason":"changed my mind"}`)
	if code != 200 || body["outcome"] != "denied" {
		t.Fatalf("deny after own approve: %d %v", code, body)
	}
	if e.outcome(id) != "denied" || e.count(`SELECT count(*) FROM approval_grants`) != 0 {
		t.Fatal("hold not denied, or a grant was issued")
	}
	// Votes are append-only: the approve vote stays on record, the Diary
	// says it was withdrawn.
	if e.count(`SELECT count(*) FROM held_approvals WHERE decision = 'approve'`) != 1 {
		t.Fatal("vote history changed")
	}
	if e.count(`SELECT count(*) FROM diary WHERE event_type = 'action.denied' AND body_json::jsonb -> 'data' ->> 'withdrew_approval' = 'true'`) != 1 {
		t.Fatal("withdrawal not recorded in the Diary")
	}
}

// Phase 5 review: two API tokens are not two people. On a two-approver hold a
// second token vote is refused (409) unless allow_token_pairs (dev) is set; a
// signed-in person may follow a token.
func TestTwoPersonRuleRefusesTokenPairs(t *testing.T) {
	tok := func(name string) authz.Principal {
		return authz.Principal{Kind: authz.KindToken, Name: name, Roles: map[string]bool{authz.RoleSecurity: true}}
	}
	t1, t2 := tok("ops-a"), tok("ops-b")
	for _, allow := range []bool{false, true} {
		e := setup(t, approvals.Config{AllowTokenPairs: allow})
		out := e.decideCopy(e.pgAct(analyst, "COPY orders TO STDOUT"))
		id := out.Action.ActionID
		if _, err := e.pool.Exec(bg, `UPDATE held_actions SET approvals_required = 2 WHERE action_id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if code, body := e.do(&t1, path(id, "approve"), `{"reason":"first"}`); code != 202 {
			t.Fatalf("first token vote: %d %v", code, body)
		}
		code, body := e.do(&t2, path(id, "approve"), `{"reason":"second token"}`)
		if !allow {
			if code != 409 || !strings.Contains(body["error"].(string), "two-person rule") {
				t.Fatalf("second token vote: %d %v", code, body)
			}
			if code, body := e.do(&security, path(id, "approve"), `{"reason":"a person"}`); code != 200 || body["outcome"] != "approved" {
				t.Fatalf("person after token: %d %v", code, body)
			}
		} else if code != 200 || body["outcome"] != "approved" {
			t.Fatalf("allowed token pair: %d %v", code, body)
		}
	}
}
