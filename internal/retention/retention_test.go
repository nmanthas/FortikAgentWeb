package retention_test

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"

	"fortik/internal/broker/pgroles"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/pgsql"
	"fortik/internal/retention"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

var bg = context.Background()

const (
	day       = 24 * time.Hour
	rowSecret = "ROW-DATA-MUST-NOT-LEAK"
)

var quiet = slog.New(slog.NewTextHandler(io.Discard, nil))

type env struct {
	t     *testing.T
	pool  *pgxpool.Pool
	diary *diary.Diary
	f     *pgrolestest.Fixture
	now   time.Time
	seq   int
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	f := pgrolestest.New(t, "shop")
	return &env{t: t, pool: pool, diary: diary.New(pool), f: f, now: time.Now().UTC().Truncate(time.Second)}
}

func (e *env) worker(opts ...retention.Option) *retention.Worker {
	opts = append([]retention.Option{retention.WithClock(func() time.Time { return e.now })}, opts...)
	return retention.New(e.pool, e.diary, e.f.Source,
		config.UndoConfig{SnapshotRetention: 30 * day, TrashRetention: 7 * day},
		config.RetentionConfig{SweepInterval: time.Hour},
		config.MemoryConfig{SnapshotRetention: 30 * day}, quiet, opts...)
}

// actionID returns an action id whose ULID carries time ts.
func actionID(ts time.Time) string {
	return "act_" + ulid.MustNew(ulid.Timestamp(ts), rand.Reader).String()
}

// snapTable creates fortik_undo.<orders_ulid(ts)> holding a secret-looking row.
func (e *env) snapTable(ts time.Time) (name, action string) {
	action = actionID(ts)
	name = pgsql.SnapshotTableName("orders", action)
	e.f.Exec(fmt.Sprintf("CREATE TABLE fortik_undo.%s (id int, note text)", pgsql.QuoteIdent(name)))
	e.f.Exec(fmt.Sprintf("INSERT INTO fortik_undo.%s VALUES (1, '%s')", pgsql.QuoteIdent(name), rowSecret))
	return name, action
}

func (e *env) trashTable(schema, table string, ts time.Time) string {
	name := pgsql.TrashTableName(table, ts)
	e.f.Exec(fmt.Sprintf("CREATE TABLE %s (id int, note text)", pgsql.QuoteQualified(schema, name)))
	e.f.Exec(fmt.Sprintf("INSERT INTO %s VALUES (1, '%s')", pgsql.QuoteQualified(schema, name), rowSecret))
	// A trash table is the customer's renamed table; like undo (which renames
	// it back), dropping it needs the integration admin to own it.
	e.f.Exec(fmt.Sprintf("ALTER TABLE %s OWNER TO %s", pgsql.QuoteQualified(schema, name), pgsql.QuoteIdent(e.f.AdminUser)))
	return name
}

// handle inserts an action and its undo handle in the given state.
func (e *env) handle(action, kind, status string, data any, created, expires time.Time) {
	e.t.Helper()
	if action == "" {
		e.seq++
		action = fmt.Sprintf("act_h%d", e.seq)
	}
	if _, err := e.pool.Exec(bg, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, ts)
		VALUES ($1, 'agent-1', 'postgres', 'DELETE', 'h', 'yellow', 'allow_reduced', 'POL-102', 'r', now())`, action); err != nil {
		e.t.Fatal(err)
	}
	raw, _ := json.Marshal(data)
	if _, err := e.pool.Exec(bg, `INSERT INTO undo_handles (action_id, agent_id, kind, handle_json, status, expires_at, created_at)
		VALUES ($1, 'agent-1', $2, $3, $4, $5, $6)`, action, kind, raw, status, expires, created); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) rowsHandle(action, table, status string, created, expires time.Time) {
	e.handle(action, undo.KindPGRows, status, undo.PGRowsData{Upstream: e.f.Upstream, Database: e.f.DB, Schema: "public",
		Table: "orders", SnapshotSchema: pgsql.SnapshotSchema, SnapshotTable: table, Op: "DELETE", PKColumns: []string{"id"}}, created, expires)
}

func (e *env) renameHandle(schema, table, trash, status string, created, expires time.Time) {
	e.handle("", undo.KindPGRename, status, undo.PGRenameData{Upstream: e.f.Upstream, Database: e.f.DB, Schema: schema,
		Table: table, TrashTable: trash, Op: "DROP"}, created, expires)
}

func (e *env) exists(schema, name string) bool {
	e.t.Helper()
	var ok bool
	if err := e.f.Super.QueryRow(bg, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, pgsql.QuoteQualified(schema, name)).Scan(&ok); err != nil {
		e.t.Fatal(err)
	}
	return ok
}

func (e *env) status(action string) string {
	e.t.Helper()
	var s string
	if err := e.pool.QueryRow(bg, `SELECT status FROM undo_handles WHERE action_id = $1`, action).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

func (e *env) events(eventType string) []diary.Entry {
	e.t.Helper()
	all, err := e.diary.Query(bg, diary.Filter{Limit: 10000})
	if err != nil {
		e.t.Fatal(err)
	}
	var out []diary.Entry
	for _, en := range all {
		if en.EventType == eventType {
			out = append(out, en)
		}
	}
	return out
}

func names(ds []retention.Dropped) []string {
	var out []string
	for _, d := range ds {
		out = append(out, d.Table)
	}
	slices.Sort(out)
	return out
}

func sorted(s ...string) []string {
	slices.Sort(s)
	return s
}

func TestSweepDropsOnlyExpiredFortikTables(t *testing.T) {
	e := newEnv(t)
	now := e.now
	snap := func(n string) string { return pgsql.SnapshotSchema + "." + n }

	// A real customer table, plus look-alikes outside Fortik's patterns.
	e.f.Exec("CREATE TABLE public.orders (id int PRIMARY KEY, note text)")
	e.f.Exec("INSERT INTO public.orders VALUES (1, 'keep me'), (2, 'keep me too')")
	oldULIDName := pgsql.SnapshotTableName("orders", actionID(now.Add(-60*day)))
	e.f.Exec("CREATE TABLE public." + pgsql.QuoteIdent(oldULIDName) + " (id int)") // snapshot-like name, wrong schema
	e.f.Exec("CREATE TABLE fortik_undo.customer_notes (id int)")                   // no handle, no ULID
	viewName := pgsql.SnapshotTableName("v", actionID(now.Add(-60*day)))
	e.f.Exec("CREATE VIEW fortik_undo." + pgsql.QuoteIdent(viewName) + " AS SELECT 1 AS x") // not a table
	e.f.Exec("CREATE TABLE public.fortik_trash_bad_name (id int)")                          // no timestamp
	e.f.Exec("CREATE TABLE public.fortik_trashcan_20200101000000 (id int)")                 // not the prefix
	e.f.Exec("CREATE SCHEMA sales")
	e.f.Exec("GRANT USAGE ON SCHEMA sales TO " + pgsql.QuoteIdent(e.f.AdminUser))

	// fortik_undo snapshot tables.
	expired, expiredAct := e.snapTable(now.Add(-40 * day))
	e.rowsHandle(expiredAct, expired, undo.StatusExpired, now.Add(-40*day), now.Add(-10*day))
	activePast, activePastAct := e.snapTable(now.Add(-31 * day))
	e.rowsHandle(activePastAct, activePast, undo.StatusActive, now.Add(-31*day), now.Add(-time.Hour))
	activeFuture, activeFutureAct := e.snapTable(now.Add(-1 * day))
	e.rowsHandle(activeFutureAct, activeFuture, undo.StatusActive, now.Add(-1*day), now.Add(29*day))
	usedOld, usedOldAct := e.snapTable(now.Add(-31 * day))
	e.rowsHandle(usedOldAct, usedOld, undo.StatusUsed, now.Add(-31*day), now.Add(-time.Hour))
	usedYoung, usedYoungAct := e.snapTable(now.Add(-2 * day))
	e.rowsHandle(usedYoungAct, usedYoung, undo.StatusUsed, now.Add(-2*day), now.Add(28*day))
	failedOld, failedOldAct := e.snapTable(now.Add(-35 * day))
	e.rowsHandle(failedOldAct, failedOld, undo.StatusFailed, now.Add(-35*day), now.Add(-5*day))
	undoingOld, undoingOldAct := e.snapTable(now.Add(-35 * day))
	e.rowsHandle(undoingOldAct, undoingOld, undo.StatusUndoing, now.Add(-35*day), now.Add(-5*day))
	orphanOld, _ := e.snapTable(now.Add(-31 * day))
	orphanYoung, _ := e.snapTable(now.Add(-5 * day))

	// An old orphan owned by a Fortik per-agent role: the admin may SET ROLE
	// to it but does not inherit it, so the drop must run as the owner.
	mgr := e.f.Manager(time.Minute)
	agent := e.f.Agent("ret-agent", pgroles.ModeReadWrite, true)
	sess, err := mgr.Session(bg, agent, "", e.f.Upstream)
	if err != nil {
		t.Fatal(err)
	}
	agentOwned, _ := e.snapTable(now.Add(-45 * day))
	e.f.Exec("ALTER TABLE fortik_undo." + pgsql.QuoteIdent(agentOwned) + " OWNER TO " + pgsql.QuoteIdent(sess.User))

	// Trash tables.
	trashOrphanOld := e.trashTable("public", "orders", now.Add(-8*day))
	trashActive := e.trashTable("public", "items", now.Add(-8*day))
	e.renameHandle("public", "items", trashActive, undo.StatusActive, now.Add(-8*day), now.Add(time.Hour))
	trashUsed := e.trashTable("public", "users", now.Add(-8*day))
	e.renameHandle("public", "users", trashUsed, undo.StatusUsed, now.Add(-8*day), now.Add(-time.Hour))
	trashFailed := e.trashTable("public", "carts", now.Add(-9*day))
	e.renameHandle("public", "carts", trashFailed, undo.StatusFailed, now.Add(-9*day), now.Add(-2*day))
	trashYoung := e.trashTable("public", "fresh", now.Add(-1*day))
	trashSalesExpired := e.trashTable("sales", "orders", now.Add(-10*day))
	e.renameHandle("sales", "orders", trashSalesExpired, undo.StatusActive, now.Add(-10*day), now.Add(-3*day)) // expires in this sweep
	// A handle for the same trash name in another schema does not protect it.
	trashOtherSchema := e.trashTable("sales", "refunds", now.Add(-8*day))
	e.renameHandle("public", "refunds", trashOtherSchema, undo.StatusActive, now.Add(-8*day), now.Add(time.Hour))
	// Something depends on this one: DROP (never CASCADE) fails and it stays.
	trashWithView := e.trashTable("public", "ledger", now.Add(-8*day))
	e.f.Exec("CREATE VIEW public.ledger_view AS SELECT * FROM public." + pgsql.QuoteIdent(trashWithView))

	// Old and Fortik-named, but owned by someone the admin cannot act as:
	// the drop fails honestly and the table stays.
	trashNotOwned := pgsql.TrashTableName("payroll", now.Add(-20*day))
	e.f.Exec("CREATE TABLE public." + pgsql.QuoteIdent(trashNotOwned) + " (id int)")

	// Memory snapshot pointers.
	e.memSnap("ms_old", "memory:support", "kb", now.Add(-31*day), now.Add(-day))
	e.memSnap("ms_expired", "memory:support", "kb", now.Add(-2*day), now.Add(-time.Minute))
	e.memSnap("ms_young", "memory:support", "kb", now.Add(-2*day), now.Add(28*day))
	e.memSnap("ms_fail", "memory:sales", "crm", now.Add(-40*day), now.Add(-10*day))
	e.memSnap("ms_done", "memory:support", "kb", now.Add(-50*day), now.Add(-20*day))
	if _, err := e.pool.Exec(bg, `UPDATE memory_snapshots SET purged_at = now() - interval '1 day' WHERE snapshot_id = 'ms_done'`); err != nil {
		t.Fatal(err)
	}
	purger := &fakePurger{fail: map[string]bool{"fortik_memory.snapshots_ms_fail": true}}

	w := e.worker(retention.WithSnapshotPurger(purger))
	rep, err := w.Sweep(bg)
	if err != nil {
		t.Fatalf("sweep: %v (report %+v)", err, rep)
	}
	if rep.Locked {
		t.Fatal("sweep reported locked")
	}
	// active-past (rows) and the sales trash handle expired in this sweep.
	if rep.ExpiredHandles != 2 {
		t.Fatalf("expired handles = %d, want 2", rep.ExpiredHandles)
	}
	if len(rep.Upstreams) != 1 {
		t.Fatalf("upstreams %+v", rep.Upstreams)
	}
	up := rep.Upstreams[0]
	if up.Upstream != "shop" || up.Database != e.f.DB || up.Error != "" {
		t.Fatalf("upstream report %+v", up)
	}
	wantSnaps := sorted(snap(expired), snap(activePast), snap(usedOld), snap(failedOld), snap(orphanOld), snap(agentOwned))
	if got := names(up.SnapshotTables); !slices.Equal(got, wantSnaps) {
		t.Fatalf("dropped snapshots\n got %v\nwant %v", got, wantSnaps)
	}
	wantTrash := sorted("public."+trashOrphanOld, "public."+trashUsed, "sales."+trashSalesExpired, "sales."+trashOtherSchema)
	if got := names(up.TrashTables); !slices.Equal(got, wantTrash) {
		t.Fatalf("dropped trash\n got %v\nwant %v\nreport %+v", got, wantTrash, up)
	}
	slices.SortFunc(up.Failed, func(a, b retention.Failure) int { return strings.Compare(a.Table, b.Table) })
	if len(up.Failed) != 2 || up.Failed[0].Table != "public."+trashWithView || !strings.Contains(up.Failed[0].Error, "depend") ||
		up.Failed[1].Table != "public."+trashNotOwned || !strings.Contains(up.Failed[1].Error, "must be owner") {
		t.Fatalf("failures %+v", up.Failed)
	}
	for _, d := range up.SnapshotTables {
		if d.Reason == "" {
			t.Fatalf("drop without a reason: %+v", d)
		}
	}

	// What must be gone is gone; everything else is untouched.
	for _, n := range []string{expired, activePast, usedOld, failedOld, orphanOld, agentOwned} {
		if e.exists(pgsql.SnapshotSchema, n) {
			t.Errorf("fortik_undo.%s still exists", n)
		}
	}
	for _, n := range []string{activeFuture, usedYoung, undoingOld, orphanYoung, "customer_notes", viewName} {
		if !e.exists(pgsql.SnapshotSchema, n) {
			t.Errorf("fortik_undo.%s was dropped", n)
		}
	}
	for _, n := range []string{trashOrphanOld, trashUsed} {
		if e.exists("public", n) {
			t.Errorf("public.%s still exists", n)
		}
	}
	for _, n := range []string{trashSalesExpired, trashOtherSchema} {
		if e.exists("sales", n) {
			t.Errorf("sales.%s still exists", n)
		}
	}
	for _, n := range []string{"orders", oldULIDName, trashActive, trashFailed, trashYoung, trashWithView, trashNotOwned,
		"fortik_trash_bad_name", "fortik_trashcan_20200101000000", "ledger_view"} {
		if !e.exists("public", n) {
			t.Errorf("public.%s was dropped", n)
		}
	}
	var customerRows int
	if err := e.f.Super.QueryRow(bg, "SELECT count(*) FROM public.orders").Scan(&customerRows); err != nil || customerRows != 2 {
		t.Fatalf("customer table rows %d (%v)", customerRows, err)
	}

	// Handles past expires_at are marked expired; the others keep their state.
	for act, want := range map[string]string{activePastAct: undo.StatusExpired, activeFutureAct: undo.StatusActive,
		undoingOldAct: undo.StatusUndoing, usedOldAct: undo.StatusUsed} {
		if got := e.status(act); got != want {
			t.Errorf("handle %s status %s, want %s", act, got, want)
		}
	}
	if evs := e.events(diary.EventUndoExpired); len(evs) != 2 {
		t.Fatalf("undo.expired events: %d", len(evs))
	}

	// Memory snapshots: due pointers purged (data through the purger), a
	// failed purge keeps its pointer, young and already-purged rows untouched.
	if got := e.purgedSnapshots(); !slices.Equal(got, []string{"ms_done", "ms_expired", "ms_old"}) {
		t.Fatalf("purged memory snapshots %v", got)
	}
	if got := purger.calls(); !slices.Equal(got, []string{
		"memory:sales/crm/fortik_memory.snapshots_ms_fail",
		"memory:support/kb/fortik_memory.snapshots_ms_expired",
		"memory:support/kb/fortik_memory.snapshots_ms_old"}) {
		t.Fatalf("purger calls %v", got)
	}
	if len(rep.Memory) != 2 {
		t.Fatalf("memory report %+v", rep.Memory)
	}

	// Diary: one retention.purged event for the upstream, one per memory
	// store with purged snapshots; names and counts, never data.
	evs := e.events(retention.EventPurged)
	if len(evs) != 2 {
		t.Fatalf("retention.purged events: %d", len(evs))
	}
	var upEv, memEv map[string]any
	for _, ev := range evs {
		if strings.Contains(ev.BodyJSON, rowSecret) || strings.Contains(ev.BodyJSON, "keep me") {
			t.Fatalf("diary event leaks row data: %s", ev.BodyJSON)
		}
		if ev.Actor != retention.Actor || ev.AgentID != "" {
			t.Fatalf("event actor/agent: %+v", ev)
		}
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(ev.Body, &body); err != nil {
			t.Fatal(err)
		}
		if _, ok := body.Data["upstream"]; ok {
			upEv = body.Data
		} else {
			memEv = body.Data
		}
	}
	if upEv["upstream"] != "shop" || upEv["snapshot_tables_dropped"] != json.Number("6") && upEv["snapshot_tables_dropped"] != float64(6) {
		t.Fatalf("upstream event %v", upEv)
	}
	if fmt.Sprint(upEv["trash_tables_dropped"]) != "4" || upEv["failed"] == nil {
		t.Fatalf("upstream event %v", upEv)
	}
	if !strings.Contains(fmt.Sprint(upEv["snapshot_tables"]), expired) || !strings.Contains(fmt.Sprint(upEv["trash_tables"]), trashUsed) {
		t.Fatalf("upstream event lacks table names: %v", upEv)
	}
	if memEv["memory_store"] != "memory:support" || fmt.Sprint(memEv["snapshots_purged"]) != "2" {
		t.Fatalf("memory event %v", memEv)
	}
	rep2, _ := e.diary.VerifyChain(bg)
	if !rep2.OK {
		t.Fatalf("diary chain: %+v", rep2)
	}

	// A second sweep finds nothing new to do (the failing drop is retried
	// and still fails, but nothing is recorded as purged).
	before := len(e.events(retention.EventPurged))
	rep, err = w.Sweep(bg)
	if err != nil {
		t.Fatal(err)
	}
	if rep.ExpiredHandles != 0 || len(rep.Upstreams[0].SnapshotTables) != 0 || len(rep.Upstreams[0].TrashTables) != 0 || len(rep.Upstreams[0].Failed) != 2 {
		t.Fatalf("second sweep %+v", rep)
	}
	if after := len(e.events(retention.EventPurged)); after != before {
		t.Fatalf("second sweep wrote %d new retention events", after-before)
	}

	// Once the purger recovers the remaining snapshot is purged.
	purger.setFail(nil)
	if _, err := w.Sweep(bg); err != nil {
		t.Fatal(err)
	}
	if got := e.purgedSnapshots(); !slices.Equal(got, []string{"ms_done", "ms_expired", "ms_fail", "ms_old"}) {
		t.Fatalf("purged memory snapshots %v", got)
	}
}

func (e *env) memSnap(id, store, ns string, created, expires time.Time) {
	e.t.Helper()
	if _, err := e.pool.Exec(bg, `INSERT INTO memory_snapshots (snapshot_id, store_key, namespace, item_count, location, created_by, created_at, expires_at)
		VALUES ($1, $2, $3, 7, $4, 'system:memory', $5, $6)`, id, store, ns, "fortik_memory.snapshots_"+id, created, expires); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) purgedSnapshots() []string {
	e.t.Helper()
	rows, err := e.pool.Query(bg, `SELECT snapshot_id FROM memory_snapshots WHERE purged_at IS NOT NULL ORDER BY 1`)
	if err != nil {
		e.t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		e.t.Fatal(err)
	}
	return out
}

type fakePurger struct {
	mu   sync.Mutex
	fail map[string]bool
	log  []string
}

func (p *fakePurger) PurgeSnapshot(_ context.Context, store, ns, location string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log = append(p.log, store+"/"+ns+"/"+location)
	if p.fail[location] {
		return errors.New("store unavailable")
	}
	return nil
}

func (p *fakePurger) calls() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := slices.Clone(p.log)
	slices.Sort(out)
	return out
}

func (p *fakePurger) setFail(m map[string]bool) {
	p.mu.Lock()
	p.fail = m
	p.mu.Unlock()
}

// TestAdvisoryLockPreventsDoubleSweep: while another session holds the
// sweep lock nothing is touched; concurrent sweeps drop each table once.
func TestAdvisoryLockPreventsDoubleSweep(t *testing.T) {
	e := newEnv(t)
	var orphans []string
	for range 5 {
		n, _ := e.snapTable(e.now.Add(-40 * day))
		orphans = append(orphans, n)
	}
	w := e.worker()

	holder, err := e.pool.Acquire(bg)
	if err != nil {
		t.Fatal(err)
	}
	var got bool
	if err := holder.QueryRow(bg, `SELECT pg_try_advisory_lock($1, $2)`, retention.LockClass, retention.LockID).Scan(&got); err != nil || !got {
		t.Fatalf("hold lock: %v %v", got, err)
	}
	rep, err := w.Sweep(bg)
	if err != nil || !rep.Locked || len(rep.Upstreams) != 0 {
		t.Fatalf("sweep while locked: %+v %v", rep, err)
	}
	for _, n := range orphans {
		if !e.exists(pgsql.SnapshotSchema, n) {
			t.Fatalf("%s dropped while another process held the lock", n)
		}
	}
	if _, err := holder.Exec(bg, `SELECT pg_advisory_unlock($1, $2)`, retention.LockClass, retention.LockID); err != nil {
		t.Fatal(err)
	}
	holder.Release()

	// Concurrent sweeps from several "processes" (workers sharing the DB).
	var wg sync.WaitGroup
	reps := make([]retention.Report, 4)
	errs := make([]error, 4)
	for i := range reps {
		wg.Add(1)
		go func() {
			defer wg.Done()
			reps[i], errs[i] = e.worker().Sweep(bg)
		}()
	}
	wg.Wait()
	dropped := 0
	for i, r := range reps {
		if errs[i] != nil {
			t.Fatalf("sweep %d: %v", i, errs[i])
		}
		for _, u := range r.Upstreams {
			dropped += len(u.SnapshotTables)
			if len(u.Failed) > 0 {
				t.Fatalf("sweep %d failures: %+v", i, u.Failed)
			}
		}
	}
	if dropped != len(orphans) {
		t.Fatalf("tables dropped %d times in total, want %d", dropped, len(orphans))
	}
	for _, n := range orphans {
		if e.exists(pgsql.SnapshotSchema, n) {
			t.Fatalf("%s survived", n)
		}
	}
	if evs := e.events(retention.EventPurged); len(evs) < 1 || len(evs) > len(orphans) {
		t.Fatalf("retention events %d", len(evs))
	}
	// The lock is free again after every sweep.
	var free bool
	if err := e.pool.QueryRow(bg, `SELECT NOT EXISTS (SELECT 1 FROM pg_locks WHERE locktype = 'advisory' AND classid = $1::int::oid AND objid = $2::int::oid)`,
		retention.LockClass, retention.LockID).Scan(&free); err != nil || !free {
		t.Fatalf("lock still held after sweeps: %v %v", free, err)
	}
}

// TestBrokenUpstreamDoesNotStopOthers: one unreachable integration is
// reported; the healthy one is still swept; memory pointers without a
// purger are purged with data_purged=false.
func TestBrokenUpstreamDoesNotStopOthers(t *testing.T) {
	e := newEnv(t)
	old, _ := e.snapTable(e.now.Add(-40 * day))
	broken := e.f.Resolved(map[string]any{"port": float64(1)}, nil)
	broken.Key = pgroles.Key("aaa_broken") // sorts first
	e.f.Source.Put(broken)
	e.memSnap("ms_1", "memory:support", "kb", e.now.Add(-31*day), e.now.Add(-day))

	rep, err := e.worker().Sweep(bg)
	if err == nil || !strings.Contains(err.Error(), "postgres:aaa_broken") {
		t.Fatalf("want an error naming the broken upstream, got %v", err)
	}
	if len(rep.Upstreams) != 2 || rep.Upstreams[0].Error == "" || rep.Upstreams[1].Upstream != "shop" || len(rep.Upstreams[1].SnapshotTables) != 1 {
		t.Fatalf("report %+v", rep.Upstreams)
	}
	if strings.Contains(err.Error(), e.f.AdminPW) {
		t.Fatal("error leaks the admin password")
	}
	if e.exists(pgsql.SnapshotSchema, old) {
		t.Fatal("healthy upstream not swept")
	}
	if len(rep.Memory) != 1 || len(rep.Memory[0].Purged) != 1 || rep.Memory[0].Purged[0].DataPurged {
		t.Fatalf("memory report %+v", rep.Memory)
	}
	evs := e.events(retention.EventPurged)
	found := false
	for _, ev := range evs {
		if strings.Contains(ev.BodyJSON, `"memory_store":"memory:support"`) {
			found = strings.Contains(ev.BodyJSON, `"data_purged":false`) && strings.Contains(ev.BodyJSON, "no memory store purger")
		}
	}
	if !found {
		t.Fatalf("memory event without purger not recorded honestly: %v", evs)
	}
}

// TestRunSweepsAndStops: Run sweeps immediately and returns on cancel.
func TestRunSweepsAndStops(t *testing.T) {
	e := newEnv(t)
	old, _ := e.snapTable(e.now.Add(-40 * day))
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { e.worker().Run(ctx); close(done) }()
	deadline := time.Now().Add(20 * time.Second)
	for e.exists(pgsql.SnapshotSchema, old) {
		if time.Now().After(deadline) {
			t.Fatal("Run did not sweep")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not stop")
	}
}
