package commap_test

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/commap"
	"fortik/internal/control"
)

// Two workers rolling up while decisions keep landing fold every action
// exactly once; re-running afterwards changes nothing.
func TestRollupExactlyOnceAcrossTwoWorkers(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		e.register(t, fmt.Sprintf("worker_%d", i), "ops", "owner@acme.test")
	}
	// Concurrent decisions on the wall clock, as in production: the settle
	// delay covers the time between an action's timestamp and its commit.
	e.dec.Now = nil
	e.worker = e.newWorker(t, 2*time.Second)
	w2 := e.newWorker(t, 2*time.Second)
	const perAgent = 40
	var stop atomic.Bool
	var wg sync.WaitGroup
	var busy atomic.Int32
	for _, w := range []*commap.Worker{e.worker, w2} {
		wg.Add(1)
		go func(w *commap.Worker) {
			defer wg.Done()
			for !stop.Load() {
				r, err := w.RollupOnce(ctx)
				if err != nil {
					t.Errorf("rollup: %v", err)
					return
				}
				if r.Busy {
					busy.Add(1)
				}
			}
		}(w)
	}
	var dw sync.WaitGroup
	for i := 0; i < 4; i++ {
		dw.Add(1)
		go func(i int) {
			defer dw.Done()
			for j := 0; j < perAgent; j++ {
				a := pgRead(fmt.Sprintf("worker_%d", i), "finance")
				if _, err := e.dec.Decide(ctx, a); err != nil {
					t.Errorf("decide: %v", err)
					return
				}
			}
		}(i)
	}
	dw.Wait()
	// Drain: both workers keep going until everything is folded.
	deadline := time.Now().Add(20 * time.Second)
	for {
		var folded int64
		if err := e.pool.QueryRow(ctx, `SELECT COALESCE(sum(count), 0) FROM edges WHERE verb = 'READ'`).Scan(&folded); err != nil {
			t.Fatal(err)
		}
		if folded >= 4*perAgent || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	stop.Store(true)
	wg.Wait()
	time.Sleep(2100 * time.Millisecond)
	e.rollup(t)
	before := e.edges(t)
	e.rollup(t) // idempotent: nothing new
	if after := e.edges(t); fmt.Sprint(after) != fmt.Sprint(before) {
		t.Fatal("a second rollup with nothing new changed edges")
	}

	var total int64
	for i := 0; i < 4; i++ {
		var n int64
		for _, r := range e.edge(t, fmt.Sprintf("agent:worker_%d", i), "store:postgres:finance", "READ") {
			n += r.Count
		}
		if n != perAgent {
			t.Errorf("worker_%d: READ edge count %d, want %d (exactly once)", i, n, perAgent)
		}
		total += n
		var owns int64
		for _, r := range e.edge(t, "user:owner@acme.test", fmt.Sprintf("agent:worker_%d", i), commap.VerbOwns) {
			owns += r.Count
		}
		if owns != perAgent {
			t.Errorf("worker_%d: OWNS edge count %d, want %d", i, owns, perAgent)
		}
	}
	var actions int64
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM actions`).Scan(&actions); err != nil {
		t.Fatal(err)
	}
	if total != actions {
		t.Fatalf("folded %d of %d actions", total, actions)
	}
	var lastID string
	if err := e.pool.QueryRow(ctx, `SELECT last_id FROM edge_rollup_state WHERE source = 'actions'`).Scan(&lastID); err != nil {
		t.Fatal(err)
	}
	var newest string
	if err := e.pool.QueryRow(ctx, `SELECT action_id FROM actions ORDER BY ts DESC, action_id DESC LIMIT 1`).Scan(&newest); err != nil {
		t.Fatal(err)
	}
	if lastID != newest {
		t.Fatalf("cursor at %s, newest action %s", lastID, newest)
	}
	t.Logf("lock contention observed %d times", busy.Load())
}

// Actions fold into 5-minute windows aligned to the epoch: counts, bytes,
// label union, worst class and at most 5 sample action ids per window.
func TestRollupWindows(t *testing.T) {
	e := newEnv(t)
	e.register(t, "fin", "finance", "cfo@acme.test")
	var first []string
	for i := 0; i < 7; i++ {
		labels := []string{"financial"}
		if i == 3 {
			labels = []string{"customer_pii"}
		}
		out := e.decideAt(t, e.base.Add(time.Duration(i)*30*time.Second), pgRead("fin", "finance", labels...))
		first = append(first, out.Action.ActionID)
	}
	// A DELETE (held, yellow or red) in the same window raises the worst class of its own edge only.
	del := pgRead("fin", "finance")
	del.Verb, del.Target["statement_type"] = action.VerbDelete, "DELETE"
	e.decideAt(t, e.base.Add(4*time.Minute), del)
	second := e.decideAt(t, e.base.Add(6*time.Minute), pgRead("fin", "finance", "financial"))
	e.rollup(t)

	rows := e.edge(t, "agent:fin", "store:postgres:finance", "READ")
	if len(rows) != 2 {
		t.Fatalf("want 2 windows, got %+v", rows)
	}
	w0, w1 := rows[0], rows[1]
	if !w0.Window.Equal(e.base) || !w1.Window.Equal(e.base.Add(5*time.Minute)) {
		t.Fatalf("windows %s, %s; base %s", w0.Window, w1.Window, e.base)
	}
	if w0.Count != 7 || w0.Bytes != 7*2048 || w1.Count != 1 {
		t.Fatalf("counts: %+v %+v", w0, w1)
	}
	if !slices.Equal(w0.Labels, []string{"customer_pii", "financial"}) {
		t.Fatalf("labels %v", w0.Labels)
	}
	if len(w0.Samples) != 5 || !slices.Equal(w0.Samples, first[:5]) {
		t.Fatalf("samples %v, want the first five %v", w0.Samples, first[:5])
	}
	if !slices.Equal(w1.Samples, []string{second.Action.ActionID}) {
		t.Fatalf("second window samples %v", w1.Samples)
	}
	dels := e.edge(t, "agent:fin", "store:postgres:finance", "DELETE")
	if len(dels) != 1 || dels[0].Class == "green" {
		t.Fatalf("DELETE edge %+v", dels)
	}
	if w0.Class != "green" {
		t.Fatalf("READ edge class %s", w0.Class)
	}
	// Folded later into an edge row that already exists: counts add up,
	// labels union, samples stay at most 5 (the earliest kept).
	for i := 0; i < 6; i++ {
		e.decideAt(t, e.base.Add(7*time.Minute+time.Duration(i)*time.Second), pgRead("fin", "finance", "phi"))
	}
	e.rollup(t)
	rows = e.edge(t, "agent:fin", "store:postgres:finance", "READ")
	if rows[1].Count != 7 || len(rows[1].Samples) != 5 || rows[1].Samples[0] != second.Action.ActionID ||
		!slices.Equal(rows[1].Labels, []string{"financial", "phi"}) || rows[0].Count != 7 {
		t.Fatalf("after second fold: %+v", rows)
	}
}

// Node mapping: app, store, memory, MCP, instance, sponsor, A2A and external
// domains (Gmail recipients through the gmail hub, HTTP direct).
func TestRollupNodeMapping(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "a1", "sales", "Owner@Acme.Test")
	e.register(t, "a2", "sales", "owner@acme.test")
	if _, err := e.pool.Exec(ctx, `INSERT INTO integrations (key, system, config_json, updated_by)
		VALUES ('google_workspace', 'google_workspace', '{"primary_domain":"acme.test","internal_domains":["acme-corp.test"]}', 'test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `INSERT INTO instances (instance_id, agent_id) VALUES ('a1-copy-1', 'a1')`); err != nil {
		t.Fatal(err)
	}
	at := e.base.Add(time.Minute)
	e.decideAt(t, at, action.Action{AgentID: "a1", InstanceID: "a1-copy-1", System: "gmail", Verb: action.VerbSend,
		Target: map[string]any{"endpoint": "gmail.users.messages.send", "to": []string{"bob@acme.test", "x@partner.example"},
			"cc": []string{"y@acme-corp.test"}, "bcc": []string{"z@other.example"}, "external_domains": 2}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "http", Verb: action.VerbRead,
		Target: map[string]any{"domain": "api.weather.example", "external": true, "method": "GET"}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "http", Verb: action.VerbRead,
		Target: map[string]any{"domain": "wiki.internal", "external": false, "method": "GET"}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "memory", Verb: action.VerbRead,
		Target: map[string]any{"store": "support", "namespace": "kb"}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "mcp", Verb: action.VerbRead,
		Target: map[string]any{"server": "github-mcp", "tool": "get_issue", "method": "tools/call"}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "a2a", Verb: action.VerbDelegate,
		Target: map[string]any{"to_agent": "a2", "channel": "a2a"}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "drive", Verb: action.VerbWrite,
		Target: map[string]any{"operation": "share", "share_type": "anyone", "file_id": "f1", "external": true}})
	e.decideAt(t, at, action.Action{AgentID: "a1", System: "shell", Verb: action.VerbRead,
		Target: map[string]any{"classifier": "fortik-shell/1", "operation": "ls"}})
	e.rollup(t)

	want := [][3]string{
		{"agent:a1", "app:gmail", "SEND"},
		{"app:gmail", "domain:partner.example", "SEND"},
		{"app:gmail", "domain:other.example", "SEND"},
		{"agent:a1", "instance:a1-copy-1", commap.VerbRuns},
		{"user:owner@acme.test", "agent:a1", commap.VerbOwns},
		{"agent:a1", "domain:api.weather.example", "READ"},
		{"agent:a1", "app:http", "READ"},
		{"agent:a1", "memory:support/kb", "READ"},
		{"agent:a1", "mcp:github-mcp", "READ"},
		{"agent:a1", "agent:a2", "DELEGATE"},
		{"agent:a1", "app:drive", "WRITE"},
		{"app:drive", "domain:anyone", "WRITE"},
		{"agent:a1", "app:shell", "READ"},
	}
	for _, w := range want {
		if len(e.edge(t, w[0], w[1], w[2])) != 1 {
			t.Errorf("missing edge %s -> %s %s", w[0], w[1], w[2])
		}
	}
	for _, internal := range []string{"domain:acme.test", "domain:acme-corp.test"} {
		if len(e.edge(t, "app:gmail", internal, "SEND")) != 0 {
			t.Errorf("internal recipient domain %s drawn as external", internal)
		}
	}
	var owns int64
	for _, r := range e.edge(t, "user:owner@acme.test", "agent:a1", commap.VerbOwns) {
		owns += r.Count
	}
	if owns != 8 {
		t.Fatalf("OWNS count %d, want 8", owns)
	}
	// Edges never carry payload contents: only ids, verbs, counts and labels.
	var targets int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM edges WHERE from_node LIKE '%bob%' OR to_node LIKE '%bob%'`).Scan(&targets); err != nil {
		t.Fatal(err)
	}
	if targets != 0 {
		t.Fatal("a recipient address leaked into a node id")
	}
}

// Delegation hops become DELEGATE edges, except those whose a2a action
// already drew the same edge (each hop counts once).
func TestRollupDelegations(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "root", "ops", "")
	e.register(t, "child", "ops", "")
	e.register(t, "grandchild", "ops", "")
	out := e.decideAt(t, e.base.Add(time.Minute), action.Action{AgentID: "root", System: "a2a", Verb: action.VerbDelegate,
		Target: map[string]any{"to_agent": "child", "channel": "a2a"}})
	ins := `INSERT INTO delegations (delegation_id, root_agent, from_agent, to_agent, chain, depth, channel, action_id, status, created_at, expires_at)
		VALUES ($1, 'root', $2, $3, $4, $5, $6, NULLIF($7, ''), $8, $9::timestamptz, $9::timestamptz + interval '1 hour')`
	if _, err := e.pool.Exec(ctx, ins, "dlg_1", "root", "child", []string{"root", "child"}, 1, "a2a", out.Action.ActionID, "open",
		e.base.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, ins, "dlg_2", "child", "grandchild", []string{"root", "child", "grandchild"}, 2, "spawn", "", "open",
		e.base.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, ins, "dlg_3", "child", "grandchild", []string{"root", "child", "grandchild"}, 2, "mcp", "", "refused",
		e.base.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	res := e.rollup(t)
	if res.Delegations != 3 {
		t.Fatalf("result %+v", res)
	}
	if r := e.edge(t, "agent:root", "agent:child", "DELEGATE"); len(r) != 1 || r[0].Count != 1 {
		t.Fatalf("root->child counted %+v (want once: the action, not again for its hop)", r)
	}
	r := e.edge(t, "agent:child", "agent:grandchild", "DELEGATE")
	if len(r) != 1 || r[0].Count != 2 || r[0].Class != "red" || len(r[0].Samples) != 0 {
		t.Fatalf("child->grandchild %+v", r)
	}
	e.rollup(t)
	if r := e.edge(t, "agent:child", "agent:grandchild", "DELEGATE"); r[0].Count != 2 {
		t.Fatal("delegations folded twice")
	}
}

// A decision whose transaction is still open when the rollup runs is not
// skipped: the horizon stops before the transaction's start, and a later
// run folds it once it commits.
func TestRollupWaitsForInflightTransactions(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "slow", "ops", "")
	e.register(t, "fast", "ops", "")
	ins := `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, ts)
		VALUES ($1, $2, 'postgres', 'READ', 'h', 'green', 'allow', 'POL-X', 'test', $3)`
	t0 := time.Now().UTC()
	tx, err := e.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	// As in Decide: the timestamp is taken just before the transaction.
	if _, err := tx.Exec(ctx, ins, "act_slow", "slow", t0); err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	// Committed meanwhile, with a later timestamp than the slow row.
	if _, err := e.pool.Exec(ctx, ins, "act_fast", "fast", t0.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	w, err := commap.NewWorker(e.pool, e.d, e.alerts, mapCfg, discard(), commap.Options{Settle: 500 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.RollupOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if n := len(e.edge(t, "agent:fast", "app:postgres", "READ")); n != 0 {
		t.Fatal("folded past an in-flight transaction: its older row would have been skipped for good")
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := w.RollupOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.edge(t, "agent:slow", "app:postgres", "READ")) != 1 || len(e.edge(t, "agent:fast", "app:postgres", "READ")) != 1 {
		t.Fatalf("after commit: %+v", e.edges(t))
	}
}

// Retention: windows older than map.retention are pruned; nothing older is folded.
func TestRetentionPrune(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	old := time.Now().UTC().Add(-40 * 24 * time.Hour)
	if _, err := e.pool.Exec(ctx, `INSERT INTO edges (window_start, from_node, to_node, verb, count, worst_class)
		VALUES ($1, 'agent:x', 'app:gmail', 'SEND', 3, 'green'), ($2, 'agent:x', 'app:gmail', 'SEND', 1, 'green')`,
		old, e.base); err != nil {
		t.Fatal(err)
	}
	n, err := e.worker.Prune(ctx)
	if err != nil || n != 1 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	if rows := e.edges(t); len(rows) != 1 || !rows[0].Window.Equal(e.base) {
		t.Fatalf("left %+v", rows)
	}
}

func TestWorkerConfigValidation(t *testing.T) {
	e := newEnv(t)
	bad := mapCfg
	bad.Window = 7 * time.Minute
	if _, err := commap.NewWorker(e.pool, e.d, e.alerts, bad, nil, commap.Options{}); err == nil {
		t.Fatal("a window that does not divide an hour was accepted")
	}
	bad = mapCfg
	bad.EncodedParamMin = 4
	if _, err := commap.NewWorker(e.pool, e.d, e.alerts, bad, nil, commap.Options{}); err == nil {
		t.Fatal("encoded_param_min below the floor was accepted")
	}
	if _, err := commap.NewWorker(e.pool, e.d, nil, mapCfg, nil, commap.Options{}); err == nil {
		t.Fatal("a worker without an alert raiser was accepted")
	}
	if _, err := commap.NewWorker(e.pool, e.d, e.alerts, mapCfg, nil, commap.Options{SensitiveLabels: []string{"Bad Label"}}); err == nil {
		t.Fatal("an invalid sensitive label was accepted")
	}
}

// slowEnricher delays one agent's decisions (a slow enricher, policy retries
// or a wait for a pool connection all look like this to the rollup).
type slowEnricher struct {
	agent string
	d     time.Duration
}

func (s slowEnricher) Key() string { return "slow_test" }
func (s slowEnricher) Enrich(_ context.Context, a action.Action, _ control.State) (any, error) {
	if a.AgentID == s.agent {
		time.Sleep(s.d)
	}
	return nil, nil
}

// Phase 5 review (map #2): a decision that started before a faster one but
// commits after it, later than the settle time, must still be folded. Decide
// stamps actions.ts no earlier than its transaction start, so the row is
// always newer than the rollup's horizon while it is being written.
func TestRollupNeverLosesASlowDecision(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "slow_a", "ops", "")
	e.register(t, "fast_b", "ops", "")
	e.dec.Now = nil // the real clock (production)
	e.dec.Enrichers = append(e.dec.Enrichers, slowEnricher{agent: "slow_a", d: 2 * time.Second})
	w := e.newWorker(t, time.Second)
	done := make(chan error, 1)
	go func() {
		_, err := e.dec.Decide(ctx, pgRead("slow_a", "finance"))
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	if _, err := e.dec.Decide(ctx, pgRead("fast_b", "finance")); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1400 * time.Millisecond)
	if _, err := w.RollupOnce(ctx); err != nil { // folds fast_b, moves the cursor
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	time.Sleep(1200 * time.Millisecond) // past the settle time
	if _, err := w.RollupOnce(ctx); err != nil {
		t.Fatal(err)
	}
	if len(e.edge(t, "agent:fast_b", "store:postgres:finance", "READ")) != 1 {
		t.Fatal("fast action not folded")
	}
	if len(e.edge(t, "agent:slow_a", "store:postgres:finance", "READ")) != 1 {
		t.Fatal("LOST: the slow action committed after the cursor moved and was never folded")
	}
}
