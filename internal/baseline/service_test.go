package baseline_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"fortik/internal/action"
	"fortik/internal/approvals"
	"fortik/internal/authz"
	"fortik/internal/baseline"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

var bg = context.Background()

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

type env struct {
	t     *testing.T
	pool  *pgxpool.Pool
	d     *diary.Diary
	ctl   *control.Store
	store baseline.Store
	svc   *baseline.Service
	dec   *decide.Service
	appr  *approvals.Service
	now   time.Time
}

// small: min_count 3 so a burst is a handful of calls.
var small = baseline.Params{Days: 14, Sigma: 3, MedianFactor: 5, MinHistoryDays: 3, MinCount: 3}

func setup(t *testing.T, store baseline.Store, p baseline.Params) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, id := range []string{"bl_green", "bl_yellow", "bl_red", "bl_new"} {
		if _, err := ctl.Register(bg, control.Agent{AgentID: id, Type: "coding", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	eng, err := policy.NewEngine(bg, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	// One fixed instant (real time, so grants and hold expiry agree with the
	// database clock): every decision of the test falls in the same hour.
	now := time.Now().UTC()
	clock := func() time.Time { return now }
	svc := baseline.New(pool, store, p, baseline.Options{}, log)
	svc.Now = clock
	e := &env{t: t, pool: pool, d: d, ctl: ctl, store: store, svc: svc, now: now}
	e.dec = &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Now: clock,
		Enrichers: []decide.Enricher{approvals.NewGrantEnricher(pool), svc},
		Observers: []decide.Observer{approvals.NewGrantObserver(d), svc}}
	e.appr = approvals.New(pool, d, undo.NewPGStore(pool, d), nil, approvals.Config{}, log)
	return e
}

// seed writes `days` days of `perHour` calls per hour before the current
// hour into baseline_hourly for (agent, verb).
func (e *env) seed(agent, verb string, days int, perHour int64) {
	e.t.Helper()
	cur := baseline.HourStart(e.now)
	for i := 1; i <= days*24; i++ {
		if _, err := e.pool.Exec(bg, `INSERT INTO baseline_hourly (agent_id, verb, hour, count) VALUES ($1, $2, $3, $4)`,
			agent, verb, cur.Add(-time.Duration(i)*time.Hour), perHour); err != nil {
			e.t.Fatal(err)
		}
	}
}

func readAct(agent string) action.Action {
	return action.Action{AgentID: agent, System: "postgres", Verb: action.VerbRead, Source: action.SourcePGProxy,
		Target: map[string]any{"statement_type": "SELECT", "environment": "prod", "tables": []any{"public.orders"}}}
}

func rememberAct(agent string) action.Action {
	return action.Action{AgentID: agent, System: "memory", Verb: action.VerbRemember, Source: action.SourceAgentGateway,
		Target: map[string]any{"store": "s", "namespace": "n"}}
}

func dropAct(agent string) action.Action {
	return action.Action{AgentID: agent, System: "postgres", Verb: action.VerbDelete, Source: action.SourcePGProxy,
		Target: map[string]any{"statement_type": "DROP_TABLE", "environment": "prod", "tables": []any{"public.orders"}}}
}

func (e *env) decide(a action.Action) decide.Outcome {
	e.t.Helper()
	b, _ := json.Marshal(a.Target)
	var tgt map[string]any
	_ = json.Unmarshal(b, &tgt)
	a.Target, a.ActionID = tgt, ""
	out, err := e.dec.Decide(bg, a)
	if err != nil {
		e.t.Fatal(err)
	}
	if out.FailClosed {
		e.t.Fatalf("fail closed: %+v", out.Result)
	}
	return out
}

func ids(r policy.Result) map[string]bool {
	m := map[string]bool{}
	for _, x := range r.Matched {
		m[x.RuleID] = true
	}
	return m
}

func (e *env) recordedBaseline(actionID string) baseline.Context {
	e.t.Helper()
	var raw []byte
	if err := e.pool.QueryRow(bg, `SELECT decision_json->'context'->'baseline' FROM actions WHERE action_id = $1`, actionID).Scan(&raw); err != nil {
		e.t.Fatal(err)
	}
	var c baseline.Context
	if err := json.Unmarshal(raw, &c); err != nil {
		e.t.Fatalf("%s: %v", raw, err)
	}
	return c
}

// stores runs f against the memory store and a real redis-server.
func stores(t *testing.T, f func(t *testing.T, s baseline.Store)) {
	t.Run("memory", func(t *testing.T) { f(t, baseline.NewMemoryStore()) })
	t.Run("redis", func(t *testing.T) {
		url := startRedis(t)
		s, err := baseline.NewStore(bg, config.CountersConfig{Provider: "redis", RedisURL: url}, small)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = s.Close() })
		f(t, s)
	})
}

// POL-660 through the real decide.Service and policy bundle: a green burst
// above the agent's own normal becomes a yellow hold for one approver, the
// approval's one-time grant releases the identical retry, and the counts
// (current included) reach baseline_hourly.
func TestPOL660PromotesGreenBurstToYellowHold(t *testing.T) {
	stores(t, func(t *testing.T, s baseline.Store) {
		e := setup(t, s, small)
		e.seed("bl_green", "READ", 14, 1) // mean 1, stddev 0: threshold 1; min_count 3
		if n, err := e.svc.Backfill(bg); err != nil || n != 14*24 {
			t.Fatalf("backfill %d %v", n, err)
		}
		for i := 1; i <= 2; i++ {
			out := e.decide(readAct("bl_green"))
			if out.Result.Class != policy.Green || out.Result.Decision != policy.Allow {
				t.Fatalf("call %d: %+v", i, out.Result)
			}
			if c := e.recordedBaseline(out.Action.ActionID); c.Current != int64(i) || c.AboveNormal || c.Threshold != 1 || c.Method != baseline.MethodSigma {
				t.Fatalf("call %d context: %+v", i, c)
			}
		}
		held := e.decide(readAct("bl_green"))
		r := held.Result
		if r.Class != policy.Yellow || r.Decision != policy.Hold || r.RuleID != baseline.RuleAboveNormal || !held.Held {
			t.Fatalf("burst: %+v", r)
		}
		c := e.recordedBaseline(held.Action.ActionID)
		if c.Current != 3 || !c.AboveNormal || c.HistoryDays != 14 {
			t.Fatalf("burst context: %+v", c)
		}
		var req int
		if err := e.pool.QueryRow(bg, `SELECT approvals_required FROM held_actions WHERE action_id = $1`, held.Action.ActionID).Scan(&req); err != nil || req != 1 {
			t.Fatalf("approvals_required %d %v", req, err)
		}
		// Another agent with no history is never above normal.
		for i := 0; i < 5; i++ {
			if o := e.decide(readAct("bl_new")); o.Result.Decision != policy.Allow {
				t.Fatalf("no-history agent: %+v", o.Result)
			}
		}

		sec := authz.Principal{Kind: authz.KindUser, Email: "sec@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
		dec, err := e.appr.Approve(bg, sec, held.Action.ActionID, approvals.ApproveRequest{Reason: "planned batch"})
		if err != nil || dec.Outcome != approvals.OutcomeApproved || dec.Grant == nil {
			t.Fatalf("approve: %+v %v", dec, err)
		}
		retry := e.decide(readAct("bl_green"))
		if retry.Result.Decision != policy.Allow || retry.Result.GrantID != dec.Grant.GrantID {
			t.Fatalf("retry with grant: %+v", retry.Result)
		}
		if again := e.decide(readAct("bl_green")); again.Result.Decision != policy.Hold || again.Result.RuleID != baseline.RuleAboveNormal {
			t.Fatalf("grant is one-time: %+v", again.Result)
		}

		// Durable copy: the 3 READs by bl_green this hour that ran (two
		// allowed, the granted retry); the two held calls are not counted, so
		// a burst a human holds or denies never trains the agent's baseline.
		if e.svc.Pending() == 0 {
			t.Fatal("nothing pending")
		}
		if err := e.svc.Flush(bg); err != nil {
			t.Fatal(err)
		}
		var n int64
		if err := e.pool.QueryRow(bg, `SELECT count FROM baseline_hourly WHERE agent_id = 'bl_green' AND verb = 'READ' AND hour = $1`,
			baseline.HourStart(e.now)).Scan(&n); err != nil || n != 3 {
			t.Fatalf("durable count %d %v", n, err)
		}
		// A second flush adds only what is new: one more granted retry.
		held2 := e.decide(readAct("bl_green"))
		if _, err := e.appr.Approve(bg, sec, held2.Action.ActionID, approvals.ApproveRequest{Reason: "planned batch"}); err != nil {
			t.Fatal(err)
		}
		if r := e.decide(readAct("bl_green")); r.Result.Decision != policy.Allow {
			t.Fatalf("second retry: %+v", r.Result)
		}
		if err := e.svc.Flush(bg); err != nil {
			t.Fatal(err)
		}
		if err := e.pool.QueryRow(bg, `SELECT count FROM baseline_hourly WHERE agent_id = 'bl_green' AND verb = 'READ' AND hour = $1`,
			baseline.HourStart(e.now)).Scan(&n); err != nil || n != 4 {
			t.Fatalf("durable count after second flush %d %v", n, err)
		}
	})
}

// POL-660 on yellow and red: a yellow that would run in its reduced form is
// held instead once above normal (Phase 5 review L3); a red is still held red
// by its own rule, its reason unchanged.
func TestPOL660HoldsReducedYellowLeavesRed(t *testing.T) {
	stores(t, func(t *testing.T, s baseline.Store) {
		e := setup(t, s, small)
		e.seed("bl_yellow", "REMEMBER", 14, 1)
		e.seed("bl_red", "DELETE", 14, 1)
		if _, err := e.svc.Backfill(bg); err != nil {
			t.Fatal(err)
		}
		var plain policy.Result
		for i := 1; i <= 4; i++ {
			out := e.decide(rememberAct("bl_yellow"))
			r := out.Result
			above := e.recordedBaseline(out.Action.ActionID).AboveNormal
			if above != (i >= 3) {
				t.Fatalf("REMEMBER %d: above %v", i, above)
			}
			if !above {
				if r.Class != policy.Yellow || r.Decision != policy.AllowReduced || r.ReducedForm["memory_staging"] != true || out.Held || ids(r)[baseline.RuleAboveNormal] {
					t.Fatalf("REMEMBER %d: %+v", i, r)
				}
			} else if r.Class != policy.Yellow || r.Decision != policy.Hold || !out.Held || r.RuleID != baseline.RuleAboveNormal ||
				len(r.ReducedForm) != 0 || !ids(r)["POL-903"] {
				t.Fatalf("REMEMBER %d above normal: %+v", i, r)
			}
			if i == 1 {
				plain = r
			}
		}
		if plain.RuleID != "POL-903" {
			t.Fatalf("plain REMEMBER rule %s", plain.RuleID)
		}
		// Held calls are not counted, so the held DROPs never raise the count
		// themselves: 5 executed DELETEs this hour put bl_red above normal.
		if err := e.store.Add(bg, "bl_red", "DELETE", baseline.HourStart(e.now).Unix(), 5); err != nil {
			t.Fatal(err)
		}
		var first policy.Result
		for i := 1; i <= 4; i++ {
			// A red DROP steps the agent down; restore it so each call is
			// decided at the same level.
			if _, err := e.ctl.SetLevel(bg, "bl_red", control.Full, "test reset", "test"); err != nil {
				t.Fatal(err)
			}
			out := e.decide(dropAct("bl_red"))
			r := out.Result
			if r.Class != policy.Red || r.Decision != policy.Hold {
				t.Fatalf("DROP %d: %+v", i, r)
			}
			if i == 1 {
				first = r
			} else if r.RuleID != first.RuleID || r.Reason != first.Reason {
				t.Fatalf("DROP %d changed: %s %q vs %s %q", i, r.RuleID, r.Reason, first.RuleID, first.Reason)
			}
			if r.ApprovalsRequired > 1 {
				t.Fatalf("DROP %d approvers %d", i, r.ApprovalsRequired)
			}
		}
		if c := e.recordedBaseline(e.lastAction("bl_red")); !c.AboveNormal || c.Current != 6 {
			t.Fatalf("the DROPs are above normal and not counted: %+v", c)
		}
	})
}

func (e *env) lastAction(agent string) string {
	e.t.Helper()
	var id string
	if err := e.pool.QueryRow(bg, `SELECT action_id FROM actions WHERE agent_id = $1 ORDER BY ts DESC, action_id DESC LIMIT 1`, agent).Scan(&id); err != nil {
		e.t.Fatal(err)
	}
	return id
}

// A store failure fails the decision closed (enricher) and is never
// silently skipped.
func TestStoreFailureFailsClosed(t *testing.T) {
	bad, err := baseline.NewRedisStore("redis://127.0.0.1:1/0", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	e := setup(t, bad, small)
	out, err := e.dec.Decide(bg, readAct("bl_green"))
	if err != nil {
		t.Fatal(err)
	}
	if !out.FailClosed || out.Result.Decision != policy.Deny || out.Result.RuleID != decide.RuleFailClosed {
		t.Fatalf("%+v", out)
	}
}

// Backfill seeds baseline_hourly from the actions table when it is empty,
// then loads it into the hot store.
func TestBackfillFromActions(t *testing.T) {
	e := setup(t, baseline.NewMemoryStore(), small)
	cur := baseline.HourStart(e.now)
	ins := func(agent, verb string, ts time.Time, failClosed bool) {
		_, err := e.pool.Exec(bg, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, fail_closed, ts)
			VALUES ($1, $2, 'postgres', $3, 'h', 'green', 'allow', 'POL-000', 'r', $4, $5)`, action.NewID("act"), agent, verb, failClosed, ts)
		if err != nil {
			e.t.Fatal(err)
		}
	}
	for i := 0; i < 4; i++ {
		ins("bl_green", "READ", cur.Add(-2*time.Hour+time.Duration(i)*time.Minute), false)
	}
	ins("bl_green", "READ", cur.Add(-2*time.Hour+30*time.Minute), true) // fail-closed: not counted
	ins("bl_green", "WRITE", cur.Add(-30*time.Hour), false)
	ins("bl_green", "READ", cur.Add(-20*24*time.Hour), false) // outside the window
	ins("bl_green", "BOGUS", cur.Add(-time.Hour), false)      // unknown verb
	n, err := e.svc.Backfill(bg)
	if err != nil || n != 2 {
		t.Fatalf("backfill %d %v", n, err)
	}
	ser, _ := e.store.Series(bg, "bl_green", "READ", 0)
	if len(ser) != 1 || ser[cur.Add(-2*time.Hour).Unix()] != 4 {
		t.Fatalf("READ series %v", ser)
	}
	if v, _ := e.store.Verbs(bg, "bl_green"); len(v) != 2 {
		t.Fatalf("verbs %v", v)
	}
	if got := countRows(t, e.pool, `SELECT count(*) FROM baseline_hourly`); got != 2 {
		t.Fatalf("baseline_hourly rows %d", got)
	}
	// Not seeded twice: a second backfill finds rows and only re-loads them.
	ins("bl_green", "READ", cur.Add(-3*time.Hour), false)
	if n, err := e.svc.Backfill(bg); err != nil || n != 2 {
		t.Fatalf("second backfill %d %v", n, err)
	}
	// A hot count above the durable copy is never lowered by a re-load.
	if err := e.store.Add(bg, "bl_green", "READ", cur.Add(-2*time.Hour).Unix(), 10); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.Backfill(bg); err != nil {
		t.Fatal(err)
	}
	if ser, _ := e.store.Series(bg, "bl_green", "READ", 0); ser[cur.Add(-2*time.Hour).Unix()] != 14 {
		t.Fatalf("hot count lowered: %v", ser)
	}
}

func countRows(t *testing.T, pool *pgxpool.Pool, q string, args ...any) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(bg, q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Retention: rows older than days+1 are pruned from baseline_hourly and the
// memory store.
func TestPrune(t *testing.T) {
	e := setup(t, baseline.NewMemoryStore(), small)
	cur := baseline.HourStart(e.now)
	for _, age := range []time.Duration{time.Hour, 14 * 24 * time.Hour, 15*24*time.Hour - time.Hour, 15*24*time.Hour + time.Hour, 40 * 24 * time.Hour} {
		if _, err := e.pool.Exec(bg, `INSERT INTO baseline_hourly (agent_id, verb, hour, count) VALUES ('bl_green', 'READ', $1, 1)`, cur.Add(-age)); err != nil {
			t.Fatal(err)
		}
		if err := e.store.Add(bg, "bl_green", "READ", cur.Add(-age).Unix(), 1); err != nil {
			t.Fatal(err)
		}
	}
	n, err := e.svc.Prune(bg)
	if err != nil || n != 2 {
		t.Fatalf("pruned %d %v", n, err)
	}
	if got := countRows(t, e.pool, `SELECT count(*) FROM baseline_hourly`); got != 3 {
		t.Fatalf("left %d", got)
	}
	if ser, _ := e.store.Series(bg, "bl_green", "READ", 0); len(ser) != 3 {
		t.Fatalf("memory left %v", ser)
	}
}

// Run flushes on its tick and once more on shutdown.
func TestRunFlushesAndStops(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	st := baseline.NewMemoryStore()
	svc := baseline.New(pool, st, small, baseline.Options{FlushInterval: 20 * time.Millisecond}, nil)
	now := time.Now().UTC()
	svc.Now = func() time.Time { return now }
	a := readAct("bl_green")
	a.TS = now
	in := policy.Input{Agent: control.State{AgentID: "bl_green", Registered: true}}
	ctx, cancel := context.WithCancel(bg)
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	if err := svc.AfterDecide(bg, nil, &decide.Outcome{Action: a, Result: policy.Result{Decision: policy.Allow}}, in); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for countRows(t, pool, `SELECT COALESCE(sum(count), 0)::int FROM baseline_hourly`) != 1 {
		if time.Now().After(deadline) {
			t.Fatal("not flushed by Run")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := svc.AfterDecide(bg, nil, &decide.Outcome{Action: a, Result: policy.Result{Decision: policy.Allow}}, in); err != nil {
		t.Fatal(err)
	}
	cancel()
	<-done
	if got := countRows(t, pool, `SELECT COALESCE(sum(count), 0)::int FROM baseline_hourly`); got != 2 {
		t.Fatalf("final flush: %d", got)
	}
	// Unregistered agents and unknown verbs are not counted.
	bogus := a
	bogus.Verb = "BOGUS"
	_ = svc.AfterDecide(bg, nil, &decide.Outcome{Action: bogus}, in)
	_ = svc.AfterDecide(bg, nil, &decide.Outcome{Action: a}, policy.Input{Agent: control.State{AgentID: "x"}})
	if svc.Pending() != 0 {
		t.Fatalf("pending %d", svc.Pending())
	}
}

// The observer and enricher stay cheap on the decision path.
func TestObserverAndEnricherLatency(t *testing.T) {
	stores(t, func(t *testing.T, s baseline.Store) {
		pool, _ := testutil.FortikDB(t)
		svc := baseline.New(pool, s, small, baseline.Options{}, nil)
		now := time.Now().UTC()
		cur := baseline.HourStart(now)
		var rows []baseline.Row
		for i := 1; i <= 14*24; i++ {
			rows = append(rows, baseline.Row{AgentID: "lat", Verb: "READ", Hour: cur.Add(-time.Duration(i) * time.Hour).Unix(), Count: int64(i % 7)})
		}
		if err := s.Merge(bg, rows); err != nil {
			t.Fatal(err)
		}
		st := control.State{AgentID: "lat", Registered: true}
		a := readAct("lat")
		a.TS = now
		const n = 2000
		enrich := make([]time.Duration, n)
		observe := make([]time.Duration, n)
		for i := 0; i < n; i++ {
			t0 := time.Now()
			if _, err := svc.Enrich(bg, a, st); err != nil {
				t.Fatal(err)
			}
			t1 := time.Now()
			if err := svc.AfterDecide(bg, nil, &decide.Outcome{Action: a, Result: policy.Result{Decision: policy.Allow}}, policy.Input{Agent: st}); err != nil {
				t.Fatal(err)
			}
			enrich[i], observe[i] = t1.Sub(t0), time.Since(t1)
		}
		p := func(d []time.Duration, q float64) time.Duration {
			s := append([]time.Duration(nil), d...)
			sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
			return s[int(float64(len(s)-1)*q)]
		}
		t.Logf("enrich p50 %v p99 %v; observe p50 %v p99 %v (race=%v)", p(enrich, .5), p(enrich, .99), p(observe, .5), p(observe, .99), raceEnabled)
		budget := 2 * time.Millisecond // a local Redis round trip is ~0.1ms
		if raceEnabled {
			budget *= 10
		}
		if p(enrich, .99) > budget || p(observe, .99) > budget {
			t.Fatalf("too slow: enrich p99 %v observe p99 %v (budget %v)", p(enrich, .99), p(observe, .99), budget)
		}
		// The durable copy is written off the decision path, in one statement.
		t0 := time.Now()
		if err := svc.Flush(bg); err != nil {
			t.Fatal(err)
		}
		t.Logf("flush of %d decisions: %v", n, time.Since(t0))
		if got := countRows(t, pool, `SELECT count::int FROM baseline_hourly WHERE agent_id = 'lat'`); got != n {
			t.Fatalf("durable %d", got)
		}
	})
}

// GET /v1/agents/{id}/baseline: roles, validation, series and thresholds.
func TestBaselineAPI(t *testing.T) {
	e := setup(t, baseline.NewMemoryStore(), small)
	e.seed("bl_green", "READ", 2, 4)
	if _, err := e.svc.Backfill(bg); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		e.decide(readAct("bl_green"))
	}
	var mu sync.Mutex
	var who *authz.Principal
	mux := http.NewServeMux()
	baseline.NewHandler(e.svc).Register(mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		p := who
		mu.Unlock()
		if p != nil {
			r = r.WithContext(authz.With(r.Context(), *p))
		}
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()
	get := func(p *authz.Principal, path string) (int, map[string]any) {
		mu.Lock()
		who = p
		mu.Unlock()
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	auditor := authz.Principal{Kind: authz.KindUser, Email: "a@acme.com", Roles: map[string]bool{authz.RoleAuditor: true}}
	agentP := authz.Principal{Kind: authz.KindAgent, Name: "bl_green"}
	if code, _ := get(nil, "/v1/agents/bl_green/baseline"); code != 401 {
		t.Fatalf("anonymous %d", code)
	}
	if code, _ := get(&agentP, "/v1/agents/bl_green/baseline"); code != 403 {
		t.Fatalf("agent %d", code)
	}
	for path, want := range map[string]int{
		"/v1/agents/nobody/baseline":                       404,
		"/v1/agents/bl_green/baseline?verb=FLY":            400,
		"/v1/agents/bl_green/baseline?bogus=1":             400,
		"/v1/agents/bl_green/baseline?verb=READ&verb=SEND": 400,
	} {
		if code, _ := get(&auditor, path); code != want {
			t.Fatalf("%s: %d want %d", path, code, want)
		}
	}
	code, body := get(&auditor, "/v1/agents/bl_green/baseline?verb=READ")
	if code != 200 {
		t.Fatalf("%d %v", code, body)
	}
	v := body
	series := v["series"].([]any)
	if v["verb"] != "READ" || len(series) != 14*24+1 || v["current"] != float64(3) || v["method"] != "median" || v["threshold"] != float64(20) ||
		v["median"] != float64(4) || v["history_days"] != float64(2) || v["above_normal"] != false || v["min_count"] != float64(3) {
		t.Fatalf("view: %v (series %d)", v, len(series))
	}
	if vs := v["verbs"].([]any); len(vs) != 1 || vs[0] != "READ" {
		t.Fatalf("verbs %v", vs)
	}
	last := series[len(series)-1].(map[string]any)
	if last["count"] != float64(3) || last["hour"] == nil {
		t.Fatalf("current hour %v", last)
	}
	if params := body["params"].(map[string]any); params["min_count"] != float64(3) || params["days"] != float64(14) {
		t.Fatalf("params %v", params)
	}
	// Without verb: the busiest verb is shown, every verb listed.
	e.decide(rememberAct("bl_green"))
	code, body = get(&auditor, "/v1/agents/bl_green/baseline")
	if vs := body["verbs"].([]any); code != 200 || len(vs) != 2 || body["verb"] != "READ" {
		t.Fatalf("default verb: %d %v", code, body["verbs"])
	}
	code, body = get(&auditor, "/v1/agents/bl_green/baseline?verb=REMEMBER")
	if code != 200 || body["verb"] != "REMEMBER" || body["current"] != float64(1) || body["method"] != baseline.MethodFirstUse || body["above_normal"] != false {
		t.Fatalf("REMEMBER: %d %v", code, body)
	}
	// An agent without counts: verb null, empty series, method none.
	code, body = get(&auditor, "/v1/agents/bl_new/baseline")
	if code != 200 || body["verb"] != nil || len(body["series"].([]any)) != 0 || len(body["verbs"].([]any)) != 0 || body["method"] != "none" {
		t.Fatalf("no counts: %d %v", code, body)
	}
}

// Phase 5 review L4: a Redis that loses its data (restart without
// persistence, FLUSHALL, eviction) must not quietly turn every baseline into
// "no history". The load marker is gone, so the next decision reloads the
// hot store from baseline_hourly before it is decided.
func TestRedisDataLossReloadsBeforeDeciding(t *testing.T) {
	url := startRedis(t)
	s, err := baseline.NewStore(bg, config.CountersConfig{Provider: "redis", RedisURL: url}, small)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e := setup(t, s, small)
	svc := baseline.New(e.pool, s, small, baseline.Options{LoadCheckInterval: time.Nanosecond}, nil)
	svc.Now = e.svc.Now
	e.svc = svc
	e.dec.Enrichers = []decide.Enricher{approvals.NewGrantEnricher(e.pool), svc}
	e.dec.Observers = []decide.Observer{approvals.NewGrantObserver(e.d), svc}
	e.seed("bl_green", "READ", 14, 1) // threshold 1, min_count 3
	if _, err := svc.Backfill(bg); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 2; i++ {
		if o := e.decide(readAct("bl_green")); o.Result.Decision != policy.Allow {
			t.Fatalf("call %d: %+v", i, o.Result)
		}
	}
	if err := svc.Flush(bg); err != nil {
		t.Fatal(err)
	}
	opt, _ := redis.ParseURL(url)
	rc := redis.NewClient(opt)
	defer rc.Close()
	if err := rc.FlushAll(bg).Err(); err != nil {
		t.Fatal(err)
	}
	o := e.decide(readAct("bl_green"))
	c := e.recordedBaseline(o.Action.ActionID)
	if o.Result.Decision != policy.Hold || o.Result.RuleID != baseline.RuleAboveNormal || c.Method != baseline.MethodSigma || c.Current != 3 {
		t.Fatalf("after FLUSHALL: %+v %+v", o.Result, c)
	}
	if ok, err := s.(baseline.LoadMarker).Loaded(bg); err != nil || !ok {
		t.Fatalf("marker not restored: %v %v", ok, err)
	}
}
