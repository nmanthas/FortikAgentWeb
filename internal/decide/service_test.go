package decide_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
	"fortik/internal/testutil"
)

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

type fixture struct {
	pool *pgxpool.Pool
	svc  *decide.Service
	ctl  *control.Store
	d    *diary.Diary
}

func setup(t *testing.T) fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, id := range []string{"claude_code_01", "finance_agent_07"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: id, Type: "test", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log}
	return fixture{pool: pool, svc: svc, ctl: ctl, d: d}
}

func pgAction(agent, stype string, verb action.Verb, env string, extra map[string]any) action.Action {
	t := map[string]any{"statement_type": stype, "environment": env, "tables": []string{"public.orders"}, "table": "orders", "schema": "public"}
	for k, v := range extra {
		t[k] = v
	}
	return action.Action{AgentID: agent, System: "postgres", Verb: verb, Target: t, Source: "pgproxy"}
}

func level(t *testing.T, f fixture, agent string) control.Level {
	t.Helper()
	st, err := f.ctl.Get(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	return st.Level
}

func count(t *testing.T, f fixture, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestGreenReadAllowedAndRecorded(t *testing.T) {
	f := setup(t)
	out, err := f.svc.Decide(context.Background(), pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Class != policy.Green || out.Result.Decision != policy.Allow || out.FailClosed {
		t.Fatalf("got %+v", out.Result)
	}
	if out.Action.ActionID == "" || out.Result.PolicyVersion == "" {
		t.Fatal("action id / policy version missing")
	}
	if count(t, f, `SELECT count(*) FROM actions WHERE action_id = $1 AND class = 'green' AND decision = 'allow'`, out.Action.ActionID) != 1 {
		t.Fatal("action row not recorded")
	}
	if count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'action.decided' AND body_json LIKE '%' || $1 || '%'`, out.Action.ActionID) != 1 {
		t.Fatal("diary event missing")
	}
}

// The accident: DROP TABLE on prod is held, the agent steps down to
// Read-only, and every piece is recorded atomically.
func TestRedDropTableHeldAndSteppedDown(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := pgAction("claude_code_01", "DROP_TABLE", action.VerbDelete, "prod", map[string]any{
		"safe_form": map[string]any{"kind": "pg_rename", "sql": `ALTER TABLE public.orders RENAME TO fortik_trash_orders_20261006`},
	})
	out, err := f.svc.Decide(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	r := out.Result
	if r.Class != policy.Red || r.Decision != policy.Hold || r.RuleID != "POL-101" || !out.Held {
		t.Fatalf("got %+v", r)
	}
	if out.LevelBefore != control.Full || out.LevelAfter != control.ReadOnly || level(t, f, "claude_code_01") != control.ReadOnly {
		t.Fatalf("step-down: before=%v after=%v", out.LevelBefore, out.LevelAfter)
	}
	if count(t, f, `SELECT count(*) FROM held_actions WHERE action_id = $1 AND outcome = 'pending' AND safe_form->>'kind' = 'pg_rename'`, out.Action.ActionID) != 1 {
		t.Fatal("held action with safe form not recorded")
	}
	for _, ev := range []string{"action.decided", "action.held", "agent.level_changed"} {
		if count(t, f, `SELECT count(*) FROM diary WHERE event_type = $1 AND agent_id = 'claude_code_01'`, ev) != 1 {
			t.Fatalf("diary event %s missing", ev)
		}
	}
	// After the step-down, writes are refused and reads still work.
	w, _ := f.svc.Decide(ctx, pgAction("claude_code_01", "INSERT", action.VerbWrite, "prod", nil))
	if w.Result.Decision != policy.Deny || w.Result.RuleID != "POL-013" {
		t.Fatalf("write after step-down: %+v", w.Result)
	}
	rd, _ := f.svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil))
	if rd.Result.Decision != policy.Allow {
		t.Fatalf("read after step-down: %+v", rd.Result)
	}
	// A second red names READ_ONLY again: no further change, no duplicate event.
	_, _ = f.svc.Decide(ctx, pgAction("claude_code_01", "TRUNCATE", action.VerbDelete, "prod", nil))
	if count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed'`) != 1 {
		t.Fatal("step-down must not repeat when the level is already as restrictive")
	}
	rep, _ := f.d.VerifyChain(ctx)
	if !rep.OK {
		t.Fatalf("diary chain broken: %v", rep.Problems)
	}
}

func TestStepDownNeverLoosens(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.ctl.SetLevel(ctx, "finance_agent_07", control.Quarantined, "investigation", "test"); err != nil {
		t.Fatal(err)
	}
	out, _ := f.svc.Decide(ctx, pgAction("finance_agent_07", "DROP_TABLE", action.VerbDelete, "prod", nil))
	if out.Result.Decision != policy.Deny || out.LevelAfter != control.Quarantined || level(t, f, "finance_agent_07") != control.Quarantined {
		t.Fatalf("got %+v after=%v", out.Result, out.LevelAfter)
	}
}

func TestYellowSnapshotReducedForm(t *testing.T) {
	f := setup(t)
	out, _ := f.svc.Decide(context.Background(), pgAction("claude_code_01", "DELETE", action.VerbDelete, "staging",
		map[string]any{"has_where": true, "where_narrow": false, "undo_preparable": true}))
	if out.Result.Decision != policy.AllowReduced || out.Result.ReducedForm["snapshot_rows"] != true || out.Held {
		t.Fatalf("got %+v", out.Result)
	}
}

func TestUnregisteredAgentDeniedAndRecorded(t *testing.T) {
	f := setup(t)
	out, _ := f.svc.Decide(context.Background(), pgAction("shadow_script", "SELECT", action.VerbRead, "prod", nil))
	if out.Result.Decision != policy.Deny || out.Result.RuleID != "POL-015" {
		t.Fatalf("got %+v", out.Result)
	}
	if count(t, f, `SELECT count(*) FROM actions WHERE agent_id = 'shadow_script'`) != 1 {
		t.Fatal("attempt by unregistered agent must be recorded")
	}
}

func TestInvalidActionRejected(t *testing.T) {
	f := setup(t)
	_, err := f.svc.Decide(context.Background(), action.Action{System: "postgres", Verb: "READ"})
	if !errors.Is(err, action.ErrInvalid) {
		t.Fatalf("want ErrInvalid, got %v", err)
	}
}

type failingEval struct{}

func (failingEval) Eval(context.Context, policy.Input) (policy.Result, error) {
	return policy.Result{}, errors.New("boom")
}

func TestPolicyFailureFailsClosed(t *testing.T) {
	f := setup(t)
	f.svc.Policy = failingEval{}
	for _, a := range []action.Action{
		pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil),
		pgAction("claude_code_01", "INSERT", action.VerbWrite, "prod", nil),
	} {
		out, err := f.svc.Decide(context.Background(), a)
		if err != nil {
			t.Fatal(err)
		}
		if out.Result.Decision.Executes() || !out.FailClosed || out.Result.RuleID != decide.RuleFailClosed {
			t.Fatalf("not fail-closed: %+v", out.Result)
		}
	}
	if count(t, f, `SELECT count(*) FROM actions WHERE fail_closed`) != 2 {
		t.Fatal("fail-closed decisions must be recorded when the store is up")
	}
}

func TestFailOpenAllowlistOnlyForReads(t *testing.T) {
	f := setup(t)
	f.svc.Policy = failingEval{}
	f.svc.Fail = config.FailConfig{GreenReadAllowlist: []config.FailOpenEntry{{System: "postgres", Agent: "*"}}}
	rd, _ := f.svc.Decide(context.Background(), pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil))
	if rd.Result.Decision != policy.Allow || rd.Result.RuleID != decide.RuleFailOpen {
		t.Fatalf("allowlisted read: %+v", rd.Result)
	}
	wr, _ := f.svc.Decide(context.Background(), pgAction("claude_code_01", "INSERT", action.VerbWrite, "prod", nil))
	if wr.Result.Decision.Executes() {
		t.Fatalf("write must fail closed even with a read allowlist: %+v", wr.Result)
	}
}

func TestStoreDownFailsClosed(t *testing.T) {
	f := setup(t)
	f.pool.Close() // control state + persistence unavailable
	out, err := f.svc.Decide(context.Background(), pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision.Executes() || !out.FailClosed {
		t.Fatalf("store down must fail closed: %+v", out.Result)
	}
}

// levelFlipEval changes the agent's level the first time it is evaluated, to
// prove Decide re-evaluates when control state moves mid-decision.
type levelFlipEval struct {
	inner decide.Evaluator
	once  sync.Once
	flip  func()
	calls int
}

func (e *levelFlipEval) Eval(ctx context.Context, in policy.Input) (policy.Result, error) {
	e.calls++
	e.once.Do(e.flip)
	return e.inner.Eval(ctx, in)
}

func TestLevelChangeDuringDecisionReEvaluates(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	fe := &levelFlipEval{inner: f.svc.Policy, flip: func() {
		_, _ = f.ctl.SetLevel(ctx, "claude_code_01", control.Killed, "kill during decision", "test")
	}}
	f.svc.Policy = fe
	out, _ := f.svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil))
	if out.Result.Decision != policy.Deny || out.Result.RuleID != "POL-010" || fe.calls != 2 {
		t.Fatalf("decision must reflect the kill: %+v calls=%d", out.Result, fe.calls)
	}
}

func TestConcurrentDecisionsKeepDiaryValid(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 15; j++ {
				st := "SELECT"
				verb := action.VerbRead
				if j == 7 && i == 3 {
					st, verb = "DROP_TABLE", action.VerbDelete
				}
				if _, err := f.svc.Decide(ctx, pgAction("finance_agent_07", st, verb, "prod", nil)); err != nil {
					t.Error(err)
				}
			}
		}(i)
	}
	wg.Wait()
	rep, err := f.d.VerifyChain(ctx)
	if err != nil || !rep.OK {
		t.Fatalf("chain: %+v %v", rep, err)
	}
	if count(t, f, `SELECT count(*) FROM actions`) != 120 || level(t, f, "finance_agent_07") != control.ReadOnly {
		t.Fatal("unexpected totals")
	}
}
