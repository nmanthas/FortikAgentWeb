package decide_test

import (
	"context"
	"errors"
	"testing"

	"fortik/internal/action"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/policy"
)

// afterEval runs a hook after a real evaluation, to break persistence at
// exactly the point the review found dangerous.
type afterEval struct {
	inner decide.Evaluator
	hook  func()
}

func (e afterEval) Eval(ctx context.Context, in policy.Input) (policy.Result, error) {
	r, err := e.inner.Eval(ctx, in)
	e.hook()
	return r, err
}

// Review finding: a failed write after a deny fell through to the fail-open
// READ allowlist, letting a KILLED agent read.
func TestDenyIsKeptWhenRecordingFails(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.svc.Fail = config.FailConfig{GreenReadAllowlist: []config.FailOpenEntry{{System: "postgres", Agent: "*"}}}
	if _, err := f.ctl.SetLevel(ctx, "finance_agent_07", control.Killed, "incident", "test"); err != nil {
		t.Fatal(err)
	}
	f.svc.Policy = afterEval{inner: f.svc.Policy, hook: func() {
		_, _ = f.pool.Exec(ctx, `ALTER TABLE actions RENAME TO actions_broken`)
	}}
	t.Cleanup(func() { _, _ = f.pool.Exec(ctx, `ALTER TABLE IF EXISTS actions_broken RENAME TO actions`) })
	out, err := f.svc.Decide(ctx, pgAction("finance_agent_07", "SELECT", action.VerbRead, "prod", nil))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision.Executes() || out.Result.RuleID != "POL-010" || !out.FailClosed {
		t.Fatalf("a KILLED agent's read must stay denied when recording fails: %+v", out.Result)
	}
}

// Review finding: a red action skipped the step-down when persistence failed.
func TestRedStillStepsDownWhenRecordingFails(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.svc.Policy = afterEval{inner: f.svc.Policy, hook: func() {
		_, _ = f.pool.Exec(ctx, `ALTER TABLE held_actions RENAME TO held_broken`)
	}}
	t.Cleanup(func() { _, _ = f.pool.Exec(ctx, `ALTER TABLE IF EXISTS held_broken RENAME TO held_actions`) })
	out, _ := f.svc.Decide(ctx, pgAction("claude_code_01", "DROP_TABLE", action.VerbDelete, "prod", nil))
	if out.Result.Decision != policy.Hold || !out.FailClosed {
		t.Fatalf("red must stay held: %+v", out.Result)
	}
	if out.LevelAfter != control.ReadOnly || level(t, f, "claude_code_01") != control.ReadOnly {
		t.Fatalf("red must still step the agent down: after=%v", out.LevelAfter)
	}
	if count(t, f, `SELECT count(*) FROM actions WHERE action_id = $1 AND fail_closed AND decision = 'hold'`, out.Action.ActionID) != 1 ||
		count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'action.decided' AND body_json LIKE '%' || $1 || '%'`, out.Action.ActionID) != 1 {
		t.Fatal("the refused red decision must still be recorded in actions and the Diary")
	}
}

// Review finding: a reused action_id was treated as an outage.
func TestReusedActionIDIsInvalidInput(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil)
	a.ActionID = "act_fixed_1"
	if _, err := f.svc.Decide(ctx, a); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Decide(ctx, a); !errors.Is(err, action.ErrInvalid) {
		t.Fatalf("reused action_id must be rejected as invalid, got %v", err)
	}
}

// Review finding: a NUL byte in the target made persistence fail.
func TestNULInTargetRejected(t *testing.T) {
	f := setup(t)
	a := pgAction("claude_code_01", "DROP_TABLE", action.VerbDelete, "prod", map[string]any{"x": "a\x00b"})
	if _, err := f.svc.Decide(context.Background(), a); !errors.Is(err, action.ErrInvalid) {
		t.Fatalf("NUL in target must be invalid, got %v", err)
	}
}

func TestActorFromContextIsRecorded(t *testing.T) {
	f := setup(t)
	ctx := decide.WithActor(context.Background(), "token:pgproxy")
	if _, err := f.svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil)); err != nil {
		t.Fatal(err)
	}
	if count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'action.decided' AND actor = 'token:pgproxy'`) != 1 {
		t.Fatal("diary actor must come from the authenticated caller")
	}
}

func TestMalformedVerbAndTypedTargetRejected(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a := pgAction("claude_code_01", "SELECT", "READ\x00", "prod", nil)
	if _, err := f.svc.Decide(ctx, a); !errors.Is(err, action.ErrInvalid) {
		t.Fatalf("NUL verb must be invalid, got %v", err)
	}
	b := pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil)
	b.Target["typed"] = map[string]string{"k": "a\x00b"}
	if _, err := f.svc.Decide(ctx, b); !errors.Is(err, action.ErrInvalid) {
		t.Fatalf("NUL inside a typed in-process container must be invalid, got %v", err)
	}
}

// Plan: 3 yellow actions held within 10 minutes move the agent to Supervised.
func TestThreeHeldYellowsStepDownToSupervised(t *testing.T) {
	f := setup(t)
	f.svc.YellowHoldsThreshold = 3
	ctx := context.Background()
	held := func() decide.Outcome {
		out, err := f.svc.Decide(ctx, pgAction("finance_agent_07", "COPY_TO_STDOUT", action.VerbExport, "prod", nil)) // POL-105 yellow hold
		if err != nil || out.Result.Decision != policy.Hold {
			t.Fatalf("expected yellow hold: %+v %v", out.Result, err)
		}
		return out
	}
	held()
	held()
	if level(t, f, "finance_agent_07") != control.Full {
		t.Fatal("two holds must not step down")
	}
	out := held()
	if out.LevelAfter != control.Supervised || level(t, f, "finance_agent_07") != control.Supervised {
		t.Fatalf("third held yellow must step down to SUPERVISED, got %v", out.LevelAfter)
	}
	if count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed' AND body_json LIKE '%LADDER-3Y%'`) != 1 {
		t.Fatal("LADDER-3Y step-down must be in the Diary")
	}
}
