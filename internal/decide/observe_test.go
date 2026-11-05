package decide_test

import (
	"context"
	"testing"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/policy"
)

// Phase 6 observe mode: the prod DROP TABLE that would be held red with a
// step-down is recorded with what would have happened, and allowed: no hold,
// no step-down. A level set by people is still enforced.
func TestObserveModeRecordsButDoesNotEnforce(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.pool.Exec(ctx, `UPDATE agents SET enforcement = 'observe' WHERE agent_id = 'claude_code_01'`); err != nil {
		t.Fatal(err)
	}
	drop := pgAction("claude_code_01", "DROP_TABLE", action.VerbDelete, "prod", map[string]any{
		"safe_form": map[string]any{"kind": "pg_rename", "sql": `ALTER TABLE public.orders RENAME TO fortik_trash_orders_20261021`},
	})
	out, err := f.svc.Decide(ctx, drop)
	if err != nil {
		t.Fatal(err)
	}
	r := out.Result
	if r.Decision != policy.Allow || r.Class != policy.Red || r.Observed == nil || r.Observed.Decision != policy.Hold ||
		r.Observed.LadderChange == nil || r.LadderChange != nil || out.Held || out.FailClosed {
		t.Fatalf("observe: %+v (observed %+v)", r, r.Observed)
	}
	if level(t, f, "claude_code_01") != control.Full {
		t.Fatal("observe mode stepped the agent down")
	}
	if count(t, f, `SELECT count(*) FROM held_actions WHERE action_id = $1`, out.Action.ActionID) != 0 ||
		count(t, f, `SELECT count(*) FROM actions WHERE action_id = $1 AND observed AND decision = 'allow' AND class = 'red'`, out.Action.ActionID) != 1 {
		t.Fatal("observe-mode action not recorded as observed")
	}
	if count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'action.decided'
		AND body_json::jsonb -> 'data' -> 'observed' ->> 'decision' = 'hold' AND body_json LIKE '%' || $1 || '%'`, out.Action.ActionID) != 1 {
		t.Fatal("Diary does not carry the would-be decision")
	}

	// The other agent follows the deployment mode (enforce): held as usual.
	enf, err := f.svc.Decide(ctx, pgAction("finance_agent_07", "DROP_TABLE", action.VerbDelete, "prod", nil))
	if err != nil || enf.Result.Decision != policy.Hold || enf.Result.Observed != nil {
		t.Fatalf("enforce: %+v %v", enf.Result, err)
	}

	// A level set by a person is enforced even in observe mode.
	if _, err := f.ctl.SetLevel(ctx, "claude_code_01", control.ReadOnly, "security review", "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	ro, err := f.svc.Decide(ctx, pgAction("claude_code_01", "INSERT", action.VerbWrite, "prod", nil))
	if err != nil || ro.Result.Decision != policy.Deny || ro.Result.RuleID != "POL-013" {
		t.Fatalf("read-only in observe mode: %+v %v", ro.Result, err)
	}

	// The deployment default can be observe too; an agent may opt back into enforce.
	f.svc.Enforcement = policy.ObserveMode
	if _, err := f.pool.Exec(ctx, `UPDATE agents SET enforcement = 'enforce' WHERE agent_id = 'claude_code_01'; UPDATE agents SET level = 0`); err != nil {
		t.Fatal(err)
	}
	fin, err := f.svc.Decide(ctx, pgAction("finance_agent_07", "TRUNCATE", action.VerbDelete, "prod", nil))
	if err != nil || fin.Result.Decision != policy.Allow || fin.Result.Observed == nil {
		t.Fatalf("deployment observe: %+v %v", fin.Result, err)
	}
	cc, err := f.svc.Decide(ctx, pgAction("claude_code_01", "TRUNCATE", action.VerbDelete, "prod", nil))
	if err != nil || cc.Result.Decision != policy.Hold {
		t.Fatalf("agent override enforce: %+v %v", cc.Result, err)
	}
}

// Unknown actions are refused in observe mode (never let through a protected path).
func TestObserveModeKeepsUnknownActionsRefused(t *testing.T) {
	f := setup(t)
	f.svc.Enforcement = policy.ObserveMode
	out, err := f.svc.Decide(context.Background(), pgAction("claude_code_01", "UNKNOWN", action.VerbWrite, "prod", nil))
	if err != nil || out.Result.Decision.Executes() {
		t.Fatalf("unclassified SQL in observe mode: %+v %v", out.Result, err)
	}
}
