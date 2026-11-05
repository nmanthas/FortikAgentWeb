package decide_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/policy"
)

// Phase 6 chaos case: Fortik's own database is down. Decisions fail closed,
// the records go to the local spool, and once the database is back the spool
// is drained into actions and the Diary (marked recovered_from_spool).
func TestDatabaseDownSpoolsThenRecovers(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	dead, err := pgxpool.New(ctx, "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer dead.Close()
	sp, err := decide.NewSpool(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	down := &decide.Service{Pool: dead, Policy: f.svc.Policy, Control: control.NewStore(dead, f.d), Diary: f.d, Spool: sp}
	var ids []string
	for i := 0; i < 3; i++ {
		out, err := down.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil))
		if err != nil {
			t.Fatal(err)
		}
		if !out.FailClosed || out.Result.Decision != policy.Deny || out.Result.RuleID != decide.RuleFailClosed {
			t.Fatalf("database down must fail closed: %+v", out.Result)
		}
		ids = append(ids, out.Action.ActionID)
	}
	if sp.Pending() != 3 {
		t.Fatalf("spooled %d", sp.Pending())
	}
	// The database is back.
	up := &decide.Service{Pool: f.pool, Policy: f.svc.Policy, Control: f.ctl, Diary: f.d, Spool: sp}
	n, err := up.DrainSpool(ctx)
	if err != nil || n != 3 || sp.Pending() != 0 {
		t.Fatalf("drain: %d %v pending %d", n, err, sp.Pending())
	}
	for _, id := range ids {
		if count(t, f, `SELECT count(*) FROM actions WHERE action_id = $1 AND fail_closed AND decision = 'deny'`, id) != 1 ||
			count(t, f, `SELECT count(*) FROM diary WHERE event_type = 'action.decided'
				AND body_json::jsonb -> 'data' ->> 'recovered_from_spool' = 'true' AND body_json LIKE '%' || $1 || '%'`, id) != 1 {
			t.Fatalf("%s not recovered into actions and the Diary", id)
		}
	}
	// Draining again is a no-op; the chain still verifies.
	if n, err := up.DrainSpool(ctx); n != 0 || err != nil {
		t.Fatalf("second drain: %d %v", n, err)
	}
	if rep, err := f.d.VerifyChain(ctx); err != nil || !rep.OK {
		t.Fatalf("chain: %+v %v", rep, err)
	}
}
