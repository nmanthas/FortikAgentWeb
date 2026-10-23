package control_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

func TestParseLevel(t *testing.T) {
	for in, want := range map[string]control.Level{"full": control.Full, "read-only": control.ReadOnly, "READ_ONLY": control.ReadOnly, "5": control.Killed, " isolated ": control.Isolated} {
		got, err := control.ParseLevel(in)
		if err != nil || got != want {
			t.Errorf("%q: got %v %v", in, got, err)
		}
	}
	if _, err := control.ParseLevel("ADMIN"); err == nil {
		t.Fatal("unknown level accepted")
	}
	if control.Level(9).Valid() || control.Killed.String() != "KILLED" {
		t.Fatal("level helpers wrong")
	}
}

func TestStepDownOnlyTightensAndSetLevelAudited(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := control.NewStore(pool, d)
	if _, err := s.Register(ctx, control.Agent{AgentID: "a1"}, "test"); err != nil {
		t.Fatal(err)
	}
	step := func(to control.Level) bool {
		var changed bool
		err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
			var err error
			_, changed, err = s.StepDownTx(ctx, tx, "a1", to, "test", "test", nil)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return changed
	}
	if !step(control.Isolated) {
		t.Fatal("FULL -> ISOLATED must apply")
	}
	if step(control.ReadOnly) {
		t.Fatal("automatic step-down must never loosen ISOLATED -> READ_ONLY")
	}
	if st, _ := s.Get(ctx, "a1"); st.Level != control.Isolated || !st.Registered {
		t.Fatalf("state %+v", st)
	}
	if _, err := s.SetLevel(ctx, "a1", control.Full, "", "op"); err == nil {
		t.Fatal("level change without a reason accepted")
	}
	from, err := s.SetLevel(ctx, "a1", control.Supervised, "reviewed", "op")
	if err != nil || from != control.Isolated {
		t.Fatalf("set level: %v %v", from, err)
	}
	if _, err := s.SetLevel(ctx, "ghost", control.Full, "x", "op"); err == nil {
		t.Fatal("unregistered agent level change accepted")
	}
	if st, _ := s.Get(ctx, "ghost"); st.Registered {
		t.Fatal("unknown agent reported registered")
	}
	// Every change is in the Diary: register, step-down, set-level.
	var n int
	_ = pool.QueryRow(ctx, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed'`).Scan(&n)
	if n != 2 {
		t.Fatalf("want 2 level_changed events, got %d", n)
	}
	// Re-registering never changes the level.
	_, _ = s.Register(ctx, control.Agent{AgentID: "a1", Name: "renamed", Level: control.Full}, "test")
	if st, _ := s.Get(ctx, "a1"); st.Level != control.Supervised {
		t.Fatal("register must not change an existing agent's level")
	}
}
