package undo_test

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

func seedAction(t *testing.T, pool *pgxpool.Pool, id string) {
	t.Helper()
	_, err := pool.Exec(context.Background(), `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, ts)
		VALUES ($1, 'a1', 'postgres', 'DELETE', 'h', 'yellow', 'allow_reduced', 'POL-102', 'r', now())`, id)
	if err != nil {
		t.Fatal(err)
	}
}

func handle(id string, exp time.Time) undo.Handle {
	data, _ := json.Marshal(undo.PGRowsData{Upstream: "acme_staging", Schema: "public", Table: "orders", SnapshotSchema: "fortik_undo", SnapshotTable: "orders_x", Op: "DELETE"})
	return undo.Handle{ActionID: id, AgentID: "a1", Kind: undo.KindPGRows, Data: data, ExpiresAt: exp}
}

func TestLifecycle(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	s := undo.NewPGStore(pool, d)
	seedAction(t, pool, "act_1")

	if _, err := s.Claim(ctx, "act_1", "u"); !errors.Is(err, undo.ErrNotFound) {
		t.Fatalf("claim before prepare: %v", err)
	}
	if err := s.Prepare(ctx, handle("act_1", time.Now().Add(time.Hour)), "interceptor:pgproxy"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, "act_1", "u"); !errors.Is(err, undo.ErrNotUndoable) {
		t.Fatalf("a prepared (not yet committed) handle must not be undoable: %v", err)
	}
	if err := s.Activate(ctx, "act_1"); err != nil {
		t.Fatal(err)
	}
	if err := s.Fail(ctx, "act_1", "x"); !errors.Is(err, undo.ErrNotUndoable) {
		t.Fatalf("fail after activate must be refused: %v", err)
	}
	h, err := s.Claim(ctx, "act_1", "user:alice")
	if err != nil || h.Status != undo.StatusUndoing {
		t.Fatalf("claim: %+v %v", h, err)
	}
	if err := s.Release(ctx, "act_1", "user:alice", "upstream down"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, "act_1", "user:alice"); err != nil {
		t.Fatalf("re-claim after release: %v", err)
	}
	if err := s.Complete(ctx, "act_1", "user:alice", map[string]any{"rows_restored": 3}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, "act_1", "user:bob"); !errors.Is(err, undo.ErrNotUndoable) {
		t.Fatalf("second undo must be refused: %v", err)
	}
	got, _ := s.Get(ctx, "act_1")
	if got.Status != undo.StatusUsed || got.UsedAt == nil || got.UsedBy != "user:alice" {
		t.Fatalf("final state %+v", got)
	}
	// prepared, activated, claimed, released, claimed, executed
	rep, _ := d.VerifyChain(ctx)
	if rep.Checked != 6 || !rep.OK {
		t.Fatalf("diary: %+v", rep)
	}
}

func TestFailVoidsHandle(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	s := undo.NewPGStore(pool, diary.New(pool))
	seedAction(t, pool, "act_2")
	_ = s.Prepare(ctx, handle("act_2", time.Now().Add(time.Hour)), "t")
	if err := s.Fail(ctx, "act_2", "statement errored"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Claim(ctx, "act_2", "u"); !errors.Is(err, undo.ErrNotUndoable) {
		t.Fatalf("voided handle must not be undoable: %v", err)
	}
}

func TestExpiredHandle(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	s := undo.NewPGStore(pool, diary.New(pool))
	seedAction(t, pool, "act_3")
	_ = s.Prepare(ctx, handle("act_3", time.Now().Add(-time.Minute)), "t")
	_ = s.Activate(ctx, "act_3")
	if _, err := s.Claim(ctx, "act_3", "u"); !errors.Is(err, undo.ErrExpired) {
		t.Fatalf("want ErrExpired, got %v", err)
	}
}

func TestConcurrentClaimOnlyOneWins(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	s := undo.NewPGStore(pool, diary.New(pool))
	seedAction(t, pool, "act_4")
	_ = s.Prepare(ctx, handle("act_4", time.Now().Add(time.Hour)), "t")
	_ = s.Activate(ctx, "act_4")
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := s.Claim(ctx, "act_4", "u"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("exactly one concurrent claim may win, got %d", wins)
	}
}

func TestPrepareValidates(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	s := undo.NewPGStore(pool, diary.New(pool))
	if err := s.Prepare(context.Background(), undo.Handle{ActionID: "x"}, "t"); err == nil {
		t.Fatal("incomplete handle accepted")
	}
	if err := s.Prepare(context.Background(), handle("no_such_action", time.Now().Add(time.Hour)), "t"); err == nil {
		t.Fatal("handle for an unrecorded action accepted (FK must hold)")
	}
}
