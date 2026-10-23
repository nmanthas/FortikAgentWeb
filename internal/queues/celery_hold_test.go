package queues

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"fortik/internal/testutil"
)

// F18: held keys are unambiguous. Agent "a" on queue "b:celery" and agent
// "a:b" on queue "celery" used to share fortik:held:a:b:celery, so resuming
// or cancelling "a:b" released or deleted suspended agent "a"'s messages.
func TestCeleryHeldKeysDoNotCollide(t *testing.T) {
	addr := startRedis(t)
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	src := newSource()
	src.set(t, SystemCelery, map[string]any{"queues": []string{"celery", "b:celery"}}, map[string]string{"redis_url": "redis://" + addr + "/0"})
	cel := NewCelery(src)

	if CeleryHeldKey("a", "b:celery") == CeleryHeldKey("a:b", "celery") {
		t.Fatal("held keys collide")
	}
	aMsg, _ := celeryV2Message(t, "a", "b:celery", 1)
	rdb.LPush(ctx, "b:celery", aMsg)
	if res, err := cel.Pause(ctx, "a", "suspicious"); err != nil || res.Affected != 1 {
		t.Fatalf("pause a: %+v %v", res, err)
	}
	heldA := CeleryHeldKey("a", "b:celery")
	if got := lrange(t, rdb, heldA); !slices.Equal(got, []string{aMsg}) {
		t.Fatalf("held for a: %v", got)
	}
	// Resuming and cancelling the other agent leave a's held work alone.
	if res, err := cel.Resume(ctx, "a:b", "other agent"); err != nil || res.Affected != 0 {
		t.Fatalf("resume a:b: %+v %v", res, err)
	}
	if res, err := cel.Cancel(ctx, "a:b", "other agent"); err != nil || res.Affected != 0 {
		t.Fatalf("cancel a:b: %+v %v", res, err)
	}
	if n := rdb.LLen(ctx, "celery").Val() + rdb.LLen(ctx, "b:celery").Val(); n != 0 {
		t.Fatalf("a's held message was released into a queue (%d queued)", n)
	}
	if got := lrange(t, rdb, heldA); !slices.Equal(got, []string{aMsg}) {
		t.Fatalf("a's held message touched by another agent's resume/cancel: %v", got)
	}
	// a's own resume puts it back in its own queue.
	if res, err := cel.Resume(ctx, "a", "cleared"); err != nil || res.Affected != 1 {
		t.Fatalf("resume a: %+v %v", res, err)
	}
	if got := lrange(t, rdb, "b:celery"); !slices.Equal(got, []string{aMsg}) {
		t.Fatalf("b:celery after resume: %v", got)
	}

	// Defence in depth: a held list holding another agent's message (it
	// cannot happen through Pause) never releases or deletes it.
	xMsg, _ := celeryV2Message(t, "x", "celery", 2)
	yMsg, _ := celeryV2Message(t, "y", "celery", 3)
	stray := CeleryHeldKey("y", "celery")
	rdb.RPush(ctx, stray, xMsg, yMsg)
	if res, err := cel.Resume(ctx, "y", "r"); err != nil || res.Affected != 1 {
		t.Fatalf("resume y: %+v %v", res, err)
	}
	if got := lrange(t, rdb, stray); !slices.Equal(got, []string{xMsg}) {
		t.Fatalf("stray held list after y's resume: %v", got)
	}
	if got := lrange(t, rdb, "celery"); !slices.Equal(got, []string{yMsg}) {
		t.Fatalf("celery after y's resume: %v", got)
	}
	if res, err := cel.Cancel(ctx, "y", "r"); err != nil || res.Affected != 1 {
		t.Fatalf("cancel y: %+v %v", res, err)
	}
	if got := lrange(t, rdb, stray); !slices.Equal(got, []string{xMsg}) {
		t.Fatalf("y's cancel deleted x's held message: %v", got)
	}
}

// F21: the hold is one-shot, so the detail says later messages are not
// held; HoldWorker re-holds messages enqueued for agents that stay
// suspended or quarantined, and leaves everyone else's alone.
func TestCeleryHoldWorkerReholdsContainedAgents(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	addr := startRedis(t)
	ctx := context.Background()
	rdb := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() { _ = rdb.Close() })
	src := newSource()
	src.set(t, SystemCelery, map[string]any{"queues": []string{"celery"}}, map[string]string{"redis_url": "redis://" + addr + "/0"})
	cel := NewCelery(src)

	for _, q := range []string{
		`INSERT INTO agents (agent_id) VALUES ('susp'), ('quar'), ('free'), ('killed')`,
		`UPDATE agents SET suspended_at = now(), suspended_by = 'test', suspended_reason = 'test' WHERE agent_id = 'susp'`,
		`UPDATE agents SET level = 4 WHERE agent_id = 'quar'`,
		`UPDATE agents SET level = 5 WHERE agent_id = 'killed'`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	// The one-shot hold is honest about later arrivals.
	res, err := cel.Pause(ctx, "susp", "suspicious")
	if err != nil || !strings.Contains(res.Detail, "messages enqueued after this moment are NOT held") ||
		!strings.Contains(res.Detail, "no periodic re-hold is running") {
		t.Fatalf("pause detail: %+v %v", res, err)
	}

	msg := func(agent string, n int) string { raw, _ := celeryV2Message(t, agent, "celery", n); return raw }
	s1, q1, f1, k1, untagged := msg("susp", 1), msg("quar", 1), msg("free", 1), msg("killed", 1), msg("", 0)
	for _, m := range []string{s1, f1, q1, untagged, k1} {
		rdb.LPush(ctx, "celery", m)
	}
	w := NewHoldWorker(pool, cel, time.Hour, nil)
	held, err := w.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if held["susp"] != 1 || held["quar"] != 1 || held["killed"] != 1 || held["free"] != 0 || len(held) != 3 {
		t.Fatalf("held: %v", held)
	}
	if got := lrange(t, rdb, "celery"); !slices.Equal(got, []string{untagged, f1}) {
		t.Fatalf("queue after re-hold: %v", got)
	}
	if got := lrange(t, rdb, CeleryHeldKey("susp", "celery")); !slices.Equal(got, []string{s1}) {
		t.Fatalf("susp held: %v", got)
	}
	// Re-held messages are released by the normal Resume, oldest first.
	s2 := msg("susp", 2)
	rdb.LPush(ctx, "celery", s2)
	if held, err := w.RunOnce(ctx); err != nil || held["susp"] != 1 {
		t.Fatalf("second pass: %v %v", held, err)
	}
	if got := lrange(t, rdb, CeleryHeldKey("susp", "celery")); !slices.Equal(got, []string{s2, s1}) {
		t.Fatalf("susp held after second pass: %v", got)
	}

	// An agent resumed while the pass runs: what the pass just held is
	// released again (its resume may already have run).
	f2 := msg("quar", 2)
	rdb.LPush(ctx, "celery", f2)
	w.afterHold = func() {
		if _, err := pool.Exec(ctx, `UPDATE agents SET level = 0 WHERE agent_id = 'quar'`); err != nil {
			t.Error(err)
		}
	}
	held, err = w.RunOnce(ctx)
	if err != nil || held["quar"] != 0 {
		t.Fatalf("pass during resume: %v %v", held, err)
	}
	if n := rdb.LLen(ctx, CeleryHeldKey("quar", "celery")).Val(); n != 0 {
		t.Fatalf("%d messages stay held for a resumed agent", n)
	}
	w.afterHold = nil

	// While Run is active, Pause states the re-hold interval.
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	w2 := NewHoldWorker(pool, cel, 50*time.Millisecond, nil)
	go func() { w2.Run(rctx); close(done) }()
	s3 := msg("susp", 3)
	rdb.LPush(ctx, "celery", s3)
	deadline := time.Now().Add(10 * time.Second)
	for rdb.LLen(ctx, CeleryHeldKey("susp", "celery")).Val() != 3 {
		if time.Now().After(deadline) {
			t.Fatal("Run did not re-hold the new message")
		}
		time.Sleep(20 * time.Millisecond)
	}
	res, err = cel.Pause(ctx, "susp", "again")
	if err != nil || !strings.Contains(res.Detail, "re-holds new ones every 50ms") {
		t.Fatalf("pause detail with the worker running: %+v %v", res, err)
	}
	cancel()
	<-done

	// No Celery integration: nothing to do, not an error.
	empty := NewHoldWorker(pool, NewCelery(newSource()), time.Hour, nil)
	if held, err := empty.RunOnce(ctx); err != nil || len(held) != 0 {
		t.Fatalf("unconfigured: %v %v", held, err)
	}
}
