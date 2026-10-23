package overrides

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/control"
)

func TestNewWorkerRequiresDependencies(t *testing.T) {
	if _, err := NewWorker(nil, nil, nil, time.Second, nil); err == nil {
		t.Fatal("expected error")
	}
}

func insertRed(t *testing.T, f *fixture, agent, system string) string {
	t.Helper()
	id := action.NewID("act")
	if _, err := f.pool.Exec(context.Background(), `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, ts)
		VALUES ($1, $2, $3, 'WRITE', 'h', 'red', 'deny', 'POL-301', 'force push on main', now())`, id, agent, system); err != nil {
		t.Fatal(err)
	}
	return id
}

func TestWorkerRestoresWithEventAndOwnerAlert(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	notDue := mustCreate(t, f, agentReq("code_agent_13", "github", ModeSuspended, time.Hour))
	// A red action on ANOTHER system or by ANOTHER agent does not block.
	insertRed(t, f, "code_agent_12", "aws")
	insertRed(t, f, "finance_agent_07", "github")
	f.expire(t, o.OverrideID)

	res, err := f.worker(t).Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if res != (SweepResult{Restored: 1}) {
		t.Fatalf("sweep %+v", res)
	}
	got, _ := f.store.Get(ctx, o.OverrideID)
	if got.Status != StatusRestored || got.RestoredAt == nil {
		t.Fatalf("restored: %+v", got)
	}
	if status(t, f, notDue.OverrideID) != StatusActive {
		t.Fatal("an override that is not due was touched")
	}
	ev := f.events(t, EventRestored)
	if len(ev) != 1 || ev[0]["override_id"] != o.OverrideID {
		t.Fatalf("restored events %v", ev)
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type = $1 AND actor = $2 AND agent_id = 'code_agent_12'`, EventRestored, Actor); n != 1 {
		t.Fatal("restored event actor/agent")
	}
	var kind, sev, details string
	if err := f.pool.QueryRow(ctx, `SELECT kind, severity, details::text FROM alerts WHERE agent_id = 'code_agent_12'`).Scan(&kind, &sev, &details); err != nil {
		t.Fatal(err)
	}
	if kind != KindRestored || sev != "info" || !strings.Contains(details, `"notify": "Jane@Acme.com"`) {
		t.Fatalf("alert %s %s %s", kind, sev, details)
	}
	// Idempotent: nothing more to do.
	if res, err := f.worker(t).Sweep(ctx); err != nil || res != (SweepResult{}) {
		t.Fatalf("second sweep %+v %v", res, err)
	}
	f.verifyDiary(t)
}

func TestWorkerBlocksWhenAgentFrozen(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	if _, err := f.ctl.SetLevel(ctx, "code_agent_12", control.Quarantined, "review", secActor); err != nil {
		t.Fatal(err)
	}
	f.expire(t, o.OverrideID)
	res, err := f.worker(t).Sweep(ctx)
	if err != nil || res != (SweepResult{Blocked: 1}) {
		t.Fatalf("sweep %+v %v", res, err)
	}
	got, _ := f.store.Get(ctx, o.OverrideID)
	if got.Status != StatusBlocked || got.BlockedReason != "agent code_agent_12 is QUARANTINED" {
		t.Fatalf("blocked: %+v", got)
	}
	if !got.InForce() {
		t.Fatal("blocked must stay in force")
	}
	if n := f.count(t, `SELECT count(*) FROM alerts WHERE kind = 'override_restore_blocked' AND severity = 'warning'`); n != 1 {
		t.Fatal("restore-blocked alert")
	}
	if ev := f.events(t, EventRestoreBlocked); len(ev) != 1 || ev[0]["agent_level"] != "QUARANTINED" {
		t.Fatalf("events %v", ev)
	}
	// A blocked override is not picked up again.
	if res, _ := f.worker(t).Sweep(ctx); res != (SweepResult{}) {
		t.Fatalf("re-swept blocked: %+v", res)
	}
}

func TestWorkerBlocksOnRedActionTeamScope(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	o := mustCreate(t, f, CreateRequest{Scope: ScopeTeam, ScopeID: "platform", System: "github", Mode: ModeReadOnly, Duration: time.Hour, Reason: "freeze"})
	red := insertRed(t, f, "code_agent_13", "github")
	f.expire(t, o.OverrideID)
	if res, err := f.worker(t).Sweep(ctx); err != nil || res.Blocked != 1 {
		t.Fatalf("sweep %+v %v", res, err)
	}
	got, _ := f.store.Get(ctx, o.OverrideID)
	if got.Status != StatusBlocked || !strings.Contains(got.BlockedReason, red) {
		t.Fatalf("%+v", got)
	}
	if ev := f.events(t, EventRestoreBlocked); ev[0]["red_action_id"] != red {
		t.Fatalf("event %v", ev)
	}
}

// A red action BEFORE the override started does not block the restore, nor
// does a record Fortik synthesised because it could not decide (FAIL-CLOSED).
func TestWorkerIgnoresRedBeforeStartAndFailClosed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	insertRed(t, f, "code_agent_12", "github")
	time.Sleep(5 * time.Millisecond)
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	if _, err := f.pool.Exec(ctx, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, fail_closed, ts)
		VALUES ($1, 'code_agent_12', 'github', 'WRITE', 'h', 'red', 'deny', 'FAIL-CLOSED', 'store down', true, now())`, action.NewID("act")); err != nil {
		t.Fatal(err)
	}
	f.expire(t, o.OverrideID)
	if res, err := f.worker(t).Sweep(ctx); err != nil || res.Restored != 1 {
		t.Fatalf("sweep %+v %v", res, err)
	}
}

func TestWorkerSupersededByNewerOverride(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	older := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	newer := mustCreate(t, f, agentReq("code_agent_12", "github", ModeReadOnly, 2*time.Hour))
	f.expire(t, older.OverrideID)
	if res, err := f.worker(t).Sweep(ctx); err != nil || res != (SweepResult{Superseded: 1}) {
		t.Fatalf("sweep %+v %v", res, err)
	}
	if status(t, f, older.OverrideID) != StatusSuperseded || status(t, f, newer.OverrideID) != StatusActive {
		t.Fatal("statuses")
	}
	if ev := f.events(t, EventSuperseded); len(ev) != 1 || ev[0]["superseded_by"] != newer.OverrideID {
		t.Fatalf("events %v", ev)
	}
	// An OLDER override in force does not stop the newer one restoring.
	f.expire(t, newer.OverrideID)
	if res, err := f.worker(t).Sweep(ctx); err != nil || res.Restored != 1 {
		t.Fatalf("sweep %+v %v", res, err)
	}
}

// The access-profile version saved at suspension comes back if the profile
// changed during the suspension; an unchanged profile is left alone.
func TestWorkerRestoresSavedProfileVersion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	v1 := json.RawMessage(`{"repos":["acme/api","acme/web"],"permissions":{"contents":"write"}}`)
	if _, err := f.profiles.Put(ctx, "code_agent_12", "github", v1, secActor, "seed"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.profiles.Put(ctx, "code_agent_13", "github", v1, secActor, "seed"); err != nil {
		t.Fatal(err)
	}
	changed := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	same := mustCreate(t, f, agentReq("code_agent_13", "github", ModeSuspended, time.Hour))
	if changed.RestoreProfileVersion != 1 {
		t.Fatalf("saved version %d", changed.RestoreProfileVersion)
	}
	if _, err := f.profiles.Put(ctx, "code_agent_12", "github", json.RawMessage(`{"repos":["acme/api"],"permissions":{"contents":"read"}}`), secActor, "narrowed during incident"); err != nil {
		t.Fatal(err)
	}
	f.expire(t, changed.OverrideID)
	f.expire(t, same.OverrideID)
	if res, err := f.worker(t).Sweep(ctx); err != nil || res.Restored != 2 {
		t.Fatalf("sweep %+v %v", res, err)
	}
	cur, err := f.profiles.Current(ctx, "code_agent_12", "github")
	if err != nil {
		t.Fatal(err)
	}
	var stored1 []byte
	if err := f.pool.QueryRow(ctx, `SELECT profile_json FROM access_profiles WHERE agent_id = 'code_agent_12' AND system = 'github' AND version = 1`).Scan(&stored1); err != nil {
		t.Fatal(err)
	}
	if cur.Version != 3 || !jsonEqual(cur.Profile, stored1) || cur.ChangedBy != Actor {
		t.Fatalf("profile after restore: %+v", cur)
	}
	if cur, _ := f.profiles.Current(ctx, "code_agent_13", "github"); cur.Version != 1 {
		t.Fatalf("unchanged profile re-written: v%d", cur.Version)
	}
	var restored map[string]any
	for _, ev := range f.events(t, EventRestored) {
		if ev["override_id"] == changed.OverrideID {
			restored = ev
		}
	}
	pr, _ := restored["profile_restored"].(map[string]any)
	if pr == nil || pr["reverted_to"] != float64(1) || pr["to_version"] != float64(3) {
		t.Fatalf("restored event %v", restored)
	}
}

type failingReverter struct{ err error }

func (r failingReverter) Revert(context.Context, string, string, int, string, string) (access.Profile, error) {
	return access.Profile{}, r.err
}

// A revert that can never succeed blocks the override; a transient failure
// leaves it active (still enforced) for the next sweep.
func TestWorkerProfileRevertFailures(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	if _, err := f.profiles.Put(ctx, "code_agent_12", "github", json.RawMessage(`{"repos":["acme/api"],"permissions":{"contents":"write"}}`), secActor, "seed"); err != nil {
		t.Fatal(err)
	}
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	if _, err := f.profiles.Put(ctx, "code_agent_12", "github", json.RawMessage(`{"repos":["acme/web"],"permissions":{"contents":"write"}}`), secActor, "changed"); err != nil {
		t.Fatal(err)
	}
	f.expire(t, o.OverrideID)

	w, _ := NewWorker(f.store, failingReverter{errBoom}, f.alerts, time.Second, nil)
	res, err := w.Sweep(ctx)
	if err == nil || !errors.Is(err, errBoom) || res != (SweepResult{}) {
		t.Fatalf("transient: %+v %v", res, err)
	}
	if status(t, f, o.OverrideID) != StatusActive {
		t.Fatal("transient failure must leave the override active")
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type LIKE 'override.restore%'`); n != 0 {
		t.Fatal("events written by a rolled-back sweep")
	}

	w, _ = NewWorker(f.store, failingReverter{fmt.Errorf("%w: schema", access.ErrInvalidProfile)}, f.alerts, time.Second, nil)
	if res, err := w.Sweep(ctx); err != nil || res.Blocked != 1 {
		t.Fatalf("permanent: %+v %v", res, err)
	}
	got, _ := f.store.Get(ctx, o.OverrideID)
	if got.Status != StatusBlocked || !strings.Contains(got.BlockedReason, "could not put back access profile v1") {
		t.Fatalf("%+v", got)
	}
}

// An alert that cannot be raised rolls the restore back (retried later).
func TestWorkerAlertFailureRollsBack(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	f.expire(t, o.OverrideID)
	f.alerts.err = errBoom
	if _, err := f.worker(t).Sweep(ctx); !errors.Is(err, errBoom) {
		t.Fatalf("got %v", err)
	}
	if status(t, f, o.OverrideID) != StatusActive {
		t.Fatal("status changed without its alert")
	}
	f.alerts.err = nil
	if res, err := f.worker(t).Sweep(ctx); err != nil || res.Restored != 1 {
		t.Fatalf("retry %+v %v", res, err)
	}
}

// Several workers sweeping at once settle each due override exactly once.
func TestWorkersConcurrentSkipLocked(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	const n = 24
	agents := []string{"code_agent_12", "code_agent_13", "code_agent_14", "finance_agent_07"}
	for i := range n {
		o := mustCreate(t, f, agentReq(agents[i%len(agents)], Systems[i%len(Systems)], ModeSuspended, time.Duration(i+1)*time.Hour))
		f.expire(t, o.OverrideID)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := SweepResult{}
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := f.worker(t).Sweep(ctx)
			if err != nil {
				t.Error(err)
			}
			mu.Lock()
			total.Restored += res.Restored
			total.Superseded += res.Superseded
			total.Blocked += res.Blocked
			mu.Unlock()
		}()
	}
	wg.Wait()
	settled := total.Restored + total.Superseded + total.Blocked
	if settled != n {
		t.Fatalf("settled %d of %d: %+v", settled, n, total)
	}
	events := f.count(t, `SELECT count(*) FROM diary WHERE event_type IN ('override.restored', 'override.superseded', 'override.restore_blocked')`)
	if events != n {
		t.Fatalf("%d settle events for %d overrides", events, n)
	}
	if left := f.count(t, `SELECT count(*) FROM access_overrides WHERE status = 'active'`); left != 0 {
		t.Fatalf("%d still active", left)
	}
	f.verifyDiary(t)
}

func TestWorkerRunStopsOnCancel(t *testing.T) {
	f := setup(t)
	o := mustCreate(t, f, agentReq("code_agent_12", "github", ModeSuspended, time.Hour))
	f.expire(t, o.OverrideID)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { f.worker(t).Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for status(t, f, o.OverrideID) != StatusRestored {
		if time.Now().After(deadline) {
			t.Fatal("Run did not restore")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}
