package containment_test

// Regression tests for the Phase 4 review findings (F1-F8, F24, F26, F27).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/memory"
	"fortik/internal/population"
	"fortik/internal/queues"
)

// F1: an instance suspend (which never revokes) must not count as having
// completed the agent suspension's revocation: a retry revokes again.
func TestRetryAfterInstanceSuspendRevokesAgain(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	e.rev.setFail("a1", true)
	op := opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"x"}`))
	if op.Status != containment.StatusPartial {
		t.Fatalf("suspend with failing revoker: %+v", op)
	}
	wantSteps(t, op, "a1", map[string]string{"revoke_credentials": "failed"})
	e.rev.setFail("a1", false)
	inst := opOf(t, e.post(t, security, "/v1/instances/a1-i1/suspend", `{"reason":"y"}`))
	if inst.Status != containment.StatusDone {
		t.Fatalf("instance suspend: %+v", inst)
	}
	retry := opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"retry"}`))
	wantSteps(t, retry, "a1", map[string]string{"mark_suspended": "skipped", "revoke_credentials": "done", "pause_queue": "done"})
	if e.rev.count("a1") != 2 {
		t.Fatalf("retry did not revoke again: %v", e.rev.all())
	}
	if d := stepsOf(retry, "a1")["revoke_credentials"].Detail; strings.Contains(d, inst.OpID) {
		t.Fatalf("retry points at the instance op: %q", d)
	}
	// Repeats after a complete run skip, pointing at the op that revoked,
	// and a repeat of a repeat still points there (not at the skipping op).
	rep := opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"again"}`))
	rep2 := opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"again"}`))
	for _, o := range []containment.Op{rep, rep2} {
		wantSteps(t, o, "a1", map[string]string{"revoke_credentials": "skipped"})
		if d := stepsOf(o, "a1")["revoke_credentials"].Detail; !strings.Contains(d, retry.OpID) {
			t.Fatalf("repeat should point at %s: %q", retry.OpID, d)
		}
	}
	if e.rev.count("a1") != 2 {
		t.Fatalf("repeats revoked again: %v", e.rev.all())
	}
}

// F2 / F24 (D1): a rollback to a snapshot replaces a whole namespace, so
// memory_restore with rollback_snapshot_id needs the security role on every
// route, and the manager refuses it to a non-security caller too.
func TestRollbackSnapshotNeedsSecurity(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "ja", "payments", "jane@acme.com", 1)
	opOf(t, e.post(t, jane, "/v1/agents/ja/memory/remove", `{"reason":"mine"}`))
	for _, c := range []struct{ path, body string }{
		{"/v1/agents/ja/memory/restore", `{"reason":"x","rollback_snapshot_id":"msnap_OTHER_TEAMS_NAMESPACE"}`},
		{"/v1/containment", `{"op":"memory_restore","target_type":"agent","target_id":"ja","reason":"x","rollback_snapshot_id":"msnap_OTHER_TEAMS_NAMESPACE"}`},
	} {
		if r := e.post(t, jane, c.path, c.body); r.code != 403 || !strings.Contains(r.raw, "security role") {
			t.Fatalf("owner rollback via %s: %d %s", c.path, r.code, r.raw)
		}
	}
	_, err := e.mgr.RunAs(context.Background(), containment.Request{Op: containment.OpMemoryRestore, TargetType: "agent", TargetID: "ja",
		Reason: "x", RollbackSnapshotID: "msnap_X"}, "", containment.Caller{Actor: "user:jane@acme.com"})
	if !errors.Is(err, containment.ErrForbidden) {
		t.Fatalf("RunAs rollback without security: %v", err)
	}
	if n := e.mem.count("rollback:msnap_OTHER_TEAMS_NAMESPACE") + e.mem.count("rollback:msnap_X"); n != 0 {
		t.Fatalf("rollback ran: %v", e.mem.all())
	}
	if n := e.count(t, `SELECT count(*) FROM containment_ops WHERE op = 'memory_restore'`); n != 0 {
		t.Fatalf("refused rollbacks recorded %d ops", n)
	}
	// The owner may still restore access without a rollback; security may roll back.
	opOf(t, e.post(t, jane, "/v1/agents/ja/memory/restore", `{"reason":"mine"}`))
	op := opOf(t, e.post(t, security, "/v1/agents/ja/memory/restore", `{"reason":"x","rollback_snapshot_id":"msnap_1"}`))
	wantSteps(t, op, "", map[string]string{"rollback_snapshot": "done"})
}

// F3: an e-stop release (or a resume) resumes only what that suspension
// paused: a copy suspended on its own stays suspended, and a QUARANTINED
// agent's queued work and copies stay paused.
func TestReleaseResumesOnlyWhatTheSuspensionPaused(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	e.agent(t, "a1", "payments", "jane@acme.com", 3)
	e.agent(t, "q1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	e.register(t, "a1", "a1-rogue")
	e.register(t, "q1", "q1-i1")
	opOf(t, e.post(t, security, "/v1/instances/a1-rogue/suspend", `{"reason":"rogue copy"}`))
	if _, err := e.ctl.SetLevel(ctx, "q1", control.Quarantined, "review", "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mgr.RevokeAll(ctx, "q1", "user:sec@acme.com", "review"); err != nil {
		t.Fatal(err)
	}
	if hb := e.heartbeat(t, "q1", "q1-i1"); hb.code != 423 {
		t.Fatalf("quarantined copy: %d", hb.code)
	}
	stop := opOf(t, e.post(t, security, "/v1/fleet/estop", `{"reason":"incident","confirm":"STOP ALL AGENTS"}`))
	rel := opOf(t, e.post(t, security, "/v1/fleet/release", `{"reason":"clear","op_id":"`+stop.OpID+`"}`))
	wantSteps(t, rel, "q1", map[string]string{"clear_suspension": "done", "resume_queue": "skipped", "resume_instances": "skipped"})
	if d := stepsOf(rel, "q1")["resume_queue"].Detail; !strings.Contains(d, "QUARANTINED") {
		t.Fatalf("quarantine skip detail: %q", d)
	}
	if hb := e.heartbeat(t, "a1", "a1-rogue"); hb.code != 423 {
		t.Fatalf("copy suspended on its own after the release: %d %s", hb.code, hb.raw)
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 200 {
		t.Fatalf("copy the e-stop suspended after the release: %d %s", hb.code, hb.raw)
	}
	if hb := e.heartbeat(t, "q1", "q1-i1"); hb.code != 423 {
		t.Fatalf("quarantined copy after the release: %d %s", hb.code, hb.raw)
	}
	if e.q.count("resume:q1") != 0 {
		t.Fatalf("quarantined queue resumed: %v", e.q.all())
	}
	if e.state(t, "q1").Level != control.Quarantined {
		t.Fatal("level changed")
	}
	// A plain resume of the (no longer suspended) QUARANTINED agent leaves
	// its work paused too.
	op := opOf(t, e.post(t, security, "/v1/agents/q1/resume", `{"reason":"x"}`))
	wantSteps(t, op, "q1", map[string]string{"clear_suspension": "skipped", "resume_queue": "skipped", "resume_instances": "skipped"})
	if hb := e.heartbeat(t, "q1", "q1-i1"); hb.code != 423 || e.q.count("resume:q1") != 0 {
		t.Fatalf("quarantined agent resumed: %d %v", hb.code, e.q.all())
	}
}

// F4: operations on one agent are serialised: a suspend issued while a
// resume is still in its queue step runs after it, so the end state is
// suspended with queues paused and copies suspended.
func TestOpsOnOneAgentAreSerialised(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"one"}`))
	g := e.q.setGate("resume")

	run := func(op string) <-chan error {
		ch := make(chan error, 1)
		go func() {
			_, err := e.mgr.Run(context.Background(), containment.Request{Op: op, TargetType: "agent", TargetID: "a1", Reason: op}, "user:sec@acme.com")
			ch <- err
		}()
		return ch
	}
	resumed := run(containment.OpResume)
	select {
	case <-g.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("resume never reached its queue step")
	}
	suspended := run(containment.OpSuspend)
	select {
	case err := <-suspended:
		t.Fatalf("suspend finished while the resume was still running (err %v)", err)
	case <-time.After(500 * time.Millisecond):
	}
	close(g.release)
	for _, ch := range []<-chan error{resumed, suspended} {
		select {
		case err := <-ch:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("operation did not finish")
		}
	}
	if !e.state(t, "a1").Suspended {
		t.Fatal("not suspended")
	}
	if got := e.q.all(); got[len(got)-1] != "pause:a1" {
		t.Fatalf("queue calls end with %v, want a final pause", got)
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 423 {
		t.Fatalf("copy after resume+suspend: %d %s", hb.code, hb.raw)
	}
}

// F5 (D4): suspending one copy does not free its copy_cap slot, and the
// step says how far a one-copy suspension reaches.
func TestSuspendedCopyKeepsItsCopyCapSlot(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	e.register(t, "a1", "a1-i1")
	op := opOf(t, e.post(t, security, "/v1/instances/a1-i1/suspend", `{"reason":"rogue"}`))
	s := stepsOf(op, "a1")
	if !strings.Contains(s["suspend_instances"].Detail, "keeps its copy_cap slot") ||
		!strings.Contains(s["revoke_credentials"].Detail, "relies on the copy's cooperation") {
		t.Fatalf("step details: %+v", op.Steps)
	}
	e.mustDeny(t, pgRead("a1", "a1-i1"), population.RuleInstance)
	r := e.registerResp(t, "a1", "a1-i2")
	if r.code != 403 || !strings.Contains(r.raw, population.RuleCopyCap) {
		t.Fatalf("fresh copy while one is suspended at copy_cap 1: %d %s", r.code, r.raw)
	}
}

// F6: the owner's resume is decided under the agent's lock, so a fleet
// e-stop that lands between the handler's checks and the resume is not
// lifted by it.
func TestOwnerResumeCannotLiftEStopThatLandsMeanwhile(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	e.agent(t, "ja", "payments", "jane@acme.com", 1)
	opOf(t, e.post(t, jane, "/v1/agents/ja/suspend", `{"reason":"mine"}`))
	before := len(e.q.all())

	conn, err := e.pool.Acquire(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended($1, 0))`, containment.LockKey("ja")); err != nil {
		t.Fatal(err)
	}
	done := make(chan resp, 1)
	go func() { done <- e.postNoFatal(jane, "/v1/agents/ja/resume", `{"reason":"mine"}`) }()
	time.Sleep(300 * time.Millisecond) // the request passed the handler's checks and waits for the lock
	if _, err := e.pool.Exec(ctx, `UPDATE agents SET suspended_by = 'estop:cop_01ARZ3NDEKTSV4RRFFQ69G5FAV' WHERE agent_id = 'ja'`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, containment.LockKey("ja")); err != nil {
		t.Fatal(err)
	}
	var r resp
	select {
	case r = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("resume did not finish")
	}
	if r.code != 403 || !strings.Contains(r.raw, "imposed by estop:cop_01ARZ3NDEKTSV4RRFFQ69G5FAV requires the security role") {
		t.Fatalf("owner resume after the e-stop landed: %d %s", r.code, r.raw)
	}
	if !e.state(t, "ja").Suspended || len(e.q.all()) != before {
		t.Fatalf("e-stop lifted: suspended=%v queue %v", e.state(t, "ja").Suspended, e.q.all())
	}
}

// F26 (D2): an owner lifts only containment they imposed themselves.
func TestOwnerLiftsOnlyOwnContainment(t *testing.T) {
	e := newEnv(t, envOpts{})
	ctx := context.Background()
	e.agent(t, "jb", "payments", "jane@acme.com", 2)
	e.register(t, "jb", "jb-i1")
	e.register(t, "jb", "jb-i2")
	want403 := func(path, by string) {
		t.Helper()
		r := e.post(t, jane, path, `{"reason":"mine"}`)
		if r.code != 403 || !strings.Contains(r.raw, "lifting a containment imposed by "+by+" requires the security role") {
			t.Fatalf("owner POST %s: %d %s", path, r.code, r.raw)
		}
	}
	mode := func() string {
		return e.str(t, `SELECT COALESCE((SELECT mode FROM memory_access WHERE agent_id = 'jb'), 'full')`)
	}

	opOf(t, e.post(t, security, "/v1/agents/jb/suspend", `{"reason":"compromise?"}`))
	want403("/v1/agents/jb/resume", "user:sec@acme.com")
	if !e.state(t, "jb").Suspended {
		t.Fatal("owner lifted security's suspension")
	}
	opOf(t, e.post(t, security, "/v1/agents/jb/resume", `{"reason":"ok"}`))

	opOf(t, e.post(t, security, "/v1/agents/jb/memory/remove", `{"reason":"poison"}`))
	want403("/v1/agents/jb/memory/restore", "user:sec@acme.com")
	if mode() != "none" {
		t.Fatal("owner lifted security's memory cut")
	}
	opOf(t, e.post(t, security, "/v1/agents/jb/memory/restore", `{"reason":"ok"}`))

	// Her own suspension and memory cut she may lift.
	opOf(t, e.post(t, jane, "/v1/agents/jb/suspend", `{"reason":"mine"}`))
	op := opOf(t, e.post(t, jane, "/v1/agents/jb/resume", `{"reason":"mine"}`))
	wantSteps(t, op, "jb", map[string]string{"clear_suspension": "done", "resume_instances": "done"})
	opOf(t, e.post(t, jane, "/v1/agents/jb/memory/remove", `{"reason":"mine"}`))
	opOf(t, e.post(t, jane, "/v1/agents/jb/memory/restore", `{"reason":"mine"}`))
	if mode() != "full" {
		t.Fatal(mode())
	}

	// A copy security suspended: not hers to resume, alone or via her
	// agent-wide suspend/resume.
	opOf(t, e.post(t, security, "/v1/instances/jb-i1/suspend", `{"reason":"rogue"}`))
	want403("/v1/instances/jb-i1/resume", "user:sec@acme.com")
	opOf(t, e.post(t, jane, "/v1/agents/jb/suspend", `{"reason":"mine"}`))
	opOf(t, e.post(t, jane, "/v1/agents/jb/resume", `{"reason":"mine"}`))
	if hb := e.heartbeat(t, "jb", "jb-i1"); hb.code != 423 {
		t.Fatalf("security's copy suspension lifted: %d", hb.code)
	}
	if hb := e.heartbeat(t, "jb", "jb-i2"); hb.code != 200 {
		t.Fatalf("her own suspension of jb-i2 not lifted: %d", hb.code)
	}

	// The level API's quarantine set memory staging_only: not hers to lift.
	if _, err := e.ctl.SetLevel(ctx, "jb", control.Quarantined, "review", "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mgr.RevokeAll(ctx, "jb", "user:sec@acme.com", "review"); err != nil {
		t.Fatal(err)
	}
	want403("/v1/agents/jb/memory/restore", "user:sec@acme.com")
	if mode() != "staging_only" {
		t.Fatal(mode())
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.resumed' AND actor = 'user:jane@acme.com'`); n != 2 {
		t.Fatalf("jane's resumes recorded: %d, want 2 (her own suspensions only)", n)
	}
}

// F7: an owner reading their agent's history sees only that agent's steps
// of team and fleet operations.
func TestOwnerHistoryShowsOnlyOwnSteps(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "jane-a", "payments", "jane@acme.com", 1)
	e.agent(t, "bob-secret-agent", "ops", "bob@acme.com", 1)
	stop := opOf(t, e.post(t, security, "/v1/fleet/estop", `{"reason":"x","confirm":"STOP ALL AGENTS"}`))
	opOf(t, e.post(t, security, "/v1/fleet/release", `{"reason":"y","op_id":"`+stop.OpID+`"}`))
	r := call(t, e.api, jane, "GET", "/v1/containment?target_type=agent&target_id=jane-a", "")
	if r.code != 200 {
		t.Fatalf("owner history: %d %s", r.code, r.raw)
	}
	if strings.Contains(r.raw, "bob-secret-agent") {
		t.Fatalf("owner history leaks another agent: %s", r.raw)
	}
	ops := r.body["operations"].([]any)
	if len(ops) != 2 {
		t.Fatalf("ops: %s", r.raw)
	}
	for _, o := range ops {
		steps := o.(map[string]any)["steps"].([]any)
		if len(steps) == 0 {
			t.Fatalf("own steps dropped: %s", r.raw)
		}
		for _, s := range steps {
			if s.(map[string]any)["agent_id"] != "jane-a" {
				t.Fatalf("foreign step: %v", s)
			}
		}
	}
	if r := call(t, e.api, auditor, "GET", "/v1/containment?target_type=agent&target_id=jane-a", ""); !strings.Contains(r.raw, "bob-secret-agent") {
		t.Fatalf("auditor sees the whole operation: %s", r.raw)
	}
}

// F8: the level API's deadline bounds the containment: a queue system that
// hangs fails its step at the deadline instead of holding the request for
// the 30s step timeout, the copies and memory are still contained, and the
// operation is recorded as finished.
func TestLevelAPIKeepsItsDeadline(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	e.register(t, "a1", "a1-i1")
	e.q.setGate("cancel") // never released
	if _, err := e.ctl.SetLevel(context.Background(), "a1", control.Killed, "compromise", "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	res, err := e.mgr.RevokeAll(ctx, "a1", "user:sec@acme.com", "compromise")
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("RevokeAll took %s with a 1s deadline", el)
	}
	if err == nil || !strings.Contains(err.Error(), "cancel_queue") {
		t.Fatalf("err: %v", err)
	}
	op, gerr := e.mgr.Get(context.Background(), res[containment.ResultKeyOp])
	if gerr != nil || op.FinishedAt == nil || op.Status != containment.StatusPartial {
		t.Fatalf("op: %v %+v", gerr, op)
	}
	wantSteps(t, op, "a1", map[string]string{"revoke_credentials": "done", "cancel_queue": "failed", "stop_instances": "done", "set_memory_access": "done"})
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 410 {
		t.Fatalf("copy after kill: %d", hb.code)
	}
}

// F27 (D3): reasons may span lines (\n, \t) up to 1000 bytes; other
// control characters are refused.
func TestReasonsAllowNewlinesUpTo1000Bytes(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "j1", "payments", "jane@acme.com", 1)
	op := opOf(t, e.post(t, jane, "/v1/agents/j1/suspend", `{"reason":"line one\nline two\tindented"}`))
	if op.Reason != "line one\nline two\tindented" {
		t.Fatalf("reason: %q", op.Reason)
	}
	long := strings.Repeat("x", 1000)
	opOf(t, e.post(t, jane, "/v1/agents/j1/resume", fmt.Sprintf(`{"reason":%q}`, long)))
	for _, bad := range []string{strings.Repeat("x", 1001), "a\u0007b", "a\rb", "a\u0000b"} {
		if r := e.post(t, jane, "/v1/agents/j1/suspend", fmt.Sprintf(`{"reason":%q}`, bad)); r.code != 400 {
			t.Fatalf("reason %q: %d %s", bad, r.code, r.raw)
		}
	}
	// Team ids stay single-line.
	if r := e.post(t, security, "/v1/teams/a%0Ab/suspend", `{"reason":"x"}`); r.code != 400 {
		t.Fatalf("team id with newline: %d %s", r.code, r.raw)
	}
}

// A failed queue step keeps what the adapter reports it did (Result.Detail)
// beside the error; a configured integration whose secret is missing, or a
// run truncated at a cap, is a FAILED step (only ErrNotConfigured skips).
func TestFailedQueueStepKeepsAdapterDetail(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	e.agent(t, "a2", "payments", "jane@acme.com", 1)
	e.q.mu.Lock()
	e.q.failDetail = map[string]string{"pause": "temporal: only the first 10000 workflows were signalled, the rest were NOT"}
	e.q.mu.Unlock()
	e.q.setFail("pause", fmt.Errorf("%w: 10000 workflow cap", queues.ErrTruncated))
	op := opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"x"}`))
	s := stepsOf(op, "a1")["pause_queue"]
	if s.Status != containment.StepFailed || !strings.Contains(s.Detail, "pause FAILED") ||
		!strings.Contains(s.Detail, "only the first 10000 workflows were signalled, the rest were NOT") {
		t.Fatalf("truncated pause step: %+v", s)
	}
	if op.Status != containment.StatusPartial {
		t.Fatalf("op status %s", op.Status)
	}
	e.q.setFail("pause", queues.ErrSecretMissing)
	op = opOf(t, e.post(t, security, "/v1/agents/a2/suspend", `{"reason":"x"}`))
	if s := stepsOf(op, "a2")["pause_queue"]; s.Status != containment.StepFailed {
		t.Fatalf("secret-missing pause step: %+v", s)
	}
}

// memory_restore names the writes held for review (they are not promoted
// at once when access returns to full), and a rollback to a snapshot that
// is not clean is a failed step that leaves access unchanged.
func TestMemoryRestoreReportsHeldWritesAndUncleanSnapshot(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	opOf(t, e.post(t, security, "/v1/agents/a1/memory/remove", `{"reason":"poison","memory_mode":"staging_only"}`))

	op := opOf(t, e.post(t, security, "/v1/agents/a1/memory/restore", `{"reason":"x","rollback_snapshot_id":"msnap_dirty1"}`))
	s := stepsOf(op, "")["rollback_snapshot"]
	if s.Status != containment.StepFailed || !strings.Contains(s.Detail, "msnap_dirty1 is not clean") || !strings.Contains(s.Detail, "NOT rolled back") {
		t.Fatalf("unclean rollback step: %+v", s)
	}
	wantSteps(t, op, "a1", map[string]string{"set_memory_access": "skipped"})
	if mode := e.str(t, `SELECT mode FROM memory_access WHERE agent_id = 'a1'`); mode != "staging_only" {
		t.Fatalf("access changed after a refused rollback: %s", mode)
	}

	e.mem.mu.Lock()
	e.mem.held = map[string][]memory.StagedItem{"a1": {
		{Store: "kb", Namespace: "support", ID: "mem_1"}, {Store: "kb", Namespace: "support", ID: "mem_2"},
	}}
	e.mem.mu.Unlock()
	op = opOf(t, e.post(t, security, "/v1/agents/a1/memory/restore", `{"reason":"cleared"}`))
	d := stepsOf(op, "a1")["set_memory_access"]
	if d.Status != containment.StepDone || !strings.Contains(d.Detail, "2 writes made during the memory cut") ||
		!strings.Contains(d.Detail, "kb/support/mem_1, kb/support/mem_2") {
		t.Fatalf("restore step: %+v", d)
	}
}
