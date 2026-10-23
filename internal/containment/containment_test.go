package containment_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"fortik/internal/api"
	"fortik/internal/authz"
	"fortik/internal/broker"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/memory"
	"fortik/internal/population"
)

// The real implementations satisfy the interfaces the manager depends on,
// and the manager satisfies the level API's Revoker.
var (
	_ containment.CredentialRevoker = (*broker.Service)(nil)
	_ containment.MemoryAccess      = (*memory.Service)(nil)
	_ containment.Instances         = (*population.InstanceControl)(nil)
	_ api.Revoker                   = (*containment.Manager)(nil)
	_ containment.Service           = (*containment.Manager)(nil)
)

// Suspend -> every action refused (POL-016), credentials revoked, queues
// paused, copies told to pause (423); a second suspend is a no-op; resume
// -> actions allowed, queues resumed, copies live.
func TestSuspendResumeAgent(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 3)
	e.register(t, "a1", "a1-i1")
	e.register(t, "a1", "a1-i2")
	e.mustAllow(t, pgRead("a1", ""))

	op := opOf(t, e.post(t, jane, "/v1/agents/a1/suspend", `{"reason":"odd export pattern"}`))
	if op.Status != containment.StatusDone || op.Op != containment.OpSuspend || op.Actor != "user:jane@acme.com" || op.FinishedAt == nil {
		t.Fatalf("suspend op: %+v", op)
	}
	wantSteps(t, op, "a1", map[string]string{"mark_suspended": "done", "revoke_credentials": "done", "pause_queue": "done", "suspend_instances": "done"})
	if d := stepsOf(op, "a1")["revoke_credentials"].Detail; !strings.Contains(d, "github: installation tokens revoked") || !strings.Contains(d, "postgres: role") {
		t.Fatalf("revoke detail should carry the broker's per-system descriptions: %q", d)
	}
	if d := stepsOf(op, "a1")["pause_queue"].Detail; !strings.Contains(d, "temporal: 2 affected") {
		t.Fatalf("pause detail: %q", d)
	}
	order := []string{}
	for _, s := range op.Steps {
		order = append(order, s.Name)
	}
	if strings.Join(order, ",") != "mark_suspended,revoke_credentials,pause_queue,suspend_instances" {
		t.Fatalf("step order: %v", order)
	}
	if !e.state(t, "a1").Suspended {
		t.Fatal("agent not suspended")
	}
	e.mustDeny(t, pgRead("a1", ""), "POL-016")
	e.mustDeny(t, externalSend("a1"), "POL-016")
	for _, id := range []string{"a1-i1", "a1-i2"} {
		hb := e.heartbeat(t, "a1", id)
		if hb.code != 423 || hb.body["action"] != "pause" || hb.body["reason"] == "" {
			t.Fatalf("heartbeat %s: %d %s", id, hb.code, hb.raw)
		}
	}
	if e.rev.count("a1") != 1 || e.q.count("pause:a1") != 1 {
		t.Fatalf("revoker %v queue %v", e.rev.all(), e.q.all())
	}
	if n := e.count(t, `SELECT count(*) FROM containment_ops WHERE op = 'suspend' AND status = 'done'`); n != 1 {
		t.Fatalf("ops = %d", n)
	}
	ev := e.diaryData(t, "containment.suspend")
	if len(ev) != 1 || ev[0]["op_id"] != op.OpID || ev[0]["reason"] != "odd export pattern" || len(ev[0]["steps"].([]any)) != 4 {
		t.Fatalf("containment.suspend events: %+v", ev)
	}

	// Idempotent: a second suspend changes nothing and repeats no external step.
	op2 := opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"again"}`))
	wantSteps(t, op2, "a1", map[string]string{"mark_suspended": "skipped", "revoke_credentials": "skipped", "pause_queue": "skipped", "suspend_instances": "skipped"})
	if op2.Status != containment.StatusDone {
		t.Fatalf("second suspend: %+v", op2)
	}
	if e.rev.count("a1") != 1 || e.q.count("pause:a1") != 1 {
		t.Fatalf("second suspend repeated external steps: revoker %v queue %v", e.rev.all(), e.q.all())
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.suspended'`); n != 1 {
		t.Fatalf("agent.suspended events = %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'instance.suspended'`); n != 2 {
		t.Fatalf("instance.suspended events = %d", n)
	}
	if e.str(t, `SELECT suspended_reason FROM agents WHERE agent_id = 'a1'`) != "odd export pattern" {
		t.Fatal("second suspend overwrote the reason")
	}

	// Resume.
	op3 := opOf(t, e.post(t, jane, "/v1/agents/a1/resume", `{"reason":"cleared"}`))
	wantSteps(t, op3, "a1", map[string]string{"clear_suspension": "done", "resume_queue": "done", "resume_instances": "done"})
	if e.state(t, "a1").Suspended {
		t.Fatal("still suspended")
	}
	e.mustAllow(t, pgRead("a1", ""))
	if e.q.count("resume:a1") != 1 {
		t.Fatalf("queue %v", e.q.all())
	}
	for _, id := range []string{"a1-i1", "a1-i2"} {
		if hb := e.heartbeat(t, "a1", id); hb.code != 200 {
			t.Fatalf("heartbeat %s after resume: %d %s", id, hb.code, hb.raw)
		}
	}
	// Resume again: nothing to clear.
	op4 := opOf(t, e.post(t, jane, "/v1/agents/a1/resume", `{"reason":"again"}`))
	wantSteps(t, op4, "a1", map[string]string{"clear_suspension": "skipped", "resume_instances": "skipped"})
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.resumed'`); n != 1 {
		t.Fatalf("agent.resumed events = %d", n)
	}
	// After resume a new suspension runs the external steps again.
	opOf(t, e.post(t, jane, "/v1/agents/a1/suspend", `{"reason":"second incident"}`))
	if e.rev.count("a1") != 2 || e.q.count("pause:a1") != 2 {
		t.Fatalf("new suspension did not revoke/pause: revoker %v queue %v", e.rev.all(), e.q.all())
	}
}

// Concurrent suspends of one agent produce one suspension.
func TestConcurrentSuspendIsIdempotent(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	var wg sync.WaitGroup
	errs := make(chan error, 6)
	for range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := e.mgr.Run(context.Background(), containment.Request{Op: "suspend", TargetType: "agent", TargetID: "a1", Reason: "race"}, "user:sec@acme.com")
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.suspended'`); n != 1 {
		t.Fatalf("agent.suspended = %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM diary WHERE event_type = 'instance.suspended'`); n != 1 {
		t.Fatalf("instance.suspended = %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM containment_ops WHERE status = 'running'`); n != 0 {
		t.Fatalf("running ops left: %d", n)
	}
}

// Isolate: level ISOLATED, external send refused, copies over the cap paused.
func TestIsolate(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	e.register(t, "a1", "a1-i2")
	if _, err := e.pool.Exec(context.Background(), `UPDATE agents SET copy_cap = 1 WHERE agent_id = 'a1'`); err != nil {
		t.Fatal(err)
	}
	op := opOf(t, e.post(t, jane, "/v1/agents/a1/isolate", `{"reason":"suspicious egress"}`))
	wantSteps(t, op, "a1", map[string]string{"set_level": "done", "revoke_credentials": "done", "pause_extra_copies": "done"})
	if st := e.state(t, "a1"); st.Level != control.Isolated || st.Suspended {
		t.Fatalf("state: %+v", st)
	}
	e.mustDeny(t, externalSend("a1"), "POL-012")
	e.mustAllow(t, pgRead("a1", ""))
	if hb := e.heartbeat(t, "a1", "a1-i2"); hb.code != 410 {
		t.Fatalf("newest copy above the cap: %d %s", hb.code, hb.raw)
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 200 {
		t.Fatalf("copy within the cap: %d %s", hb.code, hb.raw)
	}
	// Repeat: level unchanged (never loosened), revocation not repeated.
	op2 := opOf(t, e.post(t, jane, "/v1/agents/a1/isolate", `{"reason":"again"}`))
	wantSteps(t, op2, "a1", map[string]string{"set_level": "skipped", "revoke_credentials": "skipped", "pause_extra_copies": "skipped"})
	if e.rev.count("a1") != 1 {
		t.Fatalf("revoker %v", e.rev.all())
	}
	// Isolating a QUARANTINED agent never loosens it.
	e.agent(t, "a2", "payments", "jane@acme.com", 1)
	if _, err := e.ctl.SetLevel(context.Background(), "a2", control.Quarantined, "review", "test"); err != nil {
		t.Fatal(err)
	}
	op3 := opOf(t, e.post(t, security, "/v1/agents/a2/isolate", `{"reason":"x"}`))
	wantSteps(t, op3, "a2", map[string]string{"set_level": "skipped"})
	if e.state(t, "a2").Level != control.Quarantined {
		t.Fatal("isolate loosened QUARANTINED")
	}
}

// Kill: KILLED, revoke, queue cancel, DB sessions, copies stopped (410),
// memory none, sealed in containment.kill with every step.
func TestKill(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	e.register(t, "a1", "a1-i2")

	if r := e.post(t, jane, "/v1/agents/a1/kill", `{"reason":"mine"}`); r.code != 403 {
		t.Fatalf("owner kill: %d %s", r.code, r.raw)
	}
	op := opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"exfiltration confirmed"}`))
	if op.Status != containment.StatusDone {
		t.Fatalf("kill: %+v", op)
	}
	wantSteps(t, op, "a1", map[string]string{"set_level": "done", "revoke_credentials": "done", "cancel_queue": "done",
		"terminate_db_sessions": "done", "stop_instances": "done", "set_memory_access": "done"})
	wantSteps(t, op, "", map[string]string{"seal": "done"})
	if d := stepsOf(op, "a1")["terminate_db_sessions"].Detail; !strings.Contains(d, "session terminated") {
		t.Fatalf("terminate detail: %q", d)
	}
	if st := e.state(t, "a1"); st.Level != control.Killed {
		t.Fatalf("level %s", st.Level)
	}
	e.mustDeny(t, pgRead("a1", ""), "POL-010")
	for _, id := range []string{"a1-i1", "a1-i2"} {
		if hb := e.heartbeat(t, "a1", id); hb.code != 410 {
			t.Fatalf("heartbeat %s after kill: %d %s", id, hb.code, hb.raw)
		}
	}
	if e.str(t, `SELECT mode FROM memory_access WHERE agent_id = 'a1'`) != "none" {
		t.Fatal("memory access not none")
	}
	if e.rev.count("a1") != 1 || e.q.count("cancel:a1") != 1 || e.q.count("pause:a1") != 0 {
		t.Fatalf("revoker %v queue %v", e.rev.all(), e.q.all())
	}
	ev := e.diaryData(t, "containment.kill")
	if len(ev) != 1 || ev[0]["status"] != "done" {
		t.Fatalf("containment.kill: %+v", ev)
	}
	var names []string
	for _, s := range ev[0]["steps"].([]any) {
		names = append(names, s.(map[string]any)["name"].(string))
	}
	if strings.Join(names, ",") != "set_level,revoke_credentials,cancel_queue,terminate_db_sessions,stop_instances,set_memory_access,seal" {
		t.Fatalf("sealed steps: %v", names)
	}
	// Resume after kill is refused; re-enable is the level API.
	if r := e.post(t, security, "/v1/agents/a1/resume", `{"reason":"oops"}`); r.code != 409 {
		t.Fatalf("resume after kill: %d %s", r.code, r.raw)
	}
	if r := e.post(t, security, "/v1/agents/a1/memory/restore", `{"reason":"oops"}`); r.code != 409 {
		t.Fatalf("memory restore after kill: %d %s", r.code, r.raw)
	}
	// Kill again: nothing repeated.
	op2 := opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"again"}`))
	wantSteps(t, op2, "a1", map[string]string{"set_level": "skipped", "revoke_credentials": "skipped", "cancel_queue": "skipped",
		"terminate_db_sessions": "skipped", "stop_instances": "skipped", "set_memory_access": "skipped"})
	if e.rev.count("a1") != 1 || e.q.count("cancel:a1") != 1 {
		t.Fatalf("second kill repeated steps: revoker %v queue %v", e.rev.all(), e.q.all())
	}
}

// Team operations cover every agent of the business unit (security only).
func TestTeamSuspendResumeKill(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, id := range []string{"t1", "t2", "t3"} {
		e.agent(t, id, "payments", "jane@acme.com", 1)
	}
	e.agent(t, "o1", "ops", "jane@acme.com", 1)

	if r := e.post(t, jane, "/v1/teams/payments/suspend", `{"reason":"x"}`); r.code != 403 {
		t.Fatalf("owner team suspend: %d %s", r.code, r.raw)
	}
	if r := e.post(t, security, "/v1/teams/nobody/suspend", `{"reason":"x"}`); r.code != 404 {
		t.Fatalf("unknown team: %d %s", r.code, r.raw)
	}
	op := opOf(t, e.post(t, security, "/v1/teams/payments/suspend", `{"reason":"team incident"}`))
	if op.TargetType != "team" || op.TargetID != "payments" || op.Status != "done" {
		t.Fatalf("team op: %+v", op)
	}
	for _, id := range []string{"t1", "t2", "t3"} {
		wantSteps(t, op, id, map[string]string{"mark_suspended": "done", "revoke_credentials": "done", "pause_queue": "done"})
		if !e.state(t, id).Suspended {
			t.Fatalf("%s not suspended", id)
		}
		e.mustDeny(t, pgRead(id, ""), "POL-016")
	}
	if e.state(t, "o1").Suspended {
		t.Fatal("other team suspended")
	}
	e.mustAllow(t, pgRead("o1", ""))
	ev := e.diaryData(t, "containment.suspend")
	if len(ev) != 1 || len(ev[0]["agents"].([]any)) != 3 {
		t.Fatalf("team event: %+v", ev)
	}

	opOf(t, e.post(t, security, "/v1/teams/payments/resume", `{"reason":"done"}`))
	for _, id := range []string{"t1", "t2", "t3"} {
		e.mustAllow(t, pgRead(id, ""))
	}
	if r := e.post(t, jane, "/v1/teams/payments/kill", `{"reason":"x"}`); r.code != 403 {
		t.Fatalf("owner team kill: %d", r.code)
	}
	opOf(t, e.post(t, security, "/v1/teams/payments/kill", `{"reason":"compromised team"}`))
	for _, id := range []string{"t1", "t2", "t3"} {
		if e.state(t, id).Level != control.Killed {
			t.Fatalf("%s not killed", id)
		}
	}
	if e.state(t, "o1").Level == control.Killed {
		t.Fatal("other team killed")
	}
}

// E-stop suspends every agent; release resumes only the agents that e-stop
// suspended.
func TestEStopAndRelease(t *testing.T) {
	e := newEnv(t, envOpts{})
	for _, id := range []string{"a", "b", "c", "k"} {
		e.agent(t, id, "payments", "jane@acme.com", 1)
	}
	if _, err := e.ctl.SetLevel(context.Background(), "k", control.Killed, "dead", "test"); err != nil {
		t.Fatal(err)
	}
	opOf(t, e.post(t, jane, "/v1/agents/b/suspend", `{"reason":"separate incident"}`))

	if r := e.post(t, security, "/v1/fleet/estop", `{"reason":"x"}`); r.code != 400 {
		t.Fatalf("estop without confirm: %d %s", r.code, r.raw)
	}
	if r := e.post(t, security, "/v1/fleet/estop", `{"reason":"x","confirm":"stop all agents"}`); r.code != 400 {
		t.Fatalf("estop with wrong confirm: %d %s", r.code, r.raw)
	}
	if r := e.post(t, jane, "/v1/fleet/estop", `{"reason":"x","confirm":"STOP ALL AGENTS"}`); r.code != 403 {
		t.Fatalf("owner estop: %d %s", r.code, r.raw)
	}
	if _, err := e.mgr.Run(context.Background(), containment.Request{Op: "estop", TargetType: "fleet", Reason: "x"}, "user:sec@acme.com"); !errors.Is(err, containment.ErrConfirmRequired) {
		t.Fatalf("Run estop without confirm: %v", err)
	}
	op := opOf(t, e.post(t, security, "/v1/containment", `{"op":"estop","target_type":"fleet","target_id":"fleet","reason":"incident","confirm":"STOP ALL AGENTS"}`))
	wantSteps(t, op, "a", map[string]string{"mark_suspended": "done"})
	wantSteps(t, op, "c", map[string]string{"mark_suspended": "done"})
	wantSteps(t, op, "b", map[string]string{"mark_suspended": "skipped"})
	wantSteps(t, op, "k", map[string]string{"mark_suspended": "skipped"})
	for _, id := range []string{"a", "b", "c"} {
		e.mustDeny(t, pgRead(id, ""), "POL-016")
	}
	marker := "estop:" + op.OpID
	if e.str(t, `SELECT suspended_by FROM agents WHERE agent_id = 'a'`) != marker {
		t.Fatal("e-stop marker missing")
	}
	if e.str(t, `SELECT suspended_by FROM agents WHERE agent_id = 'b'`) != "user:jane@acme.com" {
		t.Fatal("separate suspension overwritten")
	}
	// The owner cannot lift an e-stop suspension.
	if r := e.post(t, jane, "/v1/agents/a/resume", `{"reason":"mine"}`); r.code != 403 {
		t.Fatalf("owner resume of e-stopped agent: %d %s", r.code, r.raw)
	}
	// c is resumed by security and suspended again separately: release must leave it.
	opOf(t, e.post(t, security, "/v1/agents/c/resume", `{"reason":"checked"}`))
	opOf(t, e.post(t, security, "/v1/agents/c/suspend", `{"reason":"new finding"}`))

	if r := e.post(t, jane, "/v1/fleet/release", `{"reason":"x","op_id":"`+op.OpID+`"}`); r.code != 403 {
		t.Fatalf("owner release: %d", r.code)
	}
	if r := e.post(t, security, "/v1/fleet/release", `{"reason":"x","op_id":"cop_01ARZ3NDEKTSV4RRFFQ69G5FAV"}`); r.code != 404 {
		t.Fatalf("release of unknown op: %d %s", r.code, r.raw)
	}
	rel := opOf(t, e.post(t, security, "/v1/fleet/release", `{"reason":"all clear","op_id":"`+op.OpID+`"}`))
	if rel.Op != containment.OpEStopRelease || rel.TargetID != op.OpID {
		t.Fatalf("release op: %+v", rel)
	}
	wantSteps(t, rel, "a", map[string]string{"clear_suspension": "done"})
	e.mustAllow(t, pgRead("a", ""))
	for _, id := range []string{"b", "c"} {
		if !e.state(t, id).Suspended {
			t.Fatalf("%s resumed by the e-stop release", id)
		}
		e.mustDeny(t, pgRead(id, ""), "POL-016")
	}
	if e.state(t, "k").Level != control.Killed {
		t.Fatal("killed agent changed")
	}
	// Releasing again finds nothing.
	rel2 := opOf(t, e.post(t, security, "/v1/fleet/release", `{"reason":"again"}`))
	if len(rel2.Steps) != 0 || rel2.Status != "done" {
		t.Fatalf("second release: %+v", rel2)
	}
}

// Owners may suspend/resume/isolate/memory their own agents; nothing else.
func TestRolesAndValidation(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "j1", "payments", "jane@acme.com", 1)
	e.agent(t, "b1", "payments", "bob@acme.com", 1)
	e.register(t, "j1", "j1-i1")

	for _, c := range []struct {
		who  string
		path string
		body string
		code int
	}{
		{"jane", "/v1/agents/b1/suspend", `{"reason":"x"}`, 403},
		{"jane", "/v1/agents/ghost/suspend", `{"reason":"x"}`, 403},
		{"sec", "/v1/agents/ghost/suspend", `{"reason":"x"}`, 404},
		{"jane", "/v1/agents/j1/kill", `{"reason":"x"}`, 403},
		{"jane", "/v1/agents/j1/queue/cancel", `{"reason":"x"}`, 403},
		{"jane", "/v1/teams/payments/resume", `{"reason":"x"}`, 403},
		{"jane", "/v1/fleet/release", `{"reason":"x"}`, 403},
		{"auditor", "/v1/agents/j1/suspend", `{"reason":"x"}`, 403},
		{"none", "/v1/agents/j1/suspend", `{"reason":"x"}`, 401},
		{"jane", "/v1/agents/j1/suspend", `{}`, 400},
		{"jane", "/v1/agents/j1/suspend", `{"reason":"  "}`, 400},
		{"jane", "/v1/agents/j1/suspend", `{"reason":"x","extra":1}`, 400},
		{"jane", "/v1/agents/j1/suspend", `{"reason":"x"} {}`, 400},
		{"jane", "/v1/agents/j1/suspend", `{"reason":"a\u0007b"}`, 400},
		{"sec", "/v1/containment", `{"op":"kill","target_type":"instance","target_id":"j1-i1","reason":"x"}`, 400},
		{"sec", "/v1/containment", `{"op":"explode","target_type":"agent","target_id":"j1","reason":"x"}`, 400},
		{"sec", "/v1/containment", `{"op":"suspend","target_type":"agent","target_id":"j1","reason":"x","memory_mode":"none"}`, 400},
		{"jane", "/v1/agents/j1/memory/remove", `{"reason":"x","memory_mode":"partial"}`, 400},
		{"bob", "/v1/instances/j1-i1/suspend", `{"reason":"x"}`, 403},
		{"jane", "/v1/agents/j1/isolate", `{"reason":"mine"}`, 200},
		{"jane", "/v1/agents/j1/suspend", `{"reason":"mine"}`, 200},
		{"jane", "/v1/agents/j1/resume", `{"reason":"mine"}`, 200},
		{"jane", "/v1/agents/j1/memory/remove", `{"reason":"mine","memory_mode":"staging_only"}`, 200},
		{"jane", "/v1/agents/j1/memory/restore", `{"reason":"mine"}`, 200},
		{"jane", "/v1/containment", `{"op":"suspend","target_type":"agent","target_id":"j1","reason":"generic"}`, 200},
		{"jane", "/v1/containment", `{"op":"suspend","target_type":"team","target_id":"payments","reason":"generic"}`, 403},
	} {
		var p *authz.Principal
		switch c.who {
		case "jane":
			p = jane
		case "bob":
			p = bob
		case "sec":
			p = security
		case "auditor":
			p = auditor
		}
		r := e.post(t, p, c.path, c.body)
		if r.code != c.code {
			t.Fatalf("%s POST %s %s: %d %s, want %d", c.who, c.path, c.body, r.code, r.raw, c.code)
		}
	}
	// Refused requests recorded nothing.
	if n := e.count(t, `SELECT count(*) FROM containment_ops WHERE target_id IN ('b1', 'ghost', 'payments')`); n != 0 {
		t.Fatalf("refused requests recorded %d ops", n)
	}
}
