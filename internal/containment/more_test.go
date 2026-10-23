package containment_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"fortik/internal/containment"
	"fortik/internal/population"
	"fortik/internal/queues"
)

// Failed steps make the operation partial (or failed), say what did not
// happen, and are retried by the next run; nothing is claimed that did not
// happen.
func TestStepFailuresArePartialAndRetried(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	e.register(t, "a1", "a1-i1")
	e.rev.setFail("a1", true)
	e.q.setFail("cancel", errors.New("temporal frontend unreachable"))

	op := opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"compromise"}`))
	if op.Status != containment.StatusPartial {
		t.Fatalf("status %s, want partial: %+v", op.Status, op.Steps)
	}
	wantSteps(t, op, "a1", map[string]string{"set_level": "done", "revoke_credentials": "failed", "cancel_queue": "failed",
		"terminate_db_sessions": "done", "stop_instances": "done", "set_memory_access": "done"})
	s := stepsOf(op, "a1")
	if d := s["revoke_credentials"].Detail; !strings.HasPrefix(d, "revocation incomplete: ") || !strings.Contains(d, "github: revocation FAILED: github unreachable") {
		t.Fatalf("revoke detail: %q", d)
	}
	if d := s["cancel_queue"].Detail; d != "temporal: cancel FAILED: temporal frontend unreachable" {
		t.Fatalf("cancel detail: %q", d)
	}
	if ev := e.diaryData(t, "containment.kill"); len(ev) != 1 || ev[0]["status"] != "partial" {
		t.Fatalf("diary: %+v", ev)
	}

	// Retry after the failures are fixed: the failed external steps run again.
	e.rev.setFail("a1", false)
	e.q.setFail("cancel", nil)
	op2 := opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"retry"}`))
	wantSteps(t, op2, "a1", map[string]string{"set_level": "skipped", "revoke_credentials": "done", "cancel_queue": "done", "stop_instances": "skipped"})
	if op2.Status != containment.StatusDone || e.rev.count("a1") != 2 || e.q.count("cancel:a1") != 2 {
		t.Fatalf("retry: %s revoker %v queue %v", op2.Status, e.rev.all(), e.q.all())
	}
	// And then nothing is repeated.
	opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"again"}`))
	if e.rev.count("a1") != 2 {
		t.Fatalf("revoker %v", e.rev.all())
	}

	// Queue pause failure on suspend: the suspension holds; status partial.
	e.agent(t, "a2", "payments", "jane@acme.com", 1)
	e.q.setFail("pause", errors.New("redis down"))
	op3 := opOf(t, e.post(t, security, "/v1/agents/a2/suspend", `{"reason":"x"}`))
	if op3.Status != containment.StatusPartial || !e.state(t, "a2").Suspended {
		t.Fatalf("suspend with queue failure: %+v", op3)
	}
	// A repeat retries the failed queue pause (and the revocation of that run).
	e.q.setFail("pause", nil)
	op4 := opOf(t, e.post(t, security, "/v1/agents/a2/suspend", `{"reason":"retry"}`))
	wantSteps(t, op4, "a2", map[string]string{"mark_suspended": "skipped", "pause_queue": "done"})
	if e.q.count("pause:a2") != 2 {
		t.Fatalf("queue %v", e.q.all())
	}
	e.q.setFail("pause", queues.ErrNotConfigured)
	e.agent(t, "a3", "payments", "jane@acme.com", 1)
	op5 := opOf(t, e.post(t, security, "/v1/agents/a3/suspend", `{"reason":"x"}`))
	wantSteps(t, op5, "a3", map[string]string{"pause_queue": "skipped"})
	if op5.Status != containment.StatusDone {
		t.Fatalf("not-configured queue must not fail the op: %+v", op5)
	}
}

// Without memory protection or queue systems the steps say so honestly:
// memory steps fail (access NOT changed), queue steps are skipped.
func TestUnconfiguredSystems(t *testing.T) {
	e := newEnv(t, envOpts{noQueues: true, noMemory: true})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	op := opOf(t, e.post(t, jane, "/v1/agents/a1/memory/remove", `{"reason":"poisoned"}`))
	if op.Status != containment.StatusFailed {
		t.Fatalf("memory remove without memory protection: %+v", op)
	}
	if d := stepsOf(op, "a1")["set_memory_access"].Detail; !strings.Contains(d, "NOT changed") {
		t.Fatalf("detail: %q", d)
	}
	op2 := opOf(t, e.post(t, security, "/v1/agents/a1/kill", `{"reason":"x"}`))
	wantSteps(t, op2, "a1", map[string]string{"cancel_queue": "skipped", "set_memory_access": "failed", "revoke_credentials": "done"})
	if op2.Status != containment.StatusPartial {
		t.Fatalf("kill: %s", op2.Status)
	}
}

// Memory remove (none / staging_only, never loosened) and restore (with an
// optional rollback; a failed rollback leaves access unchanged).
func TestMemoryRemoveRestore(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 1)
	e.agent(t, "a2", "payments", "bob@acme.com", 1)
	mode := func(id string) string {
		return e.str(t, `SELECT COALESCE((SELECT mode FROM memory_access WHERE agent_id = $1), 'full')`, id)
	}
	op := opOf(t, e.post(t, jane, "/v1/agents/a1/memory/remove", `{"reason":"suspect writes","memory_mode":"staging_only"}`))
	wantSteps(t, op, "a1", map[string]string{"set_memory_access": "done", "revoke_memory_credentials": "skipped"})
	if mode("a1") != "staging_only" {
		t.Fatal(mode("a1"))
	}
	opOf(t, e.post(t, jane, "/v1/agents/a1/memory/remove", `{"reason":"worse"}`)) // default none
	if mode("a1") != "none" {
		t.Fatal(mode("a1"))
	}
	op = opOf(t, e.post(t, jane, "/v1/agents/a1/memory/remove", `{"reason":"x","memory_mode":"staging_only"}`))
	wantSteps(t, op, "a1", map[string]string{"set_memory_access": "skipped"})
	if mode("a1") != "none" {
		t.Fatal("memory_remove loosened none")
	}
	// Team memory cut.
	opOf(t, e.post(t, security, "/v1/containment", `{"op":"memory_remove","target_type":"team","target_id":"payments","reason":"poison","memory_mode":"none"}`))
	if mode("a2") != "none" {
		t.Fatal(mode("a2"))
	}

	// Restore with a failing rollback: access stays none.
	e.mem.setFail(true)
	op = opOf(t, e.post(t, security, "/v1/agents/a1/memory/restore", `{"reason":"clean","rollback_snapshot_id":"msnap_1"}`))
	wantSteps(t, op, "", map[string]string{"rollback_snapshot": "failed"})
	wantSteps(t, op, "a1", map[string]string{"set_memory_access": "skipped"})
	if op.Status != containment.StatusFailed || mode("a1") != "none" {
		t.Fatalf("failed rollback: %s %s", op.Status, mode("a1"))
	}
	e.mem.setFail(false)
	op = opOf(t, e.post(t, security, "/v1/agents/a1/memory/restore", `{"reason":"clean","rollback_snapshot_id":"msnap_1"}`))
	wantSteps(t, op, "", map[string]string{"rollback_snapshot": "done"})
	wantSteps(t, op, "a1", map[string]string{"set_memory_access": "done"})
	if mode("a1") != "full" || e.mem.count("rollback:msnap_1") != 2 {
		t.Fatalf("restore: %s %v", mode("a1"), e.mem.all())
	}
	if n := len(e.diaryData(t, "containment.memory_restore")); n != 2 {
		t.Fatalf("memory_restore events: %d", n)
	}
}

// One copy can be suspended and resumed; its siblings keep working.
func TestInstanceSuspendResume(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "a1", "payments", "jane@acme.com", 2)
	e.register(t, "a1", "a1-i1")
	e.register(t, "a1", "a1-i2")

	if r := e.post(t, security, "/v1/instances/nope/suspend", `{"reason":"x"}`); r.code != 404 {
		t.Fatalf("unknown instance: %d", r.code)
	}
	op := opOf(t, e.post(t, jane, "/v1/instances/a1-i1/suspend", `{"reason":"looping"}`))
	if op.TargetType != "instance" || op.TargetID != "a1-i1" {
		t.Fatalf("op: %+v", op)
	}
	wantSteps(t, op, "a1", map[string]string{"suspend_instances": "done", "revoke_credentials": "skipped", "pause_queue": "skipped"})
	if e.rev.count("a1") != 0 || len(e.q.all()) != 0 {
		t.Fatal("one-copy suspend touched agent-wide credentials or queues")
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 423 || hb.body["action"] != "pause" {
		t.Fatalf("suspended copy: %d %s", hb.code, hb.raw)
	}
	if hb := e.heartbeat(t, "a1", "a1-i2"); hb.code != 200 {
		t.Fatalf("sibling: %d %s", hb.code, hb.raw)
	}
	e.mustDeny(t, pgRead("a1", "a1-i1"), population.RuleInstance)
	e.mustAllow(t, pgRead("a1", "a1-i2"))
	if e.state(t, "a1").Suspended {
		t.Fatal("agent suspended by a copy suspension")
	}

	// A copy of a suspended agent cannot be resumed alone.
	opOf(t, e.post(t, security, "/v1/agents/a1/suspend", `{"reason":"agent-wide"}`))
	if r := e.post(t, security, "/v1/instances/a1-i1/resume", `{"reason":"x"}`); r.code != 409 {
		t.Fatalf("resume copy of suspended agent: %d %s", r.code, r.raw)
	}
	op = opOf(t, e.post(t, security, "/v1/agents/a1/resume", `{"reason":"ok"}`))
	// The agent's resume leaves a1-i1, suspended on its own, suspended (F3).
	if d := stepsOf(op, "a1")["resume_instances"].Detail; !strings.Contains(d, "a1-i1") || !strings.Contains(d, "left suspended") {
		t.Fatalf("agent resume detail: %q", d)
	}
	if hb := e.heartbeat(t, "a1", "a1-i1"); hb.code != 423 {
		t.Fatalf("copy suspended on its own after the agent's resume: %d %s", hb.code, hb.raw)
	}
	opOf(t, e.post(t, jane, "/v1/instances/a1-i1/resume", `{"reason":"mine"}`))
	opOf(t, e.post(t, jane, "/v1/instances/a1-i2/suspend", `{"reason":"one more"}`))
	op = opOf(t, e.post(t, jane, "/v1/instances/a1-i2/resume", `{"reason":"fine"}`))
	wantSteps(t, op, "a1", map[string]string{"resume_instances": "done"})
	for _, id := range []string{"a1-i1", "a1-i2"} {
		if hb := e.heartbeat(t, "a1", id); hb.code != 200 {
			t.Fatalf("%s after resume: %d %s", id, hb.code, hb.raw)
		}
	}
	e.mustAllow(t, pgRead("a1", "a1-i1"))
}

// GET /v1/containment: auditor/security see everything; an owner sees only
// their agent's history (which includes team and fleet ops covering it).
func TestHistory(t *testing.T) {
	e := newEnv(t, envOpts{})
	e.agent(t, "j1", "payments", "jane@acme.com", 1)
	e.agent(t, "b1", "ops", "bob@acme.com", 1)
	opOf(t, e.post(t, jane, "/v1/agents/j1/suspend", `{"reason":"one"}`))
	opOf(t, e.post(t, security, "/v1/teams/payments/resume", `{"reason":"two"}`))
	opOf(t, e.post(t, security, "/v1/agents/b1/isolate", `{"reason":"three"}`))

	r := call(t, e.api, jane, "GET", "/v1/containment?target_type=agent&target_id=j1", "")
	if r.code != 200 {
		t.Fatalf("owner history: %d %s", r.code, r.raw)
	}
	ops := r.body["operations"].([]any)
	if len(ops) != 2 || ops[0].(map[string]any)["op"] != "resume" || ops[1].(map[string]any)["op"] != "suspend" {
		t.Fatalf("j1 history: %s", r.raw)
	}
	if len(ops[0].(map[string]any)["steps"].([]any)) == 0 {
		t.Fatal("history without steps")
	}
	for _, c := range []struct {
		p    string
		q    string
		code int
	}{
		{"jane", "?target_type=agent&target_id=b1", 403},
		{"jane", "", 403},
		{"jane", "?target_type=team&target_id=payments", 403},
		{"auditor", "", 200},
		{"auditor", "?target_type=team&target_id=payments", 200},
		{"auditor", "?target_type=galaxy", 400},
		{"auditor", "?target_id=j1", 400},
		{"auditor", "?limit=0", 400},
		{"auditor", "?limit=abc", 400},
		{"security", "?target_type=agent&target_id=b1&limit=1", 200},
	} {
		p := jane
		switch c.p {
		case "auditor":
			p = auditor
		case "security":
			p = security
		}
		if r := call(t, e.api, p, "GET", "/v1/containment"+c.q, ""); r.code != c.code {
			t.Fatalf("%s GET %s: %d %s, want %d", c.p, c.q, r.code, r.raw, c.code)
		}
	}
	if r := call(t, e.api, nil, "GET", "/v1/containment", ""); r.code != 401 {
		t.Fatalf("unauthenticated: %d", r.code)
	}
	all, err := e.mgr.List(context.Background(), "", "", 0)
	if err != nil || len(all) != 3 {
		t.Fatalf("list all: %v %d", err, len(all))
	}
	team, err := e.mgr.List(context.Background(), "team", "payments", 0)
	if err != nil || len(team) != 1 {
		t.Fatalf("team list: %v %d", err, len(team))
	}
	got, err := e.mgr.Get(context.Background(), all[0].OpID)
	if err != nil || got.OpID != all[0].OpID || len(got.Steps) == 0 {
		t.Fatalf("get: %v %+v", err, got)
	}
	if _, err := e.mgr.Get(context.Background(), "cop_nope"); !errors.Is(err, containment.ErrNotFound) {
		t.Fatalf("get unknown: %v", err)
	}
}
