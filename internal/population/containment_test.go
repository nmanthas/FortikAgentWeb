package population_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/population"
)

// Containment of copies: suspended copies get 423 {"action":"pause"} on
// heartbeat and POL-705 on every action; resume respects the copy cap and
// stops copies that went quiet; kill stops every copy (410).
func TestInstanceControlSuspendResumeStop(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{StaleAfter: time.Minute})
	ctx := context.Background()
	ic := s.svc.InstanceControl()
	s.agent(t, "worker_1", "", "jane@acme.com", 2, false)
	for _, id := range []string{"w-1", "w-2"} {
		if r := s.register(t, "worker_1", id, "host-a"); r.code != 201 {
			t.Fatalf("register %s: %d %s", id, r.code, r.raw)
		}
	}

	// Suspend one copy.
	ids, detail, err := ic.SuspendInstances(ctx, "worker_1", "w-1", "user:sec@acme.com", "investigating")
	if err != nil || len(ids) != 1 || ids[0] != "w-1" || detail == "" {
		t.Fatalf("suspend w-1: %v %v %q", ids, err, detail)
	}
	hb := s.heartbeat(t, "worker_1", "w-1")
	if hb.code != 423 || hb.body["action"] != "pause" || hb.body["status"] != population.StatusSuspended || hb.body["reason"] != "suspended: investigating" {
		t.Fatalf("heartbeat of suspended copy: %d %s", hb.code, hb.raw)
	}
	if out := s.decide(t, memRead("worker_1", "w-1")); out.Result.Decision.Executes() || out.Result.RuleID != population.RuleInstance {
		t.Fatalf("suspended copy acted: %+v", out.Result)
	}
	if out := s.decide(t, memRead("worker_1", "w-2")); out.Result.RuleID == population.RuleInstance {
		t.Fatalf("live sibling refused: %+v", out.Result)
	}
	// Idempotent: nothing more to suspend.
	if ids, _, err := ic.SuspendInstances(ctx, "worker_1", "w-1", "user:sec@acme.com", "again"); err != nil || len(ids) != 0 {
		t.Fatalf("second suspend: %v %v", ids, err)
	}
	if n := s.count(t, `SELECT count(*) FROM diary WHERE event_type = 'instance.suspended'`); n != 1 {
		t.Fatalf("instance.suspended events = %d, want 1", n)
	}
	// List filter knows the status.
	sec := userP("sec@acme.com", authz.RoleSecurity)
	if r := call(t, s.api, &sec, "GET", "/v1/agents/worker_1/instances?status=suspended", ""); r.code != 200 || len(r.body["instances"].([]any)) != 1 {
		t.Fatalf("list suspended: %d %s", r.code, r.raw)
	}

	// A suspended copy keeps its copy_cap slot (D4): the agent's shared token
	// cannot register a fresh copy in its place.
	if r := s.register(t, "worker_1", "w-x", "host-a"); r.code != 403 || !strings.Contains(r.raw, population.RuleCopyCap) {
		t.Fatalf("register while a copy is suspended at the cap: %d %s", r.code, r.raw)
	}
	// Resuming w-1 when the cap has since dropped to 1 (w-2 live holds the
	// only slot) pauses it instead (must stop).
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET copy_cap = 1 WHERE agent_id = 'worker_1'`); err != nil {
		t.Fatal(err)
	}
	ids, detail, err = ic.ResumeInstances(ctx, "worker_1", "w-1", "user:sec@acme.com", "cleared", "")
	if err != nil || len(ids) != 0 {
		t.Fatalf("resume over cap: %v %v", ids, err)
	}
	if in, _ := s.svc.Instance(ctx, "w-1"); in.Status != population.StatusPaused {
		t.Fatalf("w-1 after resume over cap: %s (%s)", in.Status, detail)
	}
	if hb := s.heartbeat(t, "worker_1", "w-1"); hb.code != 410 {
		t.Fatalf("paused copy heartbeat: %d", hb.code)
	}
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET copy_cap = 2 WHERE agent_id = 'worker_1'`); err != nil {
		t.Fatal(err)
	}
	if r := s.register(t, "worker_1", "w-3", "host-a"); r.code != 201 {
		t.Fatalf("register w-3: %d %s", r.code, r.raw)
	}

	// Agent-wide suspend and resume.
	ids, _, err = ic.SuspendInstances(ctx, "worker_1", "", "user:sec@acme.com", "suspend agent")
	if err != nil || len(ids) != 2 {
		t.Fatalf("suspend all: %v %v", ids, err)
	}
	ids, _, err = ic.ResumeInstances(ctx, "worker_1", "", "user:sec@acme.com", "resume agent", "")
	if err != nil || len(ids) != 2 {
		t.Fatalf("resume all: %v %v", ids, err)
	}
	for _, id := range []string{"w-2", "w-3"} {
		if hb := s.heartbeat(t, "worker_1", id); hb.code != 200 {
			t.Fatalf("resumed %s heartbeat: %d %s", id, hb.code, hb.raw)
		}
	}

	// A copy that stops heartbeating while suspended is stopped on resume.
	if _, _, err := ic.SuspendInstances(ctx, "worker_1", "w-3", "user:sec@acme.com", "quiet"); err != nil {
		t.Fatal(err)
	}
	s.svc.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if _, err := s.svc.Heartbeat(ctx, "worker_1", "w-2"); err == nil {
		t.Fatal("w-2 should be stale")
	}
	if _, detail, err := ic.ResumeInstances(ctx, "worker_1", "w-3", "user:sec@acme.com", "back", ""); err != nil {
		t.Fatal(err)
	} else if in, _ := s.svc.Instance(ctx, "w-3"); in.Status != population.StatusStopped {
		t.Fatalf("quiet suspended copy after resume: %s (%s)", in.Status, detail)
	}
	s.svc.Now = nil

	// Kill: every copy not already stopped or refused is stopped.
	if r := s.register(t, "worker_1", "w-4", "host-a"); r.code != 201 {
		t.Fatalf("register w-4: %d %s", r.code, r.raw)
	}
	if _, _, err := ic.SuspendInstances(ctx, "worker_1", "w-4", "user:sec@acme.com", "x"); err != nil {
		t.Fatal(err)
	}
	ids, _, err = ic.StopInstances(ctx, "worker_1", "", "user:sec@acme.com", "agent killed")
	if err != nil || len(ids) != 2 { // w-1 (paused) and w-4 (suspended); w-2 and w-3 are already stopped
		t.Fatalf("stop: %v %v", ids, err)
	}
	if hb := s.heartbeat(t, "worker_1", "w-4"); hb.code != 410 {
		t.Fatalf("stopped copy heartbeat: %d", hb.code)
	}
	if ids, _, err := ic.StopInstances(ctx, "worker_1", "", "user:sec@acme.com", "again"); err != nil || len(ids) != 0 {
		t.Fatalf("second stop: %v %v", ids, err)
	}

	// Unknown targets.
	if _, _, err := ic.SuspendInstances(ctx, "worker_1", "nope", "a", "r"); !errors.Is(err, population.ErrInstanceNotFound) {
		t.Fatalf("unknown instance: %v", err)
	}
	if _, _, err := ic.SuspendInstances(ctx, "ghost", "", "a", "r"); !errors.Is(err, population.ErrAgentNotFound) {
		t.Fatalf("unknown agent: %v", err)
	}
}

// F5 (D4): a suspended copy keeps its copy_cap (and type population) slot,
// whatever its heartbeat, so the agent's shared token cannot register a
// fresh copy in its place and keep acting through it.
func TestSuspendedCopyKeepsItsSlot(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{StaleAfter: time.Minute})
	ctx := context.Background()
	ic := s.svc.InstanceControl()
	s.agentType(t, population.AgentType{Type: "bot", ExpectedMaxInstances: 2})
	s.agent(t, "a1", "bot", "jane@acme.com", 1, false)
	s.agent(t, "a2", "bot", "jane@acme.com", 5, false)
	if r := s.register(t, "a1", "a1-i1", "h"); r.code != 201 {
		t.Fatalf("register: %d %s", r.code, r.raw)
	}
	if r := s.register(t, "a2", "a2-i1", "h"); r.code != 201 {
		t.Fatalf("register: %d %s", r.code, r.raw)
	}
	if _, _, err := ic.SuspendInstances(ctx, "a1", "a1-i1", "user:sec@acme.com", "rogue copy"); err != nil {
		t.Fatal(err)
	}
	expectRefusal(t, s.register(t, "a1", "a1-i2", "h"), 403, population.RuleCopyCap)
	// The type population counts it too (a1-i1 suspended + a2-i1 live = 2).
	expectRefusal(t, s.register(t, "a2", "a2-i2", "h"), 403, population.RuleTypeMax)
	// Going quiet does not free the slot.
	s.svc.Now = func() time.Time { return time.Now().Add(5 * time.Minute) }
	expectRefusal(t, s.register(t, "a1", "a1-i3", "h"), 403, population.RuleCopyCap)
	s.svc.Now = nil

	// Resume counts the suspended copies it leaves suspended: with copy_cap 1
	// and two suspended copies, resuming one alone pauses it.
	s.agent(t, "b1", "", "jane@acme.com", 2, false)
	for _, id := range []string{"b1-i1", "b1-i2"} {
		if r := s.register(t, "b1", id, "h"); r.code != 201 {
			t.Fatalf("register %s: %d %s", id, r.code, r.raw)
		}
		if _, _, err := ic.SuspendInstances(ctx, "b1", id, "user:sec@acme.com", "x"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET copy_cap = 1 WHERE agent_id = 'b1'`); err != nil {
		t.Fatal(err)
	}
	ids, detail, err := ic.ResumeInstances(ctx, "b1", "b1-i1", "user:sec@acme.com", "x", "")
	if err != nil || len(ids) != 0 || !strings.Contains(detail, "paused above copy_cap 1") {
		t.Fatalf("resume one of two suspended copies at cap 1: %v %v %q", ids, err, detail)
	}
}

// F3 / F26 (D2): the agent's resume leaves a copy suspended on its own; a
// caller without the security role lifts only suspensions it imposed.
func TestResumeInstancesRespectsWhoSuspended(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{StaleAfter: time.Minute})
	ctx := context.Background()
	ic := s.svc.InstanceControl()
	s.agent(t, "a1", "", "jane@acme.com", 4, false)
	for _, id := range []string{"i1", "i2", "i3"} {
		if r := s.register(t, "a1", id, "h"); r.code != 201 {
			t.Fatalf("register %s: %d %s", id, r.code, r.raw)
		}
	}
	const sec, jane = "user:sec@acme.com", "user:jane@acme.com"
	if _, _, err := ic.SuspendInstances(ctx, "a1", "i1", sec, "rogue"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ic.SuspendInstances(ctx, "a1", "i2", jane, "mine"); err != nil {
		t.Fatal(err)
	}
	if by, ok, err := ic.SuspendedBy(ctx, "a1", "i1"); err != nil || !ok || by != sec {
		t.Fatalf("SuspendedBy i1: %q %v %v", by, ok, err)
	}
	if _, ok, err := ic.SuspendedBy(ctx, "a1", "i3"); err != nil || ok {
		t.Fatalf("SuspendedBy of a live copy: %v %v", ok, err)
	}
	// Agent-wide suspension (by jane) then resume: i3 back, i1/i2 (suspended
	// on their own) left suspended.
	if _, _, err := ic.SuspendInstances(ctx, "a1", "", jane, "agent"); err != nil {
		t.Fatal(err)
	}
	ids, detail, err := ic.ResumeInstances(ctx, "a1", "", sec, "agent back", "")
	if err != nil || len(ids) != 1 || ids[0] != "i3" || !strings.Contains(detail, "suspended on their own left suspended") {
		t.Fatalf("agent-wide resume: %v %v %q", ids, err, detail)
	}
	// Jane cannot lift security's suspension of i1, nothing changes.
	var imp *population.ImposedError
	if _, _, err := ic.ResumeInstances(ctx, "a1", "i1", jane, "x", jane); !errors.As(err, &imp) || imp.By != sec {
		t.Fatalf("owner resume of security's copy suspension: %v", err)
	}
	if in, _ := s.svc.Instance(ctx, "i1"); in.Status != population.StatusSuspended {
		t.Fatalf("i1: %s", in.Status)
	}
	// She can lift her own.
	if ids, _, err := ic.ResumeInstances(ctx, "a1", "i2", jane, "x", jane); err != nil || len(ids) != 1 {
		t.Fatalf("owner resume of own copy suspension: %v %v", ids, err)
	}
	// Agent-wide by jane, scoped to her: security's agent-wide suspension of
	// i3 is left.
	if _, _, err := ic.SuspendInstances(ctx, "a1", "", sec, "agent by security"); err != nil {
		t.Fatal(err)
	}
	ids, detail, err = ic.ResumeInstances(ctx, "a1", "", jane, "x", jane)
	if err != nil || len(ids) != 0 || !strings.Contains(detail, "suspended by someone else left suspended") {
		t.Fatalf("owner agent-wide resume: %v %v %q", ids, err, detail)
	}
}
