package swarm_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"fortik/internal/approvals"
	"fortik/internal/authz"
	"fortik/internal/broker"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/policy"
	"fortik/internal/undo"
)

var (
	sec1    = user("alice@acme.com", "security")
	sec2    = user("bob@acme.com", "security")
	auditor = user("audit@acme.com", "auditor")
)

func workerID(i int) string { return fmt.Sprintf("worker_%02d", i) }

// orchestrated registers an orchestrator and n workers it delegated to.
func orchestrated(f *fixture, n int) (string, string) {
	f.agent("orchestrator")
	first := ""
	for i := 1; i <= n; i++ {
		f.agent(workerID(i))
		id := f.delegate("orchestrator", workerID(i), "")
		if first == "" {
			first = id
		}
	}
	return "orchestrator", first
}

// killScenario is the plan's scenario 3 at any scale: an orchestrator
// delegates to n workers; workers send one identical external email each.
func killScenario(t *testing.T, n, breakerN int) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: breakerN}})
	ctx := context.Background()
	root, brief := orchestrated(f, n)

	for i := 1; i <= n; i++ {
		out := f.send(workerID(i), "")
		switch {
		case i <= breakerN:
			if out.Result.Decision != policy.AllowReduced || out.Held {
				t.Fatalf("send %d: want allow_reduced (delayed), got %s by %s", i, out.Result.Decision, out.Result.RuleID)
			}
		default:
			if out.Result.Decision != policy.Hold || out.Result.RuleID != "POL-651" || out.Result.ApprovalsRequired != 2 {
				t.Fatalf("send %d: want POL-651 hold for 2 approvers, got %s by %s (%d)", i, out.Result.Decision, out.Result.RuleID, out.Result.ApprovalsRequired)
			}
		}
	}
	held := n - breakerN
	sid := f.swarmOf(workerID(breakerN + 1))
	if got := f.count(`SELECT member_count FROM swarms WHERE swarm_id = $1`, sid); got != n+1 {
		t.Fatalf("swarm members: got %d want %d (orchestrator + workers)", got, n+1)
	}
	if f.str(`SELECT role FROM swarm_members WHERE swarm_id = $1 AND agent_id = $2`, sid, root) != "root" ||
		f.str(`SELECT root_agent_id FROM swarms WHERE swarm_id = $1`, sid) != root ||
		f.str(`SELECT detected_by FROM swarms WHERE swarm_id = $1`, sid) != "action_hash" ||
		f.str(`SELECT state FROM swarms WHERE swarm_id = $1`, sid) != "breaker_tripped" {
		t.Fatal("swarm root, signal or state wrong")
	}
	if f.count(`SELECT count(*) FROM swarm_breakers WHERE swarm_id = $1 AND state = 'tripped'`, sid) != 1 {
		t.Fatal("breaker not written")
	}
	if got := f.count(`SELECT count(*) FROM held_actions WHERE swarm_id = $1 AND approvals_required = 2 AND rule_id = 'POL-651'`, sid); got != held {
		t.Fatalf("held calls tagged with the swarm: got %d want %d", got, held)
	}
	if got := f.count(`SELECT count(*) FROM actions WHERE swarm_id = $1`, sid); got != n {
		t.Fatalf("actions tagged with the swarm: got %d want %d", got, n)
	}
	if len(f.diaryData("swarm.detected")) != 1 || len(f.diaryData("swarm.breaker_tripped")) != 1 {
		t.Fatal("detection not in the Diary")
	}
	if f.count(`SELECT count(*) FROM alerts WHERE kind = 'swarm_detected'`) != 1 {
		t.Fatal("no swarm_detected alert")
	}

	// A held call needs two DISTINCT approvers.
	appr := approvals.New(f.pool, f.d, undo.NewPGStore(f.pool, f.d), nil, approvals.Config{}, discard())
	heldID := f.str(`SELECT action_id FROM held_actions WHERE swarm_id = $1 ORDER BY created_at LIMIT 1`, sid)
	d1, err := appr.Approve(ctx, sec1, heldID, approvals.ApproveRequest{Reason: "looked at it"})
	if err != nil || d1.Outcome != "pending" || d1.Approvals != 1 || d1.ApprovalsRequired != 2 {
		t.Fatalf("first approval: %+v %v", d1, err)
	}
	if _, err := appr.Approve(ctx, sec1, heldID, approvals.ApproveRequest{Reason: "again"}); !errors.Is(err, approvals.ErrAlreadyVoted) {
		t.Fatalf("same approver twice: %v", err)
	}
	d2, err := appr.Approve(ctx, sec2, heldID, approvals.ApproveRequest{Reason: "second pair of eyes"})
	if err != nil || d2.Outcome != "approved" || d2.Grant == nil {
		t.Fatalf("second approval: %+v %v", d2, err)
	}
	stillHeld := held - 1

	// Kill the swarm through the API.
	r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/kill", `{"reason":"scenario 3: phishing swarm","keep_root_read_only":true}`)
	if r.code != 200 {
		t.Fatalf("kill: %d %s", r.code, r.raw)
	}
	op := decodeOp(t, r.raw)
	if op.Op != "kill_swarm" || op.Status != "done" {
		t.Fatalf("kill op: %s %s: %s", op.Op, op.Status, r.raw)
	}
	lastPhase := 0
	phases := map[int]bool{}
	for _, s := range op.Steps {
		if s.Status == "failed" {
			t.Fatalf("failed step: %+v", s)
		}
		if s.Phase < lastPhase {
			t.Fatalf("steps out of order: %+v after phase %d", s, lastPhase)
		}
		lastPhase = s.Phase
		phases[s.Phase] = true
	}
	for p := 1; p <= 7; p++ {
		if !phases[p] {
			t.Fatalf("phase %d missing", p)
		}
	}
	// Step 2: 0 emails delivered: every delayed send cancelled, none in flight or sent.
	if got := f.count(`SELECT count(*) FROM delayed_sends WHERE status = 'cancelled'`); got != breakerN {
		t.Fatalf("cancelled delayed sends: got %d want %d", got, breakerN)
	}
	if f.count(`SELECT count(*) FROM delayed_sends WHERE status <> 'cancelled'`) != 0 {
		t.Fatal("a delayed send is still pending, sending or sent")
	}
	if f.count(`SELECT count(*) FROM undo_handles WHERE kind = 'gmail_delayed_send' AND status <> 'failed'`) != 0 {
		t.Fatal("cancelled sends' undo handles left active")
	}
	// Held calls stay held.
	if got := f.count(`SELECT count(*) FROM held_actions WHERE swarm_id = $1 AND outcome = 'pending'`, sid); got != stillHeld {
		t.Fatalf("held calls still pending: got %d want %d", got, stillHeld)
	}
	// Steps 3-6.
	for i := 1; i <= n; i++ {
		w := workerID(i)
		if f.level(w) != control.Killed {
			t.Fatalf("%s is %s, want KILLED", w, f.level(w))
		}
		if f.adapter.count(w) != 1 || f.queue.cancels[w] != 1 {
			t.Fatalf("%s: revoked %d, queue cancels %d", w, f.adapter.count(w), f.queue.cancels[w])
		}
		if f.str(`SELECT mode FROM memory_access WHERE agent_id = $1`, w) != "none" {
			t.Fatalf("%s memory access not none", w)
		}
	}
	if f.level(root) != control.ReadOnly {
		t.Fatalf("root is %s, want READ_ONLY (keep_root_read_only)", f.level(root))
	}
	// Members get no new credentials.
	for _, a := range []string{workerID(1), root} {
		_, err := f.brk.Issue(ctx, broker.IssueRequest{AgentID: a, System: "github",
			GitHub: &broker.GHRequest{Repos: []string{"acme/api"}, Permissions: map[string]string{"contents": "read"}}})
		var ref *broker.Refusal
		if !errors.As(err, &ref) {
			t.Fatalf("credential for %s not refused: %v", a, err)
		}
	}
	// The approved call cannot be used by a KILLED worker either.
	if out := f.send(workerID(breakerN+1), ""); out.Result.Decision.Executes() {
		t.Fatal("killed worker's approved retry ran")
	}
	// Step 7: sealed bundle, exported signed.
	sealed := f.diaryData("swarm.sealed")
	if len(sealed) != 1 {
		t.Fatal("no swarm.sealed event")
	}
	b, _ := sealed[0]["brief"].(map[string]any)
	if b == nil || b["delegation_id"] != brief {
		t.Fatalf("brief: %v", sealed[0]["brief"])
	}
	if tree, _ := sealed[0]["spawn_tree"].([]any); len(tree) != n {
		t.Fatalf("spawn tree: %d hops", len(tree))
	}
	r = call(t, f.api, &auditor, "GET", "/v1/swarms/"+sid+"/bundle", "")
	if r.code != 200 || r.body["signed"] != true || r.body["bundle_root"] == nil {
		t.Fatalf("bundle: %d %.300s", r.code, r.raw)
	}
	r = call(t, f.api, &auditor, "GET", "/v1/swarms/"+sid, "")
	if r.code != 200 || r.body["frozen"] != true || r.body["release_required"] != float64(2) {
		t.Fatalf("detail: %d %.300s", r.code, r.raw)
	}
	if ms, _ := r.body["members"].([]any); len(ms) != n+1 {
		t.Fatalf("detail members: %d", len(ms))
	}
	if ops, _ := r.body["ops"].([]any); len(ops) != 1 {
		t.Fatalf("detail ops: %d", len(ops))
	}
	f.verifyChain()
}

func TestKillSwarmSmallScale(t *testing.T) { killScenario(t, 4, 2) }

// The plan's scenario 3: orchestrator + 40 workers; the 6th identical send
// trips the breaker; 0 emails delivered.
func TestKillSwarmFullScale(t *testing.T) { killScenario(t, 40, 5) }

func TestReleaseNeedsTwoDistinctApproversAndNeverUnkills(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 2}})
	root, _ := orchestrated(f, 3)
	for i := 1; i <= 3; i++ {
		f.send(workerID(i), "")
	}
	sid := f.swarmOf(workerID(1))
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/kill", `{"reason":"contain"}`); r.code != 200 {
		t.Fatalf("kill: %d %s", r.code, r.raw)
	}
	r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"false positive?"}`)
	if r.code != 200 || r.body["released"] != false || r.body["votes"] != float64(1) || r.body["required"] != float64(2) {
		t.Fatalf("first vote: %d %s", r.code, r.raw)
	}
	upper := user("ALICE@acme.com", "security")
	if r := call(t, f.api, &upper, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"again"}`); r.code != 409 {
		t.Fatalf("same approver twice: %d %s", r.code, r.raw)
	}
	if f.str(`SELECT state FROM swarms WHERE swarm_id = $1`, sid) != "killed" {
		t.Fatal("one vote released the swarm")
	}
	r = call(t, f.api, &sec2, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"confirmed false positive"}`)
	if r.code != 200 || r.body["released"] != true || r.body["votes"] != float64(2) || r.body["op"] == nil {
		t.Fatalf("second vote: %d %s", r.code, r.raw)
	}
	if f.str(`SELECT state FROM swarms WHERE swarm_id = $1`, sid) != "released" ||
		f.count(`SELECT count(*) FROM swarm_breakers WHERE swarm_id = $1 AND state = 'tripped'`, sid) != 0 {
		t.Fatal("swarm or breaker not released")
	}
	for i := 1; i <= 3; i++ {
		if f.level(workerID(i)) != control.Killed {
			t.Fatalf("release un-killed %s", workerID(i))
		}
	}
	if f.level(root) != control.ReadOnly {
		t.Fatalf("root level changed by release: %s", f.level(root))
	}
	op := decodeOp(t, mustJSON(r.body["op"]))
	if op.Op != "release_swarm" {
		t.Fatalf("release op: %+v", op)
	}
	for _, s := range op.Steps {
		if s.Name == "keep_level" && strings.HasPrefix(s.AgentID, "worker_") && !strings.Contains(s.Detail, "stays KILLED") {
			t.Fatalf("keep_level: %+v", s)
		}
	}
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"x"}`); r.code != 409 {
		t.Fatalf("release of a released swarm: %d", r.code)
	}
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/kill", `{"reason":"x"}`); r.code != 409 {
		t.Fatalf("kill of a released swarm: %d", r.code)
	}
	// Counting restarts after the release: a new agent's identical send is decided normally.
	f.agent("newcomer")
	if out := f.send("newcomer", ""); out.Result.Decision != policy.AllowReduced {
		t.Fatalf("after release: %s by %s", out.Result.Decision, out.Result.RuleID)
	}
	f.verifyChain()
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestKillIsIdempotentAndHonestAboutPartialResults(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 2}})
	orchestrated(f, 3)
	for i := 1; i <= 2; i++ {
		f.send(workerID(i), "")
	}
	f.send(workerID(3), "")
	sid := f.swarmOf(workerID(1))
	// worker_02's send was already claimed by the sender: it cannot be stopped.
	f.exec(`UPDATE delayed_sends SET status = 'sending' WHERE agent_id = $1`, workerID(2))
	f.adapter.setFail(workerID(1))
	r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/kill", `{"reason":"contain"}`)
	op := decodeOp(t, r.raw)
	if r.code != 200 || op.Status != "partial" {
		t.Fatalf("kill: %d %s", r.code, r.raw)
	}
	var sawRevokeFail, sawInFlight bool
	for _, s := range op.Steps {
		if s.Name == "revoke_credentials" && s.AgentID == workerID(1) {
			sawRevokeFail = s.Status == "failed" && strings.Contains(s.Detail, "FAILED")
		}
		if s.Name == "hold_pending_calls" && s.AgentID == workerID(2) {
			sawInFlight = s.Status == "failed" && strings.Contains(s.Detail, "could NOT be stopped")
		}
		if s.Status == "failed" && s.AgentID != workerID(1) && s.AgentID != workerID(2) {
			t.Fatalf("unexpected failure: %+v", s)
		}
	}
	if !sawRevokeFail || !sawInFlight {
		t.Fatalf("partial results not reported honestly: %s", r.raw)
	}
	// The pending send of worker_01 was cancelled; worker_02's stays in flight (reported).
	if f.str(`SELECT status FROM delayed_sends WHERE agent_id = $1`, workerID(1)) != "cancelled" {
		t.Fatal("worker_01's send not cancelled")
	}
	// Run it again: nothing is repeated that already succeeded.
	r = call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/kill", `{"reason":"again"}`)
	op = decodeOp(t, r.raw)
	if r.code != 200 {
		t.Fatalf("second kill: %d %s", r.code, r.raw)
	}
	for _, s := range op.Steps {
		switch {
		case s.Name == "freeze_spawning" && s.Status != "skipped",
			s.Name == "set_level" && s.Status != "skipped",
			s.Name == "set_memory_access" && s.Status != "skipped",
			s.Name == "revoke_credentials" && s.AgentID == workerID(3) && s.Status != "skipped":
			t.Fatalf("second kill repeated a step: %+v", s)
		}
	}
	if f.adapter.count(workerID(3)) != 1 {
		t.Fatalf("worker_03 revoked %d times", f.adapter.count(workerID(3)))
	}
	if f.adapter.count(workerID(1)) != 2 {
		t.Fatal("worker_01's failed revocation was not retried")
	}
	f.verifyChain()
}

func TestObserverHoldsACallTheEnricherMissed(t *testing.T) {
	// Without the enricher, policy never sees the breaker: the observer,
	// counting inside the decision transaction, must still hold the
	// tripping call (the concurrent-decision case).
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 2}, noEnricher: true})
	for i := 1; i <= 3; i++ {
		f.agent(workerID(i))
	}
	f.exec(`INSERT INTO instances (instance_id, agent_id) VALUES ('i-1', $1), ('i-2', $1)`, workerID(1))
	f.send(workerID(1), "i-1")
	f.send(workerID(1), "i-2") // a second registered copy counts as a distinct actor
	out := f.send(workerID(2), "")
	if out.Result.Decision != policy.Hold || out.Result.RuleID != "POL-651" || out.Result.ApprovalsRequired != 2 || !out.Held {
		t.Fatalf("tripping call: %+v", out.Result)
	}
	id := out.Action.ActionID
	if f.str(`SELECT decision FROM actions WHERE action_id = $1`, id) != "hold" ||
		f.count(`SELECT approvals_required FROM held_actions WHERE action_id = $1`, id) != 2 ||
		f.str(`SELECT decision_json->'swarm_breaker'->>'converted_from' FROM actions WHERE action_id = $1`, id) != "allow_reduced" {
		t.Fatal("conversion not recorded")
	}
	if f.count(`SELECT count(*) FROM delayed_sends WHERE action_id = $1`, id) != 0 {
		t.Fatal("converted call was queued")
	}
	sid := f.swarmOf(workerID(2))
	if got := f.count(`SELECT count(*) FROM swarm_members WHERE swarm_id = $1`, sid); got != 3 {
		t.Fatalf("members (2 copies + 1 agent): %d", got)
	}
	if out := f.send(workerID(3), ""); out.Result.RuleID != "POL-651" || !out.Held {
		t.Fatalf("later call: %+v", out.Result)
	}
	held := f.diaryData("action.held")
	if len(held) != 2 || held[0]["converted_from"] != "allow_reduced" {
		t.Fatalf("action.held events: %v", held)
	}
	f.verifyChain()
}

func TestAPIRolesAndStrictJSON(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 1}})
	f.agent("a1")
	f.agent("a2")
	f.send("a1", "")
	f.send("a2", "")
	sid := f.swarmOf("a1")
	for _, c := range []struct {
		who  authz.Principal
		path string
		body string
		want int
	}{
		{who: auditor, path: "/kill", body: `{"reason":"x"}`, want: 403},
		{who: sec1, path: "/kill", body: `{}`, want: 400},
		{who: sec1, path: "/kill", body: `{"reason":"   "}`, want: 400},
		{who: sec1, path: "/kill", body: `{"reason":"x","force":true}`, want: 400},
		{who: sec1, path: "/suspend", body: `{"reason":"x\u0007"}`, want: 400},
		{who: sec1, path: "/trip", body: `{"reason":"x","action_hash":"nothex"}`, want: 400},
		{who: auditor, path: "/release", body: `{"reason":"x"}`, want: 403},
	} {
		r := call(t, f.api, &c.who, "POST", "/v1/swarms/"+sid+c.path, c.body)
		if r.code != c.want {
			t.Fatalf("%s %s: %d want %d (%s)", c.path, c.body, r.code, c.want, r.raw)
		}
	}
	if r := call(t, f.api, &auditor, "GET", "/v1/swarms?state=breaker_tripped", ""); r.code != 200 || len(r.body["swarms"].([]any)) != 1 {
		t.Fatalf("list: %d %s", r.code, r.raw)
	}
	if r := call(t, f.api, &auditor, "GET", "/v1/swarms?state=bogus", ""); r.code != 400 {
		t.Fatalf("bad state: %d", r.code)
	}
	if r := call(t, f.api, nil, "GET", "/v1/swarms", ""); r.code != 401 {
		t.Fatalf("anonymous: %d", r.code)
	}
	if r := call(t, f.api, &auditor, "GET", "/v1/swarms/swm_nope", ""); r.code != 404 {
		t.Fatalf("unknown: %d", r.code)
	}
	if r := call(t, f.api, &auditor, "GET", "/v1/swarms/"+sid+"/bundle", ""); r.code != 409 {
		t.Fatalf("bundle before kill: %d", r.code)
	}
	// trip by hand is idempotent for the swarm's own breaker
	r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/trip", `{"reason":"belt and braces"}`)
	if op := decodeOp(t, r.raw); r.code != 200 || op.Op != "trip_breaker" || op.Steps[0].Status != "skipped" {
		t.Fatalf("trip: %d %s", r.code, r.raw)
	}
	r = call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/suspend", `{"reason":"pause them"}`)
	if op := decodeOp(t, r.raw); r.code != 200 || op.Op != "suspend" || op.Status != "done" {
		t.Fatalf("suspend: %d %s", r.code, r.raw)
	}
	if f.str(`SELECT suspended_by FROM agents WHERE agent_id = 'a1'`) != "swarm:"+sid {
		t.Fatal("swarm suspend marker missing")
	}
	if f.str(`SELECT state FROM swarms WHERE swarm_id = $1`, sid) != "suspended" {
		t.Fatal("state not suspended")
	}
}

// Phase 5 review #5: a made-up X-Fortik-Instance-Id is the caller's own
// claim: one agent sending under fake labels is ONE actor, and cannot trip
// the breaker on other agents' identical calls. A call matching a breaker
// others tripped is held, but the caller is not made a (frozen) member.
func TestFakeInstanceLabelsDoNotCountAsCopies(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 2}})
	f.agent("mal")
	f.agent("good")
	for _, inst := range []string{"", "fake-1", "fake-2", "fake-3", "fake-4"} {
		if out := f.send("mal", inst); out.Result.RuleID == "POL-651" {
			t.Fatalf("fake labels tripped the breaker: %+v", out.Result)
		}
	}
	if out := f.send("good", ""); out.Result.RuleID == "POL-651" {
		t.Fatalf("innocent call held by a breaker one agent tripped alone: %+v", out.Result)
	}
	if n := f.count(`SELECT count(*) FROM swarm_breakers`); n != 0 {
		t.Fatalf("breakers: %d", n)
	}
	// A third real agent trips it (mal and good are two actors); a later
	// agent's identical call is held for two approvers but it does not join
	// (and so is not frozen by) the swarm.
	f.agent("w3")
	out := f.send("w3", "")
	if out.Result.RuleID != "POL-651" || !out.Held {
		t.Fatalf("tripping call: %+v", out.Result)
	}
	f.agent("late")
	late := f.send("late", "")
	if late.Result.RuleID != "POL-651" || !late.Held || late.Result.ApprovalsRequired != 2 {
		t.Fatalf("late call: %+v", late.Result)
	}
	if f.count(`SELECT count(*) FROM swarm_members WHERE agent_id = 'late'`) != 0 {
		t.Fatal("a caller matching the breaker was made a swarm member")
	}
	if f.str(`SELECT swarm_id FROM held_actions WHERE action_id = $1`, late.Action.ActionID) == "" {
		t.Fatal("the late hold is not tagged with the swarm")
	}
}

// Phase 5 review #2: a call held (one approver) before the breaker tripped
// cannot be released by one person afterwards. The trip raises pending
// identical holds to two approvers, and a grant approved by one person
// before the trip no longer releases the now breaker-held call.
func TestOneApproverCannotReleaseABreakerCall(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 2}})
	f.dec.Enrichers = append(f.dec.Enrichers, approvals.NewGrantEnricher(f.pool))
	f.dec.Observers = []decide.Observer{f.sw, approvals.NewGrantObserver(f.d), f.pop}
	ctx := context.Background()
	for i := 1; i <= 4; i++ {
		f.agent(workerID(i))
	}
	for _, w := range []string{workerID(3), workerID(4)} {
		if _, err := f.ctl.SetLevel(ctx, w, control.Supervised, "review", "test"); err != nil {
			t.Fatal(err)
		}
	}
	appr := approvals.New(f.pool, f.d, undo.NewPGStore(f.pool, f.d), nil, approvals.Config{}, discard())
	h4 := f.send(workerID(4), "")
	if !h4.Held || h4.Result.ApprovalsRequired > 1 {
		t.Fatalf("supervised send: %+v", h4.Result)
	}
	d, err := appr.Approve(ctx, sec1, h4.Action.ActionID, approvals.ApproveRequest{Reason: "looks fine"})
	if err != nil || d.Outcome != approvals.OutcomeApproved || d.Grant == nil {
		t.Fatalf("one-approver grant before the trip: %+v %v", d, err)
	}
	h3 := f.send(workerID(3), "")
	if !h3.Held {
		t.Fatalf("supervised send: %+v", h3.Result)
	}
	if trip := f.send(workerID(1), ""); trip.Result.RuleID != "POL-651" {
		t.Fatalf("tripping call: %+v", trip.Result)
	}
	if n := f.count(`SELECT approvals_required FROM held_actions WHERE action_id = $1`, h3.Action.ActionID); n != 2 {
		t.Fatalf("pending identical hold kept %d approver(s) after the trip", n)
	}
	retry := f.send(workerID(4), "")
	if retry.Result.Decision != policy.Hold || retry.Result.RuleID != "POL-651" || retry.Result.GrantID != "" {
		t.Fatalf("one-approver grant released a breaker-held call: %+v", retry.Result)
	}
	if f.count(`SELECT count(*) FROM approval_grants WHERE used_at IS NOT NULL`) != 0 {
		t.Fatal("the grant was consumed")
	}
	held := f.diaryData("action.held")
	if last := held[len(held)-1]; last["approvals_required"] != float64(2) {
		t.Fatalf("Diary hold event: %v", last)
	}
	f.verifyChain()
}
