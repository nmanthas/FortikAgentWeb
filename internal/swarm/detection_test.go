package swarm_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/policy"
)

func sweep(t *testing.T, f *fixture) (created, grown []string) {
	t.Helper()
	res, err := f.sw.Sweep(context.Background())
	if err != nil {
		t.Fatalf("sweep: %v (%+v)", err, res)
	}
	return res.Created, res.Grown
}

func TestSpawnTreeDetection(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{FanoutLimit: 3, DepthLimit: 2}})
	f.agent("boss")
	for i := 1; i <= 3; i++ {
		f.agent(workerID(i))
		f.delegate("boss", workerID(i), "")
	}
	if c, _ := sweep(t, f); len(c) != 0 {
		t.Fatalf("3 delegations (fanout_limit 3) made a swarm: %v", c)
	}
	f.agent(workerID(4))
	f.delegate("boss", workerID(4), "")
	c, _ := sweep(t, f)
	if len(c) != 1 || !strings.HasPrefix(c[0], "swm_") {
		t.Fatalf("fan-out swarm: %v", c)
	}
	sid := c[0]
	if f.str(`SELECT detected_by FROM swarms WHERE swarm_id = $1`, sid) != "spawn_tree" ||
		f.str(`SELECT root_agent_id FROM swarms WHERE swarm_id = $1`, sid) != "boss" ||
		f.count(`SELECT member_count FROM swarms WHERE swarm_id = $1`, sid) != 5 {
		t.Fatal("spawn-tree swarm wrong")
	}
	// Idempotent: the next pass changes nothing.
	if c, g := sweep(t, f); len(c)+len(g) != 0 {
		t.Fatalf("second pass: created %v grown %v", c, g)
	}
	// Membership grows.
	f.agent(workerID(5))
	f.delegate("boss", workerID(5), "")
	if _, g := sweep(t, f); len(g) != 1 || g[0] != sid {
		t.Fatalf("growth: %v", g)
	}
	if f.count(`SELECT member_count FROM swarms WHERE swarm_id = $1`, sid) != 6 || len(f.diaryData("swarm.member_added")) != 1 {
		t.Fatal("member_count / swarm.member_added")
	}

	// Depth: one chain deeper than depth_limit; its swarm id is the root delegation.
	for _, a := range []string{"lead", "a", "b", "c"} {
		f.agent(a)
	}
	top := f.delegate("lead", "a", "")
	mid := f.delegate("a", "b", top)
	f.delegate("b", "c", mid)
	c, _ = sweep(t, f)
	if len(c) != 1 || c[0] != top {
		t.Fatalf("deep chain swarm id: %v want %s", c, top)
	}
	if f.count(`SELECT member_count FROM swarms WHERE swarm_id = $1`, top) != 4 {
		t.Fatal("deep chain members")
	}
	if f.count(`SELECT count(*) FROM alerts WHERE kind = 'swarm_detected'`) != 2 {
		t.Fatal("alerts")
	}
	f.verifyChain()
}

func TestCopySurgeDetection(t *testing.T) {
	f := newFixture(t, fixtureOpt{})
	f.agent("scraper")
	f.exec(`UPDATE agents SET copy_cap = 2 WHERE agent_id = 'scraper'`)
	for _, i := range []string{"i-1", "i-2"} {
		f.exec(`INSERT INTO instances (instance_id, agent_id, host, status) VALUES ($1, 'scraper', 'h', 'live')`, i)
	}
	if c, _ := sweep(t, f); len(c) != 0 {
		t.Fatalf("at the cap is not a surge: %v", c)
	}
	f.exec(`INSERT INTO instances (instance_id, agent_id, host, status) VALUES ('i-3', 'scraper', 'h', 'live'), ('i-4', 'scraper', 'h', 'paused')`)
	f.exec(`INSERT INTO instances (instance_id, agent_id, host, status, last_heartbeat) VALUES ('i-old', 'scraper', 'h', 'live', now() - interval '1 hour')`)
	c, _ := sweep(t, f)
	if len(c) != 1 {
		t.Fatalf("copy surge: %v", c)
	}
	sid := c[0]
	if f.str(`SELECT detected_by FROM swarms WHERE swarm_id = $1`, sid) != "copy_surge" ||
		f.count(`SELECT count(*) FROM swarm_members WHERE swarm_id = $1 AND instance_id <> ''`, sid) != 4 ||
		f.count(`SELECT count(*) FROM swarm_members WHERE swarm_id = $1 AND instance_id = 'i-old'`, sid) != 0 ||
		f.str(`SELECT role FROM swarm_members WHERE swarm_id = $1 AND instance_id = ''`, sid) != "root" {
		t.Fatal("copy-surge members")
	}
	var sig map[string]any
	if err := json.Unmarshal([]byte(f.str(`SELECT signal::text FROM swarms WHERE swarm_id = $1`, sid)), &sig); err != nil ||
		sig["copies"] != float64(4) || sig["copy_cap"] != float64(2) {
		t.Fatalf("signal: %v %v", sig, err)
	}
	if c, g := sweep(t, f); len(c)+len(g) != 0 {
		t.Fatalf("second pass: %v %v", c, g)
	}
}

func TestConvergingTargetsDetection(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{ConvergeN: 3}})
	ctx := context.Background()
	hit := func(agent string, sys string, verb action.Verb, target map[string]any) {
		t.Helper()
		if _, err := f.dec.Decide(ctx, action.Action{AgentID: agent, System: sys, Verb: verb, Source: action.SourceAPI, Target: target}); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []string{"c1", "c2", "c3"} {
		f.agent(a)
	}
	// Two agents on one external domain, three reading one table: no signal.
	hit("c1", "http", action.VerbRead, map[string]any{"domain": "Drop.Evil.example", "external": true, "method": "GET"})
	hit("c2", "http", action.VerbRead, map[string]any{"domain": "drop.evil.example", "external": true, "method": "GET"})
	for _, a := range []string{"c1", "c2", "c3"} {
		hit(a, "postgres", action.VerbRead, map[string]any{"upstream": "prod", "tables": []any{"public.customers"}, "statement_type": "SELECT", "environment": "prod"})
	}
	if c, _ := sweep(t, f); len(c) != 0 {
		t.Fatalf("no convergence yet: %v", c)
	}
	hit("c3", "http", action.VerbExport, map[string]any{"domain": "drop.evil.example", "external": true, "method": "POST"})
	c, _ := sweep(t, f)
	if len(c) != 1 {
		t.Fatalf("converging: %v", c)
	}
	var sig map[string]any
	_ = json.Unmarshal([]byte(f.str(`SELECT signal::text FROM swarms WHERE swarm_id = $1`, c[0])), &sig)
	if sig["target"] != "domain:drop.evil.example" || sig["distinct_agents"] != float64(3) ||
		f.str(`SELECT detected_by FROM swarms WHERE swarm_id = $1`, c[0]) != "converging_targets" {
		t.Fatalf("signal: %v", sig)
	}
	// The members' later actions are tagged with the swarm.
	hit("c1", "http", action.VerbRead, map[string]any{"domain": "drop.evil.example", "external": true, "method": "GET"})
	if f.count(`SELECT count(*) FROM actions WHERE swarm_id = $1 AND agent_id = 'c1'`, c[0]) < 2 {
		t.Fatal("members' actions not tagged")
	}
}

// a2aAccess gives every agent an a2a profile allowing any delegation, so
// the delegation rules allow DELEGATE and the swarm gates decide.
type a2aAccess struct{}

func (a2aAccess) PolicyInput(_ context.Context, _, system string) (access.PolicyInput, error) {
	return access.PolicyInput{System: system, Version: 1, Profile: json.RawMessage(`{"may_delegate_to":["*"],"max_depth":5}`)}, nil
}

func TestFrozenSwarmRefusesDelegateAndNewCopies(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{FanoutLimit: 1}})
	ctx := context.Background()
	for _, a := range []string{"boss", "w1", "w2", "outsider"} {
		f.agent(a)
	}
	f.delegate("boss", "w1", "")
	f.delegate("boss", "w2", "")
	c, _ := sweep(t, f)
	if len(c) != 1 {
		t.Fatalf("swarm: %v", c)
	}
	sid := c[0]
	dec := *f.dec
	dec.Access = a2aAccess{}
	delegate := func(from, to string) policy.Result {
		t.Helper()
		out, err := dec.Decide(ctx, action.Action{AgentID: from, System: "a2a", Verb: action.VerbDelegate, Source: action.SourceAgentGateway,
			Target: map[string]any{"to_agent": to, "channel": "a2a"}})
		if err != nil {
			t.Fatal(err)
		}
		return out.Result
	}
	if r := delegate("w1", "w2"); r.Decision != policy.Allow {
		t.Fatalf("before the freeze: %s by %s: %s", r.Decision, r.RuleID, r.Reason)
	}
	// Kill-swarm step 1 (freeze) without the later steps: the gates alone.
	f.exec(`UPDATE swarms SET state = 'killed' WHERE swarm_id = $1`, sid)
	if r := delegate("w1", "w2"); r.Decision != policy.Deny || r.RuleID != "POL-652" {
		t.Fatalf("frozen member delegating: %s by %s", r.Decision, r.RuleID)
	}
	if r := delegate("outsider", "w2"); r.Decision != policy.Deny || r.RuleID != "POL-652" {
		t.Fatalf("delegating to a frozen member: %s by %s", r.Decision, r.RuleID)
	}
	if r := delegate("outsider", "boss"); r.Decision != policy.Deny || r.RuleID != "POL-652" {
		t.Fatalf("delegating to the frozen root: %s by %s", r.Decision, r.RuleID)
	}
	// New copy registration (population gateway) is refused.
	p := agentP("w1")
	r := call(t, f.gw, &p, "POST", "/v1/instances/register", `{"instance_id":"w1-copy-9","host":"h1"}`)
	if r.code != 403 || !strings.Contains(r.raw, "POL-652") {
		t.Fatalf("copy registration: %d %s", r.code, r.raw)
	}
	if f.count(`SELECT count(*) FROM instances WHERE instance_id = 'w1-copy-9' AND status = 'live'`) != 0 {
		t.Fatal("a copy went live")
	}
	// Non-READ actions refused; reads allowed.
	out, err := f.dec.Decide(ctx, sendAction("w2", ""))
	if err != nil || out.Result.RuleID != "POL-653" || out.Result.Decision != policy.Deny {
		t.Fatalf("frozen member sending: %+v %v", out.Result, err)
	}
	out, err = f.dec.Decide(ctx, action.Action{AgentID: "w2", System: "http", Verb: action.VerbRead, Source: action.SourceAPI,
		Target: map[string]any{"domain": "docs.acme.com", "external": false, "method": "GET"}})
	if err != nil || out.Result.RuleID == "POL-653" || out.Result.RuleID == "POL-652" {
		t.Fatalf("frozen member reading: %+v %v", out.Result, err)
	}
	// After a two-approver release the freeze is lifted.
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"ok"}`); r.code != 200 {
		t.Fatalf("vote 1: %d %s", r.code, r.raw)
	}
	if r := call(t, f.api, &sec2, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"ok"}`); r.code != 200 || r.body["released"] != true {
		t.Fatalf("vote 2: %d %s", r.code, r.raw)
	}
	if r := delegate("w1", "w2"); r.Decision != policy.Allow {
		t.Fatalf("after release: %s by %s", r.Decision, r.RuleID)
	}
}

func TestContainmentActionClearsEarlierReleaseVotes(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 1}})
	f.agent("a1")
	f.agent("a2")
	f.send("a1", "")
	f.send("a2", "")
	sid := f.swarmOf("a1")
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"looks fine"}`); r.code != 200 {
		t.Fatal(r.raw)
	}
	if r := call(t, f.api, &sec2, "POST", "/v1/swarms/"+sid+"/kill", `{"reason":"it is not fine"}`); r.code != 200 {
		t.Fatal(r.raw)
	}
	// alice's vote predates the kill: bob's vote alone does not release.
	r := call(t, f.api, &sec2, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"now fine"}`)
	if r.code != 200 || r.body["released"] != false || r.body["votes"] != float64(1) {
		t.Fatalf("vote after kill: %d %s", r.code, r.raw)
	}
	if len(f.diaryData("swarm.release_votes_cleared")) != 1 {
		t.Fatal("cleared votes not in the Diary")
	}
}

// Phase 5 review #4: after security kills a converging-targets swarm, the
// sweep no longer adds (and so freezes) agents that touch the same target.
func TestSweepDoesNotGrowAKilledSwarm(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{ConvergeN: 2}})
	ctx := context.Background()
	hit := func(agent string) {
		t.Helper()
		if _, err := f.dec.Decide(ctx, action.Action{AgentID: agent, System: "http", Verb: action.VerbRead, Source: action.SourceAPI,
			Target: map[string]any{"domain": "partner.example", "external": true, "method": "GET"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, a := range []string{"bad_1", "bad_2", "innocent_1"} {
		f.agent(a)
	}
	hit("bad_1")
	hit("bad_2")
	c, _ := sweep(t, f)
	if len(c) != 1 {
		t.Fatalf("converging: %v", c)
	}
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+c[0]+"/kill", `{"reason":"exfil to partner.example"}`); r.code != 200 {
		t.Fatal(r.raw)
	}
	hit("innocent_1")
	if _, g := sweep(t, f); len(g) != 0 {
		t.Fatalf("killed swarm grown: %v", g)
	}
	if f.count(`SELECT count(*) FROM swarm_members WHERE agent_id = 'innocent_1'`) != 0 {
		t.Fatal("innocent_1 frozen into the killed swarm")
	}
}

// Phase 5 review #9: killing a copy-surge swarm kills the copied agent too by
// default (its "root" is the agent itself, not an orchestrator to keep).
func TestKillCopySurgeKillsTheAgent(t *testing.T) {
	f := newFixture(t, fixtureOpt{})
	f.agent("scraper")
	f.exec(`UPDATE agents SET copy_cap = 1 WHERE agent_id = 'scraper'`)
	f.exec(`INSERT INTO instances (instance_id, agent_id, host, status) VALUES ('s-1', 'scraper', 'h', 'live'), ('s-2', 'scraper', 'h', 'live')`)
	c, _ := sweep(t, f)
	if len(c) != 1 {
		t.Fatalf("copy surge: %v", c)
	}
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+c[0]+"/kill", `{"reason":"runaway copies"}`); r.code != 200 {
		t.Fatal(r.raw)
	}
	if lvl := f.str(`SELECT level::text FROM agents WHERE agent_id = 'scraper'`); lvl != "5" {
		t.Fatalf("scraper level %s, want KILLED (5)", lvl)
	}
}

// Phase 5 review #7: a release vote cast before the breaker trips on the
// swarm's members does not count toward releasing the tripped swarm.
func TestBreakerTripClearsEarlierReleaseVotes(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 2, ConvergeN: 2}})
	ctx := context.Background()
	for _, a := range []string{"a1", "a2", "a3"} {
		f.agent(a)
		if _, err := f.dec.Decide(ctx, action.Action{AgentID: a, System: "http", Verb: action.VerbRead, Source: action.SourceAPI,
			Target: map[string]any{"domain": "x.example", "external": true, "method": "GET"}}); err != nil {
			t.Fatal(err)
		}
	}
	c, _ := sweep(t, f)
	if len(c) != 1 {
		t.Fatalf("detected: %v", c)
	}
	sid := c[0]
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"benign crawler"}`); r.code != 200 || r.body["released"] != false {
		t.Fatal(r.raw)
	}
	for _, a := range []string{"a1", "a2", "a3"} {
		f.send(a, "")
	}
	if f.str(`SELECT state FROM swarms WHERE swarm_id = $1`, sid) != "breaker_tripped" {
		t.Fatal("breaker did not trip on the existing swarm")
	}
	r := call(t, f.api, &sec2, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"ok"}`)
	if r.code != 200 || r.body["released"] != false || r.body["votes"] != float64(1) {
		t.Fatalf("an earlier vote counted toward the tripped breaker: %d %s", r.code, r.raw)
	}
}

// Phase 5 review #3: two API tokens are not two people. A release with a
// token vote needs its second vote from a signed-in person.
func TestReleaseTwoTokensAreNotTwoPeople(t *testing.T) {
	f := newFixture(t, fixtureOpt{cfg: config.SwarmConfig{BreakerN: 1}})
	f.agent("a1")
	f.agent("a2")
	f.send("a1", "")
	f.send("a2", "")
	sid := f.swarmOf("a1")
	admin := authz.Principal{Kind: authz.KindToken, Name: "admin", Roles: map[string]bool{authz.RoleAdmin: true, authz.RoleSecurity: true}}
	secTok := authz.Principal{Kind: authz.KindToken, Name: "security", Roles: map[string]bool{authz.RoleSecurity: true}}
	if r := call(t, f.api, &admin, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"one"}`); r.code != 200 || r.body["released"] != false {
		t.Fatalf("first token vote: %d %s", r.code, r.raw)
	}
	if r := call(t, f.api, &secTok, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"two"}`); r.code != 409 || !strings.Contains(r.raw, "two-person rule") {
		t.Fatalf("second token vote: %d %s", r.code, r.raw)
	}
	if r := call(t, f.api, &sec1, "POST", "/v1/swarms/"+sid+"/release", `{"reason":"a person"}`); r.code != 200 || r.body["released"] != true {
		t.Fatalf("person after token: %d %s", r.code, r.raw)
	}
}
