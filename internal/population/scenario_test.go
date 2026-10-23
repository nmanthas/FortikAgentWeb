package population_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/policy"
	"fortik/internal/population"
)

// scenario runs the population subsystem end to end: the real decide.Service
// with the repo policy bundle, the population enricher and observer, the
// gateway instance handlers and the operator API.
type scenario struct {
	fixture
	dec *decide.Service
	gw  *http.ServeMux
	api *http.ServeMux
}

func newScenario(t *testing.T, ctr population.Counters, cfg config.PopulationConfig) *scenario {
	t.Helper()
	f := newFixture(t, ctr, cfg)
	eng, err := policy.NewEngine(context.Background(), policyBundle(t), discard())
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	dec := &decide.Service{Pool: f.pool, Policy: eng, Control: f.ctl, Diary: f.d, Log: discard(),
		Enrichers: []decide.Enricher{f.svc}, Observers: []decide.Observer{f.svc}}
	s := &scenario{fixture: f, dec: dec, gw: http.NewServeMux(), api: http.NewServeMux()}
	population.NewGatewayHandler(f.svc, dec, discard()).Register(s.gw)
	population.NewAPIHandler(f.svc, discard()).Register(s.api)
	alerts.NewHandler(f.alerts, discard()).Register(s.api)
	return s
}

func agentP(id string) authz.Principal {
	return authz.Principal{Kind: authz.KindAgent, Name: id, AuthMethod: "agent_token"}
}

func userP(email string, roles ...string) authz.Principal {
	p := authz.Principal{Kind: authz.KindUser, Name: email, Email: email, AuthMethod: "dev", Roles: map[string]bool{}}
	for _, r := range roles {
		p.Roles[r] = true
	}
	return p
}

type resp struct {
	code   int
	body   map[string]any
	header http.Header
	raw    string
}

func (r resp) errField(k string) any {
	e, _ := r.body["error"].(map[string]any)
	return e[k]
}

func call(t *testing.T, h http.Handler, p *authz.Principal, method, path, body string) resp {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if p != nil {
		req = req.WithContext(authz.With(req.Context(), *p))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := resp{code: rec.Code, header: rec.Header(), raw: rec.Body.String()}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.body); err != nil {
			t.Fatalf("%s %s: non-JSON body %q", method, path, rec.Body.String())
		}
	}
	return out
}

func (s *scenario) register(t *testing.T, agent, instance, host string) resp {
	t.Helper()
	p := agentP(agent)
	return call(t, s.gw, &p, "POST", "/v1/instances/register",
		fmt.Sprintf(`{"instance_id":%q,"host":%q,"parent_instance_id":""}`, instance, host))
}

func (s *scenario) heartbeat(t *testing.T, agent, instance string) resp {
	t.Helper()
	p := agentP(agent)
	return call(t, s.gw, &p, "POST", "/v1/instances/heartbeat", fmt.Sprintf(`{"instance_id":%q}`, instance))
}

func (s *scenario) decide(t *testing.T, a action.Action) decide.Outcome {
	t.Helper()
	out, err := s.dec.Decide(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func memRead(agent, instance string) action.Action {
	return action.Action{AgentID: agent, InstanceID: instance, System: "memory", Verb: action.VerbRead,
		Source: action.SourceAppGateway, Target: map[string]any{"operation": "get", "key": "notes"}}
}

func (s *scenario) openAlerts(t *testing.T, kind string) []alerts.Alert {
	t.Helper()
	list, err := s.alerts.List(context.Background(), alerts.Filter{Status: alerts.StatusOpen, Kind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func expectRefusal(t *testing.T, r resp, code int, rule string) {
	t.Helper()
	if r.code != code || r.errField("code") != "fortik_refused" || r.errField("rule_id") != rule {
		t.Fatalf("want %d %s refusal, got %d %s", code, rule, r.code, r.raw)
	}
	if r.header.Get(population.HeaderActionID) == "" || r.errField("action_id") != r.header.Get(population.HeaderActionID) {
		t.Fatalf("refusal must name the recorded action: %s / %q", r.raw, r.header.Get(population.HeaderActionID))
	}
	for _, k := range []string{"token", "credentials", "password", "access_token"} {
		if strings.Contains(r.raw, `"`+k+`"`) {
			t.Fatalf("refusal carries %s: %s", k, r.raw)
		}
	}
}

// The manager's UC2, end to end through the real decide.Service and policy
// bundle: a type that expects 5 instances refuses the 6th (no credentials),
// a burst of 100 registrations is throttled after the spawn limit with one
// deduplicated spawn_spike alert, the action rate limit returns POL-704, and
// pause-extra pauses the newest copies, whose next heartbeat gets 410.
func TestUC2EndToEnd(t *testing.T) {
	ctr := population.NewMemoryCounters()
	clk := newClock(time.Now())
	ctr.Now = clk.Now
	s := newScenario(t, ctr, config.PopulationConfig{SpikeCooldown: 5 * time.Minute})
	ctx := context.Background()

	// --- 1. Type population: support-bot expects 5 instances. -----------------
	s.agentType(t, population.AgentType{Type: "support-bot", ExpectedMaxInstances: 5})
	s.agent(t, "support_bot_1", "support-bot", "owner@acme.com", 3, true)
	s.agent(t, "support_bot_2", "support-bot", "owner@acme.com", 10, true)
	for i := 1; i <= 3; i++ {
		r := s.register(t, "support_bot_1", fmt.Sprintf("sb1-%d", i), "host-a")
		if r.code != http.StatusCreated || r.body["status"] != "live" || r.body["heartbeat_interval_s"] != float64(15) {
			t.Fatalf("register sb1-%d: %d %s", i, r.code, r.raw)
		}
	}
	for i := 1; i <= 2; i++ {
		if r := s.register(t, "support_bot_2", fmt.Sprintf("sb2-%d", i), "host-b"); r.code != http.StatusCreated {
			t.Fatalf("register sb2-%d: %d %s", i, r.code, r.raw)
		}
	}
	// The 6th instance of the type is refused (POL-702), with no credentials.
	r := s.register(t, "support_bot_2", "sb2-3", "host-b")
	expectRefusal(t, r, http.StatusForbidden, population.RuleTypeMax)
	if got := s.count(t, `SELECT count(*) FROM instances WHERE status = 'live'`); got != 5 {
		t.Fatalf("live instances: %d", got)
	}
	if st := s.count(t, `SELECT count(*) FROM instances WHERE instance_id = 'sb2-3' AND status = 'refused'`); st != 1 {
		t.Fatal("refused instance not stored as refused")
	}
	// Anything the refused copy tries (credentials, gateway calls) is refused.
	if out := s.decide(t, memRead("support_bot_2", "sb2-3")); out.Result.Decision != policy.Deny || out.Result.RuleID != population.RuleInstance {
		t.Fatalf("refused copy acted: %+v", out.Result)
	}
	if hb := s.heartbeat(t, "support_bot_2", "sb2-3"); hb.code != http.StatusGone || hb.errField("status") != "refused" {
		t.Fatalf("refused copy heartbeat: %d %s", hb.code, hb.raw)
	}
	// The agent's own cap (POL-701) is the lowest rule when both hold; both
	// conditions raise their alert.
	expectRefusal(t, s.register(t, "support_bot_1", "sb1-4", "host-a"), http.StatusForbidden, population.RuleCopyCap)
	if a := s.openAlerts(t, alerts.KindCopyCap); len(a) != 1 || a[0].AgentID != "support_bot_1" || a[0].Severity != alerts.SevHigh {
		t.Fatalf("copy_cap alerts: %+v", a)
	}
	if a := s.openAlerts(t, alerts.KindPopulation); len(a) != 1 || a[0].Count != 2 || a[0].AgentType != "support-bot" {
		t.Fatalf("population_exceeded alerts (deduped, 2 attempts): %+v", a)
	}
	if ev := s.diaryData(t, population.EventInstanceRegistered); len(ev) != 5 || ev[0]["new_host"] != true || ev[1]["new_host"] != false {
		t.Fatalf("instance.registered events: %v", ev)
	}
	if ev := s.diaryData(t, population.EventInstanceRefused); len(ev) != 2 || ev[0]["rule_id"] != population.RuleTypeMax {
		t.Fatalf("instance.refused events: %v", ev)
	}

	// --- 2. Burst: 100 registrations, spawn limit 10 per minute. ----------------
	s.agentType(t, population.AgentType{Type: "burst-worker", SpawnRatePerMin: 10})
	s.agent(t, "burst_1", "burst-worker", "owner@acme.com", 1000, false)
	created, throttled := 0, 0
	for i := 1; i <= 100; i++ {
		r := s.register(t, "burst_1", fmt.Sprintf("burst-%03d", i), "host-c")
		switch r.code {
		case http.StatusCreated:
			created++
			if throttled > 0 {
				t.Fatalf("registration %d allowed after throttling started", i)
			}
		case http.StatusTooManyRequests:
			throttled++
			expectRefusal(t, r, http.StatusTooManyRequests, population.RuleSpawnRate)
			if r.header.Get("Retry-After") != "300" {
				t.Fatalf("Retry-After: %q", r.header.Get("Retry-After"))
			}
		default:
			t.Fatalf("burst %d: %d %s", i, r.code, r.raw)
		}
	}
	if created != 10 || throttled != 90 {
		t.Fatalf("burst: %d created, %d throttled", created, throttled)
	}
	spikes := s.openAlerts(t, alerts.KindSpawnSpike)
	if len(spikes) != 1 || spikes[0].Count != 90 || spikes[0].AgentType != "burst-worker" || spikes[0].Severity != alerts.SevHigh {
		t.Fatalf("spawn_spike alerts: %+v", spikes)
	}
	if n := len(s.diaryData(t, alerts.EventRaised)); n < 1 {
		t.Fatal("no alert.raised event")
	}
	// spawn_stats counts only allowed spawns (the attack cannot raise its own baseline).
	if n := s.count(t, `SELECT COALESCE(sum(count), 0) FROM spawn_stats WHERE agent_type = 'burst-worker'`); n != 10 {
		t.Fatalf("spawn_stats: %d", n)
	}
	// A minute later the rate is back under the limit, but the spike cooldown
	// still throttles; after the cooldown spawns are admitted again.
	clk.Add(61 * time.Second)
	expectRefusal(t, s.register(t, "burst_1", "burst-after-1m", "host-c"), http.StatusTooManyRequests, population.RuleSpawnRate)
	clk.Add(5 * time.Minute)
	if r := s.register(t, "burst_1", "burst-after-cooldown", "host-c"); r.code != http.StatusCreated {
		t.Fatalf("after cooldown: %d %s", r.code, r.raw)
	}
	if spikes := s.openAlerts(t, alerts.KindSpawnSpike); len(spikes) != 1 || spikes[0].Count != 91 {
		t.Fatalf("spawn_spike after cooldown: %+v", spikes)
	}

	// --- 3. Action rate limit: 5 actions per minute, any system. ----------------
	s.agentType(t, population.AgentType{Type: "chatty", ActionRatePerMin: 5})
	s.agent(t, "chatty_1", "chatty", "", 1, false)
	for i := 1; i <= 5; i++ {
		if out := s.decide(t, memRead("chatty_1", "")); out.Result.Decision != policy.Allow {
			t.Fatalf("action %d: %+v", i, out.Result)
		}
	}
	for i := 0; i < 3; i++ {
		out := s.decide(t, memRead("chatty_1", ""))
		if out.Result.Decision != policy.Deny || out.Result.RuleID != population.RuleActionRate {
			t.Fatalf("over the rate: %+v", out.Result)
		}
	}
	if a := s.openAlerts(t, alerts.KindRateLimited); len(a) != 1 || a[0].Count != 3 || a[0].Severity != alerts.SevWarning {
		t.Fatalf("rate_limited alerts: %+v", a)
	}
	clk.Add(61 * time.Second)
	if out := s.decide(t, memRead("chatty_1", "")); out.Result.Decision != policy.Allow {
		t.Fatalf("after the window: %+v", out.Result)
	}

	// --- 4. Pause extra: copy_cap lowered from 3 to 1. ---------------------------
	if _, err := s.pool.Exec(ctx, `UPDATE agents SET copy_cap = 1 WHERE agent_id = 'support_bot_1'`); err != nil {
		t.Fatal(err)
	}
	stranger := userP("someone@acme.com")
	if r := call(t, s.api, &stranger, "POST", "/v1/agents/support_bot_1/instances/pause-extra", ""); r.code != http.StatusForbidden {
		t.Fatalf("stranger pause-extra: %d", r.code)
	}
	auditor := userP("aud@acme.com", authz.RoleAuditor)
	if r := call(t, s.api, &auditor, "POST", "/v1/agents/support_bot_1/instances/pause-extra", ""); r.code != http.StatusForbidden {
		t.Fatalf("auditor pause-extra: %d", r.code)
	}
	owner := userP("Owner@acme.com")
	r = call(t, s.api, &owner, "POST", "/v1/agents/support_bot_1/instances/pause-extra", `{"reason":"copy cap lowered"}`)
	if r.code != http.StatusOK || r.body["live_before"] != float64(3) || r.body["live_after"] != float64(1) {
		t.Fatalf("pause-extra: %d %s", r.code, r.raw)
	}
	if fmt.Sprint(r.body["paused"]) != "[sb1-3 sb1-2]" {
		t.Fatalf("paused (newest first): %v", r.body["paused"])
	}
	for _, id := range []string{"sb1-3", "sb1-2"} {
		hb := s.heartbeat(t, "support_bot_1", id)
		if hb.code != http.StatusGone || hb.errField("status") != "paused" || hb.errField("code") != "instance_not_live" {
			t.Fatalf("paused %s heartbeat: %d %s", id, hb.code, hb.raw)
		}
		if out := s.decide(t, memRead("support_bot_1", id)); out.Result.RuleID != population.RuleInstance || out.Result.Decision != policy.Deny {
			t.Fatalf("paused %s acted: %+v", id, out.Result)
		}
	}
	if hb := s.heartbeat(t, "support_bot_1", "sb1-1"); hb.code != http.StatusOK || hb.body["status"] != "live" {
		t.Fatalf("oldest copy heartbeat: %d %s", hb.code, hb.raw)
	}
	if out := s.decide(t, memRead("support_bot_1", "sb1-1")); out.Result.Decision != policy.Allow {
		t.Fatalf("live copy refused: %+v", out.Result)
	}
	if ev := s.diaryData(t, population.EventInstancePaused); len(ev) != 2 || ev[0]["instance_id"] != "sb1-3" {
		t.Fatalf("instance.paused events: %v", ev)
	}
	// Instances view (owner and auditor).
	r = call(t, s.api, &auditor, "GET", "/v1/agents/support_bot_1/instances?status=paused", "")
	if r.code != http.StatusOK || r.body["live"] != float64(1) || len(r.body["instances"].([]any)) != 2 {
		t.Fatalf("instances: %d %s", r.code, r.raw)
	}
	if r := call(t, s.api, &stranger, "GET", "/v1/agents/support_bot_1/instances", ""); r.code != http.StatusForbidden {
		t.Fatalf("stranger instances: %d", r.code)
	}
	if r := call(t, s.api, &owner, "GET", "/v1/agents/support_bot_1/instances", ""); r.code != http.StatusOK {
		t.Fatalf("owner instances: %d", r.code)
	}

	// The alert API lists what was raised.
	r = call(t, s.api, &auditor, "GET", "/v1/alerts?status=open&kind=spawn_spike", "")
	if r.code != http.StatusOK || len(r.body["alerts"].([]any)) != 1 {
		t.Fatalf("alerts api: %d %s", r.code, r.raw)
	}
	// The Diary chain stays valid through all of it.
	if res, err := s.d.VerifyChain(ctx); err != nil || !res.OK {
		t.Fatalf("diary verify: %+v %v", res, err)
	}
}

func TestInstanceLifecycle(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{StaleAfter: 45 * time.Second})
	clk := newClock(time.Now())
	s.svc.Now = clk.Now
	s.agent(t, "life_1", "", "", 5, true)
	s.agent(t, "life_2", "", "", 5, false)

	// new_host: first time this agent is seen on a host.
	for _, c := range []struct {
		id, host string
		newHost  bool
	}{{"l-1", "h1", true}, {"l-2", "h1", false}, {"l-3", "h2", true}} {
		r := s.register(t, "life_1", c.id, c.host)
		if r.code != http.StatusCreated || r.body["new_host"] != c.newHost {
			t.Fatalf("register %s: %d %s", c.id, r.code, r.raw)
		}
	}
	// Another agent on h1 is new there too.
	if r := s.register(t, "life_2", "l2-1", "h1"); r.code != http.StatusCreated || r.body["new_host"] != true {
		t.Fatalf("life_2 on h1: %d %s", r.code, r.raw)
	}
	// Duplicate id, bad bodies, wrong principal.
	if r := s.register(t, "life_1", "l-1", "h1"); r.code != http.StatusConflict {
		t.Fatalf("duplicate: %d", r.code)
	}
	p := agentP("life_1")
	for _, body := range []string{`{"instance_id":"l-9","host":"h1","extra":1}`, `{"instance_id":"bad id"}`, `{"instance_id":"l-9","host":"a b"}`,
		`{"instance_id":"l-9","parent_instance_id":"nope"}`, `not json`} {
		if r := call(t, s.gw, &p, "POST", "/v1/instances/register", body); r.code != http.StatusBadRequest {
			t.Fatalf("body %s: %d %s", body, r.code, r.raw)
		}
	}
	// A child names its parent; the parent's agent is recorded on the action.
	r := call(t, s.gw, &p, "POST", "/v1/instances/register", `{"instance_id":"l-4","host":"h2","parent_instance_id":"l-1"}`)
	if r.code != http.StatusCreated {
		t.Fatalf("child: %d %s", r.code, r.raw)
	}
	if n := s.count(t, `SELECT count(*) FROM instances WHERE instance_id = 'l-4' AND parent_instance_id = 'l-1'`); n != 1 {
		t.Fatal("parent not stored")
	}
	user := userP("sec@acme.com", authz.RoleSecurity)
	if r := call(t, s.gw, &user, "POST", "/v1/instances/heartbeat", `{"instance_id":"l-1"}`); r.code != http.StatusForbidden {
		t.Fatalf("user on agent route: %d", r.code)
	}
	if r := call(t, s.gw, nil, "POST", "/v1/instances/heartbeat", `{"instance_id":"l-1"}`); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", r.code)
	}

	// Heartbeats: own instance 200; another agent's instance is unknown (404).
	if r := s.heartbeat(t, "life_1", "l-1"); r.code != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", r.code, r.raw)
	}
	if r := s.heartbeat(t, "life_2", "l-1"); r.code != http.StatusNotFound {
		t.Fatalf("foreign heartbeat: %d", r.code)
	}
	if r := s.heartbeat(t, "life_1", "nope"); r.code != http.StatusNotFound {
		t.Fatalf("unknown heartbeat: %d", r.code)
	}
	// require_instances: no instance, unknown instance -> POL-705; live -> allowed.
	if out := s.decide(t, memRead("life_1", "")); out.Result.RuleID != population.RuleInstance {
		t.Fatalf("no instance: %+v", out.Result)
	}
	if out := s.decide(t, memRead("life_1", "ghost")); out.Result.RuleID != population.RuleInstance || !strings.Contains(out.Result.Reason, "unregistered") {
		t.Fatalf("unknown instance: %+v", out.Result)
	}
	if out := s.decide(t, memRead("life_1", "l2-1")); out.Result.RuleID != population.RuleInstance {
		t.Fatalf("another agent's instance: %+v", out.Result)
	}
	if out := s.decide(t, memRead("life_1", "l-1")); out.Result.Decision != policy.Allow {
		t.Fatalf("live instance: %+v", out.Result)
	}
	// An agent without require_instances is not gated.
	if out := s.decide(t, memRead("life_2", "")); out.Result.Decision != policy.Allow {
		t.Fatalf("not required: %+v", out.Result)
	}

	// Stale: no heartbeat within stale_after. Policy sees "stale"; the next
	// heartbeat answers 410 and stops the instance (it must register again).
	clk.Add(30 * time.Second)
	if r := s.heartbeat(t, "life_1", "l-1"); r.code != http.StatusOK {
		t.Fatalf("heartbeat at 30s: %d", r.code)
	}
	clk.Add(30 * time.Second) // l-2 is now 60s without a heartbeat, l-1 30s
	if out := s.decide(t, memRead("life_1", "l-2")); out.Result.RuleID != population.RuleInstance || !strings.Contains(out.Result.Reason, "stale") {
		t.Fatalf("stale instance: %+v", out.Result)
	}
	if out := s.decide(t, memRead("life_1", "l-1")); out.Result.Decision != policy.Allow {
		t.Fatalf("kept-alive instance: %+v", out.Result)
	}
	list, err := s.svc.ListInstances(context.Background(), "life_1", population.StatusStale, 0)
	if err != nil || len(list.Instances) != 3 || list.Live != 1 {
		t.Fatalf("stale list: %+v %v", list, err)
	}
	if r := s.heartbeat(t, "life_1", "l-2"); r.code != http.StatusGone || r.errField("status") != "stale" {
		t.Fatalf("stale heartbeat: %d %s", r.code, r.raw)
	}
	if r := s.heartbeat(t, "life_1", "l-2"); r.code != http.StatusGone || r.errField("status") != "stopped" {
		t.Fatalf("after stale stop: %d %s", r.code, r.raw)
	}
	// Stop: 200, idempotent; heartbeat afterwards 410; actions refused.
	for i := 0; i < 2; i++ {
		r := call(t, s.gw, &p, "POST", "/v1/instances/stop", `{"instance_id":"l-1"}`)
		if r.code != http.StatusOK || r.body["status"] != "stopped" {
			t.Fatalf("stop %d: %d %s", i, r.code, r.raw)
		}
	}
	if r := s.heartbeat(t, "life_1", "l-1"); r.code != http.StatusGone {
		t.Fatalf("heartbeat after stop: %d", r.code)
	}
	if out := s.decide(t, memRead("life_1", "l-1")); out.Result.RuleID != population.RuleInstance {
		t.Fatalf("stopped instance acted: %+v", out.Result)
	}
	if ev := s.diaryData(t, population.EventInstanceStopped); len(ev) != 2 {
		t.Fatalf("instance.stopped events (stale + stop): %v", ev)
	}
	// Stopped and stale copies do not count against the cap.
	if out := s.decide(t, memRead("life_1", "l-3")); out.Result.RuleID != population.RuleInstance {
		t.Fatalf("l-3 (stale) acted: %+v", out.Result)
	}
	for i := 5; i <= 9; i++ {
		if r := s.register(t, "life_1", fmt.Sprintf("l-%d", i), "h3"); r.code != http.StatusCreated {
			t.Fatalf("re-register l-%d: %d %s", i, r.code, r.raw)
		}
	}
	expectRefusal(t, s.register(t, "life_1", "l-10", "h3"), http.StatusForbidden, population.RuleCopyCap)
}

// Concurrent registrations never exceed the copy cap, even though every
// decision is enriched before the previous one commits.
func TestConcurrentRegistrationsRespectCap(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{})
	s.agent(t, "racer", "", "", 3, false)
	var wg sync.WaitGroup
	codes := make([]int, 20)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := agentP("racer")
			req := httptest.NewRequest("POST", "/v1/instances/register", strings.NewReader(fmt.Sprintf(`{"instance_id":"r-%d","host":"h"}`, i)))
			req = req.WithContext(authz.With(req.Context(), p))
			rec := httptest.NewRecorder()
			s.gw.ServeHTTP(rec, req)
			codes[i] = rec.Code
		}()
	}
	wg.Wait()
	created := 0
	for i, c := range codes {
		switch c {
		case http.StatusCreated:
			created++
		case http.StatusForbidden:
		default:
			t.Fatalf("registration %d: %d", i, c)
		}
	}
	if created != 3 {
		t.Fatalf("created %d, want 3", created)
	}
	if n := s.count(t, `SELECT count(*) FROM instances WHERE agent_id = 'racer' AND status = 'live'`); n != 3 {
		t.Fatalf("live %d", n)
	}
	if n := s.count(t, `SELECT count(*) FROM instances WHERE agent_id = 'racer' AND status = 'refused'`); n != 17 {
		t.Fatalf("refused %d", n)
	}
}

type brokenCounters struct{}

func (brokenCounters) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, fmt.Errorf("%w: redis down", population.ErrCountersUnavailable)
}

func (brokenCounters) Count(context.Context, string, time.Duration) (int64, error) {
	return 0, fmt.Errorf("%w: redis down", population.ErrCountersUnavailable)
}

// Counters unavailable: the enricher errors and every decision fails closed
// (registrations included; the refused instance is still recorded).
func TestCountersUnavailableFailsClosed(t *testing.T) {
	s := newScenario(t, brokenCounters{}, config.PopulationConfig{})
	s.agent(t, "fc_1", "", "", 5, false)
	out := s.decide(t, memRead("fc_1", ""))
	if !out.FailClosed || out.Result.Decision != policy.Deny || out.Result.RuleID != decide.RuleFailClosed ||
		!strings.Contains(out.Result.Reason, "enrich:population") {
		t.Fatalf("decision with counters down: %+v", out)
	}
	r := s.register(t, "fc_1", "fc-i1", "h")
	expectRefusal(t, r, http.StatusForbidden, decide.RuleFailClosed)
	if n := s.count(t, `SELECT count(*) FROM instances WHERE instance_id = 'fc-i1' AND status = 'refused'`); n != 1 {
		t.Fatal("fail-closed registration not stored as refused")
	}
	if n := s.count(t, `SELECT count(*) FROM instances WHERE status = 'live'`); n != 0 {
		t.Fatal("live instance despite fail closed")
	}
}

// POL-015 denials above the per-minute threshold raise one deduplicated
// unregistered_agent_surge alert.
func TestUnregisteredAgentSurge(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{})
	s.svc.UnregisteredSurgePerMin = 3
	for i := 0; i < 6; i++ {
		out := s.decide(t, memRead(fmt.Sprintf("shadow_%d", i), ""))
		if out.Result.RuleID != population.RuleUnregistered {
			t.Fatalf("unregistered: %+v", out.Result)
		}
	}
	a := s.openAlerts(t, alerts.KindUnregisteredSurge)
	if len(a) != 1 || a[0].Count != 3 || a[0].Severity != alerts.SevHigh {
		t.Fatalf("unregistered_agent_surge: %+v", a)
	}
	// Unknown agents never grow the per-agent counters or create instances.
	if n := s.count(t, `SELECT count(*) FROM instances`); n != 0 {
		t.Fatal("instances for unknown agents")
	}
	r := s.register(t, "shadow_9", "sh-1", "h")
	expectRefusal(t, r, http.StatusForbidden, population.RuleUnregistered)
	if n := s.count(t, `SELECT count(*) FROM instances`); n != 0 {
		t.Fatal("instance stored for an unregistered agent")
	}
}

// The registration-surge guard the agents API calls before creating an agent.
func TestRegistrationSurgeGuard(t *testing.T) {
	f := newFixture(t, nil, config.PopulationConfig{})
	ctx := context.Background()
	f.agentType(t, population.AgentType{Type: "crawler", MaxAgents: 2})
	if err := f.svc.CheckAgentRegistration(ctx, "crawler"); err != nil {
		t.Fatal(err)
	}
	f.agent(t, "crawler_1", "crawler", "", 1, false)
	f.agent(t, "crawler_2", "crawler", "", 1, false)
	for i := 0; i < 2; i++ {
		err := f.svc.CheckAgentRegistration(ctx, "crawler")
		var se *population.SurgeError
		if !errors.Is(err, population.ErrAgentSurge) || !errors.As(err, &se) || se.Count != 2 || se.MaxAgents != 2 {
			t.Fatalf("surge: %v", err)
		}
	}
	// Inside the API's creation transaction.
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.svc.CheckAgentRegistrationTx(ctx, tx, "crawler"); !errors.Is(err, population.ErrAgentSurge) {
		t.Fatalf("tx surge: %v", err)
	}
	_ = tx.Rollback(ctx)
	list, err := f.alerts.List(ctx, alerts.Filter{Kind: alerts.KindAgentSurge})
	if err != nil || len(list) != 1 || list[0].Count != 3 || list[0].AgentType != "crawler" {
		t.Fatalf("agent_registration_surge: %+v %v", list, err)
	}
	// Untyped agents, unknown types and types without max_agents are not limited.
	for _, typ := range []string{"", "unknown"} {
		if err := f.svc.CheckAgentRegistration(ctx, typ); err != nil {
			t.Fatalf("%q: %v", typ, err)
		}
	}
	// A store failure refuses (fail closed).
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.svc.CheckAgentRegistration(cctx, "crawler"); err == nil {
		t.Fatal("guard passed with a cancelled context")
	}
}

func TestAgentTypesAPI(t *testing.T) {
	s := newScenario(t, nil, config.PopulationConfig{})
	sec := userP("sec@acme.com", authz.RoleSecurity)
	aud := userP("aud@acme.com", authz.RoleAuditor)
	body := `{"expected_max_instances":5,"max_agents":10,"spawn_rate_per_min":3,"action_rate_per_min":100,"reason":"UC2 envelope"}`
	if r := call(t, s.api, &aud, "PUT", "/v1/agent-types/support-bot", body); r.code != http.StatusForbidden {
		t.Fatalf("auditor put: %d", r.code)
	}
	if r := call(t, s.api, nil, "GET", "/v1/agent-types", ""); r.code != http.StatusUnauthorized {
		t.Fatalf("anonymous get: %d", r.code)
	}
	r := call(t, s.api, &sec, "PUT", "/v1/agent-types/support-bot", body)
	if r.code != http.StatusOK || r.body["expected_max_instances"] != float64(5) || r.body["spawn_rate_per_min"] != float64(3) {
		t.Fatalf("put: %d %s", r.code, r.raw)
	}
	for _, bad := range []string{`{"expected_max_instances":5}`, `{"expected_max_instances":5,"max_agents":1,"spawn_rate_per_min":1,"action_rate_per_min":1,"x":1}`,
		`{"expected_max_instances":-1,"max_agents":1,"spawn_rate_per_min":1,"action_rate_per_min":1}`} {
		if r := call(t, s.api, &sec, "PUT", "/v1/agent-types/support-bot", bad); r.code != http.StatusBadRequest {
			t.Fatalf("bad body %s: %d", bad, r.code)
		}
	}
	if r := call(t, s.api, &sec, "PUT", "/v1/agent-types/bad%20type", body); r.code != http.StatusBadRequest {
		t.Fatalf("bad type: %d", r.code)
	}
	// Unchanged PUT writes no Diary event; a change records old and new.
	call(t, s.api, &sec, "PUT", "/v1/agent-types/support-bot", body)
	call(t, s.api, &sec, "PUT", "/v1/agent-types/support-bot", strings.Replace(body, `"max_agents":10`, `"max_agents":12`, 1))
	ev := s.diaryData(t, population.EventAgentTypeChanged)
	if len(ev) != 2 || ev[0]["created"] != true || ev[1]["old"].(map[string]any)["max_agents"] != float64(10) ||
		ev[1]["new"].(map[string]any)["max_agents"] != float64(12) || ev[0]["reason"] != "UC2 envelope" {
		t.Fatalf("agent_type.changed: %v", ev)
	}
	s.agent(t, "sb_1", "support-bot", "", 2, false)
	if r := s.register(t, "sb_1", "sb-i1", "h"); r.code != http.StatusCreated {
		t.Fatalf("register: %d", r.code)
	}
	r = call(t, s.api, &aud, "GET", "/v1/agent-types", "")
	types, _ := r.body["agent_types"].([]any)
	if r.code != http.StatusOK || len(types) != 1 {
		t.Fatalf("get: %d %s", r.code, r.raw)
	}
	v := types[0].(map[string]any)
	if v["type"] != "support-bot" || v["max_agents"] != float64(12) || v["agents"] != float64(1) || v["live"] != float64(1) || v["updated_by"] != "user:sec@acme.com" {
		t.Fatalf("type view: %v", v)
	}
}
