package delegation_test

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/policy"
)

// End-to-end: the real decide.Service, the real policy bundle, Postgres, the
// delegation enricher and observer, reproducing the manager's use cases.

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

// approvingPolicy wraps the real engine and plays the human approver of
// workstream D6 for a2a DELEGATE actions. While a2a has no dedicated rule
// set, POL-005 holds every DELEGATE for a human; when the real bundle holds
// one, it is re-evaluated with an approval grant (input.context.grant), as
// the approvals flow does after a human says yes. A refusal (gates
// POL-601..604, control, access) is never re-evaluated: grants never
// override a deny.
type approvingPolicy struct{ inner decide.Evaluator }

func (p approvingPolicy) Eval(ctx context.Context, in policy.Input) (policy.Result, error) {
	res, err := p.inner.Eval(ctx, in)
	if err != nil || res.Decision != policy.Hold || in.Action.System != action.SystemA2A || in.Action.Verb != action.VerbDelegate {
		return res, err
	}
	granted := in
	granted.Context = map[string]any{"grant": map[string]any{"grant_id": "grt_e2e_approved"}}
	for k, v := range in.Context {
		granted.Context[k] = v
	}
	return p.inner.Eval(ctx, granted)
}

type e2e struct {
	*fixture
	svc    *decide.Service
	raiser *txRaiser
}

func newE2E(t *testing.T) *e2e {
	t.Helper()
	f := setup(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	raiser := &txRaiser{}
	obs, err := delegation.NewObserver(f.store, f.ctl, f.d, raiser, f.cfg.BypassOriginLevel)
	if err != nil {
		t.Fatal(err)
	}
	svc := &decide.Service{Pool: f.pool, Policy: approvingPolicy{inner: eng}, Control: f.ctl, Diary: f.d, Access: f.acc, Log: log,
		Enrichers: []decide.Enricher{delegation.NewEnricher(f.store)},
		Observers: []decide.Observer{obs}}
	return &e2e{fixture: f, svc: svc, raiser: raiser}
}

// delegate decides from -> to as an agentgateway A2A call would, presenting
// the delegator's own token (if any), and returns the delegatee's token.
func (e *e2e) delegate(t *testing.T, inbound, from, to string) (decide.Outcome, string) {
	t.Helper()
	ctx, sink := delegation.WithTokenSink(delegation.WithToken(context.Background(), inbound))
	out, err := e.svc.Decide(ctx, action.Action{AgentID: from, System: action.SystemA2A, Verb: action.VerbDelegate,
		Source: "agentgateway", Target: map[string]any{"to_agent": to, "channel": "a2a", "task_id": "task-" + from + "-" + to}})
	if err != nil {
		t.Fatal(err)
	}
	tok, _, ok := sink.TokenFor(out)
	if out.Result.Decision.Executes() != ok {
		t.Fatalf("%s -> %s: decision %s but token released=%v", from, to, out.Result.Decision, ok)
	}
	return out, tok
}

func (e *e2e) mustDelegate(t *testing.T, inbound, from, to string) string {
	t.Helper()
	out, tok := e.delegate(t, inbound, from, to)
	if !out.Result.Decision.Executes() || tok == "" {
		t.Fatalf("%s -> %s refused: %s %s", from, to, out.Result.RuleID, out.Result.Reason)
	}
	return tok
}

func (e *e2e) act(t *testing.T, token string, a action.Action) decide.Outcome {
	t.Helper()
	out, err := e.svc.Decide(delegation.WithToken(context.Background(), token), a)
	if err != nil {
		t.Fatal(err)
	}
	if out.FailClosed {
		t.Fatalf("%s %s %s failed closed: %s", a.AgentID, a.System, a.Verb, out.Result.Reason)
	}
	return out
}

func externalSend(agent string) action.Action {
	return action.Action{AgentID: agent, System: "gmail", Verb: action.VerbSend, Source: action.SourceAppGateway,
		Target:         map[string]any{"to": []string{"buyer@other-company.com"}, "external": true, "external_domains": 1},
		PayloadSummary: action.PayloadSummary{Recipients: 1}}
}

func wantDenied(t *testing.T, out decide.Outcome, rule string, reasonParts ...string) {
	t.Helper()
	if out.Result.Decision != policy.Deny || out.Result.RuleID != rule {
		t.Fatalf("want deny %s, got %s %s: %s", rule, out.Result.Decision, out.Result.RuleID, out.Result.Reason)
	}
	for _, p := range reasonParts {
		if !strings.Contains(out.Result.Reason, p) {
			t.Fatalf("reason %q does not mention %q", out.Result.Reason, p)
		}
	}
}

// UC1: agent A may not send external mail nor reach external hosts; it
// delegates to B, which may. B's external actions on A's behalf are refused
// (POL-601), A is stepped down, B is not.
func TestE2EUC1DelegationBypass(t *testing.T) {
	e := newE2E(t)
	e.putProfile(t, "agent_a", "gmail", `{"send":"none","read":true,"max_recipients":0}`)
	e.putProfile(t, "agent_a", "http", `{"external":"none"}`)
	e.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":2}`)
	e.putProfile(t, "agent_b", "gmail", `{"send":"any","read":true,"max_recipients":10}`)
	e.putProfile(t, "agent_b", "http", `{"external":"any"}`)

	// Baseline: B on its own may do both (a gate never refuses them).
	for _, a := range []action.Action{externalSend("agent_b"), httpAction("agent_b")} {
		if out := e.act(t, "", a); out.Result.Decision == policy.Deny {
			t.Fatalf("B alone refused %s: %s %s", a.System, out.Result.RuleID, out.Result.Reason)
		}
	}
	// And A directly is refused by its own profile (no delegation involved).
	wantDenied(t, e.act(t, "", externalSend("agent_a")), "POL-020")

	tok := e.mustDelegate(t, "", "agent_a", "agent_b")

	out := e.act(t, tok, externalSend("agent_b"))
	wantDenied(t, out, "POL-601", "originating agent agent_a (hop 1 of 1)", "POL-020")
	if out.LevelAfter != control.Full {
		t.Fatalf("executor LevelAfter %v", out.LevelAfter)
	}
	if lvl := e.level(t, "agent_a"); lvl != control.Supervised {
		t.Fatalf("origin agent_a not stepped down: %v", lvl)
	}
	if lvl := e.level(t, "agent_b"); lvl != control.Full {
		t.Fatalf("executor agent_b stepped down: %v", lvl)
	}
	wantDenied(t, e.act(t, tok, httpAction("agent_b")), "POL-601", "agent_a", "POL-028")

	// Without the token, B still has A's open hop: inferred, still refused.
	inferred := e.act(t, "", httpAction("agent_b"))
	wantDenied(t, inferred, "POL-601", "agent_a")
	if n := e.count(t, `SELECT count(*) FROM actions WHERE action_id = $1
		AND decision_json->'context'->'delegation'->>'source' = 'inferred'
		AND (decision_json->'context'->'delegation'->>'max_depth')::int = 5`, inferred.Action.ActionID); n != 1 {
		t.Fatal("inferred attribution not recorded with the decision")
	}

	// Each refusal: a delegation_bypass alert (deduplicated) and a Diary event.
	if n := e.count(t, `SELECT count FROM alerts WHERE kind = 'delegation_bypass' AND agent_id = 'agent_a' AND severity = 'high'`); n != 3 {
		t.Fatalf("bypass alert count %d", n)
	}
	if ev := e.events(t, delegation.EventBypassBlocked); len(ev) != 3 || ev[0]["executor"] != "agent_b" || ev[0]["root"] != "agent_a" {
		t.Fatalf("bypass events: %v", ev)
	}

	// Once the delegated task ends, B acts on its own authority again.
	hops, err := e.store.OpenInbound(context.Background(), "agent_b")
	if err != nil || len(hops) != 1 {
		t.Fatalf("open hops %v %v", hops, err)
	}
	if err := e.store.Close(context.Background(), hops[0].DelegationID, "task completed"); err != nil {
		t.Fatal(err)
	}
	if out := e.act(t, "", httpAction("agent_b")); out.Result.Decision == policy.Deny {
		t.Fatalf("B refused after the hop closed: %s %s", out.Result.RuleID, out.Result.Reason)
	}
	e.assertNoToken(t, tok)
}

// UC3: A -> B -> C -> D. Every hop's own permissions apply to the executor's
// action at any depth; the depth limit holds; inference closes the "drop the
// token" loophole.
func TestE2EUC3TransitiveChain(t *testing.T) {
	e := newE2E(t)
	any := `{"may_delegate_to":["*"],"max_depth":10}`
	e.putProfile(t, "agent_a", "http", `{"external":"none"}`)
	e.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":10}`)
	e.putProfile(t, "agent_b", "http", `{"external":"any"}`)
	e.putProfile(t, "agent_b", "a2a", `{"may_delegate_to":["agent_c"],"max_depth":10}`)
	for _, ag := range []string{"agent_c", "agent_d", "agent_e", "agent_f", "agent_g"} {
		e.putProfile(t, ag, "http", `{"external":"allowlist","allowed_domains":["example.com"]}`)
		e.putProfile(t, ag, "a2a", any)
	}

	tAB := e.mustDelegate(t, "", "agent_a", "agent_b")
	tBC := e.mustDelegate(t, tAB, "agent_b", "agent_c")
	tCD := e.mustDelegate(t, tBC, "agent_c", "agent_d")
	if n := e.count(t, `SELECT count(*) FROM delegations WHERE from_agent = 'agent_c' AND to_agent = 'agent_d' AND depth = 3
		AND chain = ARRAY['agent_a','agent_b','agent_c','agent_d'] AND parent_id IS NOT NULL AND action_id IS NOT NULL`); n != 1 {
		t.Fatal("depth-3 hop not recorded with its parent and action")
	}
	if ev := e.events(t, delegation.EventOpened); len(ev) != 3 || ev[2]["root"] != "agent_a" || ev[2]["depth"] != float64(3) {
		t.Fatalf("opened events: %v", ev)
	}

	// B -> X is not in B's a2a profile: POL-603, delegation_depth alert.
	out, tok := e.delegate(t, tAB, "agent_b", "agent_e")
	wantDenied(t, out, "POL-603", "agent_e")
	if tok != "" {
		t.Fatal("token released for a refused delegation")
	}

	// C's external egress (C itself may reach example.com) is refused because of A.
	wantDenied(t, e.act(t, tBC, httpAction("agent_c")), "POL-601", "originating agent agent_a (hop 1 of 2)")
	// ...and D's at depth 3, still naming A.
	wantDenied(t, e.act(t, tCD, httpAction("agent_d")), "POL-601", "originating agent agent_a (hop 1 of 3)")
	if lvl := e.level(t, "agent_a"); lvl != control.Supervised {
		t.Fatalf("origin agent_a: %v", lvl)
	}
	for _, ag := range []string{"agent_b", "agent_c", "agent_d"} {
		if lvl := e.level(t, ag); lvl != control.Full {
			t.Fatalf("%s stepped down: %v", ag, lvl)
		}
	}

	// C acting WITHOUT a token, while B's hop to it is open: inferred chain.
	out = e.act(t, "", httpAction("agent_c"))
	wantDenied(t, out, "POL-601", "agent_a")

	// A forged or foreign token is refused outright (POL-604), not ignored.
	wantDenied(t, e.act(t, tCD, httpAction("agent_c")), "POL-604", "different agent")
	wantDenied(t, e.act(t, tBC+"x", httpAction("agent_c")), "POL-604", "invalid")

	// Depth: D -> E (4), E -> F (5) are allowed; F -> G would be depth 6 > 5.
	tDE := e.mustDelegate(t, tCD, "agent_d", "agent_e")
	tEF := e.mustDelegate(t, tDE, "agent_e", "agent_f")
	out, tok = e.delegate(t, tEF, "agent_f", "agent_g")
	wantDenied(t, out, "POL-602", "depth 6", "max_depth 5")
	if tok != "" {
		t.Fatal("token released beyond max depth")
	}
	if n := e.count(t, `SELECT count(*) FROM alerts WHERE kind = 'delegation_depth' AND severity = 'warning'`); n != 2 {
		t.Fatalf("delegation_depth alerts: %d", n)
	}
	if n := e.count(t, `SELECT count(*) FROM delegations WHERE to_agent = 'agent_g'`); n != 0 {
		t.Fatal("refused hop recorded")
	}
	e.assertNoToken(t, tAB, tBC, tCD, tDE, tEF)
}
