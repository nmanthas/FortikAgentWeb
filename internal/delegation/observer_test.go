package delegation_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/policy"
)

// stubPolicy returns a fixed result (the observer reacts to the rule id;
// the real bundle is exercised by the end-to-end tests).
type stubPolicy struct{ res policy.Result }

func (s *stubPolicy) Eval(context.Context, policy.Input) (policy.Result, error) { return s.res, nil }

func observerService(t *testing.T, f *fixture, res policy.Result, raiser delegation.AlertRaiser) *decide.Service {
	t.Helper()
	obs, err := delegation.NewObserver(f.store, f.ctl, f.d, raiser, "SUPERVISED")
	if err != nil {
		t.Fatal(err)
	}
	return &decide.Service{Pool: f.pool, Policy: &stubPolicy{res: res}, Control: f.ctl, Diary: f.d, Access: f.acc,
		Log:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		Enrichers: []decide.Enricher{delegation.NewEnricher(f.store)}, Observers: []decide.Observer{obs}}
}

var bypassResult = policy.Result{Class: policy.Green, Decision: policy.Deny, RuleID: "POL-601",
	Reason: "delegation bypass: originating agent agent_a (hop 1 of 1) may not READ on http: no access profile (POL-020)"}

func TestNewObserverValidates(t *testing.T) {
	f := setup(t)
	r := &txRaiser{}
	if _, err := delegation.NewObserver(f.store, f.ctl, f.d, nil, "SUPERVISED"); err == nil {
		t.Fatal("nil raiser accepted")
	}
	if _, err := delegation.NewObserver(f.store, f.ctl, f.d, r, "sideways"); err == nil {
		t.Fatal("bad level accepted")
	}
	if _, err := delegation.NewObserver(f.store, f.ctl, f.d, r, "FULL"); err == nil {
		t.Fatal("FULL accepted")
	}
}

// POL-601: the ORIGIN agent (chain[0]) is stepped down, an alert is raised
// and delegation.bypass_blocked is written, all in the decision transaction;
// the executor keeps its level.
func TestObserverBypassStepsDownOrigin(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	raiser := &txRaiser{}
	svc := observerService(t, f, bypassResult, raiser)
	_, tok, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})

	out, err := svc.Decide(delegation.WithToken(ctx, tok), httpAction("agent_b"))
	if err != nil {
		t.Fatal(err)
	}
	if out.FailClosed || out.Result.RuleID != "POL-601" || out.Result.Decision != policy.Deny {
		t.Fatalf("outcome: %+v", out)
	}
	if lvl := f.level(t, "agent_a"); lvl != control.Supervised {
		t.Fatalf("origin level: %v", lvl)
	}
	if lvl := f.level(t, "agent_b"); lvl != control.Full {
		t.Fatalf("executor level: %v", lvl)
	}
	if out.LevelAfter != control.Full {
		t.Fatalf("executor LevelAfter: %v", out.LevelAfter)
	}
	var kind, sev, agent, actionID string
	var details []byte
	if err := f.pool.QueryRow(ctx, `SELECT kind, severity, agent_id, action_id, details FROM alerts`).Scan(&kind, &sev, &agent, &actionID, &details); err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	_ = json.Unmarshal(details, &d)
	if kind != "delegation_bypass" || sev != "high" || agent != "agent_a" || actionID != out.Action.ActionID ||
		d["executor"] != "agent_b" || d["root"] != "agent_a" || d["rule_id"] != "POL-601" || len(d["chain"].([]any)) != 1 {
		t.Fatalf("alert: %s %s %s %s %v", kind, sev, agent, actionID, d)
	}
	ev := f.events(t, delegation.EventBypassBlocked)
	if len(ev) != 1 || ev[0]["executor"] != "agent_b" || ev[0]["root"] != "agent_a" || ev[0]["action_id"] != out.Action.ActionID ||
		ev[0]["source"] != "token" || !slices.Equal(toStrings(ev[0]["stepped_down"]), []string{"agent_a"}) {
		t.Fatalf("bypass event: %v", ev)
	}
	lc := f.events(t, "agent.level_changed")
	last := lc[len(lc)-1]
	if last["to"] != "SUPERVISED" || last["rule_id"] != "POL-601" || last["executor"] != "agent_b" {
		t.Fatalf("level event: %v", last)
	}
	// A second attempt bumps the same open alert; the level never loosens.
	if _, err := svc.Decide(delegation.WithToken(ctx, tok), httpAction("agent_b")); err != nil {
		t.Fatal(err)
	}
	if n := f.count(t, `SELECT count FROM alerts WHERE kind = 'delegation_bypass'`); n != 2 {
		t.Fatalf("dedup count: %d", n)
	}
	if _, err := f.ctl.SetLevel(ctx, "agent_a", control.ReadOnly, "test", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Decide(delegation.WithToken(ctx, tok), httpAction("agent_b")); err != nil {
		t.Fatal(err)
	}
	if lvl := f.level(t, "agent_a"); lvl != control.ReadOnly {
		t.Fatalf("step-down loosened the origin: %v", lvl)
	}
	f.assertNoToken(t, tok)
}

// A failing alert raiser rolls the whole decision back: no step-down, no
// Diary event, and the action is refused fail-closed.
func TestObserverBypassIsAtomic(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	raiser := &txRaiser{fail: true}
	svc := observerService(t, f, bypassResult, raiser)
	_, tok, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	before := f.count(t, `SELECT count(*) FROM diary`)

	out, err := svc.Decide(delegation.WithToken(ctx, tok), httpAction("agent_b"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision.Executes() || !out.FailClosed {
		t.Fatalf("outcome after rollback: %+v", out)
	}
	if lvl := f.level(t, "agent_a"); lvl != control.Full {
		t.Fatalf("step-down survived the rollback: %v", lvl)
	}
	if n := len(f.events(t, delegation.EventBypassBlocked)); n != 0 {
		t.Fatalf("bypass event survived the rollback: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type = 'agent.level_changed' AND seq > $1`, before); n != 0 {
		t.Fatalf("level event survived the rollback: %d", n)
	}
	raiser.setFail(false)
	if _, err := svc.Decide(delegation.WithToken(ctx, tok), httpAction("agent_b")); err != nil {
		t.Fatal(err)
	}
	if lvl := f.level(t, "agent_a"); lvl != control.Supervised {
		t.Fatalf("after recovery: %v", lvl)
	}
}

// Inferred chains step down every distinct originating agent.
func TestObserverInferredStepsDownEveryRoot(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	svc := observerService(t, f, bypassResult, &txRaiser{})
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_c", Chain: []string{"agent_a", "agent_c"}, Channel: "a2a"})
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_e", To: "agent_c", Chain: []string{"agent_d", "agent_e", "agent_c"}, Channel: "a2a"})
	if _, err := svc.Decide(ctx, httpAction("agent_c")); err != nil {
		t.Fatal(err)
	}
	for agent, want := range map[string]control.Level{"agent_a": control.Supervised, "agent_d": control.Supervised,
		"agent_e": control.Full, "agent_c": control.Full} {
		if lvl := f.level(t, agent); lvl != want {
			t.Errorf("%s: %v, want %v", agent, lvl, want)
		}
	}
	ev := f.events(t, delegation.EventBypassBlocked)
	if len(ev) != 1 || ev[0]["source"] != "inferred" || !slices.Equal(toStrings(ev[0]["roots"]), []string{"agent_a", "agent_d"}) {
		t.Fatalf("event: %v", ev)
	}
}

func TestObserverDepthAlert(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	for _, rule := range []string{"POL-602", "POL-603"} {
		svc := observerService(t, f, policy.Result{Class: policy.Green, Decision: policy.Deny, RuleID: rule, Reason: "too deep"}, &txRaiser{})
		a := action.Action{AgentID: "agent_b", System: "a2a", Verb: action.VerbDelegate, Source: "agentgateway",
			Target: map[string]any{"to_agent": "agent_c", "channel": "a2a"}}
		if _, err := svc.Decide(ctx, a); err != nil {
			t.Fatal(err)
		}
	}
	var sev string
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT severity, count FROM alerts WHERE kind = 'delegation_depth' AND agent_id = 'agent_b'`).Scan(&sev, &n); err != nil {
		t.Fatal(err)
	}
	if sev != "warning" || n != 2 {
		t.Fatalf("depth alert: %s %d", sev, n)
	}
	if lvl := f.level(t, "agent_b"); lvl != control.Full {
		t.Fatalf("depth refusal stepped down: %v", lvl)
	}
}

// An allowed DELEGATE records the hop under the delegator's own chain and
// hands the token to the transport's sink, never to the Outcome or the Diary.
func TestObserverOpensHopOnAllowedDelegate(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	svc := observerService(t, f, policy.Result{Class: policy.Green, Decision: policy.Allow, RuleID: "POL-000", Reason: "ok"}, &txRaiser{})
	h1, tok1, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})

	dctx, sink := delegation.WithTokenSink(delegation.WithToken(ctx, tok1))
	a := action.Action{AgentID: "agent_b", System: "a2a", Verb: action.VerbDelegate, Source: "agentgateway",
		Target: map[string]any{"to_agent": "agent_c", "channel": "a2a", "task_id": "task-7"}}
	out, err := svc.Decide(dctx, a)
	if err != nil {
		t.Fatal(err)
	}
	tok2, hop, ok := sink.TokenFor(out)
	if !ok || tok2 == "" {
		t.Fatalf("no token in sink: %+v", out)
	}
	if hop.ParentID != h1.DelegationID || hop.From != "agent_b" || hop.To != "agent_c" || hop.Depth != 2 || hop.TaskID != "task-7" ||
		hop.ActionID != out.Action.ActionID || !slices.Equal(hop.Chain, []string{"agent_a", "agent_b", "agent_c"}) {
		t.Fatalf("hop: %+v", hop)
	}
	c, err := f.store.Verify(ctx, tok2, "agent_c")
	if err != nil || c.DelegationID != hop.DelegationID || c.Root != "agent_a" {
		t.Fatalf("new token: %+v %v", c, err)
	}
	if n := f.count(t, `SELECT count(*) FROM delegations WHERE delegation_id = $1 AND action_id = $2 AND status = 'open'`, hop.DelegationID, out.Action.ActionID); n != 1 {
		t.Fatal("hop not stored with its action")
	}
	raw, _ := json.Marshal(out)
	if json.Valid(raw) && (strings.Contains(string(raw), tok2) || strings.Contains(string(raw), tok1)) {
		t.Fatal("token in the Outcome")
	}
	// The sink never releases the token for another or a refused outcome.
	other := out
	other.Action.ActionID = "someone-else"
	if _, _, ok := sink.TokenFor(other); ok {
		t.Fatal("token released for another action")
	}
	refused := out
	refused.Result.Decision = policy.Deny
	if _, _, ok := sink.TokenFor(refused); ok {
		t.Fatal("token released for a refusal")
	}
	failed := out
	failed.FailClosed = true
	if _, _, ok := sink.TokenFor(failed); ok {
		t.Fatal("token released for a fail-closed outcome")
	}
	var nilSink *delegation.Sink
	if _, _, ok := nilSink.TokenFor(out); ok {
		t.Fatal("nil sink")
	}
	if s := sink.String() + string(must(json.Marshal(sink))); tok2 != "" && strings.Contains(s, tok2) {
		t.Fatal("sink prints its token")
	}

	// A direct delegation (no inbound chain), without a sink: recorded at depth 1.
	out, err = svc.Decide(ctx, action.Action{AgentID: "agent_d", System: "a2a", Verb: action.VerbDelegate, Source: "agentgateway",
		Target: map[string]any{"to_agent": "agent_e"}})
	if err != nil || !out.Result.Decision.Executes() {
		t.Fatalf("%+v %v", out, err)
	}
	if n := f.count(t, `SELECT count(*) FROM delegations WHERE from_agent = 'agent_d' AND to_agent = 'agent_e' AND depth = 1
		AND chain = ARRAY['agent_d','agent_e'] AND channel = 'a2a' AND parent_id IS NULL`); n != 1 {
		t.Fatal("direct hop not stored")
	}
	f.assertNoToken(t, tok1, tok2)
}

// A malformed allowed DELEGATE cannot be recorded: the decision fails closed.
func TestObserverMalformedDelegateFailsClosed(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	svc := observerService(t, f, policy.Result{Class: policy.Green, Decision: policy.Allow, RuleID: "POL-000", Reason: "ok"}, &txRaiser{})
	for _, tgt := range []map[string]any{
		{"channel": "a2a"},
		{"to_agent": "agent_c", "channel": "carrier-pigeon"},
		{"to_agent": "agent_c", "task_id": 7},
		{"to_agent": "not an agent"},
	} {
		out, err := svc.Decide(ctx, action.Action{AgentID: "agent_b", System: "a2a", Verb: action.VerbDelegate, Source: "agentgateway", Target: tgt})
		if err != nil {
			t.Fatal(err)
		}
		if out.Result.Decision.Executes() || !out.FailClosed {
			t.Errorf("%v: %+v", tgt, out.Result)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM delegations`); n != 0 {
		t.Fatalf("hops stored: %d", n)
	}
}

func toStrings(v any) []string {
	out := []string{}
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func must(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

// PreLock row-locks exactly the originating agents of a POL-601 refusal.
func TestObserverPreLockLocksOrigins(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	obs, err := delegation.NewObserver(f.store, f.ctl, f.d, &txRaiser{}, "SUPERVISED")
	if err != nil {
		t.Fatal(err)
	}
	_, tok, err := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	if err != nil {
		t.Fatal(err)
	}
	a := httpAction("agent_b")
	in := policy.Input{Action: a, Context: map[string]any{delegation.Key: enrich(t, f, delegation.WithToken(ctx, tok), a)}}
	locked := func(agent string) bool {
		t.Helper()
		var lockedErr error
		_ = pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
			_, lockedErr = tx.Exec(ctx, `SELECT 1 FROM agents WHERE agent_id = $1 FOR UPDATE NOWAIT`, agent)
			return lockedErr
		})
		var pgErr *pgconn.PgError
		if lockedErr != nil && !(errors.As(lockedErr, &pgErr) && pgErr.Code == "55P03") {
			t.Fatal(lockedErr)
		}
		return lockedErr != nil
	}
	for _, c := range []struct {
		rule       string
		wantLocked bool
	}{{"POL-028", false}, {"POL-601", true}} {
		tx, err := f.pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := obs.PreLock(ctx, tx, policy.Result{RuleID: c.rule}, in); err != nil {
			t.Fatal(err)
		}
		if got := locked("agent_a"); got != c.wantLocked {
			t.Errorf("%s: origin locked=%v", c.rule, got)
		}
		if locked("agent_b") {
			t.Errorf("%s: executor locked by PreLock", c.rule)
		}
		_ = tx.Rollback(ctx)
	}
}
