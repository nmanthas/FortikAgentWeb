package delegation_test

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/delegation"
)

func httpAction(agent string) action.Action {
	return action.Action{AgentID: agent, System: "http", Verb: action.VerbRead, Source: "agentgateway",
		Target: map[string]any{"domain": "example.com", "external": true, "method": "GET"}}
}

func enrich(t *testing.T, f *fixture, ctx context.Context, a action.Action) *delegation.Attribution {
	t.Helper()
	v, err := delegation.NewEnricher(f.store).Enrich(ctx, a, control.State{AgentID: a.AgentID, Registered: true})
	if err != nil {
		t.Fatal(err)
	}
	att, ok := v.(*delegation.Attribution)
	if !ok {
		t.Fatalf("enricher returned %T", v)
	}
	return att
}

func ids(chain []delegation.HopState) []string {
	out := []string{}
	for _, h := range chain {
		out = append(out, h.AgentID)
	}
	return out
}

func TestEnricherToken(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.putProfile(t, "agent_a", "http", `{"external":"none"}`)
	if _, err := f.ctl.SetLevel(ctx, "agent_a", control.Supervised, "test", "test"); err != nil {
		t.Fatal(err)
	}
	h1, tok1, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	_, tok2, _ := f.store.Open(ctx, delegation.Hop{ParentID: h1.DelegationID, From: "agent_b", To: "agent_c",
		Chain: []string{"agent_a", "agent_b", "agent_c"}, Channel: "a2a"})

	att := enrich(t, f, delegation.WithToken(ctx, tok2), httpAction("agent_c"))
	if !att.Present || att.Source != "token" || att.Depth != 2 || att.Root != "agent_a" || att.TokenError != "" ||
		!slices.Equal(ids(att.Chain), []string{"agent_a", "agent_b"}) || !slices.Equal(att.Roots, []string{"agent_a"}) ||
		!slices.Equal(att.Lineage, []string{"agent_a", "agent_b", "agent_c"}) {
		t.Fatalf("token attribution: %+v", att)
	}
	a := att.Chain[0]
	if !a.Registered || a.Level != int(control.Supervised) || a.LevelName != "SUPERVISED" || a.Access == nil ||
		a.Access.System != "http" || a.Access.Version != 1 || !jsonEqual(a.Access.Profile, json.RawMessage(`{"external":"none","allowed_domains":[]}`)) {
		t.Fatalf("hop A: %+v %s", a, a.Access.Profile)
	}
	b := att.Chain[1]
	if b.Access == nil || b.Access.Version != 0 || string(b.Access.Profile) != "null" {
		t.Fatalf("hop B without profile: %+v", b)
	}

	// The token of the hop A->B presented by B: chain [A].
	att = enrich(t, f, delegation.WithToken(ctx, tok1), httpAction("agent_b"))
	if att.Source != "token" || !slices.Equal(ids(att.Chain), []string{"agent_a"}) || att.DelegationID != h1.DelegationID {
		t.Fatalf("hop 1: %+v", att)
	}

	// JSON (policy input / decision record) has token_error but never the
	// observer-only fields.
	raw, _ := json.Marshal(att)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	for _, k := range []string{"present", "source", "depth", "root", "chain", "delegation_id"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %s in %s", k, raw)
		}
	}
	for _, k := range []string{"Lineage", "Roots", "lineage", "roots", "token_error"} {
		if _, ok := m[k]; ok {
			t.Fatalf("unexpected %s in %s", k, raw)
		}
	}
}

func TestEnricherTokenErrors(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	_, tok, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	cases := map[string]struct {
		ctx   context.Context
		agent string
		want  string
	}{
		"tampered":    {delegation.WithToken(ctx, tok[:len(tok)-3]+"AAA"), "agent_b", "invalid delegation token"},
		"garbage":     {delegation.WithToken(ctx, "not-a-token"), "agent_b", "invalid delegation token"},
		"wrong agent": {delegation.WithToken(ctx, tok), "agent_c", "delegation token was issued to a different agent"},
	}
	for name, c := range cases {
		att := enrich(t, f, c.ctx, httpAction(c.agent))
		if !att.Present || att.TokenError != c.want || len(att.Chain) != 0 {
			t.Errorf("%s: %+v", name, att)
		}
		raw, _ := json.Marshal(att)
		if strings.Contains(string(raw), tok) || !strings.Contains(string(raw), `"token_error"`) {
			t.Errorf("%s: json %s", name, raw)
		}
	}
	f.clock.Advance(16 * time.Minute)
	att := enrich(t, f, delegation.WithToken(ctx, tok), httpAction("agent_b"))
	if att.TokenError != "expired delegation token" {
		t.Fatalf("expired: %+v", att)
	}
	// A token error is a refusal, not an inference fallback, even with open hops.
	if att.Source != "token" {
		t.Fatalf("source: %+v", att)
	}
}

func TestEnricherInferredUnion(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	h1, _, _ := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_b", Chain: []string{"agent_a", "agent_b"}, Channel: "a2a"})
	f.clock.Advance(time.Second)
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_e", To: "agent_b", Chain: []string{"agent_d", "agent_e", "agent_b"}, Channel: "a2a"})
	f.clock.Advance(time.Second)
	// A self-delegation (Task subagent) adds nothing upstream.
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_b", To: "agent_b", Chain: []string{"agent_b", "agent_b"}, Channel: "hook_task"})

	att := enrich(t, f, ctx, httpAction("agent_b"))
	if !att.Present || att.Source != "inferred" || att.Depth != 2 || att.Root != "" || att.DelegationID != "" ||
		!slices.Equal(ids(att.Chain), []string{"agent_a", "agent_d", "agent_e"}) ||
		!slices.Equal(att.Roots, []string{"agent_a", "agent_d"}) {
		t.Fatalf("inferred: %+v", att)
	}
	if !slices.Equal(att.Lineage, []string{"agent_a", "agent_d", "agent_e", "agent_b"}) {
		t.Fatalf("lineage: %v", att.Lineage)
	}

	// One open hop: its id and root are known.
	att = enrich(t, f, ctx, httpAction("agent_a"))
	if att.Present {
		t.Fatalf("agent_a has no inbound hops: %+v", att)
	}
	_ = f.store.Close(ctx, h1.DelegationID, "done")
	f.clock.Advance(time.Second)
	att = enrich(t, f, ctx, httpAction("agent_b"))
	if att.Root != "agent_d" || att.Depth != 2 || !slices.Equal(ids(att.Chain), []string{"agent_d", "agent_e"}) {
		t.Fatalf("after close: %+v", att)
	}

	// Expired hops no longer count.
	f.clock.Advance(16 * time.Minute)
	if att := enrich(t, f, ctx, httpAction("agent_b")); att.Present {
		t.Fatalf("expired hops inferred: %+v", att)
	}
}

func TestEnricherNoneAndNonStrict(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	att := enrich(t, f, ctx, httpAction("agent_c"))
	if att.Present || att.Chain == nil || len(att.Chain) != 0 {
		t.Fatalf("none: %+v", att)
	}
	raw, _ := json.Marshal(att)
	if string(raw) != `{"present":false,"source":"","depth":0,"chain":[],"max_depth":5}` {
		t.Fatalf("none json: %s", raw)
	}
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_c", Chain: []string{"agent_a", "agent_c"}, Channel: "a2a"})
	if att := enrich(t, f, ctx, httpAction("agent_c")); !att.Present {
		t.Fatal("strict agent not inferred")
	}
	if _, err := f.pool.Exec(ctx, `UPDATE agents SET delegation_strict = false WHERE agent_id = 'agent_c'`); err != nil {
		t.Fatal(err)
	}
	if att := enrich(t, f, ctx, httpAction("agent_c")); att.Present {
		t.Fatalf("non-strict agent inferred: %+v", att)
	}
	// Only self-delegations open: nothing upstream.
	_, _, _ = f.store.Open(ctx, delegation.Hop{From: "agent_d", To: "agent_d", Chain: []string{"agent_d", "agent_d"}, Channel: "hook_task"})
	if att := enrich(t, f, ctx, httpAction("agent_d")); att.Present {
		t.Fatalf("self-delegation inferred: %+v", att)
	}
}

func TestEnricherStoreErrorFailsClosed(t *testing.T) {
	f := setup(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := delegation.NewEnricher(f.store).Enrich(ctx, httpAction("agent_c"), control.State{}); err == nil {
		t.Fatal("cancelled store query returned no error")
	}
}

// LoadHopStates matches control.Get and access.PGStore.PolicyInput exactly.
func TestLoadHopStatesMatchesPerAgentSources(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.putProfile(t, "agent_a", "http", `{"external":"none"}`)
	f.putProfile(t, "agent_a", "http", `{"external":"allowlist","allowed_domains":["*.example.org"]}`)
	f.putProfile(t, "agent_b", "postgres", `{"upstreams":{"acme_prod":"read_only"}}`)
	if _, err := f.ctl.SetLevel(ctx, "agent_b", control.ReadOnly, "test", "test"); err != nil {
		t.Fatal(err)
	}
	agents := []string{"agent_b", "ghost", "agent_a"}
	for _, system := range []string{"http", "postgres", "memory", "a2a"} {
		got, err := delegation.LoadHopStates(ctx, f.pool, agents, system)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != len(agents) {
			t.Fatalf("%s: %d states", system, len(got))
		}
		for i, id := range agents {
			st, err := f.ctl.Get(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			pi, err := f.acc.PolicyInput(ctx, id, system)
			if err != nil {
				t.Fatal(err)
			}
			h := got[i]
			if h.AgentID != id || h.Registered != st.Registered || h.Level != int(st.Level) || h.LevelName != st.LevelName {
				t.Errorf("%s/%s state: %+v vs %+v", system, id, h, st)
			}
			if h.Access.System != pi.System || h.Access.Version != pi.Version || !jsonEqual(h.Access.Profile, pi.Profile) {
				t.Errorf("%s/%s access: %+v vs %+v", system, id, h.Access, pi)
			}
		}
	}
}

func jsonEqual(a, b json.RawMessage) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	ra, _ := json.Marshal(x)
	rb, _ := json.Marshal(y)
	return string(ra) == string(rb)
}

// A token never hides the agent's other open inbound hops, and a closed
// hop's token is refused.
func TestEnricherTokenDoesNotMaskInbound(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	f.putProfile(t, "agent_a", "http", `{"external":"none"}`)
	_, self, err := f.store.Open(ctx, delegation.Hop{From: "agent_c", To: "agent_c", Chain: []string{"agent_c", "agent_c"}, Channel: "hook_task"})
	if err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(time.Second)
	if _, _, err := f.store.Open(ctx, delegation.Hop{From: "agent_a", To: "agent_c", Chain: []string{"agent_a", "agent_c"}, Channel: "a2a"}); err != nil {
		t.Fatal(err)
	}
	att := enrich(t, f, delegation.WithToken(ctx, self), httpAction("agent_c"))
	if att.TokenError != "" || !slices.Equal(ids(att.Chain), []string{"agent_a"}) || !slices.Contains(att.Roots, "agent_a") ||
		!slices.Equal(att.Lineage, []string{"agent_c", "agent_a", "agent_c"}) {
		t.Fatalf("self token masked inbound chain: %+v", att)
	}

	hb, tb, err := f.store.Open(ctx, delegation.Hop{From: "agent_b", To: "agent_d", Chain: []string{"agent_b", "agent_d"}, Channel: "a2a"})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.Close(ctx, hb.DelegationID, "done"); err != nil {
		t.Fatal(err)
	}
	att = enrich(t, f, delegation.WithToken(ctx, tb), httpAction("agent_d"))
	if !att.Present || att.TokenError != "delegation token's hop is no longer open" || len(att.Chain) != 0 {
		t.Fatalf("closed hop token accepted: %+v", att)
	}
	if _, err := f.store.Verify(ctx, tb, "agent_d"); !errors.Is(err, delegation.ErrRevokedToken) {
		t.Fatalf("verify closed: %v", err)
	}
}
