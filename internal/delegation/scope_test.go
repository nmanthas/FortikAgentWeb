package delegation_test

import (
	"context"
	"slices"
	"testing"

	"fortik/internal/action"
	"fortik/internal/delegation"
)

func TestTaskScopeIntersectNeverWidens(t *testing.T) {
	a := &delegation.TaskScope{Systems: []string{"http", "gmail"}, Domains: []string{"example.com"}}
	b := &delegation.TaskScope{Systems: []string{"http", "postgres"}, Verbs: []string{"READ"}, Domains: []string{"docs.example.com", "other.com"}}
	got := delegation.Intersect(a, b)
	if !slices.Equal(got.Systems, []string{"http"}) || !slices.Equal(got.Verbs, []string{"READ"}) || !slices.Equal(got.Domains, []string{"docs.example.com"}) {
		t.Fatalf("intersect: %+v", got)
	}
	// Nothing in common reads as deny-all, never as unrestricted.
	none := delegation.Intersect(&delegation.TaskScope{Systems: []string{"gmail"}}, &delegation.TaskScope{Systems: []string{"http"}})
	if !slices.Equal(none.Systems, []string{delegation.DenyAll}) {
		t.Fatalf("empty intersection: %+v", none)
	}
	// An unrestricted side takes the other side; nil with nil stays nil.
	if got := delegation.Intersect(nil, a); !slices.Equal(got.Systems, a.Systems) {
		t.Fatalf("nil side: %+v", got)
	}
	if delegation.Intersect(nil, nil) != nil {
		t.Fatal("nil with nil must stay unrestricted")
	}
	// The deny-all marker survives further narrowing.
	if got := delegation.Intersect(none, &delegation.TaskScope{Systems: []string{"gmail"}}); !slices.Equal(got.Systems, []string{delegation.DenyAll}) {
		t.Fatalf("deny-all widened: %+v", got)
	}
}

func TestParseTaskScope(t *testing.T) {
	s, err := delegation.ParseTaskScope(map[string]any{"systems": []any{"HTTP"}, "verbs": []any{"read"}, "domains": []any{"Example.COM"}})
	if err != nil || s.Systems[0] != "http" || s.Verbs[0] != "READ" || s.Domains[0] != "example.com" {
		t.Fatalf("parse: %+v %v", s, err)
	}
	if s, err := delegation.ParseTaskScope(nil); s != nil || err != nil {
		t.Fatal("absent scope")
	}
	for _, bad := range []any{"http", map[string]any{"systems": "http"}, map[string]any{"teleport": []any{"x"}},
		map[string]any{"systems": []any{1}}, map[string]any{"domains": []any{"bad domain!"}}, map[string]any{"verbs": []any{"-"}}} {
		if _, err := delegation.ParseTaskScope(bad); err == nil {
			t.Errorf("accepted %#v", bad)
		}
	}
}

// A delegates to B for example.com/http only; B hands the task to C asking
// for example.com and other.com. C gets the intersection (example.com), every
// hop carries the root DELEGATE's correlation id, the scope is signed into
// the token, and C's own broader permission does not reach other.com.
func TestE2ETaskScopeNarrowsAlongTheChain(t *testing.T) {
	e := newE2E(t)
	for _, ag := range []string{"agent_a", "agent_b", "agent_c"} {
		e.putProfile(t, ag, "http", `{"external":"any"}`)
		e.putProfile(t, ag, "a2a", `{"may_delegate_to":["*"],"max_depth":10}`)
	}
	scoped := func(inbound, from, to string, scope map[string]any) string {
		t.Helper()
		ctx, sink := delegation.WithTokenSink(delegation.WithToken(context.Background(), inbound))
		out, err := e.svc.Decide(ctx, action.Action{AgentID: from, System: action.SystemA2A, Verb: action.VerbDelegate, Source: "agentgateway",
			Target: map[string]any{"to_agent": to, "channel": "a2a", "task_scope": scope}})
		if err != nil {
			t.Fatal(err)
		}
		tok, _, ok := sink.TokenFor(out)
		if !ok {
			t.Fatalf("%s -> %s refused: %s %s", from, to, out.Result.RuleID, out.Result.Reason)
		}
		return tok
	}
	tAB := scoped("", "agent_a", "agent_b", map[string]any{"systems": []any{"http", "a2a"}, "domains": []any{"example.com"}})
	tBC := scoped(tAB, "agent_b", "agent_c", map[string]any{"domains": []any{"example.com", "other.com"}})

	var corrs []string
	rows, err := e.pool.Query(context.Background(), `SELECT correlation_id, scope->>'domains' FROM delegations ORDER BY depth`)
	if err != nil {
		t.Fatal(err)
	}
	var doms []string
	for rows.Next() {
		var c, d string
		if err := rows.Scan(&c, &d); err != nil {
			t.Fatal(err)
		}
		corrs, doms = append(corrs, c), append(doms, d)
	}
	rows.Close()
	if len(corrs) != 2 || corrs[0] == "" || corrs[0] != corrs[1] {
		t.Fatalf("correlation ids: %v", corrs)
	}
	if doms[0] != `["example.com"]` || doms[1] != `["example.com"]` {
		t.Fatalf("B->C must be narrowed to example.com: %v", doms)
	}

	in := httpAction("agent_c")
	if out := e.act(t, tBC, in); out.Result.Decision == "deny" {
		t.Fatalf("in scope refused: %s %s", out.Result.RuleID, out.Result.Reason)
	}
	in.Target["domain"] = "other.com"
	wantDenied(t, e.act(t, tBC, in), "POL-605", "other.com", corrs[0])
	// C on its own (no token, hop closed) is not bound by A's task.
	if _, err := e.pool.Exec(context.Background(), `UPDATE delegations SET status = 'closed'`); err != nil {
		t.Fatal(err)
	}
	if out := e.act(t, "", in); out.Result.Decision == "deny" {
		t.Fatalf("C's own work refused: %s %s", out.Result.RuleID, out.Result.Reason)
	}
}
