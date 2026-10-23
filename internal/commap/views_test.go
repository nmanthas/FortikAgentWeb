package commap_test

import (
	"context"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/commap"
)

// scenario is the plan's exfiltration path: a finance agent reads the
// finance database and writes a report to Drive; a mailer agent reads the
// report and mails it to an outside domain. Another agent mails other data
// through the same Gmail hub at the same time (it must not join the path).
type scenario struct {
	pgRead, driveWrite, driveRead, gmailSend, otherSend, otherRead string
}

func (e *env) exfilScenario(t *testing.T) scenario {
	t.Helper()
	e.register(t, "finance_agent", "finance", "cfo@acme.test")
	e.register(t, "mailer_agent", "comms", "comms@acme.test")
	e.register(t, "other_agent", "comms", "comms@acme.test")
	var s scenario
	s.pgRead = e.decideAt(t, e.base.Add(time.Minute), pgRead("finance_agent", "finance", "financial")).Action.ActionID
	s.driveWrite = e.decideAt(t, e.base.Add(2*time.Minute), action.Action{AgentID: "finance_agent", System: "drive", Verb: action.VerbWrite,
		Target:         map[string]any{"endpoint": "drive.files.create", "file_id": "q3_report"},
		PayloadSummary: action.PayloadSummary{Bytes: 4096, DataLabels: []string{"financial"}}}).Action.ActionID
	s.driveRead = e.decideAt(t, e.base.Add(6*time.Minute), action.Action{AgentID: "mailer_agent", System: "drive", Verb: action.VerbRead,
		Target:         map[string]any{"endpoint": "drive.files.get", "file_id": "q3_report"},
		PayloadSummary: action.PayloadSummary{Bytes: 4096, DataLabels: []string{"financial"}}}).Action.ActionID
	s.gmailSend = e.decideAt(t, e.base.Add(7*time.Minute), action.Action{AgentID: "mailer_agent", System: "gmail", Verb: action.VerbSend,
		Target:         map[string]any{"endpoint": "gmail.users.messages.send", "to": []string{"cfo@evil.example"}, "external_domains": 1},
		PayloadSummary: action.PayloadSummary{Bytes: 5000, Recipients: 1, Attachments: 1, DataLabels: []string{"financial"}}}).Action.ActionID
	s.otherRead = e.decideAt(t, e.base.Add(6*time.Minute), pgRead("other_agent", "finance", "financial")).Action.ActionID
	s.otherSend = e.decideAt(t, e.base.Add(7*time.Minute), action.Action{AgentID: "other_agent", System: "gmail", Verb: action.VerbSend,
		Target:         map[string]any{"endpoint": "gmail.users.messages.send", "to": []string{"ap@supplier.example"}, "external_domains": 1},
		PayloadSummary: action.PayloadSummary{Bytes: 100, Recipients: 1, DataLabels: []string{"financial"}}}).Action.ActionID
	e.rollup(t)
	return s
}

func pathURL(label, dest string, from, to time.Time) string {
	v := url.Values{"label": {label}, "dest": {dest}, "from": {rfc(from)}, "to": {rfc(to)}}
	return "/v1/map/path?" + v.Encode()
}

func TestPathTraceExfiltration(t *testing.T) {
	e := newEnv(t)
	s := e.exfilScenario(t)
	var res commap.PathResult
	if code := e.get(t, pathURL("financial", "domain:evil.example", e.base, e.base.Add(time.Hour)), &res); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(res.Paths) != 1 || res.Truncated {
		t.Fatalf("want exactly one complete path, got %+v", res)
	}
	p := res.Paths[0]
	wantNodes := []string{"store:postgres:finance", "agent:finance_agent", "app:drive", "agent:mailer_agent", "app:gmail", "domain:evil.example"}
	if !slices.Equal(p.Nodes, wantNodes) {
		t.Fatalf("path %v\nwant %v", p.Nodes, wantNodes)
	}
	wantIDs := [][]string{{s.pgRead}, {s.driveWrite}, {s.driveRead}, {s.gmailSend}, {s.gmailSend}}
	wantVerbs := []string{"READ", "WRITE", "READ", "SEND", "SEND"}
	for i, h := range p.Hops {
		if h.From != wantNodes[i] || h.To != wantNodes[i+1] || h.Verb != wantVerbs[i] || !slices.Equal(h.ActionIDs, wantIDs[i]) || !h.ActionIDsComplete {
			t.Errorf("hop %d: %+v", i, h)
		}
		if i > 0 && h.WindowStart.Before(p.Hops[i-1].WindowStart) {
			t.Errorf("hop %d goes back in time", i)
		}
	}
	// READ hops run in data-flow direction; the edge itself is caller -> target.
	if p.Hops[0].EdgeFrom != "agent:finance_agent" || p.Hops[0].EdgeTo != "store:postgres:finance" {
		t.Fatalf("hop 0 edge %+v", p.Hops[0])
	}
	if len(res.Hops) != 5 {
		t.Fatalf("distinct hops %d", len(res.Hops))
	}
	for _, h := range res.Hops {
		if slices.Contains(h.ActionIDs, s.otherSend) || slices.Contains(h.ActionIDs, s.otherRead) {
			t.Fatalf("the other agent's mail joined the path through the shared gmail hub: %+v", h)
		}
	}
	// The other agent's own destination traces back to it, not to the mailer.
	if code := e.get(t, pathURL("financial", "domain:supplier.example", e.base, e.base.Add(time.Hour)), &res); code != 200 {
		t.Fatal(code)
	}
	if len(res.Paths) != 1 || !slices.Equal(res.Paths[0].Nodes, []string{"store:postgres:finance", "agent:other_agent", "app:gmail", "domain:supplier.example"}) {
		t.Fatalf("supplier path %+v", res.Paths)
	}
	// A label that never went there: no path.
	if code := e.get(t, pathURL("customer_pii", "domain:evil.example", e.base, e.base.Add(time.Hour)), &res); code != 200 || len(res.Paths) != 0 {
		t.Fatalf("pii path %d %+v", code, res.Paths)
	}
	// Depth bound: two hops only reach back to the mailer.
	if code := e.get(t, pathURL("financial", "domain:evil.example", e.base, e.base.Add(time.Hour))+"&depth=2", &res); code != 200 {
		t.Fatal(code)
	}
	if len(res.Paths) != 1 || !slices.Equal(res.Paths[0].Nodes, []string{"agent:mailer_agent", "app:gmail", "domain:evil.example"}) {
		t.Fatalf("depth 2: %+v", res.Paths)
	}
}

// Path traces are cycle-safe: data bouncing between two agents never loops.
func TestPathTraceCycleSafe(t *testing.T) {
	e := newEnv(t)
	e.register(t, "a", "x", "")
	e.register(t, "b", "x", "")
	for i := 0; i < 3; i++ {
		e.decideAt(t, e.base.Add(time.Duration(i)*time.Minute), action.Action{AgentID: "a", System: "a2a", Verb: action.VerbDelegate,
			Target: map[string]any{"to_agent": "b"}, PayloadSummary: action.PayloadSummary{DataLabels: []string{"secret"}}})
		e.decideAt(t, e.base.Add(time.Duration(i)*time.Minute), action.Action{AgentID: "b", System: "a2a", Verb: action.VerbDelegate,
			Target: map[string]any{"to_agent": "a"}, PayloadSummary: action.PayloadSummary{DataLabels: []string{"secret"}}})
	}
	e.decideAt(t, e.base.Add(3*time.Minute), action.Action{AgentID: "a", System: "http", Verb: action.VerbExport,
		Target: map[string]any{"domain": "drop.example", "external": true, "method": "POST"}, PayloadSummary: action.PayloadSummary{DataLabels: []string{"secret"}}})
	e.rollup(t)
	var res commap.PathResult
	if code := e.get(t, pathURL("secret", "domain:drop.example", e.base, e.base.Add(time.Hour)), &res); code != 200 {
		t.Fatal(code)
	}
	if len(res.Paths) != 1 || !slices.Equal(res.Paths[0].Nodes, []string{"agent:b", "agent:a", "domain:drop.example"}) {
		t.Fatalf("paths %+v", res.Paths)
	}
}

// Time replay: from/to select windows; a trace limited to the later
// windows starts at Drive.
func TestTimeReplay(t *testing.T) {
	e := newEnv(t)
	e.exfilScenario(t)
	later := e.base.Add(5 * time.Minute)
	var m commap.MapResult
	if code := e.get(t, "/v1/map?view=agent&from="+rfc(later)+"&to="+rfc(later.Add(5*time.Minute)), &m); code != 200 {
		t.Fatal(code)
	}
	for _, ed := range m.Edges {
		if ed.WindowStart == nil || !ed.WindowStart.Equal(later) {
			t.Fatalf("edge outside the replay window: %+v", ed)
		}
		if ed.From == "agent:finance_agent" {
			t.Fatalf("finance agent acted only in the first window: %+v", ed)
		}
	}
	if m.Window.From != later {
		t.Fatalf("window %+v", m.Window)
	}
	var all commap.MapResult
	e.get(t, "/v1/map?view=agent&from="+rfc(e.base)+"&to="+rfc(e.base.Add(time.Hour)), &all)
	if len(all.Edges) <= len(m.Edges) {
		t.Fatalf("full range %d edges, replay window %d", len(all.Edges), len(m.Edges))
	}
	var res commap.PathResult
	e.get(t, pathURL("financial", "domain:evil.example", later, later.Add(5*time.Minute)), &res)
	if len(res.Paths) != 1 || res.Paths[0].Nodes[0] != "app:drive" {
		t.Fatalf("replayed trace %+v", res.Paths)
	}
	// A range before anything happened is empty, not an error.
	var empty commap.MapResult
	if code := e.get(t, "/v1/map?from="+rfc(e.base.Add(-3*time.Hour))+"&to="+rfc(e.base.Add(-2*time.Hour)), &empty); code != 200 || len(empty.Edges) != 0 {
		t.Fatalf("%d %+v", code, empty.Edges)
	}
}

func hasEdge(m commap.MapResult, from, to, verb string) bool {
	for _, e := range m.Edges {
		if e.From == from && e.To == to && e.Verb == verb && !e.Reach {
			return true
		}
	}
	return false
}

func node(m commap.MapResult, id string) *commap.Node {
	for i := range m.Nodes {
		if m.Nodes[i].ID == id {
			return &m.Nodes[i]
		}
	}
	return nil
}

func TestViews(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.exfilScenario(t)
	if _, err := e.pool.Exec(ctx, `INSERT INTO swarms (swarm_id, root_agent_id, detected_by, member_count, state)
		VALUES ('swm_1', 'mailer_agent', 'action_hash', 2, 'breaker_tripped'), ('swm_old', NULL, 'manual', 1, 'released');
		INSERT INTO swarm_members (swarm_id, agent_id, role) VALUES ('swm_1', 'mailer_agent', 'root'), ('swm_1', 'other_agent', 'member'),
		('swm_old', 'finance_agent', 'member')`); err != nil {
		t.Fatal(err)
	}
	q := "&from=" + rfc(e.base) + "&to=" + rfc(e.base.Add(time.Hour))

	t.Run("agent", func(t *testing.T) {
		var m commap.MapResult
		if code := e.get(t, "/v1/map?view=agent&id=finance_agent"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if !hasEdge(m, "agent:finance_agent", "store:postgres:finance", "READ") || !hasEdge(m, "agent:finance_agent", "app:drive", "WRITE") ||
			!hasEdge(m, "user:cfo@acme.test", "agent:finance_agent", commap.VerbOwns) {
			t.Fatalf("ego edges %+v", m.Edges)
		}
		if hasEdge(m, "agent:mailer_agent", "app:gmail", "SEND") {
			t.Fatal("another agent's edge in the agent view")
		}
		n := node(m, "agent:finance_agent")
		if n == nil || n.Team != "finance" || n.Owner != "cfo@acme.test" || n.Level != "FULL" || n.Registered == nil || !*n.Registered {
			t.Fatalf("agent node %+v", n)
		}
		// The mailer's view includes its egress through the gmail hub, not the other agent's.
		if code := e.get(t, "/v1/map?view=agent&id=mailer_agent"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if !hasEdge(m, "app:gmail", "domain:evil.example", "SEND") || hasEdge(m, "app:gmail", "domain:supplier.example", "SEND") {
			t.Fatalf("mailer egress %+v", m.Edges)
		}
		if code := e.get(t, "/v1/map?view=agent&id=nobody"+q, nil); code != 404 {
			t.Fatalf("unknown agent: %d", code)
		}
	})

	t.Run("team", func(t *testing.T) {
		var m commap.MapResult
		if code := e.get(t, "/v1/map?view=team"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if len(m.Clusters) != 2 || m.Clusters[0].ID != "team:comms" || m.Clusters[1].ID != "team:finance" ||
			!slices.Equal(m.Clusters[0].Members, []string{"agent:mailer_agent", "agent:other_agent"}) {
			t.Fatalf("clusters %+v", m.Clusters)
		}
		if code := e.get(t, "/v1/map?view=team&id=comms"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if hasEdge(m, "agent:finance_agent", "app:drive", "WRITE") || !hasEdge(m, "agent:other_agent", "app:gmail", "SEND") ||
			!hasEdge(m, "app:gmail", "domain:supplier.example", "SEND") {
			t.Fatalf("team edges %+v", m.Edges)
		}
		if code := e.get(t, "/v1/map?view=team&id=nope"+q, nil); code != 404 {
			t.Fatalf("unknown team %d", code)
		}
	})

	t.Run("swarm", func(t *testing.T) {
		var m commap.MapResult
		if code := e.get(t, "/v1/map?view=swarm"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if len(m.Clusters) != 1 {
			t.Fatalf("active swarms only: %+v", m.Clusters)
		}
		c := m.Clusters[0]
		if c.SwarmID != "swm_1" || c.State != "breaker_tripped" || !c.Collapsed || c.MemberCount != 2 || c.RootAgentID != "mailer_agent" ||
			!slices.Equal(c.Members, []string{"agent:mailer_agent", "agent:other_agent"}) {
			t.Fatalf("cluster %+v", c)
		}
		if n := node(m, "agent:mailer_agent"); n == nil || !slices.Equal(n.SwarmIDs, []string{"swm_1"}) {
			t.Fatalf("swarm ids on node %+v", n)
		}
		if n := node(m, "agent:finance_agent"); n == nil || len(n.SwarmIDs) != 0 {
			t.Fatalf("released swarm shown on node %+v", n)
		}
		if code := e.get(t, "/v1/map?view=swarm&id=swm_1"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if hasEdge(m, "agent:finance_agent", "app:drive", "WRITE") || !hasEdge(m, "agent:mailer_agent", "app:gmail", "SEND") {
			t.Fatalf("swarm edges %+v", m.Edges)
		}
		if code := e.get(t, "/v1/map?view=swarm&id=swm_nope"+q, nil); code != 404 {
			t.Fatalf("unknown swarm %d", code)
		}
	})

	t.Run("external", func(t *testing.T) {
		var m commap.MapResult
		if code := e.get(t, "/v1/map?view=external"+q, &m); code != 200 {
			t.Fatal(code)
		}
		for _, w := range [][3]string{{"app:gmail", "domain:evil.example", "SEND"}, {"app:gmail", "domain:supplier.example", "SEND"},
			{"agent:mailer_agent", "app:gmail", "SEND"}, {"agent:other_agent", "app:gmail", "SEND"}} {
			if !hasEdge(m, w[0], w[1], w[2]) {
				t.Errorf("external view misses %v", w)
			}
		}
		if hasEdge(m, "agent:finance_agent", "store:postgres:finance", "READ") {
			t.Fatal("internal edge in the external view")
		}
		if n := node(m, "domain:evil.example"); n == nil || !n.External {
			t.Fatalf("domain node %+v", n)
		}
		if code := e.get(t, "/v1/map?view=external&id=evil.example"+q, &m); code != 200 {
			t.Fatal(code)
		}
		if !hasEdge(m, "agent:mailer_agent", "app:gmail", "SEND") || hasEdge(m, "agent:other_agent", "app:gmail", "SEND") ||
			hasEdge(m, "app:gmail", "domain:supplier.example", "SEND") {
			t.Fatalf("one domain: %+v", m.Edges)
		}
	})

	t.Run("truncation", func(t *testing.T) {
		small, err := commap.NewService(e.pool, mapCfg, commap.Limits{MaxEdges: 2})
		if err != nil {
			t.Fatal(err)
		}
		m, err := small.Map(ctx, commap.Query{View: commap.ViewAgent, Window: commap.Window{From: e.base, To: e.base.Add(time.Hour)}})
		if err != nil {
			t.Fatal(err)
		}
		if len(m.Edges) != 2 || !m.Truncated || m.TotalEdges <= 2 {
			t.Fatalf("truncation: %d edges, truncated=%v total=%d", len(m.Edges), m.Truncated, m.TotalEdges)
		}
	})
}

func reachTo(m commap.MapResult, to string) *commap.Edge {
	for i := range m.Edges {
		if m.Edges[i].Reach && m.Edges[i].To == to {
			return &m.Edges[i]
		}
	}
	return nil
}

// Blast radius: everything the agent can reach now (profiles, overrides,
// memory access, level), not just what it called.
func TestBlastRadius(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	e.register(t, "fin", "finance", "cfo@acme.test")
	e.decideAt(t, e.base.Add(time.Minute), pgRead("fin", "finance", "financial"))
	e.rollup(t)
	profiles := map[string]string{
		"postgres": `{"upstreams":{"finance":"read_only","crm":"read_write"}}`,
		"http":     `{"external":"allowlist","allowed_domains":["api.partner.example"]}`,
		"gmail":    `{"send":"any","read":true,"max_recipients":10}`,
		"a2a":      `{"may_delegate_to":["reporter"],"max_depth":2}`,
		"mcp":      `{"servers":{"github-mcp":["*"]}}`,
	}
	for sys, p := range profiles {
		if _, err := e.pool.Exec(ctx, `INSERT INTO access_profiles (agent_id, system, version, profile_json, changed_by, reason)
			VALUES ('fin', $1, 1, $2, 'test', 'test')`, sys, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := e.pool.Exec(ctx, `
		INSERT INTO access_overrides (override_id, scope, scope_id, system, mode, reason, created_by)
		VALUES ('ovr_1', 'agent', 'fin', 'gmail', 'suspended', 'incident', 'sec@acme.test'),
		       ('ovr_2', 'team', 'finance', 'postgres', 'read_only', 'audit', 'sec@acme.test'),
		       ('ovr_3', 'agent', 'fin', 'mcp', 'suspended', 'old', 'sec@acme.test');
		UPDATE access_overrides SET status = 'released' WHERE override_id = 'ovr_3';
		INSERT INTO integrations (key, system, updated_by) VALUES ('memory:support', 'memory', 'test');
		INSERT INTO memory_access (agent_id, mode, reason, changed_by) VALUES ('fin', 'staging_only', 'review', 'sec@acme.test');
		INSERT INTO credential_issuances (issuance_id, agent_id, system, expires_at) VALUES ('iss_1', 'fin', 'postgres', now() + interval '1 hour')`); err != nil {
		t.Fatal(err)
	}
	q := "/v1/map?view=blast&id=fin&from=" + rfc(e.base) + "&to=" + rfc(e.base.Add(time.Hour))
	var m commap.MapResult
	if code := e.get(t, q, &m); code != 200 {
		t.Fatal(code)
	}
	if m.Agent == nil || m.Agent.ID != "agent:fin" {
		t.Fatalf("agent %+v", m.Agent)
	}
	if !hasEdge(m, "agent:fin", "store:postgres:finance", "READ") {
		t.Fatal("observed edges missing from the blast view")
	}
	check := func(to, effective string) *commap.Edge {
		t.Helper()
		r := reachTo(m, to)
		if r == nil {
			t.Fatalf("no reach to %s: %+v", to, m.Edges)
		}
		if r.Effective != effective {
			t.Fatalf("reach %s effective %s, want %s (%+v)", to, r.Effective, effective, r)
		}
		return r
	}
	crm := check("store:postgres:crm", "read") // read_write narrowed by the team override
	if len(crm.Limits) != 1 || crm.Detail["live_credentials"] != float64(1) {
		t.Fatalf("crm %+v", crm)
	}
	check("store:postgres:finance", "read")
	check("domain:api.partner.example", "read_write")
	check("app:gmail", "none") // suspended by override
	check("domain:*", "none")  // gmail send any, suspended
	check("agent:reporter", "read_write")
	check("mcp:github-mcp", "read_write") // released override no longer applies
	check("memory:support/*", "read_write")
	if n := node(m, "store:postgres:crm"); n == nil || !n.Reachable || !n.Halo {
		t.Fatalf("crm should be reachable and halo (not called): %+v", n)
	}
	if n := node(m, "store:postgres:finance"); n == nil || !n.Reachable || n.Halo {
		t.Fatalf("finance is reachable and was called: %+v", n)
	}
	if n := node(m, "app:gmail"); n == nil || n.Reachable {
		t.Fatalf("gmail is suspended: not reachable: %+v", n)
	}
	if !slices.Equal(m.Unprofiled, []string{"files", "shell"}) {
		t.Fatalf("unprofiled %v", m.Unprofiled)
	}
	// Isolated: external reach is cut, internal reads only.
	if _, err := e.ctl.SetLevel(ctx, "fin", 3, "test", "user:sec@acme.test"); err != nil {
		t.Fatal(err)
	}
	if code := e.get(t, q, &m); code != 200 {
		t.Fatal(code)
	}
	check("domain:api.partner.example", "none")
	check("mcp:github-mcp", "read")
	if code := e.get(t, "/v1/map?view=blast&id=ghost", nil); code != 404 {
		t.Fatalf("unknown agent %d", code)
	}
}

func TestAPIValidation(t *testing.T) {
	e := newEnv(t)
	e.register(t, "a", "t", "")
	cases := map[string]int{
		"/v1/map?view=galaxy":                                         400,
		"/v1/map?view=agent&color=red":                                400,
		"/v1/map?view=agent&view=team":                                400,
		"/v1/map?view=agent&id=bad%20id":                              400,
		"/v1/map?view=blast":                                          400,
		"/v1/map?view=external&id=domain:x.example":                   400,
		"/v1/map?view=team&id=%00":                                    400,
		"/v1/map?from=yesterday":                                      400,
		"/v1/map?from=2026-01-02T00:00:00Z&to=2026-01-01T00:00:00Z":   400,
		"/v1/map?from=2025-01-01T00:00:00Z&to=2026-01-01T00:00:00Z":   400, // longer than retention
		"/v1/map?to=2999-01-01T00:00:00Z":                             400,
		"/v1/map/path?label=financial":                                400,
		"/v1/map/path?label=Financial&dest=domain:x.example":          400,
		"/v1/map/path?label=financial&dest=evil.example":              400,
		"/v1/map/path?label=financial&dest=domain:x.example&depth=99": 400,
		"/v1/map/path?label=financial&dest=domain:x.example&depth=x":  400,
		"/v1/map/path?label=financial&dest=domain:x.example":          200,
		"/v1/map":                 200,
		"/v1/map?view=agent&id=a": 200,
	}
	for path, want := range cases {
		if got := e.get(t, path, nil); got != want {
			t.Errorf("%s: %d, want %d", path, got, want)
		}
	}
	if got := e.getAs(t, principal(authz.RoleInterceptor), "/v1/map", nil); got != 403 {
		t.Errorf("interceptor role: %d", got)
	}
	if got := e.getAs(t, nil, "/v1/map/path?label=a&dest=domain:x.example", nil); got != 401 {
		t.Errorf("anonymous: %d", got)
	}
	if got := e.getAs(t, principal(authz.RoleSecurity), "/v1/map", nil); got != 200 {
		t.Errorf("security role: %d", got)
	}
}

// Phase 5 review (map #5): in a busy window (an edge folding more actions
// than its 5 samples) an agent that sent labelled mail only to a partner is
// never shown as an origin of a leak to another domain through the same app.
func TestBusyWindowNeverBlamesTheWrongAgent(t *testing.T) {
	e := newEnv(t)
	e.register(t, "innocent_a", "sales", "")
	e.register(t, "exfil_b", "sales", "")
	send := func(agent, to string, at time.Duration) {
		e.decideAt(t, e.base.Add(at), action.Action{AgentID: agent, System: "gmail", Verb: action.VerbSend,
			Target:         map[string]any{"endpoint": "gmail.users.messages.send", "to": []string{to}, "external_domains": 1},
			PayloadSummary: action.PayloadSummary{Bytes: 100, Recipients: 1, DataLabels: []string{"customer_pii"}}})
	}
	for i := 0; i < 6; i++ {
		send("innocent_a", "bob@partner.example", time.Minute+time.Duration(i)*time.Second)
	}
	send("exfil_b", "x@evil.example", 2*time.Minute)
	e.rollup(t)
	var res commap.PathResult
	if code := e.get(t, pathURL("customer_pii", "domain:evil.example", e.base, e.base.Add(time.Hour)), &res); code != 200 {
		t.Fatalf("status %d", code)
	}
	if len(res.Paths) != 1 || res.Paths[0].Nodes[0] != "agent:exfil_b" {
		t.Fatalf("paths %+v", res.Paths)
	}
	var m commap.MapResult
	q := url.Values{"view": {"external"}, "id": {"evil.example"}, "from": {rfc(e.base)}, "to": {rfc(e.base.Add(time.Hour))}}
	if code := e.get(t, "/v1/map?"+q.Encode(), &m); code != 200 {
		t.Fatalf("external view status %d", code)
	}
	for _, ed := range m.Edges {
		if ed.From == "agent:innocent_a" {
			t.Fatalf("external view of evil.example shows innocent_a: %+v", ed)
		}
	}
}

// Phase 5 review (map #6): an agent with no http profile can read any
// external domain by default; its blast radius says so.
func TestBlastRadiusShowsDefaultOpenWeb(t *testing.T) {
	e := newEnv(t)
	e.register(t, "browser", "support", "")
	q := "/v1/map?view=blast&id=browser&from=" + rfc(e.base) + "&to=" + rfc(e.base.Add(time.Hour))
	var m commap.MapResult
	if code := e.get(t, q, &m); code != 200 {
		t.Fatal(code)
	}
	r := reachTo(m, "domain:*")
	if r == nil || r.Effective != "read" || !strings.Contains(r.Granted, "no http profile") {
		t.Fatalf("default-open web reach: %+v", r)
	}
}
