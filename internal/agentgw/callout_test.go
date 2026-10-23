package agentgw

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/genproto/googleapis/rpc/code"
	"google.golang.org/grpc/metadata"

	"fortik/internal/agentgw/extmcp"
	"fortik/internal/config"
	"fortik/internal/control"
)

// --- ext_authz helpers -----------------------------------------------------------

func a2aCtx(route string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), MetaRouteAgent, route)
}

func httpCtx(domain string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), MetaRouteHTTP, domain)
}

func checkReq(method, path, host string, headers map[string]string, body string) *authv3.CheckRequest {
	return &authv3.CheckRequest{Attributes: &authv3.AttributeContext{Request: &authv3.AttributeContext_Request{
		Http: &authv3.AttributeContext_HttpRequest{Method: method, Path: path, Host: host, Headers: headers, Body: body},
	}}}
}

func a2aBody(method string, params string) string {
	return `{"jsonrpc":"2.0","id":1,"method":"` + method + `","params":` + params + `}`
}

const sendParams = `{"message":{"role":"user","parts":[{"kind":"text","text":"summarise the report"}],"messageId":"m-1"}}`

func (f *fixture) check(t *testing.T, ctx context.Context, req *authv3.CheckRequest) *authv3.CheckResponse {
	t.Helper()
	resp, err := authv3.NewAuthorizationClient(f.conn).Check(ctx, req)
	if err != nil {
		t.Fatalf("Check returned a gRPC error (must always answer): %v", err)
	}
	return resp
}

// okHeaders returns the headers an allow sets, or fails if it is not an allow.
func okHeaders(t *testing.T, resp *authv3.CheckResponse) (map[string]string, []string) {
	t.Helper()
	ok := resp.GetOkResponse()
	if resp.GetStatus().GetCode() != int32(code.Code_OK) || ok == nil {
		t.Fatalf("want allow, got status %v body %s", resp.GetStatus(), resp.GetDeniedResponse().GetBody())
	}
	set := map[string]string{}
	for _, h := range ok.GetHeaders() {
		set[h.GetHeader().GetKey()] = h.GetHeader().GetValue()
	}
	return set, ok.GetHeadersToRemove()
}

// denied returns the refusal JSON of a deny (A2A: JSON-RPC error.data).
func denied(t *testing.T, resp *authv3.CheckResponse, wantHTTP int) map[string]any {
	t.Helper()
	d := resp.GetDeniedResponse()
	if d == nil || resp.GetStatus().GetCode() == int32(code.Code_OK) {
		t.Fatalf("want deny, got %v", resp)
	}
	if int(d.GetStatus().GetCode()) != wantHTTP {
		t.Fatalf("deny HTTP status = %d, want %d (body %s)", d.GetStatus().GetCode(), wantHTTP, d.GetBody())
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(d.GetBody()), &body); err != nil {
		t.Fatalf("deny body is not JSON: %s", d.GetBody())
	}
	if e, ok := body["error"].(map[string]any); ok {
		if data, ok := e["data"].(map[string]any); ok {
			return data
		}
		return e
	}
	t.Fatalf("deny body has no error: %s", d.GetBody())
	return nil
}

func (f *fixture) delegateFrom(t *testing.T, agent, route, inbound string, spoof map[string]string) *authv3.CheckResponse {
	t.Helper()
	h := map[string]string{"authorization": bearer(agent), "content-type": "application/json"}
	if inbound != "" {
		h[headerDelegation] = inbound
	}
	for k, v := range spoof {
		h[k] = v
	}
	return f.check(t, a2aCtx(route), checkReq("POST", "/a2a/"+route, "gw.local", h, a2aBody("message/send", sendParams)))
}

// --- ext_authz: A2A -----------------------------------------------------------------

func TestA2ADelegationAllowedInjectsToken(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":3}`)

	resp := f.delegateFrom(t, "agent_a", "agent-b", "", map[string]string{
		HeaderAgentID: "agent_c", HeaderActionID: "act_forged", headerDelegation: "",
	})
	set, remove := okHeaders(t, resp)
	if set[HeaderAgentID] != "agent_a" {
		t.Fatalf("x-fortik-agent-id = %q: the client value must be overwritten with the authenticated agent", set[HeaderAgentID])
	}
	if !strings.HasPrefix(set[HeaderActionID], "act_") || set[HeaderActionID] == "act_forged" {
		t.Fatalf("action id = %q", set[HeaderActionID])
	}
	if !slices.Contains(remove, "authorization") {
		t.Fatalf("the agent's Fortik token must not reach the delegatee: remove=%v", remove)
	}
	tok := set[headerDelegation]
	if tok == "" {
		t.Fatal("no X-Fortik-Delegation injected on an allowed delegation")
	}
	claims, err := f.deleg.Verify(context.Background(), tok, "agent_b")
	if err != nil {
		t.Fatalf("injected token does not verify for agent_b: %v", err)
	}
	if !slices.Equal(claims.Chain, []string{"agent_a", "agent_b"}) || claims.Depth != 1 || claims.Root != "agent_a" {
		t.Fatalf("claims: %+v", claims)
	}
	if n := f.count(t, `SELECT count(*) FROM delegations WHERE from_agent='agent_a' AND to_agent='agent_b' AND status='open' AND action_id=$1`, set[HeaderActionID]); n != 1 {
		t.Fatalf("open hops = %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM actions WHERE action_id=$1 AND agent_id='agent_a' AND system='a2a' AND verb='DELEGATE' AND source='agentgateway' AND target->>'to_agent'='agent_b'`, set[HeaderActionID]); n != 1 {
		t.Fatal("DELEGATE action not recorded as expected")
	}
	if strings.Contains(f.diaryBodies(t), tok) || strings.Contains(f.diaryBodies(t), agentTokens["agent_a"]) {
		t.Fatal("a token reached the Diary or the actions table")
	}

	// UC3: agent_b presents the token and delegates on to agent_c; the new
	// hop extends the chain.
	f.putProfile(t, "agent_b", "a2a", `{"may_delegate_to":["agent_c"],"max_depth":3}`)
	resp = f.delegateFrom(t, "agent_b", "agent-c", tok, nil)
	set, _ = okHeaders(t, resp)
	claims, err = f.deleg.Verify(context.Background(), set[headerDelegation], "agent_c")
	if err != nil || !slices.Equal(claims.Chain, []string{"agent_a", "agent_b", "agent_c"}) || claims.Depth != 2 {
		t.Fatalf("second hop: %+v %v", claims, err)
	}

	// The token is only valid for the agent it was issued to.
	f.putProfile(t, "agent_c", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	resp = f.delegateFrom(t, "agent_c", "agent-b", tok, nil)
	data := denied(t, resp, 403)
	if data["rule_id"] != "POL-604" && data["rule_id"] != RuleDelegationToken {
		t.Fatalf("wrong-agent token: %v", data)
	}
	// A forged token is refused, never ignored.
	resp = f.delegateFrom(t, "agent_b", "agent-c", "v1.Zm9yZ2Vk.c2ln", nil)
	data = denied(t, resp, 403)
	if data["rule_id"] != "POL-604" && data["rule_id"] != RuleDelegationToken {
		t.Fatalf("forged token: %v", data)
	}
	// A token in A2A metadata is honoured too, and must agree with the header.
	body := a2aBody("message/send", `{"message":{"metadata":{"fortik_delegation":"other"}}}`)
	resp = f.check(t, a2aCtx("agent-c"), checkReq("POST", "/a2a/agent-c", "gw.local",
		map[string]string{"authorization": bearer("agent_b"), headerDelegation: tok}, body))
	denied(t, resp, 400)
}

func TestA2ADeniedWithoutProfile(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	resp := f.delegateFrom(t, "agent_a", "agent-b", "", nil)
	data := denied(t, resp, 403)
	if data["rule_id"] != "POL-020" || data["decision"] != "deny" || data["code"] != "fortik_refused" {
		t.Fatalf("refusal: %v", data)
	}
	d := resp.GetDeniedResponse()
	if !strings.Contains(d.GetBody(), `"jsonrpc":"2.0"`) || !strings.Contains(d.GetBody(), `"id":1`) {
		t.Fatalf("A2A refusal must be a JSON-RPC error echoing the id: %s", d.GetBody())
	}
	for _, h := range d.GetHeaders() {
		if h.GetHeader().GetKey() == headerDelegation {
			t.Fatal("token header on a refusal")
		}
	}
	if n := f.count(t, `SELECT count(*) FROM delegations`); n != 0 {
		t.Fatalf("hop opened for a refusal: %d", n)
	}
	// May not delegate to an agent outside may_delegate_to (POL-603).
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_c"],"max_depth":3}`)
	data = denied(t, f.delegateFrom(t, "agent_a", "agent-b", "", nil), 403)
	if data["rule_id"] != "POL-603" {
		t.Fatalf("not in may_delegate_to: %v", data)
	}
}

func TestA2AMalformedAndBatchDenied(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	h := map[string]string{"authorization": bearer("agent_a")}
	for name, body := range map[string]string{
		"batch":          `[` + a2aBody("message/send", sendParams) + `,` + a2aBody("message/send", sendParams) + `]`,
		"malformed":      `{"jsonrpc":"2.0","id":1,"method":`,
		"unknown method": a2aBody("tasks/explode", `{}`),
		"dup keys":       `{"jsonrpc":"2.0","id":1,"method":"tasks/get","method":"message/send","params":` + sendParams + `}`,
	} {
		resp := f.check(t, a2aCtx("agent-b"), checkReq("POST", "/a2a/agent-b", "gw.local", h, body))
		data := denied(t, resp, 400)
		if data["decision"] != "deny" {
			t.Errorf("%s: %v", name, data)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM actions WHERE verb='UNKNOWN' AND decision='deny'`); n != 4 {
		t.Fatalf("unclassified requests must be recorded and denied: %d", n)
	}
	if n := f.count(t, `SELECT count(*) FROM delegations`); n != 0 {
		t.Fatal("hop opened by a malformed request")
	}
	// No HTTP attributes at all.
	resp, err := authv3.NewAuthorizationClient(f.conn).Check(a2aCtx("agent-b"), &authv3.CheckRequest{})
	if err != nil || resp.GetDeniedResponse() == nil {
		t.Fatalf("empty request: %v %v", resp, err)
	}
}

func TestA2AAuthentication(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	body := a2aBody("message/send", sendParams)
	for name, h := range map[string]map[string]string{
		"missing token":                  {},
		"invalid token":                  {"authorization": "Bearer nope-not-a-token"},
		"spoofed agent header, no token": {HeaderAgentID: "agent_a"},
		"basic auth":                     {"authorization": "Basic YWdlbnRfYTpw"},
	} {
		resp := f.check(t, a2aCtx("agent-b"), checkReq("POST", "/a2a/agent-b", "gw.local", h, body))
		data := denied(t, resp, 401)
		if data["code"] != "unauthenticated" || resp.GetStatus().GetCode() != int32(code.Code_UNAUTHENTICATED) {
			t.Errorf("%s: %v", name, data)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM actions`); n != 0 {
		t.Fatalf("unauthenticated requests reached Decide: %d", n)
	}
}

func TestRouteIdentity(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	h := map[string]string{"authorization": bearer("agent_a"),
		// Client copies of the route headers are never read.
		MetaRouteAgent: "agent-b", MetaRouteHTTP: "api.example.com"}
	body := a2aBody("message/send", sendParams)
	cases := map[string]context.Context{
		"no route metadata":   context.Background(),
		"unconfigured route":  a2aCtx("agent-z"),
		"two routes":          metadata.AppendToOutgoingContext(context.Background(), MetaRouteAgent, "agent-b", MetaRouteHTTP, "x.com"),
		"MCP route on authz":  metadata.AppendToOutgoingContext(context.Background(), MetaRouteMCP, "memory"),
		"repeated route meta": metadata.AppendToOutgoingContext(context.Background(), MetaRouteAgent, "agent-b", MetaRouteAgent, "agent-c"),
	}
	for name, ctx := range cases {
		resp := f.check(t, ctx, checkReq("POST", "/a2a/agent-b", "gw.local", h, body))
		if resp.GetDeniedResponse() == nil {
			t.Errorf("%s: allowed", name)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM delegations`); n != 0 {
		t.Fatal("hop opened without a route identity")
	}
}

// With the bundle exactly as checked in: while a2a is not yet a rule
// system, a DELEGATE is held (POL-005): refused, no hop, no token. Once the
// hook workstream lists a2a (docs/PHASE3_DESIGN.md §3.4) it is allowed.
func TestStockBundleDelegation(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{}, fixtureOpts{stockBundle: true})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":3}`)
	resp := f.delegateFrom(t, "agent_a", "agent-b", "", nil)
	if stockRuleSystem(t, "a2a") {
		set, _ := okHeaders(t, resp)
		if set[headerDelegation] == "" {
			t.Fatal("no token")
		}
		return
	}
	data := denied(t, resp, 403)
	if data["decision"] != "hold" || data["held"] != true || data["rule_id"] != "POL-005" {
		t.Fatalf("stock bundle: %v", data)
	}
	if n := f.count(t, `SELECT count(*) FROM delegations`); n != 0 {
		t.Fatal("held DELEGATE opened a hop")
	}
}

func TestA2ATaskMethods(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":3}`)
	h := map[string]string{"authorization": bearer("agent_a")}
	resp := f.check(t, a2aCtx("agent-b"), checkReq("POST", "/a2a/agent-b", "gw.local", h, a2aBody("tasks/get", `{"id":"t-1"}`)))
	set, _ := okHeaders(t, resp)
	if set[headerDelegation] != "" {
		t.Fatal("token injected on a READ")
	}
	resp = f.check(t, a2aCtx("agent-b"), checkReq("GET", "/a2a/agent-b/.well-known/agent-card.json", "gw.local", h, ""))
	okHeaders(t, resp)
	if n := f.count(t, `SELECT count(*) FROM actions WHERE verb='READ' AND system='a2a' AND decision='allow'`); n != 2 {
		t.Fatalf("READ actions: %d", n)
	}
}

// --- ext_authz: HTTP egress -------------------------------------------------------------

func TestHTTPEgress(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{InternalHosts: []string{"intranet.acme.com"}})
	f.putProfile(t, "agent_a", "http", `{"external":"allowlist","allowed_domains":["api.example.com"]}`)
	h := map[string]string{"authorization": bearer("agent_a")}

	resp := f.check(t, httpCtx("api.example.com"), checkReq("GET", "/v1/items?q=1", "api.example.com", h, ""))
	set, _ := okHeaders(t, resp)
	if set[HeaderAgentID] != "agent_a" {
		t.Fatal("identity not injected")
	}
	var target string
	if err := f.pool.QueryRow(context.Background(), `SELECT target::text FROM actions WHERE action_id=$1`, set[HeaderActionID]).Scan(&target); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"domain": "api.example.com"`, `"external": true`, `"method": "GET"`} {
		if !strings.Contains(target, want) {
			t.Fatalf("target %s lacks %s", target, want)
		}
	}
	if strings.Contains(target, "q=1") {
		t.Fatal("query string stored")
	}

	// A domain outside the allowlist (route + host agree).
	resp = f.check(t, httpCtx("evil.example.net"), checkReq("GET", "/", "evil.example.net", h, ""))
	if data := denied(t, resp, 403); data["rule_id"] != "POL-028" {
		t.Fatalf("outside allowlist: %v", data)
	}
	// A body to an external host is EXPORT (held while http has no rule set).
	resp = f.check(t, httpCtx("api.example.com"), checkReq("POST", "/v1/items", "api.example.com",
		map[string]string{"authorization": bearer("agent_a"), "content-length": "12"}, `{"a":"data"}`))
	if !stockRuleSystem(t, "http") {
		if data := denied(t, resp, 403); data["decision"] != "hold" {
			t.Fatalf("external POST: %v", data)
		}
	}
	if n := f.count(t, `SELECT count(*) FROM actions WHERE system='http' AND verb='EXPORT' AND target->>'method'='POST' AND (target->>'external')::boolean`); n != 1 {
		t.Fatal("external POST not recorded as EXPORT")
	}
	// Host header that disagrees with the route is unclassifiable.
	resp = f.check(t, httpCtx("api.example.com"), checkReq("GET", "/", "evil.example.net", h, ""))
	denied(t, resp, 400)
}

// --- ext_mcp -------------------------------------------------------------------------------

func mcpCtx(route string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), MetaRouteMCP, route)
}

func mcpHdrs(kv ...string) []*extmcp.McpHeader {
	var out []*extmcp.McpHeader
	for i := 0; i+1 < len(kv); i += 2 {
		out = append(out, &extmcp.McpHeader{Key: kv[i], Value: []byte(kv[i+1])})
	}
	return out
}

func (f *fixture) mcpCheck(t *testing.T, ctx context.Context, method, params string, hdrs []*extmcp.McpHeader) *extmcp.McpRequestResult {
	t.Helper()
	req := &extmcp.McpRequest{ServiceNames: []string{"memory"}, Method: method, Headers: hdrs}
	if params != "" {
		req.McpRequest = []byte(params)
	}
	res, err := extmcp.NewExtMcpClient(f.conn).CheckRequest(ctx, req)
	if err != nil {
		t.Fatalf("CheckRequest returned a gRPC error (must always answer): %v", err)
	}
	return res
}

func mcpRefusal(t *testing.T, res *extmcp.McpRequestResult) *extmcp.AuthorizationError {
	t.Helper()
	e := res.GetError()
	if e == nil {
		t.Fatalf("want refusal, got %v", res)
	}
	return e
}

func TestMCPGuardrails(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "mcp", `{"servers":{"memory":["*"]}}`)
	auth := mcpHdrs("authorization", bearer("agent_a"), HeaderAgentID, "agent_c", MetaRouteMCP, "evil")

	// Read tool: allowed, verified identity injected over the spoofed one.
	res := f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"read_graph","arguments":{}}`, auth)
	if res.GetPass() == nil {
		t.Fatalf("read_graph: %v", res)
	}
	set := map[string]string{}
	for _, h := range res.GetHeaderMutation().GetSet() {
		set[h.GetKey()] = string(h.GetValue())
	}
	if set[HeaderAgentID] != "agent_a" || !strings.HasPrefix(set[HeaderActionID], "act_") {
		t.Fatalf("header mutation: %v", set)
	}
	if rm := res.GetHeaderMutation().GetRemove(); !slices.Contains(rm, "authorization") || !slices.Contains(rm, headerDelegation) {
		t.Fatalf("remove: %v", rm)
	}
	// tools/list, resources/read, prompts/get: READ.
	for _, m := range []string{"tools/list", "resources/read", "prompts/get"} {
		if res := f.mcpCheck(t, mcpCtx("memory"), m, `{}`, auth); res.GetPass() == nil {
			t.Errorf("%s: %v", m, res)
		}
	}
	// Delete tool: held (POL-802, and POL-005 while mcp has no rule set).
	e := mcpRefusal(t, f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"delete_entities","arguments":{"entityNames":["x"]}}`, auth))
	if !strings.Contains(e.GetReason(), "hold") || !strings.Contains(e.GetReason(), "action_id=") {
		t.Fatalf("delete_entities: %v", e)
	}
	// Unmapped tool: EXECUTE, held (POL-801, and POL-005 while mcp has no rule set).
	e = mcpRefusal(t, f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"frobnicate"}`, auth))
	if !strings.Contains(e.GetReason(), "hold") {
		t.Fatalf("frobnicate: %v", e)
	}
	// Mapped memory write: REMEMBER. Held by POL-005 until mcp is a rule
	// system (docs/PHASE3_DESIGN.md §3.4), then allowed under the profile.
	res = f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"create_entities","arguments":{"entities":[{"name":"x"}]}}`, auth)
	rememberDecision := "hold"
	if stockRuleSystem(t, "mcp") {
		rememberDecision = "allow"
		if res.GetPass() == nil {
			t.Fatalf("create_entities with mcp rules: %v", res)
		}
	} else if e := mcpRefusal(t, res); !strings.Contains(e.GetReason(), "POL-005") {
		t.Fatalf("create_entities: %v", e)
	}
	var verbs []string
	rows, err := f.pool.Query(context.Background(), `SELECT verb || ':' || decision FROM actions WHERE system='mcp' AND target->>'method'='tools/call' ORDER BY ts`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		verbs = append(verbs, s)
	}
	if !slices.Equal(verbs, []string{"READ:allow", "DELETE:hold", "EXECUTE:hold", "REMEMBER:" + rememberDecision}) {
		t.Fatalf("recorded: %v", verbs)
	}
	// initialize / ping: allowed for an authenticated agent without a decision.
	before := f.count(t, `SELECT count(*) FROM actions`)
	for _, m := range []string{"initialize", "ping"} {
		if res := f.mcpCheck(t, mcpCtx("memory"), m, "", auth); res.GetPass() == nil {
			t.Errorf("%s: %v", m, res)
		}
	}
	if f.count(t, `SELECT count(*) FROM actions`) != before {
		t.Fatal("initialize/ping were decided")
	}
	// ... but not without a token.
	mcpRefusal(t, f.mcpCheck(t, mcpCtx("memory"), "initialize", "", nil))
	// Not in the profile: POL-029.
	f.putProfile(t, "agent_b", "mcp", `{"servers":{"memory":["search_nodes"]}}`)
	e = mcpRefusal(t, f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"read_graph"}`, mcpHdrs("authorization", bearer("agent_b"))))
	if !strings.Contains(e.GetReason(), "POL-029") {
		t.Fatalf("profile: %v", e)
	}
}

func TestMCPRefusals(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "mcp", `{"servers":{"memory":["*"]}}`)
	read := `{"name":"read_graph"}`
	auth := mcpHdrs("authorization", bearer("agent_a"))
	cases := []struct {
		name   string
		ctx    context.Context
		method string
		params string
		hdrs   []*extmcp.McpHeader
		code   extmcp.AuthorizationError_Code
	}{
		{"missing token", mcpCtx("memory"), "tools/call", read, nil, extmcp.AuthorizationError_PERMISSION_DENIED},
		{"invalid token", mcpCtx("memory"), "tools/call", read, mcpHdrs("authorization", "Bearer bogus"), extmcp.AuthorizationError_PERMISSION_DENIED},
		{"spoofed id only", mcpCtx("memory"), "tools/call", read, mcpHdrs(HeaderAgentID, "agent_a"), extmcp.AuthorizationError_PERMISSION_DENIED},
		{"two tokens", mcpCtx("memory"), "tools/call", read, mcpHdrs("authorization", bearer("agent_a"), "Authorization", bearer("agent_b")), extmcp.AuthorizationError_INVALID},
		{"no route", context.Background(), "tools/call", read, auth, extmcp.AuthorizationError_PERMISSION_DENIED},
		{"unknown route", mcpCtx("nope"), "tools/call", read, auth, extmcp.AuthorizationError_PERMISSION_DENIED},
		{"also A2A route", metadata.AppendToOutgoingContext(mcpCtx("memory"), MetaRouteAgent, "agent-b"), "tools/call", read, auth, extmcp.AuthorizationError_PERMISSION_DENIED},
		{"malformed params", mcpCtx("memory"), "tools/call", `{"name":`, auth, extmcp.AuthorizationError_INVALID},
		{"no tool name", mcpCtx("memory"), "tools/call", `{}`, auth, extmcp.AuthorizationError_INVALID},
		{"unknown method", mcpCtx("memory"), "sampling/createMessage", `{}`, auth, extmcp.AuthorizationError_INVALID},
	}
	for _, c := range cases {
		e := mcpRefusal(t, f.mcpCheck(t, c.ctx, c.method, c.params, c.hdrs))
		if e.GetCode() != c.code || !strings.HasPrefix(e.GetReason(), "fortik: ") {
			t.Errorf("%s: %v", c.name, e)
		}
	}
	// Response phase passes through (requests are decided before execution).
	r, err := extmcp.NewExtMcpClient(f.conn).CheckResponse(mcpCtx("memory"), &extmcp.McpResponse{Method: "tools/call"})
	if err != nil || r.GetPass() == nil {
		t.Fatalf("CheckResponse: %v %v", r, err)
	}
}

// UC1 through MCP: agent_a may not use the memory server; it asks agent_b
// (who may) to do it. With the token, or inferred from the open hop without
// it, the call is refused as a delegation bypass and agent_a is stepped down.
func TestMCPDelegationBypassBlocked(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":3}`)
	f.putProfile(t, "agent_b", "mcp", `{"servers":{"memory":["*"]}}`)
	set, _ := okHeaders(t, f.delegateFrom(t, "agent_a", "agent-b", "", nil))
	tok := set[headerDelegation]

	for name, hdrs := range map[string][]*extmcp.McpHeader{
		"with token":         mcpHdrs("authorization", bearer("agent_b"), headerDelegation, tok),
		"inferred, no token": mcpHdrs("authorization", bearer("agent_b")),
	} {
		e := mcpRefusal(t, f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"read_graph"}`, hdrs))
		if !strings.Contains(e.GetReason(), "POL-601") {
			t.Errorf("%s: %v", name, e)
		}
	}
	st, err := f.ctl.Get(context.Background(), "agent_a")
	if err != nil {
		t.Fatal(err)
	}
	if st.Level < control.Supervised {
		t.Fatalf("originating agent not stepped down: %v", st.Level)
	}
	if strings.Contains(f.diaryBodies(t), tok) {
		t.Fatal("token in the Diary")
	}
	// A bad inbound token on MCP is refused too.
	e := mcpRefusal(t, f.mcpCheck(t, mcpCtx("memory"), "tools/call", `{"name":"read_graph"}`,
		mcpHdrs("authorization", bearer("agent_b"), headerDelegation, "garbage")))
	if !strings.Contains(e.GetReason(), "POL-604") && !strings.Contains(e.GetReason(), RuleDelegationToken) {
		t.Fatalf("bad token: %v", e)
	}
}
