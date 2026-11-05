package saasrest

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

const (
	testAgent = "0Xxg70000020uCOCAY"
	agentBase = "/gw/salesforce/einstein/ai-agent/v1"
)

// agentforce configures Salesforce with a separate Agent API app on the
// local fake and lets bot_rw and bot_ro talk to testAgent.
func (e *env) agentforce(messages string) {
	e.t.Helper()
	e.sf.AgentClientID, e.sf.AgentClientSecret = "sf-agent-client", "agent-secret-value-456"
	e.sf.Agents = map[string]string{testAgent: "Fortik Kill Switch", "0Xxg7000000OTHER1A": "Other Agent"}
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "agent_api_url": e.sfURL, "agent_client_id": "sf-agent-client"},
		map[string]any{"client_secret": "sf-secret-value-123", "agent_client_secret": "agent-secret-value-456"})
	extra := ""
	if messages != "" {
		extra = `,"agentforce_messages":"` + messages + `"`
	}
	e.profile("bot_rw", "salesforce", `{"mode":"read_write","objects":["*"],"agentforce_agents":["`+testAgent+`"]`+extra+`}`)
	e.profile("bot_ro", "salesforce", `{"mode":"read_only","objects":["*"],"agentforce_agents":["`+testAgent+`"]}`)
}

func (e *env) startSession(agent string) (string, gwResp) {
	e.t.Helper()
	r := e.call(agent, "POST", agentBase+"/agents/"+testAgent+"/sessions", `{"instanceConfig":{"endpoint":"https://evil.example.com"},"bypassUser":true}`, nil)
	var sr struct {
		SessionID string `json:"sessionId"`
	}
	_ = json.Unmarshal([]byte(r.body), &sr)
	return sr.SessionID, r
}

func (e *env) target(actionID string) map[string]any {
	e.t.Helper()
	var raw []byte
	_ = e.pool.QueryRow(e.ctx, `SELECT target FROM actions WHERE action_id = $1`, actionID).Scan(&raw)
	var t map[string]any
	_ = json.Unmarshal(raw, &t)
	return t
}

func TestAgentAPITestConnection(t *testing.T) {
	e := setup(t)
	e.agentforce("")
	e.test("salesforce")
	v := e.status("salesforce")
	ag, _ := v.Capabilities["agent_api"].(map[string]any)
	if v.State != StateConnected || ag["status"] != "ready" || ag["token_format"] != "jwt" || ag["credentials"] != "separate Agent API app" {
		t.Fatalf("agent api check: %v", ag)
	}
	agents, _ := ag["agents"].([]any)
	if len(agents) != 2 || !strings.Contains(e.sf.bodies[len(e.sf.bodies)-1]+v.Detail+toJSON(agents), testAgent) {
		t.Fatalf("agents: %v", agents)
	}
	if e.sf.count("POST /einstein") != 0 {
		t.Fatal("Test connection started an Agent API session")
	}
	// Without a separate app, the REST app's opaque token is reported as not ready.
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "agent_api_url": e.sfURL, "agent_client_id": ""}, nil)
	e.test("salesforce")
	v = e.status("salesforce")
	ag, _ = v.Capabilities["agent_api"].(map[string]any)
	if v.State != StateConnected || ag["status"] != "not_ready" || !strings.Contains(ag["detail"].(string), "JWT") {
		t.Fatalf("opaque token: %v", ag)
	}
	// A consumer key without its secret is never sent.
	other := strings.Replace(e.sfURL, "127.0.0.1", "localhost", 1) // another tenant: another host
	e.configure("salesforce:nosecret", map[string]any{"instance_url": other, "client_id": "sf-client", "agent_client_id": "sf-agent-client"},
		map[string]any{"client_secret": "sf-secret-value-123"})
	before := len(e.sf.requests)
	e.test("salesforce:nosecret")
	if v := e.status("salesforce:nosecret"); v.State != StateInvalid || !strings.Contains(v.Detail, "Agent API consumer secret") || len(e.sf.requests) != before {
		t.Fatalf("missing agent secret: %+v", v)
	}
	// A non-Salesforce Agent API host is refused at save time or by the guard.
	if code, _ := e.do("PUT", "/v1/integrations/salesforce", map[string]any{"config": map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "agent_api_url": "ftp://x"}}); code != 400 {
		t.Fatalf("bad agent api url accepted: %d", code)
	}
	e.noSecretAnywhere(v)
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestAgentAPIGateway(t *testing.T) {
	e := setup(t)
	e.agentforce("")
	sid, r := e.startSession("bot_rw")
	if r.status != 200 || r.decision != "allow" || sid == "" {
		t.Fatalf("start: %+v", r)
	}
	tgt := e.target(r.actionID)
	if tgt["api"] != "agent_api" || tgt["operation"] != "agent_session_start" || tgt["agentforce_agent"] != testAgent || tgt["integration_id"] != "salesforce:default" {
		t.Fatalf("start target %v", tgt)
	}
	// Fortik names its own org, whatever the agent sent.
	sb := e.sf.StartBodies[len(e.sf.StartBodies)-1]
	if ic, _ := sb["instanceConfig"].(map[string]any); ic["endpoint"] != e.sfURL || sb["externalSessionKey"] == "" {
		t.Fatalf("start body %v", sb)
	}
	msg := agentBase + "/sessions/" + sid + "/messages"
	body := `{"message":{"type":"Text","text":"Close case 00001234"}}`
	// A message is held for approval and not sent.
	before := e.sf.count("POST /einstein/ai-agent/v1/sessions/")
	h := e.call("bot_rw", "POST", msg, body, nil)
	if h.status != 403 || h.decision != "hold" || h.rule != "POL-1214" || e.sf.count("POST /einstein/ai-agent/v1/sessions/") != before {
		t.Fatalf("message not held: %+v", h)
	}
	if ht := e.target(h.actionID); ht["message_preview"] != "Close case 00001234" || ht["session_id"] != sid || ht["message_sha256"] == "" {
		t.Fatalf("held target %v", ht)
	}
	e.approve(h.actionID)
	// Another message is not covered by that approval.
	if o := e.call("bot_rw", "POST", msg, `{"message":{"type":"Text","text":"Delete all cases"}}`, nil); o.decision != "hold" {
		t.Fatalf("other message ran on an approval: %+v", o)
	}
	ok := e.call("bot_rw", "POST", msg, body, nil)
	if ok.status != 200 || !strings.Contains(ok.body, "echo: Close case 00001234") {
		t.Fatalf("approved retry: %+v", ok)
	}
	if again := e.call("bot_rw", "POST", msg, body, nil); again.decision != "hold" {
		t.Fatalf("approval reused: %+v", again)
	}
	// Another agent cannot use the session; a read-only agent cannot message.
	if x := e.call("bot_ro", "POST", msg, body, nil); x.status != 403 || x.decision != "deny" {
		t.Fatalf("foreign session: %+v", x)
	}
	rosid, _ := e.startSession("bot_ro")
	if ro := e.call("bot_ro", "POST", agentBase+"/sessions/"+rosid+"/messages", body, nil); ro.rule != "POL-021" {
		t.Fatalf("read-only message: %+v", ro)
	}
	// Agents not in the profile; streaming; unknown Agent API paths.
	if n := e.call("bot_rw", "POST", agentBase+"/agents/0Xxg7000000OTHER1A/sessions", "{}", nil); n.rule != "POL-1213" {
		t.Fatalf("unlisted agent: %+v", n)
	}
	if s := e.call("bot_rw", "POST", msg+"/stream", body, nil); s.decision != "deny" {
		t.Fatalf("stream: %+v", s)
	}
	if u := e.call("bot_rw", "GET", agentBase+"/agents", "", nil); u.decision != "deny" {
		t.Fatalf("unknown path: %+v", u)
	}
	if b := e.call("bot_rw", "POST", msg, `{"message":{"type":"Text","text":""}}`, nil); b.decision != "deny" {
		t.Fatalf("empty message: %+v", b)
	}
	// agentforce_messages "allow": messages run without approval.
	e.profile("bot_rw", "salesforce", `{"mode":"read_write","objects":["*"],"agentforce_agents":["`+testAgent+`"],"agentforce_messages":"allow"}`)
	if a := e.call("bot_rw", "POST", msg, `{"text":"short form"}`, nil); a.status != 200 || !strings.Contains(a.body, "echo: short form") {
		t.Fatalf("allowed message: %+v", a)
	}
	// End: the session is forgotten.
	if d := e.call("bot_rw", "DELETE", agentBase+"/sessions/"+sid, "", nil); d.status != 200 || d.decision != "allow" {
		t.Fatalf("end: %+v", d)
	}
	if after := e.call("bot_rw", "POST", msg, body, nil); after.decision != "deny" {
		t.Fatalf("message after end: %+v", after)
	}
	e.noSecretAnywhere()
}

func (e *env) rpc(agent, path string, id int, method string, params any) map[string]any {
	e.t.Helper()
	b, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
	r := e.call(agent, "POST", path, string(b), nil)
	if r.status != 200 {
		e.t.Fatalf("%s: HTTP %d %s", method, r.status, r.body)
	}
	var out map[string]any
	_ = json.Unmarshal([]byte(r.body), &out)
	res, _ := out["result"].(map[string]any)
	if res == nil {
		e.t.Fatalf("%s: %s", method, r.body)
	}
	return res
}

func toolText(res map[string]any) string {
	c, _ := res["content"].([]any)
	if len(c) == 0 {
		return ""
	}
	m, _ := c[0].(map[string]any)
	s, _ := m["text"].(string)
	return s
}

func TestAgentMCP(t *testing.T) {
	e := setup(t)
	e.agentforce("")
	const path = "/mcp/agentforce/default"
	init := e.rpc("bot_rw", path, 1, "initialize", map[string]any{"protocolVersion": "2025-06-18"})
	if init["protocolVersion"] != "2025-06-18" {
		t.Fatalf("initialize %v", init)
	}
	tools, _ := e.rpc("bot_rw", path, 2, "tools/list", map[string]any{})["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools %v", tools)
	}
	list := e.rpc("bot_rw", path, 3, "tools/call", map[string]any{"name": "agentforce_list_agents", "arguments": map[string]any{}})
	if list["isError"] != false || !strings.Contains(toolText(list), testAgent) {
		t.Fatalf("list %v", list)
	}
	// A message is held: the session was started and the reply says how to retry.
	held := e.rpc("bot_rw", path, 4, "tools/call", map[string]any{"name": "agentforce_send_message", "arguments": map[string]any{"agent_id": testAgent, "message": "Status of case 42?"}})
	meta, _ := held["_meta"].(map[string]any)
	sc, _ := held["structuredContent"].(map[string]any)
	sid, _ := sc["session_id"].(string)
	if held["isError"] != true || meta["fortik/decision"] != "hold" || sid == "" || !strings.Contains(toolText(held), "HELD") || e.sf.count("POST /einstein/ai-agent/v1/sessions/") != 0 {
		t.Fatalf("held %v", held)
	}
	e.approve(meta["fortik/action_id"].(string))
	ok := e.rpc("bot_rw", path, 5, "tools/call", map[string]any{"name": "agentforce_send_message", "arguments": map[string]any{"agent_id": testAgent, "message": "Status of case 42?", "session_id": sid}})
	if ok["isError"] != false || !strings.Contains(toolText(ok), "echo: Status of case 42?") {
		t.Fatalf("approved %v", ok)
	}
	// Same decisions as REST: an unlisted agent is refused.
	no := e.rpc("bot_rw", path, 6, "tools/call", map[string]any{"name": "agentforce_send_message", "arguments": map[string]any{"agent_id": "0Xxg7000000OTHER1A", "message": "hi"}})
	if no["isError"] != true || !strings.Contains(toolText(no), "POL-1213") {
		t.Fatalf("unlisted %v", no)
	}
	// An unknown tenant has no connection.
	tn := e.rpc("bot_rw", "/mcp/agentforce/nosuch", 7, "tools/call", map[string]any{"name": "agentforce_send_message", "arguments": map[string]any{"agent_id": testAgent, "message": "hi"}})
	if tn["isError"] != true {
		t.Fatalf("unknown tenant %v", tn)
	}
	end := e.rpc("bot_rw", path, 8, "tools/call", map[string]any{"name": "agentforce_end_session", "arguments": map[string]any{"session_id": sid}})
	if end["isError"] != false {
		t.Fatalf("end %v", end)
	}
	bad := e.rpc("bot_rw", path, 9, "tools/call", map[string]any{"name": "agentforce_send_message", "arguments": map[string]any{"agent_id": testAgent, "message": "x", "extra": 1}})
	if bad["isError"] != true {
		t.Fatalf("unknown argument accepted %v", bad)
	}
	// Without an agent token nothing is served.
	req, _ := http.NewRequest("POST", e.gw.URL+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 401 {
		t.Fatalf("no token: %v %v", res, err)
	}
	e.noSecretAnywhere()
}

func TestAgentAPIHelpers(t *testing.T) {
	if f, s := inspectToken("abc"); f != "opaque" || s != nil {
		t.Fatal(f, s)
	}
	b, _ := startBody([]byte(`{"externalSessionKey":"bad key with spaces","instanceConfig":{"endpoint":"https://evil"},"bypassUser":false,"variables":[{"name":"x"}]}`), "https://acme.my.salesforce.com")
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if ic := m["instanceConfig"].(map[string]any); ic["endpoint"] != "https://acme.my.salesforce.com" || m["bypassUser"] != false || m["externalSessionKey"] == "bad key with spaces" {
		t.Fatalf("start body %v", m)
	}
	if _, err := startBody([]byte(`[1]`), "x"); err == nil {
		t.Fatal("array body accepted")
	}
	for _, bad := range []string{`{}`, `not json`, `{"message":{"type":"Image","text":"x"}}`, `{"text":"` + strings.Repeat("a", maxMessageChars+1) + `"}`, `{"text":"x","variables":{"a":1}}`} {
		if _, _, _, err := parseAgentMessage([]byte(bad)); err == nil {
			t.Fatalf("accepted %q", bad[:min(len(bad), 40)])
		}
	}
	if txt, _, _, err := parseAgentMessage([]byte(`{"message":{"sequenceId":3,"type":"Text","text":"hi"},"variables":[]}`)); err != nil || txt != "hi" {
		t.Fatal(txt, err)
	}
}
