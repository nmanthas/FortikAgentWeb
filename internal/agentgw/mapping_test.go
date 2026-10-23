package agentgw

import (
	"encoding/json"
	"strings"
	"testing"

	"fortik/internal/action"
)

func TestParseRPC(t *testing.T) {
	ok := []string{
		`{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{}}}`,
		` {"jsonrpc":"2.0","id":"x","method":"tasks/get","params":null} `,
		`{"jsonrpc":"2.0","method":"tasks/get"}`,
	}
	for _, b := range ok {
		if _, err := parseRPC([]byte(b)); err != nil {
			t.Errorf("parseRPC(%s): %v", b, err)
		}
	}
	bad := map[string]string{
		"batch":         `[{"jsonrpc":"2.0","id":1,"method":"message/send"}]`,
		"empty":         ``,
		"not object":    `"x"`,
		"dup key":       `{"jsonrpc":"2.0","id":1,"method":"tasks/get","method":"message/send"}`,
		"nested dup":    `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"a":{"b":1,"b":2}}}`,
		"unknown field": `{"jsonrpc":"2.0","id":1,"method":"tasks/get","extra":1}`,
		"trailing":      `{"jsonrpc":"2.0","id":1,"method":"tasks/get"} {"x":1}`,
		"version":       `{"jsonrpc":"1.0","id":1,"method":"tasks/get"}`,
		"bad method":    `{"jsonrpc":"2.0","id":1,"method":"tasks get"}`,
		"array params":  `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":[1]}`,
		"deep":          `{"jsonrpc":"2.0","method":"x","params":` + strings.Repeat(`{"a":`, 40) + `1` + strings.Repeat(`}`, 40) + `}`,
	}
	for name, b := range bad {
		if _, err := parseRPC([]byte(b)); err == nil {
			t.Errorf("%s: parseRPC accepted %s", name, b)
		}
	}
	if _, err := parseRPC([]byte(bad["batch"])); err != errBatch {
		t.Errorf("batch error = %v", err)
	}
}

func TestMapA2A(t *testing.T) {
	tok := "tok.abc"
	cases := []struct {
		name     string
		method   string
		path     string
		body     string
		verb     action.Verb
		delegate bool
		taskID   string
		meta     string
		bad      string // substring of Malformed
	}{
		{name: "message/send", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"role":"user","parts":[],"messageId":"m1"}}}`, verb: action.VerbDelegate, delegate: true},
		{name: "message/send continuing a task", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"taskId":"t-9","contextId":"c1"}}}`, verb: action.VerbDelegate, delegate: true, taskID: "t-9"},
		{name: "message/stream", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/stream","params":{"message":{}}}`, verb: action.VerbDelegate, delegate: true},
		{name: "tasks/send", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/send","params":{"id":"t1","message":{}}}`, verb: action.VerbDelegate, delegate: true, taskID: "t1"},
		{name: "tasks/sendSubscribe", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/sendSubscribe","params":{"id":"t1"}}`, verb: action.VerbDelegate, delegate: true, taskID: "t1"},
		{name: "tasks/get", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"t1"}}`, verb: action.VerbRead, taskID: "t1"},
		{name: "tasks/cancel", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/cancel","params":{"id":"t1"}}`, verb: action.VerbWrite, taskID: "t1"},
		{name: "agent card", method: "GET", path: "/a2a/agent_b/.well-known/agent-card.json", verb: action.VerbRead},
		{name: "metadata token", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"metadata":{"fortik_delegation":"` + tok + `"}}}}`, verb: action.VerbDelegate, delegate: true, meta: tok},
		{name: "same token twice", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"metadata":{"fortik_delegation":"` + tok + `"},"message":{"metadata":{"fortik_delegation":"` + tok + `"}}}}`, verb: action.VerbDelegate, delegate: true, meta: tok},

		{name: "batch", method: "POST", body: `[{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}]`, bad: "batch"},
		{name: "unknown method", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/explode","params":{}}`, bad: "unknown A2A method"},
		{name: "missing message", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{}}`, bad: "message is missing"},
		{name: "tasks/get without id", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{}}`, bad: "task id"},
		{name: "numeric task id", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":7}}`, bad: "task id"},
		{name: "conflicting tokens", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"metadata":{"fortik_delegation":"a"},"message":{"metadata":{"fortik_delegation":"b"}}}}`, bad: "conflicting"},
		{name: "non-string token", method: "POST", body: `{"jsonrpc":"2.0","id":1,"method":"message/send","params":{"message":{"metadata":{"fortik_delegation":1}}}}`, bad: "metadata"},
		{name: "malformed json", method: "POST", body: `{"jsonrpc":"2.0",`, bad: "malformed A2A request"},
		{name: "PUT", method: "PUT", body: `{}`, bad: "unsupported A2A HTTP method"},
		{name: "other GET", method: "GET", path: "/a2a/agent_b/tasks", bad: "unsupported A2A GET"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			path := c.path
			if path == "" {
				path = "/a2a/agent_b"
			}
			m := mapA2A(c.method, path, "agent-b", "agent_b", []byte(c.body))
			if m.System != action.SystemA2A || m.Target["to_agent"] != "agent_b" || m.Target["channel"] != ChannelA2A {
				t.Fatalf("system/target: %+v", m)
			}
			if c.bad != "" {
				if m.Malformed == "" || !strings.Contains(m.Malformed, c.bad) || m.Verb != "UNKNOWN" || m.Delegate {
					t.Fatalf("want malformed %q, got %+v", c.bad, m)
				}
				return
			}
			if m.Malformed != "" || m.Verb != c.verb || m.Delegate != c.delegate || m.MetaToken != c.meta {
				t.Fatalf("got %+v", m)
			}
			if got, _ := m.Target["task_id"].(string); got != c.taskID {
				t.Fatalf("task_id = %q, want %q", got, c.taskID)
			}
			if strings.Contains(stringify(m.Target), tok) {
				t.Fatal("delegation token copied into the target")
			}
		})
	}
	// The JSON-RPC id is echoed in refusals.
	m := mapA2A("POST", "/a2a", "r", "agent_b", []byte(`{"jsonrpc":"2.0","id":"q-1","method":"tasks/explode"}`))
	if string(m.RPCID) != `"q-1"` {
		t.Fatalf("rpc id = %s", m.RPCID)
	}
}

func stringify(m map[string]any) string {
	var b strings.Builder
	for k, v := range m {
		b.WriteString(k)
		if s, ok := v.(string); ok {
			b.WriteString(s)
		}
	}
	return b.String()
}

func TestMapMCP(t *testing.T) {
	verbs := mustVerbs(t)
	cases := []struct {
		method, params string
		verb           action.Verb
		noDecide       bool
		bad            string
		tool           string
	}{
		{method: "tools/call", params: `{"name":"read_graph","arguments":{}}`, verb: action.VerbRead, tool: "read_graph"},
		{method: "tools/call", params: `{"name":"create_entities","arguments":{"entities":[]}}`, verb: action.VerbRemember, tool: "create_entities"},
		{method: "tools/call", params: `{"name":"delete_entities"}`, verb: action.VerbDelete, tool: "delete_entities"},
		{method: "tools/call", params: `{"name":"frobnicate"}`, verb: action.VerbExecute, tool: "frobnicate"},
		{method: "tools/call", params: `{"name":"search_anything"}`, verb: action.VerbRead, tool: "search_anything"},
		{method: "tools/list", verb: action.VerbRead},
		{method: "resources/read", params: `{"uri":"memory://x"}`, verb: action.VerbRead},
		{method: "prompts/get", params: `{"name":"p"}`, verb: action.VerbRead},
		{method: "initialize", params: `{"protocolVersion":"2025-06-18"}`, noDecide: true},
		{method: "ping", noDecide: true},
		{method: "tools/call", params: `{"arguments":{}}`, bad: "without a tool name"},
		{method: "tools/call", params: `{"name":"bad name; rm"}`, bad: "invalid MCP tool name"},
		{method: "tools/call", params: `{"name":"a","name":"read_graph"}`, bad: "malformed"},
		{method: "tools/call", params: `{"name":7}`, bad: "malformed"},
		{method: "sampling/createMessage", bad: "unknown MCP method"},
		{method: "", bad: "invalid MCP method"},
	}
	for _, c := range cases {
		m := mapMCP(verbs, "memory", "memory", c.method, []byte(c.params))
		name := c.method + " " + c.params
		if m.System != action.SystemMCP || m.Target["server"] != "memory" {
			t.Errorf("%s: %+v", name, m)
			continue
		}
		if c.bad != "" {
			if !strings.Contains(m.Malformed, c.bad) || m.Verb != "UNKNOWN" || m.NoDecide {
				t.Errorf("%s: want malformed %q, got %+v", name, c.bad, m)
			}
			continue
		}
		if m.Malformed != "" || m.NoDecide != c.noDecide || (!c.noDecide && m.Verb != c.verb) {
			t.Errorf("%s: got %+v", name, m)
		}
		if c.tool != "" && m.Target["tool"] != c.tool {
			t.Errorf("%s: tool %v", name, m.Target["tool"])
		}
	}
}

func TestMapHTTP(t *testing.T) {
	hm := newHostMatcher([]string{"intranet.acme.com", "*.corp.acme.com"})
	cases := []struct {
		method, authority string
		body              bool
		verb              action.Verb
		external          bool
		bad               bool
	}{
		{method: "GET", authority: "api.example.com", verb: action.VerbRead, external: true},
		{method: "GET", authority: "API.Example.com:443", verb: action.VerbRead, external: true},
		{method: "POST", authority: "api.example.com", body: true, verb: action.VerbExport, external: true},
		{method: "POST", authority: "api.example.com", verb: action.VerbExport, external: true},
		{method: "GET", authority: "api.example.com", body: true, verb: action.VerbExport, external: true},
		{method: "DELETE", authority: "intranet.acme.com", verb: action.VerbDelete},
		{method: "PUT", authority: "wiki.corp.acme.com", body: true, verb: action.VerbWrite},
		{method: "GET", authority: "corp.acme.com", verb: action.VerbRead},
		{method: "GET", authority: "evilcorp.acme.com.attacker.net", verb: action.VerbRead, external: true},
		{method: "GET", authority: "user@api.example.com", bad: true},
		{method: "GET", authority: "", bad: true},
		{method: "GET", authority: "bad host", bad: true},
	}
	for _, c := range cases {
		m := mapHTTP(hm, "", "r", c.method, c.authority, "/v1/x?secret=1", c.body, 10)
		if c.bad {
			if m.Malformed == "" {
				t.Errorf("%s %s: want malformed, got %+v", c.method, c.authority, m)
			}
			continue
		}
		if m.Malformed != "" || m.Verb != c.verb || m.Target["external"] != c.external || m.System != action.SystemHTTP {
			t.Errorf("%s %s: got %+v", c.method, c.authority, m)
		}
		if m.Target["path"] != "/v1/x" {
			t.Errorf("query string kept in path: %v", m.Target["path"])
		}
	}
	// The request host must match the route's domain.
	if m := mapHTTP(hm, "api.example.com", "r", "GET", "other.example.com", "/", false, 0); m.Malformed == "" {
		t.Fatalf("host mismatch not refused: %+v", m)
	}
}

func mustVerbs(t *testing.T) *ToolVerbs {
	t.Helper()
	v, err := LoadToolVerbs(policyDir())
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestToolVerbs(t *testing.T) {
	v := mustVerbs(t)
	cases := []struct {
		server, tool string
		verb         action.Verb
		source       string
	}{
		{"memory", "read_graph", action.VerbRead, VerbFromMap},
		{"memory", "create_entities", action.VerbRemember, VerbFromMap},
		{"memory", "delete_relations", action.VerbDelete, VerbFromMap},
		{"github-mcp", "merge_pull_request", action.VerbWrite, VerbFromMap},
		{"other", "get_weather", action.VerbRead, VerbFromHeuristic},
		{"other", "list_files", action.VerbRead, VerbFromHeuristic},
		{"other", "fetchUrl", action.VerbRead, VerbFromHeuristic},
		{"other", "get_and_delete_item", action.VerbExecute, VerbDefault},
		{"other", "delete_everything", action.VerbDelete, VerbFromHeuristic},
		{"other", "get_then_update", action.VerbExecute, VerbDefault},
		{"other", "store_memory", action.VerbRemember, VerbFromHeuristic},
		{"other", "remember_this", action.VerbRemember, VerbFromHeuristic},
		{"other", "add_observations", action.VerbRemember, VerbFromHeuristic},
		{"other", "send_email", action.VerbExecute, VerbDefault},
		{"other", "frobnicate", action.VerbExecute, VerbDefault},
		{"other", "", "UNKNOWN", VerbDefault},
		{"other", "x y", "UNKNOWN", VerbDefault},
		{"other", strings.Repeat("a", 200), "UNKNOWN", VerbDefault},
	}
	for _, c := range cases {
		verb, src := v.Verb(c.server, c.tool)
		if verb != c.verb || src != c.source {
			t.Errorf("Verb(%s, %s) = %s/%s, want %s/%s", c.server, c.tool, verb, src, c.verb, c.source)
		}
	}
	var nilTV *ToolVerbs
	if verb, _ := nilTV.Verb("memory", "read_graph"); verb != "UNKNOWN" {
		t.Fatal("nil table classified a tool")
	}
}

func TestParseToolVerbsStrict(t *testing.T) {
	bad := []string{
		`{"tool_verbs":{},"read_prefixes":["get_"],"unsafe_name_tokens":["x"],"extra":1}`,
		`{"tool_verbs":{"s":{"t":"FROB"}},"read_prefixes":["get_"],"unsafe_name_tokens":["x"]}`,
		`{"tool_verbs":{"":{}},"read_prefixes":["get_"],"unsafe_name_tokens":["x"]}`,
		`{"tool_verbs":{},"read_prefixes":[],"unsafe_name_tokens":["x"]}`,
		`{"tool_verbs":{},"read_prefixes":["get_",""],"unsafe_name_tokens":["x"]}`,
		`{"tool_verbs":{}} {}`,
		`not json`,
	}
	for _, b := range bad {
		if _, err := ParseToolVerbs([]byte(b)); err == nil {
			t.Errorf("accepted %s", b)
		}
	}
}

func TestHostMatcherAndNormalize(t *testing.T) {
	hm := newHostMatcher([]string{" Intranet.ACME.com. ", ".svc.local", "", "*.corp.acme.com"})
	for host, want := range map[string]bool{
		"intranet.acme.com": true, "a.svc.local": true, "svc.local": true, "x.corp.acme.com": true,
		"corp.acme.com": true, "acme.com": false, "notsvc.local": false, "intranet.acme.com.evil": false,
	} {
		if got := hm.internal(host); got != want {
			t.Errorf("internal(%s) = %v", host, got)
		}
	}
	for in, want := range map[string]string{"Example.COM:8080": "example.com", "[::1]:80": "::1", "127.0.0.1": "127.0.0.1", "example.com.": "example.com"} {
		if got, err := normalizeHost(in); err != nil || got != want {
			t.Errorf("normalizeHost(%s) = %q %v", in, got, err)
		}
	}
}

func TestMapHTTPSummarisesEncodedQueryWithoutStoringIt(t *testing.T) {
	val := strings.Repeat("QUJDRGVm9+", 30)
	m := mapHTTP(hostMatcher{}, "", "r", "GET", "collector.example.net", "/p.gif?d="+val+"&page=2", false, 0)
	raw, _ := json.Marshal(m.Target)
	if strings.Contains(string(raw), "QUJD") || strings.Contains(string(raw), "page=2") {
		t.Fatalf("target stores the query: %s", raw)
	}
	ps, ok := m.Target["encoded_params"].([]any)
	if !ok || len(ps) != 1 || ps[0].(map[string]any)["length"] != 300 {
		t.Fatalf("encoded_params: %v", m.Target["encoded_params"])
	}
	if m := mapHTTP(hostMatcher{}, "", "r", "GET", "example.com", "/search?q=hello", false, 0); m.Target["encoded_params"] != nil {
		t.Fatalf("plain query summarised: %v", m.Target)
	}
}
