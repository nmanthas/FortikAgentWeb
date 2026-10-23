package agentgw

import (
	"strings"
	"testing"
)

// Regression: encoding/json matches keys case-insensitively (last wins) while
// upstreams match exactly; case-variant keys must be refused, not reinterpreted.
func TestCaseVariantKeysRefused(t *testing.T) {
	a2a := []string{
		`{"jsonrpc":"2.0","id":1,"method":"message/send","Method":"tasks/get","params":{"id":"t1"}}`,
		`{"jsonrpc":"2.0","id":1,"method":"tasks/get","params":{"id":"t1","ID":"t2"}}`,
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"message/send\",\"method\u017f\":1}",
		"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"message/send\",\"\u006dethod\":\"x\",\"jſonrpc\":\"2.0\"}",
	}
	for _, b := range a2a {
		m := mapA2A("POST", "/a2a", "r", "agent_b", []byte(b))
		if m.Malformed == "" {
			t.Errorf("A2A %s accepted: verb=%s delegate=%v", b, m.Verb, m.Delegate)
		}
	}
	verbs := mustVerbs(t)
	for _, c := range [][2]string{
		{"tools/call", `{"name":"delete_entities","Name":"read_graph","arguments":{}}`},
		{"tools/call", "{\"name\":\"delete_entities\",\"NAME\":\"read_graph\"}"},
		{"resources/read", `{"uri":"a://x","URI":"a://y"}`},
		{"prompts/get", `{"name":"p","nAme":"q"}`},
	} {
		m := mapMCP(verbs, "memory", "memory", c[0], []byte(c[1]))
		if !strings.Contains(m.Malformed, "malformed") && m.Malformed == "" {
			t.Errorf("MCP %s %s accepted: %+v", c[0], c[1], m)
		}
	}
}
