package saasrest

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestServiceNowMCP drives /mcp/servicenow_rest/<tenant> against the LOCAL
// FAKE ServiceNow: every tool call is decided like the REST call it becomes.
func TestServiceNowMCP(t *testing.T) {
	e := setup(t)
	e.configure("servicenow", map[string]any{"instance_url": e.snURL, "username": "fortik.integration"}, map[string]any{"password": "sn-password-value-123"})
	const path = "/mcp/servicenow_rest/default"
	call := func(agent string, id int, tool string, args map[string]any) (map[string]any, map[string]any) {
		t.Helper()
		res := e.rpc(agent, path, id, "tools/call", map[string]any{"name": tool, "arguments": args})
		meta, _ := res["_meta"].(map[string]any)
		return res, meta
	}

	init := e.rpc("bot_rw", path, 1, "initialize", map[string]any{"protocolVersion": "2025-11-25"})
	if info, _ := init["serverInfo"].(map[string]any); init["protocolVersion"] != "2025-11-25" || info["name"] != "fortik-servicenow" {
		t.Fatalf("initialize %v", init)
	}
	tools, _ := e.rpc("bot_rw", path, 2, "tools/list", map[string]any{})["tools"].([]any)
	if len(tools) != 4 {
		t.Fatalf("tools %v", tools)
	}

	// Reads: the query string is built from the arguments, display values by default.
	q, meta := call("bot_rw", 3, "servicenow_query_table", map[string]any{"table": "incident", "query": "active=true^priority=1", "fields": []string{"number", "short_description"}, "limit": 5})
	if q["isError"] != false || !strings.Contains(toolText(q), "INC0010001") || meta["fortik/decision"] != "allow" {
		t.Fatalf("query %v", q)
	}
	e.sn.mu.Lock()
	got, _ := url.ParseQuery(e.sn.queries[len(e.sn.queries)-1])
	e.sn.mu.Unlock()
	if got.Get("sysparm_query") != "active=true^priority=1" || got.Get("sysparm_limit") != "5" || got.Get("sysparm_fields") != "number,short_description" ||
		got.Get("sysparm_display_value") != "true" || got.Get("sysparm_exclude_reference_link") != "true" {
		t.Fatalf("query string %v", got)
	}
	if tg := e.target(meta["fortik/action_id"].(string)); tg["object"] != "incident" || tg["operation"] != "list" || tg["transport"] != "rest_api" {
		t.Fatalf("query target %v", tg)
	}
	g, _ := call("bot_rw", 4, "servicenow_get_record", map[string]any{"table": "incident", "sys_id": "abc123abc123abc123abc123abc123ab"})
	if g["isError"] != false || !strings.Contains(toolText(g), "Printer jam") {
		t.Fatalf("get %v", g)
	}
	if nf, _ := call("bot_rw", 5, "servicenow_get_record", map[string]any{"table": "incident", "sys_id": snMissing}); nf["isError"] != true || !strings.Contains(toolText(nf), "No incident record") {
		t.Fatalf("missing record %v", nf)
	}
	// ServiceNow's own ACL refusal is reported as ServiceNow's.
	if acl, _ := call("bot_rw", 6, "servicenow_query_table", map[string]any{"table": "change_request"}); acl["isError"] != true || !strings.Contains(toolText(acl), "ServiceNow answered HTTP 403") {
		t.Fatalf("acl %v", acl)
	}

	// A create is held and not sent; the target shows what would be written.
	vals := map[string]any{"short_description": "Printer jam on floor 3", "urgency": 2}
	h, meta := call("bot_rw", 7, "servicenow_create_record", map[string]any{"table": "incident", "values": vals})
	held := meta["fortik/action_id"].(string)
	if h["isError"] != true || meta["fortik/decision"] != "hold" || !strings.Contains(toolText(h), "HELD") || !strings.Contains(toolText(h), held) || e.sn.count("POST") != 0 {
		t.Fatalf("held create %v", h)
	}
	if tg := e.target(held); tg["body_sha256"] == nil || !strings.Contains(tg["body_preview"].(string), "Printer jam on floor 3") || tg["operation"] != "create" {
		t.Fatalf("held target %v", tg)
	}
	e.approve(held)
	// The approval covers only those values: other values are held again.
	if o, m := call("bot_rw", 8, "servicenow_create_record", map[string]any{"table": "incident", "values": map[string]any{"short_description": "something else"}}); m["fortik/decision"] != "hold" || o["isError"] != true || e.sn.count("POST") != 0 {
		t.Fatalf("approval released other values %v", o)
	}
	c, _ := call("bot_rw", 9, "servicenow_create_record", map[string]any{"table": "incident", "values": map[string]any{"urgency": 2, "short_description": "Printer jam on floor 3"}})
	sc, _ := c["structuredContent"].(map[string]any)
	if c["isError"] != false || !strings.Contains(toolText(c), "Created incident record INC0010002") || sc["sys_id"] != snCreated || e.sn.count("POST") != 1 {
		t.Fatalf("approved create %v", c)
	}
	e.sn.mu.Lock()
	var sent map[string]any
	_ = json.Unmarshal([]byte(e.sn.bodies[len(e.sn.bodies)-1]), &sent)
	e.sn.mu.Unlock()
	if sent["short_description"] != "Printer jam on floor 3" || sent["urgency"] != float64(2) || len(sent) != 2 {
		t.Fatalf("sent body %v", sent)
	}
	if again, _ := call("bot_rw", 10, "servicenow_create_record", map[string]any{"table": "incident", "values": vals}); again["isError"] != true || e.sn.count("POST") != 1 {
		t.Fatalf("approval reused %v", again)
	}

	// An update: held, approved, applied once.
	upd := map[string]any{"table": "incident", "sys_id": snCreated, "values": map[string]any{"state": "6"}}
	u, meta := call("bot_rw", 11, "servicenow_update_record", upd)
	if u["isError"] != true || meta["fortik/decision"] != "hold" || e.sn.count("PATCH") != 0 {
		t.Fatalf("held update %v", u)
	}
	e.approve(meta["fortik/action_id"].(string))
	if ok, _ := call("bot_rw", 12, "servicenow_update_record", upd); ok["isError"] != false || !strings.Contains(toolText(ok), "Updated incident record") || e.sn.count("PATCH") != 1 {
		t.Fatalf("approved update %v", ok)
	}

	// The agent's ServiceNow profile applies: read-only, then a table restriction.
	if ro, m := call("bot_ro", 13, "servicenow_create_record", map[string]any{"table": "incident", "values": vals}); ro["isError"] != true || m["fortik/decision"] != "deny" || !strings.Contains(toolText(ro), "refused") {
		t.Fatalf("read-only create %v", ro)
	}
	e.profile("bot_ro", "servicenow", `{"mode":"read_only","objects":["problem"]}`)
	if tr, _ := call("bot_ro", 14, "servicenow_query_table", map[string]any{"table": "incident"}); tr["isError"] != true || !strings.Contains(toolText(tr), "POL-1211") {
		t.Fatalf("table restriction %v", tr)
	}

	// Bad arguments never reach the gateway.
	for i, bad := range []map[string]any{
		{"table": "incident", "extra": 1},
		{"table": "incident/../sys_user"},
		{"table": "incident", "limit": 1000},
		{"table": "incident", "fields": []string{"number;drop"}},
	} {
		if r, _ := call("bot_rw", 20+i, "servicenow_query_table", bad); r["isError"] != true || !strings.Contains(toolText(r), "invalid arguments") {
			t.Fatalf("bad query arguments %v accepted: %v", bad, r)
		}
	}
	for i, bad := range []map[string]any{
		{"table": "incident", "values": map[string]any{}},
		{"table": "incident", "values": map[string]any{"caller": map[string]any{"x": 1}}},
		{"table": "incident", "values": map[string]any{"bad field": "x"}},
		{"table": "incident"},
	} {
		if r, _ := call("bot_rw", 30+i, "servicenow_create_record", bad); r["isError"] != true || !strings.Contains(toolText(r), "invalid arguments") {
			t.Fatalf("bad create arguments %v accepted: %v", bad, r)
		}
	}
	if r, _ := call("bot_rw", 40, "servicenow_update_record", map[string]any{"table": "incident", "sys_id": "NOTANID", "values": map[string]any{"state": "6"}}); r["isError"] != true {
		t.Fatalf("bad sys_id accepted %v", r)
	}
	if e.sn.count("POST") != 1 || e.sn.count("PATCH") != 1 {
		t.Fatal("a refused call reached ServiceNow")
	}
	unknown := e.call("bot_rw", "POST", path, `{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"servicenow_delete_record","arguments":{}}}`, nil)
	if !strings.Contains(unknown.body, `"error"`) || !strings.Contains(unknown.body, "unknown tool") {
		t.Fatalf("unknown tool %s", unknown.body)
	}
	// An unknown tenant has no connection; without an agent token nothing is served.
	if tn := e.rpc("bot_rw", "/mcp/servicenow_rest/nosuch", 42, "tools/call", map[string]any{"name": "servicenow_query_table", "arguments": map[string]any{"table": "incident"}}); tn["isError"] != true {
		t.Fatalf("unknown tenant %v", tn)
	}
	req, _ := http.NewRequest("POST", e.gw.URL+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	if res, err := http.DefaultClient.Do(req); err != nil || res.StatusCode != 401 {
		t.Fatalf("no token: %v %v", res, err)
	}
	e.noSecretAnywhere()
}

func TestBodyDigest(t *testing.T) {
	a, pa := bodyDigest([]byte(`{"b": 1, "a": "x"}`))
	b, _ := bodyDigest([]byte(`{"a":"x","b":1}`))
	if a != b || pa != `{"a":"x","b":1}` {
		t.Fatalf("key order or spacing changed the digest: %s %s %s", a, b, pa)
	}
	// Large numbers are kept exactly, not rounded to the same float.
	x, _ := bodyDigest([]byte(`{"n":12345678901234567890}`))
	y, _ := bodyDigest([]byte(`{"n":12345678901234567891}`))
	if x == y {
		t.Fatal("different numbers share a digest")
	}
	// Not JSON (an OData $batch): the raw bytes.
	r1, p1 := bodyDigest([]byte("--batch_1\r\nContent-Type: application/http"))
	r2, _ := bodyDigest([]byte("--batch_2\r\nContent-Type: application/http"))
	if r1 == r2 || !strings.HasPrefix(p1, "--batch_1") {
		t.Fatal("raw body digest")
	}
	if _, p := bodyDigest([]byte(`"` + strings.Repeat("é", 400) + `"`)); len(p) > bodyPreviewChars+len("…") || !strings.HasSuffix(p, "…") {
		t.Fatalf("preview not bounded: %d", len(p))
	}
}
