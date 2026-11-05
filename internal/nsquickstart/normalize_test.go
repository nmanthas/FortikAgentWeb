package nsquickstart

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"fortik/internal/action"
	"fortik/internal/mcpclient"
	"fortik/internal/mcpclient/mcpfake"
)

func testCatalog(t *testing.T, current bool) Catalog {
	t.Helper()
	cat := Catalog{Tools: map[string]storedTool{}, Current: current, ServerID: "quickstart-mcp-server@my.quickstartapi.netsuite.com"}
	for _, n := range append(append([]string{}, mcpfake.ReadOnlyTools...), mcpfake.WriteTools...) {
		var tool struct {
			Name        string          `json:"name"`
			InputSchema json.RawMessage `json:"inputSchema"`
		}
		_ = json.Unmarshal(mcpfake.Tool(n), &tool)
		mt := mcpclient.Tool{Name: n, InputSchema: tool.InputSchema}
		cat.Tools[n] = storedTool{Tool: mt, Hash: toolHash(mt)}
	}
	return cat
}

func testMapping(t *testing.T) *Mapping {
	t.Helper()
	m, err := LoadMapping(policyDir())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func norm(t *testing.T, tool, args string) map[string]any {
	t.Helper()
	a := testMapping(t).Normalize(tool, json.RawMessage(args), testCatalog(t, true))
	b, _ := json.Marshal(a.Target)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	out["_verb"] = string(a.Verb)
	out["_system"] = a.System
	return out
}

func strs(v any) []string {
	var out []string
	for _, x := range v.([]any) {
		out = append(out, x.(string))
	}
	return out
}

func TestNormalizeUpdate(t *testing.T) {
	tg := norm(t, "update_record", `{"recordType":"Vendor","id":42,"fieldValues":{"email":"a@b.c","Memo":"x"}}`)
	if tg["_system"] != "netsuite" || tg["_verb"] != "WRITE" || tg["transport"] != "mcp" || tg["integration"] != "netsuite_quickstart" {
		t.Fatalf("%v", tg)
	}
	if tg["operation"] != "update" || tg["record_type"] != "vendor" || tg["record_id"] != "42" || tg["undo_possible"] != true || tg["understood"] != true {
		t.Fatalf("%v", tg)
	}
	if got := strs(tg["fields"]); !slices.Equal(got, []string{"email", "memo"}) {
		t.Fatalf("fields %v", got)
	}
	// No value is in the target.
	b, _ := json.Marshal(tg)
	if strings.Contains(string(b), "a@b.c") {
		t.Fatal("a field value leaked into the target")
	}
	// Structured values and sublists: names kept, undo not possible.
	tg = norm(t, "update_record", `{"recordType":"Invoice","id":"7","fieldValues":{"billAddress":{"fieldValues":{"city":"X"}}},"sublistValues":{"item":{"mode":"update","lines":[{"id":1,"fieldValues":{"amount":5}}]}}}`)
	if tg["undo_possible"] != false || !slices.Contains(strs(tg["fields"]), "billaddress.city") || !slices.Contains(strs(tg["fields"]), "item.amount") || !slices.Equal(strs(tg["sublists"]), []string{"item"}) {
		t.Fatalf("structured %v", tg)
	}
	// Nothing to change: not understood.
	tg = norm(t, "update_record", `{"recordType":"Invoice","id":"7"}`)
	if tg["understood"] != false || !strings.Contains(strings.Join(strs(tg["not_understood"]), ";"), "no fields") {
		t.Fatalf("empty update %v", tg)
	}
}

func TestNormalizeOtherOperations(t *testing.T) {
	tg := norm(t, "execute_record_transform", `{"sourceRecordType":"VendorBill","sourceId":5,"transformId":"payVendorBill"}`)
	if tg["operation"] != "transform" || tg["record_type"] != "vendorbill" || tg["record_id"] != "5" || tg["transform_id"] != "payvendorbill" {
		t.Fatalf("transform %v", tg)
	}
	tg = norm(t, "send_record_email", `{"recordType":"Invoice","id":3,"actionId":"send","to":[{"email":"x@Gmail.com"},{"id":9}],"bcc":[{"email":"y@acme.com"}]}`)
	if tg["_verb"] != "SEND" || tg["recipient_overrides"].(float64) != 3 || !slices.Equal(strs(tg["recipient_domains"]), []string{"acme.com", "gmail.com"}) || tg["recipient_entity_ids"].(float64) != 1 || tg["attach_pdf"] != true {
		t.Fatalf("email %v", tg)
	}
	tg = norm(t, "set_preferences", `{"preferenceKey":"mcp_server_enabled","value":false}`)
	if tg["preference_key"] != "MCP_SERVER_ENABLED" || tg["_verb"] != "WRITE" {
		t.Fatalf("preference %v", tg)
	}
	tg = norm(t, "set_record_attachment", `{"recordType":"Invoice","id":3,"operation":"delete","lineId":4}`)
	if tg["attachment_operation"] != "delete" {
		t.Fatalf("attachment %v", tg)
	}
	tg = norm(t, "upload_temporary_file", `{"recordType":"Invoice","fileName":"Bill.PDF","contentType":"application/pdf","fileBytes":"QUJDRA=="}`)
	if tg["file_extension"] != "pdf" || tg["file_bytes"].(float64) != 6 {
		t.Fatalf("upload %v", tg)
	}
	tg = norm(t, "list_records", `{"recordType":"Term","limit":5}`)
	if tg["_verb"] != "READ" || tg["limit"].(float64) != 5 {
		t.Fatalf("list %v", tg)
	}
	tg = norm(t, "brand_new_tool", `{}`)
	if tg["_verb"] != "UNKNOWN" || !strings.Contains(tg["reason"].(string), "not in the QuickStart tool mapping") {
		t.Fatalf("unknown %v", tg)
	}
}

func TestArgsHashBindsExactArguments(t *testing.T) {
	a := norm(t, "update_record", `{"recordType":"Vendor","id":42,"fieldValues":{"email":"a@b.c","memo":"x"}}`)
	b := norm(t, "update_record", `{ "fieldValues": {"memo":"x", "email":"a@b.c"}, "id":42, "recordType":"Vendor" }`)
	c := norm(t, "update_record", `{"recordType":"Vendor","id":42,"fieldValues":{"email":"z@b.c","memo":"x"}}`)
	if a["args_sha256"] != b["args_sha256"] {
		t.Fatal("the same arguments in another order hash differently")
	}
	if a["args_sha256"] == c["args_sha256"] {
		t.Fatal("different values hash the same: an approval would cover them")
	}
	// Big numbers keep their exact value.
	d := norm(t, "read_record", `{"recordType":"Vendor","id":12345678901234567890}`)
	e := norm(t, "read_record", `{"recordType":"Vendor","id":12345678901234567891}`)
	if d["args_sha256"] == e["args_sha256"] || d["record_id"] != "12345678901234567890" {
		t.Fatalf("large ids: %v %v", d["record_id"], e["record_id"])
	}
}

func TestSchemaValidation(t *testing.T) {
	cases := []struct {
		tool, args string
		want       string // "" = valid
	}{
		{"read_record", `{"recordType":"Term","id":"5"}`, ""},
		{"read_record", `{"recordType":"Term","id":5}`, ""},
		{"read_record", `{"recordType":"Term"}`, `required argument "id"`},
		{"read_record", `{"recordType":"Term","id":5,"x":1}`, `"x" is not in the tool's schema`},
		{"read_record", `{"recordType":"Term","id":true}`, "none of the schema's alternatives"},
		{"list_records", `{"recordType":"Term","limit":51}`, "out of range"},
		{"list_records", `{"recordType":7}`, "wrong type"},
		{"set_record_attachment", `{"recordType":"Invoice","id":1,"operation":"shred"}`, "not one of the allowed values"},
		{"read_record", `[1,2]`, "must be a JSON object"},
		{"read_record", `{bad`, "not valid JSON"},
	}
	for _, c := range cases {
		tg := norm(t, c.tool, c.args)
		errs, _ := tg["schema_errors"].([]any)
		joined := ""
		for _, e := range errs {
			joined += e.(string) + ";"
		}
		if c.want == "" && joined != "" || c.want != "" && !strings.Contains(joined, c.want) {
			t.Errorf("%s %s: %q", c.tool, c.args, joined)
		}
	}
	// A tool the server does not offer, or a stale catalog, is marked.
	cat := testCatalog(t, false)
	delete(cat.Tools, "read_record")
	a := testMapping(t).Normalize("read_record", json.RawMessage(`{"recordType":"Term","id":1}`), cat)
	if a.Target["tool_offered"] != false || a.Target["catalog_current"] != false {
		t.Fatalf("%v", a.Target)
	}
}

func TestRecordValuesShapes(t *testing.T) {
	// The live read_record shape (2026-10-25): structuredContent.record.fieldValues.
	live := `{"content":[{"type":"text","text":"Record"}],"structuredContent":{"recordType":"Term","id":"1","record":{"recordType":"Term","id":"1","fieldValues":{"name":"Net 30","discountPercentage":null}}}}`
	v, err := recordValues(json.RawMessage(live))
	if err != nil || string(v["name"]) != `"Net 30"` || string(v["discountPercentage"]) != "null" {
		t.Fatalf("%v %v", v, err)
	}
	// The same object as JSON text content.
	text := `{"content":[{"type":"text","text":"{\"record\":{\"fieldValues\":{\"memo\":\"m\"}}}"}]}`
	if v, err := recordValues(json.RawMessage(text)); err != nil || string(v["memo"]) != `"m"` {
		t.Fatalf("%v %v", v, err)
	}
	if _, err := recordValues(json.RawMessage(`{"content":[{"type":"text","text":"nothing"}]}`)); err == nil {
		t.Fatal("an unrecognised result was accepted")
	}
}

func TestMappingFile(t *testing.T) {
	m := testMapping(t)
	for _, n := range append(append([]string{}, DocumentedReadTools...), DocumentedWriteTools...) {
		c, ok := m.Tools[n]
		if !ok {
			t.Errorf("documented tool %s is not mapped", n)
			continue
		}
		read := slices.Contains(DocumentedReadTools, n)
		if read != (c.Verb == "READ") {
			t.Errorf("%s: verb %s disagrees with the documented list", n, c.Verb)
		}
	}
	if _, err := ParseMapping([]byte(`{"mapping_version":"x","tools":{"a":{"verb":"PATCH","operation":"x"}}}`)); err == nil {
		t.Fatal("unknown verb accepted")
	}
	if _, err := ParseMapping([]byte(`{"mapping_version":"x","tools":{"a":{"verb":"READ","operation":"x"}},"surprise":1}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestOutcomeOf(t *testing.T) {
	cases := []struct {
		err  error
		verb string
		want string
	}{
		{&mcpclient.Error{Kind: mcpclient.KindAuthFailed, Step: "initialize", HTTPStatus: 401}, "WRITE", "not_executed"},
		{&mcpclient.Error{Kind: mcpclient.KindUnavailable, Step: "initialize"}, "WRITE", "not_executed"},
		{&mcpclient.Error{Kind: mcpclient.KindCallFailed, Step: "tools/call", HTTPStatus: 400}, "WRITE", "not_executed"},
		{&mcpclient.Error{Kind: mcpclient.KindCallFailed, Step: "tools/call", HTTPStatus: 200, Detail: "JSON-RPC error -32602: bad"}, "WRITE", "not_executed"},
		{&mcpclient.Error{Kind: mcpclient.KindUnavailable, Step: "tools/call", HTTPStatus: 502}, "WRITE", "unknown"},
		{&mcpclient.Error{Kind: mcpclient.KindUnavailable, Step: "tools/call"}, "WRITE", "unknown"},
		{&mcpclient.Error{Kind: mcpclient.KindUnavailable, Step: "tools/call"}, "READ", "failed"},
	}
	for i, c := range cases {
		if got := outcomeOf(c.err, actionVerb(c.verb)); got != c.want {
			t.Errorf("case %d: %s, want %s", i, got, c.want)
		}
	}
}

func actionVerb(v string) action.Verb { return action.Verb(v) }
