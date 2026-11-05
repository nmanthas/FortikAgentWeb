package nsquickstart

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/delegation"
	"fortik/internal/overrides"
	"fortik/internal/policy"
)

func toolNames(out map[string]any) []string {
	res, _ := out["result"].(map[string]any)
	var names []string
	for _, t := range res["tools"].([]any) {
		names = append(names, t.(map[string]any)["name"].(string))
	}
	return names
}

func TestProxyProtocolAndListing(t *testing.T) {
	e := newPEnv(t)
	init := e.rpc("qs_rw", "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "t"}})
	res := init["result"].(map[string]any)
	if res["protocolVersion"] != "2025-06-18" || res["capabilities"].(map[string]any)["tools"] == nil {
		t.Fatalf("initialize %v", init)
	}
	if out := e.rpc("qs_rw", "ping", nil); out["result"] == nil {
		t.Fatalf("ping %v", out)
	}
	if out := e.rpc("", "tools/list", nil); out["http_status"] != 401 {
		t.Fatalf("no agent token: %v", out)
	}
	rw := toolNames(e.rpc("qs_rw", "tools/list", nil))
	ro := toolNames(e.rpc("qs_ro", "tools/list", nil))
	if len(rw) != 27 || len(ro) != 16 {
		t.Fatalf("read_write sees %d tools, read_only %d", len(rw), len(ro))
	}
	for _, n := range ro {
		if e.svcMapping().Tools[n].Verb != "READ" {
			t.Fatalf("read_only agent offered %s", n)
		}
	}
	// Write tools say they are held.
	for _, tt := range e.rpc("qs_rw", "tools/list", nil)["result"].(map[string]any)["tools"].([]any) {
		m := tt.(map[string]any)
		if m["name"] == "update_record" && !strings.HasPrefix(m["description"].(string), "[Fortik: calls to this tool are held") {
			t.Fatalf("update_record description %q", m["description"])
		}
	}
	// No profile: refused (POL-020), the tools are not even listed.
	if out := e.rpc("qs_noprof", "tools/list", nil); out["error"] == nil || !strings.Contains(out["error"].(map[string]any)["message"].(string), "POL-020") {
		t.Fatalf("unprofiled agent: %v", out)
	}
	// quickstart_tools narrows the list.
	if _, err := e.acc.Put(e.ctx, "qs_rw", "netsuite", json.RawMessage(`{"mode":"read_write","record_types":["*"],"suiteql":false,"quickstart_tools":["read_record","list_records"]}`), "user:sec@acme.com", "narrow"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(toolNames(e.rpc("qs_rw", "tools/list", nil)), ","); got != "list_records,read_record" {
		t.Fatalf("narrowed list %s", got)
	}
	if _, meta, _ := e.call("qs_rw", "run_report", map[string]any{"reportId": "r1"}); meta["fortik/decision"] != "deny" {
		t.Fatalf("tool outside quickstart_tools: %v", meta)
	}
	if e.toolCalls("run_report") != 0 {
		t.Fatal("a refused call reached QuickStart")
	}
}

func (e *penv) svcMapping() *Mapping {
	m, err := LoadMapping(policyDir())
	if err != nil {
		e.t.Fatal(err)
	}
	return m
}

func TestProxyReadForwardedAndRecorded(t *testing.T) {
	e := newPEnv(t)
	res, meta, text := e.call("qs_ro", "read_record", map[string]any{"recordType": "customer", "id": 12})
	if res["isError"] == true || meta["fortik/executed"] != true || !strings.Contains(text, "LOCAL FAKE record") {
		t.Fatalf("read: %v %v", res, meta)
	}
	// QuickStart's result passes through, with Fortik's action id added.
	if sc := res["structuredContent"].(map[string]any); sc["record"].(map[string]any)["fieldValues"].(map[string]any)["phone"] != "+1 555 0101" {
		t.Fatalf("structured content %v", sc)
	}
	id := meta["fortik/action_id"].(string)
	dec, rule, tgt := e.decision(id)
	if dec != "allow" || tgt["transport"] != "mcp" || tgt["integration"] != "netsuite_quickstart" || tgt["record_type"] != "customer" || tgt["record_id"] != "12" || rule == "" {
		t.Fatalf("action %s %s %v", dec, rule, tgt)
	}
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM diary WHERE event_type = $1 AND body_json LIKE '%'||$2||'%'`, EventToolExecuted, id).Scan(&n)
	if n != 1 {
		t.Fatalf("%d execution records", n)
	}
	// The upstream call carried Fortik's token, never the agent's.
	for _, h := range e.fake.AuthHeaders() {
		if h != "Bearer "+tokenA {
			t.Fatalf("upstream Authorization %q", h)
		}
	}
	// Field values are not in the action record.
	var tgtRaw string
	_ = e.pool.QueryRow(e.ctx, `SELECT target::text FROM actions WHERE action_id = $1`, id).Scan(&tgtRaw)
	if strings.Contains(tgtRaw, "555") {
		t.Fatal("a field value was stored in the action target")
	}
}

func TestProxyUpdateHeldApprovedRetriedOnceAndUndone(t *testing.T) {
	e := newPEnv(t)
	args := map[string]any{"recordType": "customer", "id": 12, "fieldValues": map[string]any{"phone": "+1 555 9999"}}
	_, meta, text := e.call("qs_rw", "update_record", args)
	if meta["fortik/decision"] != "hold" || meta["fortik/executed"] != false || !strings.Contains(text, "did NOT execute") || !strings.Contains(text, "repeat exactly the same call") {
		t.Fatalf("first call: %v %s", meta, text)
	}
	held := meta["fortik/action_id"].(string)
	if _, rule, tgt := e.decision(held); rule != "POL-1120" || tgt["undo_possible"] != true || tgt["args_sha256"] == "" {
		t.Fatalf("held action %s %v", rule, tgt)
	}
	if e.toolCalls("update_record") != 0 {
		t.Fatal("a held update reached QuickStart")
	}
	// Retrying before approval is held again (never runs).
	if _, m2, _ := e.call("qs_rw", "update_record", args); m2["fortik/decision"] != "hold" {
		t.Fatalf("unapproved retry: %v", m2)
	}
	e.approve(held)
	// Different arguments are not covered by the approval.
	other := map[string]any{"recordType": "customer", "id": 12, "fieldValues": map[string]any{"phone": "+1 555 0000"}}
	if _, m3, _ := e.call("qs_rw", "update_record", other); m3["fortik/decision"] != "hold" {
		t.Fatalf("other arguments after approval: %v", m3)
	}
	// The identical retry runs once, after a snapshot.
	res, m4, _ := e.call("qs_rw", "update_record", args)
	if m4["fortik/decision"] != "allow" || m4["fortik/executed"] != true || m4["fortik/undo"] != "available" || res["isError"] == true {
		t.Fatalf("approved retry: %v %v", m4, res)
	}
	if e.fake.Record("customer", "12")["phone"] != "+1 555 9999" || e.toolCalls("update_record") != 1 || e.toolCalls("read_record") != 1 {
		t.Fatalf("upstream state %v, calls %v", e.fake.Record("customer", "12"), e.fake.ToolCalls())
	}
	// The grant is used up: a duplicate retry is held again.
	if _, m5, _ := e.call("qs_rw", "update_record", args); m5["fortik/decision"] != "hold" || e.toolCalls("update_record") != 1 {
		t.Fatalf("duplicate retry: %v", m5)
	}
	// Undo writes the previous value back.
	ran := m4["fortik/action_id"].(string)
	h, err := e.und.Claim(e.ctx, ran, "user:sec@acme.com")
	if err != nil {
		t.Fatalf("claim undo: %v", err)
	}
	out, err := e.exec.Undo(e.ctx, h)
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if e.fake.Record("customer", "12")["phone"] != "+1 555 0101" || !strings.Contains(out["note"].(string), "last writer wins") {
		t.Fatalf("after undo %v %v", e.fake.Record("customer", "12"), out)
	}
	// The previous value was kept in the secret store only, never in Postgres.
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM undo_handles WHERE handle_json::text LIKE '%0101%'`).Scan(&n)
	if n != 0 {
		t.Fatal("the snapshot value is in Postgres")
	}
}

func TestProxyUpdateWithoutUndoAndRedDelete(t *testing.T) {
	e := newPEnv(t)
	// A structured value cannot be snapshotted: the reason says so.
	args := map[string]any{"recordType": "customer", "id": 12, "fieldValues": map[string]any{"addressbook": map[string]any{"fieldValues": map[string]any{"city": "Y"}}}}
	_, meta, text := e.call("qs_rw", "update_record", args)
	if meta["fortik/decision"] != "hold" || !strings.Contains(text, "undo: not available") {
		t.Fatalf("structured update: %v %s", meta, text)
	}
	e.approve(meta["fortik/action_id"].(string))
	_, m2, _ := e.call("qs_rw", "update_record", args)
	if m2["fortik/executed"] != true || m2["fortik/undo"] != nil || e.toolCalls("read_record") != 0 {
		t.Fatalf("approved structured update: %v", m2)
	}
	// Deletes are red: an approval never releases them unchanged.
	del := map[string]any{"recordType": "customer", "id": 12}
	_, d1, dt := e.call("qs_rw", "delete_record", del)
	if d1["fortik/decision"] != "hold" || !strings.Contains(dt, "never released unchanged") {
		t.Fatalf("delete: %v %s", d1, dt)
	}
	if _, err := e.appr.Approve(e.ctx, approver, d1["fortik/action_id"].(string), approvalsReq()); err == nil || !strings.Contains(err.Error(), "never run unchanged") {
		t.Fatalf("approving a red delete: %v", err)
	}
	if _, d2, _ := e.call("qs_rw", "delete_record", del); d2["fortik/executed"] != false || e.toolCalls("delete_record") != 0 {
		t.Fatalf("approved delete ran: %v", d2)
	}
}

func TestProxyRefusals(t *testing.T) {
	e := newPEnv(t)
	cases := []struct {
		agent, tool string
		args        any
		rule        string
	}{
		{"qs_rw", "set_preferences", map[string]any{"preferenceKey": "MCP_SERVER_ENABLED", "value": false}, "POL-1102"},
		{"qs_rw", "brand_new_tool", map[string]any{}, "POL-002"},
		{"qs_rw", "read_record", map[string]any{"recordType": "customer"}, "POL-1101"},                         // id missing
		{"qs_rw", "read_record", map[string]any{"recordType": "customer", "id": 1, "extra": true}, "POL-1101"}, // not in schema
		{"qs_ro", "update_record", map[string]any{"recordType": "customer", "id": 12, "fieldValues": map[string]any{"phone": "1"}}, "POL-021"},
		{"qs_noprof", "read_record", map[string]any{"recordType": "customer", "id": 12}, "POL-020"},
	}
	for _, c := range cases {
		_, meta, text := e.call(c.agent, c.tool, c.args)
		_, rule, _ := e.decision(meta["fortik/action_id"].(string))
		if meta["fortik/decision"] != "deny" || rule != c.rule || meta["fortik/executed"] != false {
			t.Errorf("%s %s: %v %s (%s)", c.agent, c.tool, meta, rule, text)
		}
	}
	if len(e.fake.ToolCalls()) != 0 {
		t.Fatalf("refused calls reached QuickStart: %v", e.fake.ToolCalls())
	}
	// Payment-like transforms need two approvers; one is not enough.
	tr := map[string]any{"sourceRecordType": "vendorBill", "sourceId": 5, "transformId": "vendorbill_to_vendorpayment"}
	_, m, text := e.call("qs_rw", "execute_record_transform", tr)
	if m["fortik/decision"] != "hold" || !strings.Contains(text, "2 different approvers") {
		t.Fatalf("payment transform: %v %s", m, text)
	}
	e.approve(m["fortik/action_id"].(string))
	if _, m2, _ := e.call("qs_rw", "execute_record_transform", tr); m2["fortik/executed"] != false {
		t.Fatalf("one approval released a two-approver hold: %v", m2)
	}
}

func TestProxySuspensionLevelsAndStaleCatalog(t *testing.T) {
	e := newPEnv(t)
	read := map[string]any{"recordType": "customer", "id": 12}
	// A timed NetSuite suspension of one agent blocks its QuickStart calls ...
	if _, err := e.ov.Create(e.ctx, overrides.CreateRequest{Scope: overrides.ScopeAgent, ScopeID: "qs_rw", System: "netsuite", Mode: overrides.ModeSuspended,
		Duration: time.Hour, Reason: "incident"}, "user:sec@acme.com", nil); err != nil {
		t.Fatal(err)
	}
	if _, meta, _ := e.call("qs_rw", "read_record", read); meta["fortik/decision"] != "deny" {
		t.Fatalf("suspended agent: %v", meta)
	}
	// ... not another agent's.
	if _, meta, _ := e.call("qs_ro", "read_record", read); meta["fortik/executed"] != true {
		t.Fatalf("other agent: %v", meta)
	}
	// A suspension of the generic mcp system does not touch NetSuite calls.
	if _, err := e.ov.Create(e.ctx, overrides.CreateRequest{Scope: overrides.ScopeAgent, ScopeID: "qs_ro", System: "mcp", Mode: overrides.ModeSuspended,
		Duration: time.Hour, Reason: "unrelated"}, "user:sec@acme.com", nil); err != nil {
		t.Fatal(err)
	}
	if _, meta, _ := e.call("qs_ro", "read_record", read); meta["fortik/executed"] != true {
		t.Fatalf("mcp suspension blocked a NetSuite call: %v", meta)
	}
	// Killing the agent stops everything, including tools/list.
	if _, err := e.ctl.SetLevel(e.ctx, "qs_ro", control.Killed, "test", "test"); err != nil {
		t.Fatal(err)
	}
	if out := e.rpc("qs_ro", "tools/list", nil); out["error"] == nil {
		t.Fatalf("killed agent listed tools: %v", out)
	}
	if _, meta, _ := e.call("qs_ro", "read_record", read); meta["fortik/decision"] != "deny" {
		t.Fatalf("killed agent: %v", meta)
	}
	// A new token without a check: the tool list is no longer verified.
	e.ctl.SetLevel(e.ctx, "qs_ro", control.Full, "test", "test")
	q, _ := json.Marshal("Acme test")
	tok := tokenB
	if _, err := e.ints.Configure(context.Background(), IntegrationKey, integrationsInput(q, e.fakeU, &tok), "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	_, meta, text := e.call("qs_ro", "list_records", map[string]any{"recordType": "customer"})
	if meta["fortik/decision"] != "deny" || !strings.Contains(text, "not verified") {
		t.Fatalf("stale catalog: %v %s", meta, text)
	}
}

func TestProxyUpstreamFailureOutcomes(t *testing.T) {
	e := newPEnv(t)
	e.fake.InitStatus = 503
	e.svc.up(IntegrationKey).drop()
	_, meta, text := e.call("qs_rw", "read_record", map[string]any{"recordType": "customer", "id": 12})
	if meta["fortik/executed"] != false || !strings.Contains(text, "not executed") {
		t.Fatalf("unavailable: %v %s", meta, text)
	}
	if !strings.Contains(text, "unavailable") {
		t.Fatalf("detail: %s", text)
	}
}

// A read-only agent cannot widen its NetSuite access by delegating to a
// read-write agent and having it call QuickStart (authority laundering):
// the delegate's write on its behalf is refused (POL-601), with the token in
// X-Fortik-Delegation or inferred from the open hop; reads are fine.
func TestProxyDelegatedQuickStartWriteRefused(t *testing.T) {
	e := newPEnv(t)
	if _, err := e.acc.Put(e.ctx, "qs_ro", "a2a", json.RawMessage(`{"may_delegate_to":["qs_rw"],"max_depth":2}`), "user:sec@acme.com", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.acc.Put(e.ctx, "qs_rw", "a2a", json.RawMessage(`{"may_delegate_to":[],"max_depth":1}`), "user:sec@acme.com", "test"); err != nil {
		t.Fatal(err)
	}
	ctx, sink := delegation.WithTokenSink(context.Background())
	del := action.Action{AgentID: "qs_ro", System: action.SystemA2A, Verb: action.VerbDelegate, Source: action.SourceAgentGateway,
		Target: map[string]any{"to_agent": "qs_rw", "channel": "a2a", "task_id": "task-close-books"}}
	out, err := e.dec.Decide(ctx, del)
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision == policy.Hold { // approved by a human, then repeated
		e.approve(out.Action.ActionID)
		ctx, sink = delegation.WithTokenSink(context.Background())
		del.ActionID = ""
		if out, err = e.dec.Decide(ctx, del); err != nil {
			t.Fatal(err)
		}
	}
	tok, _, ok := sink.TokenFor(out)
	if !ok {
		t.Fatalf("delegation refused: %s %s", out.Result.RuleID, out.Result.Reason)
	}
	hdr := map[string]string{delegation.Header: tok}
	upd := map[string]any{"name": "update_record", "arguments": map[string]any{"recordType": "customer", "id": 12, "fieldValues": map[string]any{"phone": "1"}}}
	res := e.rpcH("qs_rw", "tools/call", upd, hdr)["result"].(map[string]any)
	meta := res["_meta"].(map[string]any)
	if _, rule, _ := e.decision(meta["fortik/action_id"].(string)); meta["fortik/decision"] != "deny" || rule != "POL-601" {
		t.Fatalf("delegated write: %v %s", meta, rule)
	}
	// Without the token the open hop is inferred: still refused.
	_, m2, _ := e.call("qs_rw", "update_record", upd["arguments"])
	if _, rule, _ := e.decision(m2["fortik/action_id"].(string)); rule != "POL-601" {
		t.Fatalf("inferred delegation: %v %s", m2, rule)
	}
	// Reads within the origin's (read-only) profile run.
	read := map[string]any{"name": "read_record", "arguments": map[string]any{"recordType": "customer", "id": 12}}
	if m := e.rpcH("qs_rw", "tools/call", read, hdr)["result"].(map[string]any)["_meta"].(map[string]any); m["fortik/executed"] != true {
		t.Fatalf("delegated read: %v", m)
	}
	// A forged token is refused, never ignored.
	bad := e.rpcH("qs_rw", "tools/call", read, map[string]string{delegation.Header: "forged.token.value"})["result"].(map[string]any)["_meta"].(map[string]any)
	if _, rule, _ := e.decision(bad["fortik/action_id"].(string)); bad["fortik/decision"] != "deny" || rule != "POL-604" {
		t.Fatalf("forged token: %v %s", bad, rule)
	}
	if e.toolCalls("update_record") != 0 {
		t.Fatal("a refused delegated write reached QuickStart")
	}
}
