# NetSuite QuickStart MCP (QuickStart Milestone 2): POL-1101..1108, POL-1120,
# and the NetSuite rules applied to QuickStart tool calls.
package fortik.tests

import data.fortik.decide

qs(verb, extra) := ns_acc(
	ns(verb, object.union(
		{
			"transport": "mcp", "integration": "netsuite_quickstart", "server_id": "quickstart-mcp-server@my.quickstartapi.netsuite.com",
			"tool_offered": true, "catalog_current": true, "understood": true, "mapping_version": "test",
			"args_sha256": "abc",
		},
		extra,
	)),
	rw_all,
)

qs_prof(inp, profile) := object.union(inp, {"access": {"system": "netsuite", "version": 1, "profile": profile}})

test_qs_read_allowed_green if {
	r := nres(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "record_id": "12"}))
	r.decision == "allow"
	r.class == "green"
}

test_qs_report_and_describe_allowed if {
	nres(qs("READ", {"tool": "run_report", "operation": "report", "report_id": "r1"})).decision == "allow"
	nres(qs("READ", {"tool": "get_record_model", "operation": "describe"})).decision == "allow"
	nres(qs("READ", {"tool": "tools/list", "operation": "list_tools"})).decision == "allow"
}

test_qs_update_held_not_snapshot_allowed if {
	r := nres(qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "customer", "record_id": "12", "fields": ["phone"], "undo_possible": true}))
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == "POL-1120"
	contains(r.reason, "snapshotted")
	n := nres(qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "customer", "record_id": "12", "fields": ["addressbook.city"], "undo_possible": false}))
	contains(n.reason, "undo: not available")
}

test_qs_update_released_by_grant if {
	inp := qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "customer", "record_id": "12", "fields": ["phone"], "undo_possible": true})
	r := nres(object.union(inp, {"context": {"grant": {"grant_id": "g1", "approvals": 1}}}))
	r.decision == "allow"
	r.grant_id == "g1"
}

test_qs_delete_red_never_released if {
	inp := qs("DELETE", {"tool": "delete_record", "operation": "delete", "record_type": "salesorder", "record_id": "77"})
	r := nres(inp)
	r.decision == "hold"
	r.class == "red"
	r.rule_id == "POL-1002"
	g := nres(object.union(inp, {"context": {"grant": {"grant_id": "g1", "approvals": 3}}}))
	g.decision == "hold"
}

test_qs_payment_create_two_approvers if {
	r := nres(qs("WRITE", {"tool": "create_record", "operation": "create", "record_type": "vendorpayment", "fields": ["entity", "total"]}))
	r.decision == "hold"
	r.rule_id == "POL-1003"
	r.approvals_required == 2
}

test_qs_payment_like_transform if {
	r := nres(qs("WRITE", {"tool": "execute_record_transform", "operation": "transform", "record_type": "vendorbill", "record_id": "5", "transform_id": "vendorbill_to_vendorpayment", "fields": []}))
	r.decision == "hold"
	r.approvals_required == 2
	r.rule_id == "POL-1105"
	a := nres(qs("EXECUTE", {"tool": "execute_record_action", "operation": "record_action", "record_type": "invoice", "record_id": "5", "action_id": "submit"}))
	a.decision == "hold"
	a.rule_id == "POL-1120"
	not a.approvals_required
	v := nres(qs("EXECUTE", {"tool": "execute_record_action", "operation": "record_action", "record_type": "invoice", "record_id": "5", "action_id": "void"}))
	v.rule_id == "POL-1105"
	v.approvals_required == 2
	p := nres(qs("WRITE", {"tool": "execute_record_transform", "operation": "transform", "record_type": "vendorbill", "record_id": "5", "transform_id": "payvendorbill", "fields": []}))
	p.rule_id == "POL-1105"
	j := nres(qs("WRITE", {"tool": "create_record", "operation": "create", "record_type": "journalentry", "fields": ["memo"]}))
	j.rule_id == "POL-1105"
	j.approvals_required == 2
	b := nres(qs("WRITE", {"tool": "create_record", "operation": "create", "record_type": "banktransfer", "fields": ["amount"]}))
	b.approvals_required == 2
}

test_qs_bank_change_held if {
	r := nres(qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "vendor", "record_id": "9", "fields": ["achaccountnumber"], "undo_possible": true}))
	r.decision == "hold"
	r.rule_id in {"POL-1004", "POL-1120"}
	some m in r.matched
	m.rule_id == "POL-1004"
}

test_qs_financial_setup_red if {
	r := nres(qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "account", "record_id": "1", "fields": ["acctname"]}))
	r.class == "red"
	r.rule_id == "POL-1005"
	f := nres(qs("WRITE", {"tool": "create_record", "operation": "create", "record_type": "fiscalperiod", "fields": ["name"]}))
	f.class == "red"
}

test_qs_email_held if {
	r := nres(qs("SEND", {"tool": "send_record_email", "operation": "send_email", "record_type": "invoice", "record_id": "3", "recipient_overrides": 1, "recipient_domains": ["gmail.com"]}))
	r.decision == "hold"
	r.rule_id == "POL-1106"
	contains(r.reason, "gmail.com")
	s := nres(qs("SEND", {"tool": "submit_contact_support_request", "operation": "support_request", "query_type": "ISSUE"}))
	s.rule_id == "POL-1106"
}

test_qs_preferences if {
	r := nres(qs("WRITE", {"tool": "set_preferences", "operation": "preference_write", "preference_key": "TIMEZONE"}))
	r.decision == "hold"
	r.rule_id == "POL-1103"
	r.approvals_required == 2
	d := nres(qs("WRITE", {"tool": "set_preferences", "operation": "preference_write", "preference_key": "MCP_SERVER_ENABLED"}))
	d.decision == "deny"
	d.rule_id == "POL-1102"
}

test_qs_attachment_delete_red if {
	r := nres(qs("WRITE", {"tool": "set_record_attachment", "operation": "attachment", "record_type": "invoice", "record_id": "3", "attachment_operation": "delete"}))
	r.class == "red"
	r.rule_id == "POL-1104"
	a := nres(qs("WRITE", {"tool": "set_record_attachment", "operation": "attachment", "record_type": "invoice", "record_id": "3", "attachment_operation": "append"}))
	a.class == "yellow"
	a.rule_id == "POL-1120"
}

test_qs_not_understood_held if {
	r := nres(qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "customer", "understood": false, "not_understood": ["update names no record id"], "fields": []}))
	r.decision == "hold"
	r.rule_id == "POL-1107"
	contains(r.reason, "no record id")
}

test_qs_invalid_refused if {
	nres(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "tool_offered": false})).rule_id == "POL-1101"
	nres(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "catalog_current": false})).decision == "deny"
	r := nres(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "schema_errors": ["required argument \"id\" is missing"]}))
	r.decision == "deny"
	r.rule_id == "POL-1101"
	contains(r.reason, "schema")
}

test_qs_unknown_tool_denied if {
	r := nres(qs("UNKNOWN", {"tool": "new_tool", "reason": "tool is not in the QuickStart tool mapping"}))
	r.decision == "deny"
	r.rule_id == "POL-002"
}

test_qs_unknown_operation_malformed if {
	r := nres(qs("WRITE", {"tool": "x", "operation": "teleport"}))
	r.decision == "deny"
	r.rule_id == "POL-1006"
}

test_qs_read_only_profile_refuses_writes if {
	ro := {"mode": "read_only", "record_types": ["*"], "suiteql": false}
	r := nres(qs_prof(qs("WRITE", {"tool": "update_record", "operation": "update", "record_type": "customer", "record_id": "1", "fields": ["phone"]}), ro))
	r.decision == "deny"
	r.rule_id == "POL-021"
	nres(qs_prof(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "record_id": "1"}), ro)).decision == "allow"
}

test_qs_record_types_profile if {
	p := {"mode": "read_write", "record_types": ["customer"], "suiteql": false}
	nres(qs_prof(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "vendor", "record_id": "1"}), p)).rule_id == "POL-1007"
	nres(qs_prof(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "record_id": "1"}), p)).decision == "allow"
}

test_qs_tools_allowlist if {
	p := {"mode": "read_write", "record_types": ["*"], "suiteql": false, "quickstart_tools": ["read_record", "list_records"]}
	r := nres(qs_prof(qs("READ", {"tool": "run_report", "operation": "report"}), p))
	r.decision == "deny"
	r.rule_id == "POL-1108"
	nres(qs_prof(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "record_id": "1"}), p)).decision == "allow"
	nres(qs_prof(qs("READ", {"tool": "tools/list", "operation": "list_tools"}), p)).decision == "allow"
	all := {"mode": "read_write", "record_types": ["*"], "suiteql": false, "quickstart_tools": ["*"]}
	nres(qs_prof(qs("READ", {"tool": "run_report", "operation": "report"}), all)).decision == "allow"
}

test_qs_no_profile_denied if {
	r := nres(object.union(qs("READ", {"tool": "read_record", "operation": "get", "record_type": "customer", "record_id": "1"}), {"access": {"system": "netsuite", "version": 0, "profile": null}}))
	r.decision == "deny"
	r.rule_id == "POL-020"
}

# The REST gateway keeps its snapshot-first updates (QuickStart is excluded).
test_qs_rest_update_unchanged if {
	r := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "customer", "record_id": "12", "fields": ["phone"]}), rw_all))
	r.decision == "allow_reduced"
	r.rule_id == "POL-1001"
}
