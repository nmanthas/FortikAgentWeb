# Integration platform Milestone 1: one NetSuite tenant over REST and MCP.
# The same business operation by the same agent under the same profile gets
# the same decision on either transport (POL-1010 tenant restriction included);
# the only difference is the configured one for MCP updates.
package fortik.tests

import data.fortik.decide

tenant_target(transport, extra) := object.union(
	{"transport": transport, "integration_id": "netsuite:acme", "connection": "netsuite:acme"},
	extra,
) if {
	transport == "rest_api"
} else := object.union(
	{
		"transport": "mcp", "integration": "netsuite_mcp", "integration_id": "netsuite:acme", "connection": "netsuite_mcp:acme",
		"tool_offered": true, "catalog_current": true, "understood": true, "mapping_version": "test", "args_sha256": "abc",
	},
	extra,
)

via(transport, verb, extra, profile) := nres(ns_acc(ns(verb, tenant_target(transport, extra)), profile))

ns_transports := ["rest_api", "mcp"]

# Both transports reach the same decision and rule.
same_both(verb, extra, profile) := r if {
	a := via("rest_api", verb, extra, profile)
	b := via("mcp", verb, extra, profile)
	a.decision == b.decision
	a.rule_id == b.rule_id
	r := a
}

ns_read := {"operation": "get", "record_type": "customer", "record_id": "12", "tool": "read_record"}

test_transport_read_same if {
	r := same_both("READ", ns_read, rw_all)
	r.decision == "allow"
}

test_transport_read_only_profile_same if {
	ro := {"mode": "read_only", "record_types": ["*"], "suiteql": true}
	r := same_both("WRITE", {"operation": "update", "record_type": "customer", "record_id": "12", "fields": ["phone"], "tool": "update_record", "undo_possible": true}, ro)
	r.decision == "deny"
	r.rule_id == "POL-021"
}

test_transport_record_types_same if {
	p := {"mode": "read_write", "record_types": ["customer"], "suiteql": true}
	r := same_both("READ", {"operation": "get", "record_type": "vendor", "record_id": "1", "tool": "read_record"}, p)
	r.decision == "deny"
	r.rule_id == "POL-1007"
}

test_transport_delete_payment_bank_same if {
	d := same_both("DELETE", {"operation": "delete", "record_type": "salesorder", "record_id": "77", "tool": "delete_record"}, rw_all)
	d.decision == "hold"
	d.class == "red"
	d.rule_id == "POL-1002"
	p := same_both("WRITE", {"operation": "create", "record_type": "vendorpayment", "fields": ["entity", "total"], "tool": "create_record"}, rw_all)
	p.rule_id == "POL-1003"
	p.approvals_required == 2
	b := same_both("WRITE", {"operation": "update", "record_type": "vendor", "record_id": "9", "fields": ["achaccountnumber"], "tool": "update_record", "undo_possible": true}, rw_all)
	b.decision == "hold"
	b.rule_id == "POL-1004"
}

# --- POL-1010: the tenant restriction applies to every transport --------------

test_transport_tenant_restricted_same if {
	p := object.union(rw_all, {"integrations": ["netsuite:globex"]})
	r := same_both("READ", ns_read, p)
	r.decision == "deny"
	r.rule_id == "POL-1010"
	contains(r.reason, "netsuite:acme")
}

test_transport_tenant_listed_or_wildcard_allowed if {
	every t in ns_transports {
		via(t, "READ", ns_read, object.union(rw_all, {"integrations": ["netsuite:acme"]})).decision == "allow"
		via(t, "READ", ns_read, object.union(rw_all, {"integrations": ["*"]})).decision == "allow"
		via(t, "READ", ns_read, rw_all).decision == "allow"
	}
}

test_transport_restricted_profile_refuses_unnamed_tenant if {
	r := nres(ns_acc(ns("READ", {"transport": "rest_api", "operation": "get", "record_type": "customer", "record_id": "12"}), object.union(rw_all, {"integrations": ["netsuite:acme"]})))
	r.decision == "deny"
	r.rule_id == "POL-1010"
}

test_transport_switch_does_not_bypass_restriction if {
	# The tenant a restricted agent may not reach stays refused when it
	# switches transport (or connection type) for the same tenant.
	p := object.union(rw_all, {"integrations": ["netsuite:acme"]})
	every t in ns_transports {
		r := nres(ns_acc(ns("READ", object.union(tenant_target(t, ns_read), {"integration_id": "netsuite:globex"})), p))
		r.decision == "deny"
		r.rule_id == "POL-1010"
	}
	q := nres(ns_acc(ns("READ", object.union(tenant_target("mcp", ns_read), {"integration": "netsuite_quickstart", "integration_id": "netsuite:quickstart"})), p))
	q.rule_id == "POL-1010"
}

# --- Updates: the one configured difference ----------------------------------

ns_upd := {"operation": "update", "record_type": "customer", "record_id": "12", "fields": ["phone"], "tool": "update_record", "undo_possible": true}

test_transport_update_default_mcp_held if {
	r := via("rest_api", "WRITE", ns_upd, rw_all)
	r.decision == "allow_reduced"
	r.rule_id == "POL-1001"
	m := via("mcp", "WRITE", ns_upd, rw_all)
	m.decision == "hold"
	m.rule_id == "POL-1120"
}

test_transport_update_same_when_mcp_approval_off if {
	inp := ns_acc(ns("WRITE", tenant_target("mcp", ns_upd)), rw_all)
	m := decide.result with input as inp with data.fortik.config.netsuite.mcp_writes_require_approval as false
	m.decision == "allow_reduced"
	m.rule_id == "POL-1001"
	m.reduced_form.record_snapshot == true
}

test_transport_update_without_undo_still_held_when_off if {
	inp := ns_acc(ns("WRITE", tenant_target("mcp", object.union(ns_upd, {"undo_possible": false}))), rw_all)
	m := decide.result with input as inp with data.fortik.config.netsuite.mcp_writes_require_approval as false
	m.decision == "hold"
	m.rule_id == "POL-1120"
}

test_transport_off_does_not_release_red_or_payments if {
	d := ns_acc(ns("DELETE", tenant_target("mcp", {"operation": "delete", "record_type": "salesorder", "record_id": "77", "tool": "delete_record"})), rw_all)
	r := decide.result with input as d with data.fortik.config.netsuite.mcp_writes_require_approval as false
	r.decision == "hold"
	r.rule_id == "POL-1002"
	p := ns_acc(ns("WRITE", tenant_target("mcp", {"operation": "create", "record_type": "vendorpayment", "fields": ["entity"], "tool": "create_record"})), rw_all)
	q := decide.result with input as p with data.fortik.config.netsuite.mcp_writes_require_approval as false
	q.rule_id == "POL-1003"
}

# --- MCP-only checks name the connection type --------------------------------

test_transport_ai_connector_unverified_catalog_refused if {
	r := via("mcp", "READ", object.union(ns_read, {"catalog_current": false}), rw_all)
	r.decision == "deny"
	r.rule_id == "POL-1101"
	startswith(r.reason, "NetSuite MCP call refused")
	q := nres(ns_acc(ns("READ", object.union(tenant_target("mcp", ns_read), {"integration": "netsuite_quickstart", "catalog_current": false})), rw_all))
	startswith(q.reason, "QuickStart call refused")
}
