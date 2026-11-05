# NetSuite (Milestone 1): POL-1001..1009 and the netsuite access profile.
package fortik.tests

import data.fortik.decide

ns(verb, target) := mk("netsuite", verb, target, {}, 0)

ns_acc(inp, profile) := object.union(inp, {"access": {"system": "netsuite", "version": 1, "profile": profile}})

rw_all := {"mode": "read_write", "record_types": ["*"], "suiteql": true}

nres(inp) := r if {
	r := decide.result with input as inp
}

test_ns_read_allowed if {
	r := nres(ns_acc(ns("READ", {"operation": "get", "record_type": "customer", "record_id": "12"}), rw_all))
	r.decision == "allow"
	r.class == "green"
}

test_ns_update_snapshot_first if {
	r := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "customer", "record_id": "12", "fields": ["phone"]}), rw_all))
	r.decision == "allow_reduced"
	r.rule_id == "POL-1001"
	r.reduced_form.record_snapshot == true
}

test_ns_delete_held_red if {
	r := nres(ns_acc(ns("DELETE", {"operation": "delete", "record_type": "salesorder", "record_id": "77"}), rw_all))
	r.decision == "hold"
	r.class == "red"
	r.rule_id == "POL-1002"
}

test_ns_payment_two_approvers if {
	r := nres(ns_acc(ns("WRITE", {"operation": "create", "record_type": "vendorpayment", "fields": ["entity", "total"]}), rw_all))
	r.decision == "hold"
	r.rule_id == "POL-1003"
	r.approvals_required == 2
	t := nres(ns_acc(ns("WRITE", {"operation": "transform", "record_type": "vendorbill", "record_id": "5", "to_record_type": "vendorpayment", "fields": []}), rw_all))
	t.rule_id == "POL-1003"
}

test_ns_bank_details_held if {
	r := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "vendor", "record_id": "9", "fields": ["achaccountnumber", "email"]}), rw_all))
	r.decision == "hold"
	r.rule_id == "POL-1004"
	c := nres(ns_acc(ns("WRITE", {"operation": "create", "record_type": "customrecord_2663_entity_bank_details", "fields": ["name"]}), rw_all))
	c.rule_id == "POL-1004"
}

# Evidence only: a vendor update that does not touch bank fields is a normal
# snapshotted update, not a "bank change".
test_ns_no_bank_guess if {
	r := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "vendor", "record_id": "9", "fields": ["email"]}), rw_all))
	r.rule_id == "POL-1001"
}

test_ns_financial_setup_held_red if {
	r := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "accountingperiod", "record_id": "3", "fields": ["closed"]}), rw_all))
	r.decision == "hold"
	r.class == "red"
	r.rule_id == "POL-1005"
}

test_ns_upsert_held if {
	r := nres(ns_acc(ns("WRITE", {"operation": "upsert", "record_type": "customer", "record_id": "eid:C-1", "fields": ["companyname"]}), rw_all))
	r.decision == "hold"
	r.rule_id == "POL-1009"
}

test_ns_malformed_denied if {
	r := nres(ns_acc(ns("WRITE", {"operation": "update", "record_id": "1", "fields": ["x"]}), rw_all))
	r.decision == "deny"
	r.rule_id == "POL-1006"
	f := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "customer", "record_id": "1", "fields": "phone"}), rw_all))
	f.rule_id == "POL-1006"
	o := nres(ns_acc(ns("WRITE", {"operation": "teleport", "record_type": "customer"}), rw_all))
	o.rule_id == "POL-1006"
}

test_ns_unknown_verb_denied if {
	r := nres(ns_acc(ns("UNKNOWN", {"operation": "unknown", "unclassified": "path traversal"}), rw_all))
	r.decision == "deny"
}

# --- access profile ------------------------------------------------------------

test_ns_no_profile_denied if {
	r := nres(object.union(ns("READ", {"operation": "get", "record_type": "customer", "record_id": "1"}), {"access": {"system": "netsuite", "version": 0, "profile": null}}))
	r.decision == "deny"
	r.rule_id == "POL-020"
}

test_ns_read_only_profile if {
	ro := {"mode": "read_only", "record_types": ["*"], "suiteql": true}
	nres(ns_acc(ns("READ", {"operation": "list", "record_type": "customer"}), ro)).decision == "allow"
	w := nres(ns_acc(ns("WRITE", {"operation": "update", "record_type": "customer", "record_id": "1", "fields": ["phone"]}), ro))
	w.decision == "deny"
	w.rule_id == "POL-021"
}

test_ns_record_types_restricted if {
	p := {"mode": "read_write", "record_types": ["customer", "salesorder"], "suiteql": true}
	nres(ns_acc(ns("READ", {"operation": "get", "record_type": "customer", "record_id": "1"}), p)).decision == "allow"
	v := nres(ns_acc(ns("READ", {"operation": "get", "record_type": "vendor", "record_id": "1"}), p))
	v.decision == "deny"
	v.rule_id == "POL-1007"
	q := nres(ns_acc(ns("READ", {"operation": "query", "query_tables": ["customer", "employee"], "limit": 10}), p))
	q.rule_id == "POL-1007"
	u := nres(ns_acc(ns("READ", {"operation": "query", "query_tables": [], "limit": 10}), p))
	u.rule_id == "POL-1007"
	ok := nres(ns_acc(ns("READ", {"operation": "query", "query_tables": ["customer"], "limit": 10}), p))
	ok.decision == "allow"
}

test_ns_suiteql_needs_permission if {
	p := {"mode": "read_only", "record_types": ["*"], "suiteql": false}
	r := nres(ns_acc(ns("READ", {"operation": "query", "query_tables": ["customer"], "limit": 10}), p))
	r.decision == "deny"
	r.rule_id == "POL-1008"
}

# A NetSuite action delegated from an agent with no NetSuite write access is
# refused through the inherited restriction (POL-601), like every system.
test_ns_delegated_write_refused if {
	origin := {"agent_id": "planner", "registered": true, "level": 0, "level_name": "FULL", "access": {"system": "netsuite", "version": 1, "profile": {"mode": "read_only", "record_types": ["*"], "suiteql": true}}}
	inp := object.union(
		ns_acc(ns("WRITE", {"operation": "update", "record_type": "customer", "record_id": "1", "fields": ["phone"]}), rw_all),
		{"context": {"delegation": {"present": true, "source": "token", "delegation_id": "d1", "depth": 1, "root": "planner", "chain": [origin]}}},
	)
	r := nres(inp)
	r.decision == "deny"
	r.rule_id == "POL-601"
}

# Observed activity (after the fact): a write by a read-only agent is what the
# policy would refuse; the sync records it as a violation.
test_ns_observed_change_by_read_only_agent if {
	ro := {"mode": "read_only", "record_types": ["*"], "suiteql": true}
	r := nres(ns_acc(ns("WRITE", {"operation": "observed_change", "record_id": "1", "record_type_id": "-3", "field": "phone"}), ro))
	r.decision == "deny"
	r.rule_id == "POL-021"
}
