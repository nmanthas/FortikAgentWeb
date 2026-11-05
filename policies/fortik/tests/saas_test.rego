# Salesforce, ServiceNow, SAP: POL-1201..1206, the access gates (POL-020,
# POL-021, POL-1010, POL-1211, POL-1212) and REST/MCP parity.
package fortik.tests

import data.fortik.decide

saas_rw := {"mode": "read_write", "objects": ["*"]}

saas_rest(system, verb, extra, profile) := object.union(
	mk(system, verb, object.union({"transport": "rest_api", "integration_id": sprintf("%s:default", [system]), "connection": system}, extra), {}, 0),
	{"access": {"system": system, "version": 1, "profile": profile}},
)

saas_mcp(system, verb, extra, profile) := object.union(
	mk(
		system, verb, object.union(
			{
				"transport": "mcp", "integration": sprintf("%s_mcp", [system]), "integration_id": sprintf("%s:default", [system]),
				"connection": sprintf("%s_mcp", [system]), "tool": "read_thing", "tool_offered": true, "catalog_current": true,
				"understood": true, "mapping_version": "test", "args_sha256": "abc",
			},
			extra,
		),
		{}, 0,
	),
	{"access": {"system": system, "version": 1, "profile": profile}},
)

sres(inp) := r if {
	r := decide.result with input as inp
}

saas_all := ["salesforce", "servicenow", "sap"]

test_saas_reads_allowed if {
	every s in saas_all {
		r := sres(saas_rest(s, "READ", {"operation": "get", "object": "Account", "record_id": "1"}, saas_rw))
		r.decision == "allow"
		r.class == "green"
	}
}

test_saas_write_held if {
	every s in saas_all {
		r := sres(saas_rest(s, "WRITE", {"operation": "update", "object": "Account", "record_id": "1"}, saas_rw))
		r.decision == "hold"
		r.rule_id == "POL-1201"
		r.class == "yellow"
	}
}

test_saas_delete_red_never_released if {
	inp := saas_rest("servicenow", "DELETE", {"operation": "delete", "object": "incident", "record_id": "a1"}, saas_rw)
	r := sres(inp)
	r.decision == "hold"
	r.class == "red"
	r.rule_id == "POL-1202"
	g := sres(object.union(inp, {"context": {"grant": {"grant_id": "g1", "approvals": 3}}}))
	g.decision == "hold"
}

test_saas_execute_and_other_side_effects_held if {
	e := sres(saas_rest("salesforce", "EXECUTE", {"operation": "action", "object": "actions/standard/emailSimple"}, saas_rw))
	e.decision == "hold"
	e.rule_id == "POL-1203"
	x := sres(saas_rest("sap", "EXPORT", {"operation": "list", "object": "API_BUSINESS_PARTNER/A_BusinessPartner"}, saas_rw))
	x.decision == "hold"
	x.rule_id == "POL-1205"
}

test_saas_approved_write_released if {
	inp := saas_rest("salesforce", "WRITE", {"operation": "create", "object": "Contact"}, saas_rw)
	r := sres(object.union(inp, {"context": {"grant": {"grant_id": "g1", "approvals": 1}}}))
	r.decision == "allow"
	r.grant_id == "g1"
}

test_saas_malformed_denied if {
	r := sres(object.union(mk("sap", "READ", {"operation": "get"}, {}, 0), {"access": {"system": "sap", "version": 1, "profile": saas_rw}}))
	r.decision == "deny"
	r.rule_id == "POL-1204"
}

test_saas_unknown_denied if {
	r := sres(saas_rest("salesforce", "UNKNOWN", {"operation": "unknown", "reason": "path is outside the API"}, saas_rw))
	r.decision == "deny"
	r.rule_id == "POL-002"
}

test_saas_no_profile_or_none_denied if {
	r := sres(object.union(saas_rest("salesforce", "READ", {"operation": "get", "object": "Account"}, saas_rw), {"access": {"system": "salesforce", "version": 0, "profile": null}}))
	r.decision == "deny"
	r.rule_id == "POL-020"
	n := sres(saas_rest("salesforce", "READ", {"operation": "get", "object": "Account"}, {"mode": "none", "objects": ["*"]}))
	n.rule_id == "POL-020"
}

test_saas_read_only_profile if {
	ro := {"mode": "read_only", "objects": ["*"]}
	sres(saas_rest("servicenow", "READ", {"operation": "list", "object": "incident"}, ro)).decision == "allow"
	w := sres(saas_rest("servicenow", "WRITE", {"operation": "create", "object": "incident"}, ro))
	w.decision == "deny"
	w.rule_id == "POL-021"
}

test_saas_objects_restricted if {
	p := {"mode": "read_write", "objects": ["account", "contact"]}
	sres(saas_rest("salesforce", "READ", {"operation": "get", "object": "Account", "record_id": "1"}, p)).decision == "allow"
	o := sres(saas_rest("salesforce", "READ", {"operation": "get", "object": "Opportunity", "record_id": "1"}, p))
	o.decision == "deny"
	o.rule_id == "POL-1211"
	q := sres(saas_rest("salesforce", "READ", {"operation": "query", "object": ""}, p))
	q.rule_id == "POL-1211"
	sres(saas_rest("salesforce", "READ", {"operation": "describe", "object": "versions"}, p)).decision == "allow"
}

test_saas_tenant_restricted_on_both_transports if {
	p := object.union(saas_rw, {"integrations": ["salesforce:other"]})
	r := sres(saas_rest("salesforce", "READ", {"operation": "get", "object": "Account"}, p))
	m := sres(saas_mcp("salesforce", "READ", {}, p))
	r.decision == "deny"
	r.rule_id == "POL-1010"
	m.decision == "deny"
	m.rule_id == "POL-1010"
	contains(r.reason, "Salesforce integration salesforce:default")
	ok := object.union(saas_rw, {"integrations": ["salesforce:default"]})
	sres(saas_rest("salesforce", "READ", {"operation": "get", "object": "Account"}, ok)).decision == "allow"
	sres(saas_mcp("salesforce", "READ", {}, ok)).decision == "allow"
}

test_saas_mcp_tools_restricted if {
	p := object.union(saas_rw, {"mcp_tools": ["other_tool"]})
	r := sres(saas_mcp("servicenow", "READ", {}, p))
	r.decision == "deny"
	r.rule_id == "POL-1212"
	sres(saas_mcp("servicenow", "READ", {}, object.union(saas_rw, {"mcp_tools": ["read_thing"]}))).decision == "allow"
}

test_saas_mcp_unverified_catalog_or_schema_denied if {
	c := sres(saas_mcp("sap", "READ", {"catalog_current": false}, saas_rw))
	c.decision == "deny"
	c.rule_id == "POL-1206"
	startswith(c.reason, "SAP MCP call refused")
	o := sres(saas_mcp("sap", "READ", {"tool_offered": false}, saas_rw))
	o.rule_id == "POL-1206"
	e := sres(saas_mcp("sap", "READ", {"schema_errors": ["argument x is not in the tool's schema"]}, saas_rw))
	e.rule_id == "POL-1206"
}

test_saas_same_decision_on_both_transports if {
	every s in saas_all {
		every v in ["READ", "WRITE", "DELETE"] {
			a := sres(saas_rest(s, v, {"operation": "op", "object": "Account"}, saas_rw))
			b := sres(saas_mcp(s, v, {"operation": "op", "object": "Account"}, saas_rw))
			a.decision == b.decision
			a.rule_id == b.rule_id
		}
	}
	ro := {"mode": "read_only", "objects": ["*"]}
	sres(saas_rest("sap", "WRITE", {"operation": "create", "object": "X"}, ro)).rule_id == sres(saas_mcp("sap", "WRITE", {}, ro)).rule_id
}
