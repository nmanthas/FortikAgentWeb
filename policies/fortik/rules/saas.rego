# Salesforce, ServiceNow and SAP (unified REST / MCP integrations). Actions
# come from the REST gateway (/gw/<system>/..., target.transport rest_api)
# or the provider's MCP endpoint (/mcp/<system>/<tenant>, transport mcp).
# Both carry target.integration_id (the tenant), target.connection and, for
# REST, target.operation and target.object (Salesforce object, ServiceNow
# table, SAP <SERVICE>/<EntitySet>). Fortik has no verified undo for these
# providers, so every change needs a human:
#
#   POL-1201 yellow  a write (create, update, upsert, batch): held
#   POL-1202 red     a delete: held, never released unchanged
#   POL-1203 yellow  an action, flow or function (EXECUTE): held
#   POL-1205 yellow  any other side effect (send, export, grant...): held
#   POL-1204 red     malformed target (no transport or tenant): denied
#   POL-1206 red     MCP: the tool is not in the server's current, verified
#                    tool list, or the arguments break its schema: denied
#
# Access gates (mode, objects, tenants, MCP tools) are in fortik.access.
package fortik.rules

saas_systems := {"salesforce", "servicenow", "sap"}

saas if act.system in saas_systems

saas_title := {"salesforce": "Salesforce", "servicenow": "ServiceNow", "sap": "SAP"}[act.system]

saas_what := sprintf("%s %v %v", [saas_title, object.get(tgt, "operation", object.get(tgt, "tool", "")), object.get(tgt, "object", "")])

# --- POL-1204: malformed --------------------------------------------------------

saas_malformed contains "the action names no transport" if {
	saas
	act.verb != "UNKNOWN"
	not object.get(tgt, "transport", "") in {"rest_api", "mcp"}
}

saas_malformed contains "the action names no tenant (integration_id)" if {
	saas
	act.verb != "UNKNOWN"
	not is_string(object.get(tgt, "integration_id", null))
}

findings contains {
	"rule_id": "POL-1204",
	"class": "red",
	"reason": sprintf("%s call refused: %s", [saas_title, m]),
	"ladder": "NONE",
	"deny": true,
} if {
	some m in saas_malformed
}

# --- POL-1206: MCP tool calls only as the server currently declares them ----

saas_mcp if {
	saas
	tgt.transport == "mcp"
	object.get(tgt, "operation", "") != "list_tools"
}

saas_mcp_invalid contains sprintf("tool %v is not offered by the server's current tool list", [object.get(tgt, "tool", "")]) if {
	saas_mcp
	tgt.tool_offered != true
}

saas_mcp_invalid contains "the tool list was not verified for the current settings or token (run Test connection)" if {
	saas_mcp
	tgt.catalog_current != true
}

saas_mcp_invalid contains sprintf("arguments do not match the tool's discovered schema: %v", [concat("; ", errs)]) if {
	saas_mcp
	errs := [e | some e in object.get(tgt, "schema_errors", []); is_string(e)]
	count(errs) > 0
}

findings contains {
	"rule_id": "POL-1206",
	"class": "red",
	"reason": sprintf("%s MCP call refused: %s", [saas_title, m]),
	"ladder": "NONE",
	"deny": true,
} if {
	act.verb != "UNKNOWN"
	some m in saas_mcp_invalid
}

# --- Changes need a human ------------------------------------------------------

findings contains {
	"rule_id": "POL-1201",
	"class": "yellow",
	"reason": sprintf("%s: a change Fortik cannot undo: approval required", [saas_what]),
	"hold": true,
} if {
	saas
	act.verb == "WRITE"
}

findings contains {
	"rule_id": "POL-1202",
	"class": "red",
	"reason": sprintf("%s: a delete is never run unchanged (no undo)", [saas_what]),
	"hold": true,
	"ladder": "NONE",
} if {
	saas
	act.verb == "DELETE"
}

findings contains {
	"rule_id": "POL-1203",
	"class": "yellow",
	"reason": sprintf("%s: an action, flow or function with effects Fortik cannot see: approval required", [saas_what]),
	"hold": true,
} if {
	saas
	act.verb == "EXECUTE"
}

findings contains {
	"rule_id": "POL-1205",
	"class": "yellow",
	"reason": sprintf("%s %v: approval required", [saas_title, act.verb]),
	"hold": true,
} if {
	saas
	act.verb in known_verbs
	not act.verb in {"READ", "WRITE", "DELETE", "EXECUTE"}
}
