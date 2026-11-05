# SaaS copilot connector broker (Phase 6, docs/PHASE6_DESIGN.md §6): every
# token Fortik issues to a copilot connector (authorization_code or
# refresh_token) is an action: system "connector", verb READ when every scope
# is read-only and WRITE otherwise (so a READ_ONLY agent's copilot still gets
# read-only tokens, never write ones). The control
# ladder, timed suspensions of the upstream's systems (gmail, drive, github)
# and kills apply through the usual gates; a valid registered connector is
# green (security approved its scopes at registration).
#
#   POL-690 connector disabled: refuse (defense in depth; the broker checks first)
#   POL-691 malformed connector target: fail closed
package fortik.rules

connector if act.system == "connector"

connector_upstreams := {"google_workspace", "github"}

findings contains {
	"rule_id": "POL-690",
	"class": "red",
	"reason": sprintf("connector %v is %v: no tokens are issued", [object.get(tgt, "connector_id", ""), object.get(tgt, "connector_status", "unknown")]),
	"ladder": "NONE",
	"deny": true,
} if {
	connector
	connector_well_formed
	tgt.connector_status != "active"
}

findings contains {
	"rule_id": "POL-691",
	"class": "red",
	"reason": "malformed connector token request: fail closed",
	"ladder": "NONE",
	"deny": true,
} if {
	connector
	not connector_well_formed
}

findings contains {
	"rule_id": "POL-691",
	"class": "red",
	"reason": sprintf("connector action %v: only READ / WRITE token issues are defined: fail closed", [act.verb]),
	"ladder": "NONE",
	"deny": true,
} if {
	connector
	not act.verb in {"READ", "WRITE"}
}

# The verb must match the scopes: a write-capable token is never issued as READ.
findings contains {
	"rule_id": "POL-691",
	"class": "red",
	"reason": "connector token with write scopes presented as READ: fail closed",
	"ladder": "NONE",
	"deny": true,
} if {
	connector
	act.verb == "READ"
	tgt.write != false
}

connector_well_formed if {
	is_string(tgt.connector_id)
	tgt.connector_id != ""
	tgt.upstream in connector_upstreams
	is_array(tgt.scopes)
	is_array(tgt.upstream_systems)
	tgt.grant_type in {"authorization_code", "refresh_token"}
	is_string(tgt.connector_status)
}
