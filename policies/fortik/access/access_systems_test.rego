# Phase 3 access-profile systems: a2a, http (POL-028) and mcp (POL-029).
package fortik.access_systems_test

import data.fortik.access
import data.fortik.decide

act(system, verb, target) := {
	"action": {"agent_id": "agent_1", "system": system, "verb": verb, "target": target, "payload_summary": {}, "est_cost_usd": 0},
	"agent": {"agent_id": "agent_1", "registered": true, "level": 0},
}

prof(inp, profile) := object.union(inp, {"access": {"system": inp.action.system, "version": 2, "profile": profile}})

none(inp) := object.union(inp, {"access": {"system": inp.action.system, "version": 0, "profile": null}})

gate_id(inp) := g.rule_id if g := access.gate with input as inp

denied(inp, rule) if {
	gate_id(inp) == rule
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == rule
}

open(inp) if not access.gate with input as inp

ext_get(domain) := act("http", "READ", {"domain": domain, "external": true, "method": "GET"})

int_get := act("http", "READ", {"domain": "wiki.corp.internal", "external": false, "method": "GET"})

# --- no profile ----------------------------------------------------------------

test_no_profile_denies_new_systems if {
	denied(none(act("mcp", "READ", {"server": "memory", "tool": "read_graph"})), "POL-020")
	denied(none(act("a2a", "DELEGATE", {"to_agent": "agent_2", "channel": "a2a"})), "POL-020")
}

# http without a profile: READ is allowed (browsing is restricted only once a
# profile exists); uploads are held by POL-505, not denied.
test_http_without_profile_read_allowed if {
	open(none(ext_get("example.com")))
	open(none(int_get))
	r := decide.result with input as none(ext_get("example.com"))
	r.decision == "allow"
}

test_http_without_profile_upload_held if {
	inp := none(act("http", "EXPORT", {"domain": "example.com", "external": true, "method": "POST"}))
	open(inp)
	r := decide.result with input as inp
	r.decision == "hold"
	r.rule_id == "POL-505"
}

test_self_delegation_needs_no_a2a_profile if {
	open(none(act("a2a", "DELEGATE", {"to_agent": "agent_1", "channel": "hook_task"})))
}

test_a2a_profile_present_passes_access_gate if {
	open(prof(act("a2a", "DELEGATE", {"to_agent": "agent_2"}), {"may_delegate_to": ["agent_2"], "max_depth": 2}))
}

# --- http: POL-028 -------------------------------------------------------------

test_http_internal_allowed_with_any_profile if {
	open(prof(int_get, {"external": "none", "allowed_domains": []}))
}

test_http_external_none_denied if {
	denied(prof(ext_get("example.com"), {"external": "none", "allowed_domains": []}), "POL-028")
}

test_http_missing_external_marker_counts_as_external if {
	denied(prof(act("http", "READ", {"domain": "example.com"}), {"external": "none", "allowed_domains": []}), "POL-028")
	denied(prof(act("http", "READ", {"domain": "example.com", "external": "no"}), {"external": "none", "allowed_domains": []}), "POL-028")
}

test_http_external_any_allowed if {
	open(prof(ext_get("anything.example.net"), {"external": "any", "allowed_domains": []}))
}

allow_p := {"external": "allowlist", "allowed_domains": ["*.example.org", "api.example.com"]}

test_http_allowlist_exact_and_wildcard if {
	open(prof(ext_get("api.example.com"), allow_p))
	open(prof(ext_get("API.Example.com."), allow_p))
	open(prof(ext_get("api.example.com:443"), allow_p))
	open(prof(ext_get("docs.example.org"), allow_p))
	open(prof(ext_get("a.b.example.org"), allow_p))
}

test_http_allowlist_refuses_others if {
	denied(prof(ext_get("example.org"), allow_p), "POL-028")
	denied(prof(ext_get("evil-example.org"), allow_p), "POL-028")
	denied(prof(ext_get("www.example.com"), allow_p), "POL-028")
	denied(prof(ext_get("api.example.com.evil.net"), allow_p), "POL-028")
}

test_http_allowlist_needs_domain if {
	denied(prof(act("http", "READ", {"external": true}), allow_p), "POL-028")
	denied(prof(act("http", "READ", {"external": true, "domain": 7}), allow_p), "POL-028")
}

test_http_malformed_external_mode_denied if {
	denied(prof(ext_get("example.com"), {"external": true}), "POL-028")
}

# --- mcp: POL-029 --------------------------------------------------------------

mcp_p := {"servers": {"github-mcp": ["*"], "memory": ["read_graph", "search_nodes"], "docs": []}}

mcp(server, tool) := act("mcp", "READ", {"server": server, "tool": tool})

test_mcp_listed_tools_allowed if {
	open(prof(mcp("memory", "read_graph"), mcp_p))
	open(prof(mcp("github-mcp", "create_issue"), mcp_p))
	open(prof(act("mcp", "READ", {"server": "docs"}), mcp_p))
	open(prof(mcp("docs", ""), mcp_p))
}

test_mcp_unlisted_tool_denied if {
	denied(prof(mcp("memory", "create_entities"), mcp_p), "POL-029")
	denied(prof(mcp("docs", "search"), mcp_p), "POL-029")
}

test_mcp_unlisted_server_denied if {
	denied(prof(mcp("filesystem", "read_file"), mcp_p), "POL-029")
	denied(prof(act("mcp", "READ", {"tool": "read_graph"}), mcp_p), "POL-029")
}

test_mcp_malformed_tool_denied if {
	denied(prof(act("mcp", "READ", {"server": "github-mcp", "tool": 5}), mcp_p), "POL-029")
	denied(prof(act("mcp", "READ", {"server": "github-mcp", "tool": null}), mcp_p), "POL-029")
}

test_mcp_malformed_servers_grants_nothing if {
	denied(prof(mcp("memory", "read_graph"), {"servers": ["memory"]}), "POL-029")
	denied(prof(mcp("memory", "read_graph"), {"servers": {"memory": "read_graph"}}), "POL-029")
}

test_profile_for_other_system_still_denied if {
	inp := object.union(ext_get("example.com"), {"access": {"system": "mcp", "version": 1, "profile": {"external": "any"}}})
	denied(inp, "POL-020")
}
