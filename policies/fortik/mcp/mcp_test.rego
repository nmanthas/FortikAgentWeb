package fortik.tests

import data.fortik.decide

mcp_call(server, tool, verb) := mk("mcp", verb, {"server": server, "tool": tool, "method": "tools/call"}, {}, 0)

test_mcp_mapped_read_tool_allowed if {
	r := decide.result with input as mcp_call("memory", "read_graph", "READ")
	r.decision == "allow"
	r.class == "green"
}

test_mcp_heuristic_read_tool_allowed if {
	every tool in ["get_weather", "list_files", "search_docs", "read_page", "query_index", "fetch_url", "find_user"] {
		r := decide.result with input as mcp_call("anything", tool, "READ")
		r.decision == "allow"
	}
}

test_mcp_list_and_read_methods_allowed if {
	every m in ["tools/list", "resources/read", "prompts/get"] {
		r := decide.result with input as mk("mcp", "READ", {"server": "memory", "method": m}, {}, 0)
		r.decision == "allow"
	}
}

test_mcp_unmapped_tool_held if {
	r := decide.result with input as mcp_call("memory", "do_something", "EXECUTE")
	r.decision == "hold"
	r.class == "yellow"
	"POL-801" in rule_ids(r)
}

# mcp is a rule system now: POL-801 (not POL-005) holds unmapped tools.
test_mcp_unmapped_tool_held_even_with_mcp_rules if {
	r := decide.result with input as mcp_call("memory", "do_something", "EXECUTE")
	r.decision == "hold"
	r.rule_id == "POL-801"
}

test_mcp_delete_held if {
	r := decide.result with input as mcp_call("memory", "delete_entities", "DELETE")
	r.decision == "hold"
	"POL-802" in rule_ids(r)
}

test_mcp_delete_held_even_with_mcp_rules if {
	r := decide.result with input as mcp_call("memory", "delete_entities", "DELETE")
	r.decision == "hold"
	r.rule_id == "POL-802"
}

# mcp is a rule system: a mapped write tool runs (subject to the mcp access
# profile); unmapped and destructive tools stay held (POL-801/802).
test_mcp_mapped_write_allowed_by_mcp_rules if {
	r := decide.result with input as mcp_call("memory", "create_entities", "REMEMBER")
	r.decision == "allow"
	not "POL-005" in rule_ids(r)
}

# Without mcp coverage, POL-005 would hold it.
test_mcp_mapped_write_held_without_mcp_rules if {
	r := decide.result with input as mcp_call("memory", "create_entities", "REMEMBER")
		with data.fortik.rules.partial_rule_systems as {"mcp"}
		with data.fortik.rules.covered as false
	r.decision == "hold"
	r.rule_id == "POL-005"
}

test_mcp_verb_disagreeing_with_map_denied if {
	r := decide.result with input as mcp_call("memory", "delete_entities", "READ")
	r.decision == "deny"
	r.rule_id == "POL-803"
	not r.ladder_change
}

test_mcp_read_claimed_for_unsafe_name_denied if {
	every tool in ["get_and_delete_item", "list_then_update", "do_something", "send_email"] {
		r := decide.result with input as mcp_call("other", tool, "READ")
		r.decision == "deny"
		r.rule_id == "POL-803"
	}
}

test_mcp_star_map_applies_to_every_server if {
	inp := mcp_call("svc", "wipe_cache", "READ")
	r := decide.result with input as inp with data.fortik.mcp.tool_verbs as {"*": {"wipe_cache": "READ"}}
	r.decision == "allow"
}

test_mcp_server_entry_wins_over_star if {
	inp := mcp_call("svc", "wipe_cache", "READ")
	r := decide.result with input as inp
		with data.fortik.mcp.tool_verbs as {"*": {"wipe_cache": "READ"}, "svc": {"wipe_cache": "DELETE"}}
	r.decision == "deny"
	r.rule_id == "POL-803"
}

test_mcp_malformed_target_denied if {
	r := decide.result with input as mk("mcp", "READ", {"server": 7, "tool": "read_graph"}, {}, 0)
	r.decision == "deny"
	r.rule_id == "POL-804"
	r2 := decide.result with input as mk("mcp", "READ", {"server": "memory", "tool": ["x"]}, {}, 0)
	r2.decision == "deny"
	"POL-804" in rule_ids(r2)
}

test_mcp_rules_ignore_other_systems if {
	r := decide.result with input as mk("memory", "READ", {"tool": "delete_everything"}, {}, 0)
	r.decision == "allow"
}
