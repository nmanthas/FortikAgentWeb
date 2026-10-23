# MCP tool classification (docs/PHASE3_DESIGN.md §4.2). Interception points
# (the agentgateway callout, the Claude Code hook) map an MCP tools/call to a
# verb with the shared table in policies/fortik/mcp/data.json
# (data.fortik.mcp): the explicit {server: {tool: verb}} map first, then the
# name heuristics. These rules re-check that classification so an adapter can
# never under-classify a tool, and keep side-effecting tools behind a human
# even once mcp has its own rule set.
#
#   POL-801 yellow hold  tools/call of a tool that is neither mapped nor matched
#                        by a heuristic (the adapter sends EXECUTE)
#   POL-802 yellow hold  MCP DELETE, SEND or EXPORT
#   POL-803 red deny     the action's verb disagrees with the verb table (mapped
#                        verb differs, or READ claimed for a tool that is not a
#                        read tool)
#   POL-804 red deny     malformed MCP target (server/tool not strings)
#
# Non-READ MCP actions are also held by POL-005 while mcp is not in
# rule_systems; READ tools are allowed (subject to the mcp access profile).
package fortik.rules

# Read data.fortik.mcp directly (never all of data.fortik, which would make
# every rule depend on every package, tests included).
mcp_tool_verbs := v if {
	v := data.fortik.mcp.tool_verbs
	is_object(v)
} else := {}

mcp_server := s if {
	s := tgt.server
	is_string(s)
} else := ""

mcp_tool := t if {
	t := tgt.tool
	is_string(t)
	t != ""
}

mcp_tool_lower := lower(mcp_tool)

# Explicit table: the server's own entry first, then the "*" entry.
mcp_mapped_verb := v if {
	v := mcp_tool_verbs[mcp_server][mcp_tool]
} else := v if {
	v := mcp_tool_verbs["*"][mcp_tool]
}

mcp_list(key) := v if {
	v := data.fortik.mcp[key]
	is_array(v)
} else := []

mcp_heuristic_delete if {
	some p in mcp_list("delete_prefixes")
	startswith(mcp_tool_lower, p)
}

mcp_heuristic_remember if {
	not mcp_heuristic_delete
	mcp_tool_lower in {t | some t in mcp_list("remember_tools")}
}

mcp_heuristic_remember if {
	not mcp_heuristic_delete
	some p in mcp_list("remember_prefixes")
	startswith(mcp_tool_lower, p)
}

mcp_unsafe_name if {
	some tok in mcp_list("unsafe_name_tokens")
	contains(mcp_tool_lower, tok)
}

# A read prefix only counts when no side-effect word appears anywhere in the
# name ("get_and_delete_item" is not a read).
mcp_heuristic_read if {
	not mcp_heuristic_delete
	not mcp_heuristic_remember
	not mcp_unsafe_name
	some p in mcp_list("read_prefixes")
	startswith(mcp_tool_lower, p)
}

mcp_tools_call if {
	act.system == "mcp"
	mcp_tool
}

findings contains {
	"rule_id": "POL-801",
	"class": "yellow",
	"reason": sprintf("MCP tool %s on server %s is not mapped to a verb (policies/fortik/mcp/data.json): approval required", [mcp_tool, mcp_server]),
	"hold": true,
} if {
	mcp_tools_call
	act.verb == "EXECUTE"
	not mcp_mapped_verb
}

findings contains {
	"rule_id": "POL-802",
	"class": "yellow",
	"reason": sprintf("MCP %s via %s/%s: approval required", [act.verb, mcp_server, object.get(tgt, "tool", "")]),
	"hold": true,
} if {
	act.system == "mcp"
	act.verb in {"DELETE", "SEND", "EXPORT"}
}

findings contains {
	"rule_id": "POL-803",
	"class": "red",
	"reason": sprintf("MCP tool %s on server %s is mapped to %s but was presented as %s: fail closed", [mcp_tool, mcp_server, mcp_mapped_verb, act.verb]),
	"ladder": "NONE",
	"deny": true,
} if {
	mcp_tools_call
	mcp_mapped_verb != act.verb
}

findings contains {
	"rule_id": "POL-803",
	"class": "red",
	"reason": sprintf("MCP tool %s on server %s is not a read tool but was presented as READ: fail closed", [mcp_tool, mcp_server]),
	"ladder": "NONE",
	"deny": true,
} if {
	mcp_tools_call
	act.verb == "READ"
	not mcp_mapped_verb
	not mcp_heuristic_read
}

findings contains {
	"rule_id": "POL-804",
	"class": "red",
	"reason": sprintf("malformed MCP target.%s (must be a string): fail closed", [k]),
	"ladder": "NONE",
	"deny": true,
} if {
	act.system == "mcp"
	some k in {"server", "tool"}
	v := tgt[k]
	not is_string(v)
}
