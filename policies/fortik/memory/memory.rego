# Memory protection (docs/PHASE4_DESIGN.md §3). Agents reach long-term
# (vector) memory through Fortik's memory gateway (system "memory", verbs
# READ / REMEMBER / DELETE, target {store, namespace, item_id}) and through
# MCP memory servers via agentgateway or the hook (system "mcp", target.server
# listed in data.fortik.memory.mcp_servers).
#
# The memory enricher supplies input.context.memory = {"access": mode} from
# the memory_access table (default "full"):
#   full          reads, staged writes; deletes need a human (POL-005)
#   staging_only  reads and staged writes; nothing is promoted while in it
#   none          no memory reads or writes at all; memory frozen, not deleted
#
# Deny gates (contributed to fortik.gates by gates.rego):
#   POL-901 access none (or a malformed memory context) -> deny every memory
#           and memory-MCP action, READ included
#   POL-902 access staging_only -> deny memory DELETE (and any verb other than
#           READ/REMEMBER); deny every non-READ memory-MCP call, because writes
#           through an MCP server cannot be staged
#
# Class findings (rules.rego, package fortik.rules):
#   POL-903 yellow allow_reduced {memory_staging: true}: every gateway write
#           lands staged and stays undoable until it is promoted
#   POL-904 yellow hold: a memory write carrying sensitive data labels
#
# No input.context.memory (the enricher is not wired, e.g. in a unit test)
# means the default mode "full"; a context that is present but malformed
# fails closed (POL-901).
package fortik.memory

act := input.action

tgt := t if {
	t := act.target
	is_object(t)
} else := {}

verb := object.get(act, "verb", "")

# MCP servers that are memory stores (data.json). Names are compared
# case-insensitively, as the interception points fold server names.
servers := {lower(s) | some s in configured_servers; is_string(s)}

configured_servers := v if {
	v := data.fortik.memory.mcp_servers
	is_array(v)
} else := []

memory_server if {
	s := tgt.server
	is_string(s)
	lower(s) in servers
}

# An MCP tools/call (or any MCP request) addressed to a memory server.
memory_mcp if {
	act.system == "mcp"
	memory_server
}

memory_action if act.system == "memory"

memory_action if memory_mcp

ctx := c if {
	c := input.context
	is_object(c)
} else := {}

has_ctx if "memory" in object.keys(ctx)

modes := {"full", "staging_only", "none"}

# The agent's memory access mode; "(malformed)" when the context is present
# but unusable.
access := a if {
	m := ctx.memory
	is_object(m)
	a := m.access
	is_string(a)
	a in modes
} else := "full" if {
	not has_ctx
} else := "(malformed)"

denials contains {
	"rule_id": "POL-901",
	"reason": sprintf("memory access removed for agent %v (mode none): no memory reads or writes (%v %v refused)", [object.get(act, "agent_id", ""), act.system, verb]),
} if {
	memory_action
	access == "none"
}

denials contains {
	"rule_id": "POL-901",
	"reason": "memory access context is malformed: fail closed",
} if {
	memory_action
	access == "(malformed)"
}

denials contains {
	"rule_id": "POL-902",
	"reason": sprintf("memory access is staging_only: %v refused (reads and staged writes only)", [verb]),
} if {
	act.system == "memory"
	access == "staging_only"
	not verb in {"READ", "REMEMBER"}
}

denials contains {
	"rule_id": "POL-902",
	"reason": sprintf("memory access is staging_only: %v via MCP memory server %v refused (writes through an MCP server cannot be staged)", [verb, tgt.server]),
} if {
	memory_mcp
	access == "staging_only"
	verb != "READ"
}
