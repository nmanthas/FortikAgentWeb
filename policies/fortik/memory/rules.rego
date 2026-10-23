# Memory write classification (docs/PHASE4_DESIGN.md §3, undo #6).
#
#   POL-903 yellow allow_reduced {memory_staging: true}: a memory-gateway
#           write (REMEMBER) always lands in staging, is promoted only after
#           the staging delay if nobody flags it, and is undoable (drop the
#           staged item) until then
#   POL-904 yellow hold: a memory write (gateway REMEMBER/WRITE, or a write
#           tool on an MCP memory server) carrying sensitive data labels
#
# Gateway writes that name their store and namespace are covered for POL-005
# in common.rego; a REMEMBER without them is still held there.
package fortik.rules

import data.fortik.memory

mem_write if {
	act.system == "memory"
	act.verb in {"REMEMBER", "WRITE"}
}

mem_write if {
	memory.memory_mcp
	act.verb in {"REMEMBER", "WRITE"}
}

findings contains {
	"rule_id": "POL-903",
	"class": "yellow",
	"reason": "memory write is staged: promoted only after the staging delay if not flagged, undoable until then",
	"reduced_form": {"memory_staging": true},
} if {
	act.system == "memory"
	act.verb == "REMEMBER"
}

findings contains {
	"rule_id": "POL-904",
	"class": "yellow",
	"reason": sprintf("memory write carrying sensitive data %v: approval required", [sort([l | some l in sensitive])]),
	"hold": true,
} if {
	mem_write
	count(sensitive) > 0
}
