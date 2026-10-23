package fortik.memory_test

import data.fortik.decide
import data.fortik.memory

agent := {"agent_id": "support_agent_1", "registered": true, "level": 0}

target := {"store": "support", "namespace": "kb"}

mem(verb, tgt, summary, mode) := {
	"action": {
		"agent_id": "support_agent_1",
		"system": "memory",
		"verb": verb,
		"target": tgt,
		"payload_summary": summary,
		"est_cost_usd": 0,
	},
	"agent": agent,
	"context": {"memory": {"access": mode}},
}

mcp(server, tool, verb, mode) := {
	"action": {
		"agent_id": "support_agent_1",
		"system": "mcp",
		"verb": verb,
		"target": {"server": server, "tool": tool, "method": "tools/call"},
		"payload_summary": {},
		"est_cost_usd": 0,
	},
	"agent": agent,
	"context": {"memory": {"access": mode}},
}

without_ctx(inp) := object.remove(inp, ["context"])

rule_ids(r) := {m.rule_id | some m in r.matched}

# --- full access ------------------------------------------------------------

test_full_read_allowed if {
	r := decide.result with input as mem("READ", target, {}, "full")
	r.decision == "allow"
	r.class == "green"
}

test_full_remember_staged_pol803 if {
	r := decide.result with input as mem("REMEMBER", target, {"bytes": 42}, "full")
	r.decision == "allow_reduced"
	r.class == "yellow"
	r.rule_id == "POL-903"
	r.reduced_form == {"memory_staging": true}
	not "POL-005" in rule_ids(r)
	not r.ladder_change
}

test_remember_without_store_still_held_pol005 if {
	r := decide.result with input as mem("REMEMBER", {}, {}, "full")
	r.decision == "hold"
	r.rule_id == "POL-005"
}

test_full_delete_held_pol005 if {
	r := decide.result with input as mem("DELETE", object.union(target, {"item_id": "mem_1"}), {}, "full")
	r.decision == "hold"
	r.rule_id == "POL-005"
}

test_sensitive_write_held_pol904 if {
	r := decide.result with input as mem("REMEMBER", target, {"data_labels": ["customer_pii"]}, "full")
	r.decision == "hold"
	"POL-904" in rule_ids(r)
	"POL-903" in rule_ids(r)

	# The finding that demands the hold is the one reported, not the
	# lower-numbered staging finding.
	r.rule_id == "POL-904"
	startswith(r.reason, "memory write carrying sensitive data")
}

test_non_sensitive_label_not_held if {
	r := decide.result with input as mem("REMEMBER", target, {"data_labels": ["faq"]}, "full")
	r.decision == "allow_reduced"
}

test_no_context_defaults_to_full if {
	r := decide.result with input as without_ctx(mem("READ", target, {}, "full"))
	r.decision == "allow"
	r2 := decide.result with input as without_ctx(mem("REMEMBER", target, {}, "full"))
	r2.decision == "allow_reduced"
}

# --- access none ------------------------------------------------------------

test_none_denies_everything_pol801 if {
	every v in ["READ", "REMEMBER", "DELETE", "WRITE"] {
		r := decide.result with input as mem(v, target, {}, "none")
		r.decision == "deny"
		r.rule_id == "POL-901"
		not r.ladder_change
	}
}

test_none_denies_memory_mcp_pol801 if {
	r := decide.result with input as mcp("memory", "read_graph", "READ", "none")
	r.decision == "deny"
	r.rule_id == "POL-901"
	r2 := decide.result with input as mcp("Memory", "create_entities", "REMEMBER", "none")
	r2.decision == "deny"
	r2.rule_id == "POL-901"
}

test_none_ignores_other_mcp_servers if {
	r := decide.result with input as mcp("github-mcp", "get_issue", "READ", "none")
	r.decision == "allow"
}

test_none_ignores_other_systems if {
	inp := {
		"action": {"agent_id": "support_agent_1", "system": "postgres", "verb": "READ", "target": {"statement_type": "SELECT", "environment": "prod", "tables": ["public.orders"]}, "payload_summary": {}, "est_cost_usd": 0},
		"agent": agent,
		"context": {"memory": {"access": "none"}},
	}
	r := decide.result with input as inp
	r.decision == "allow"
}

test_malformed_context_fails_closed if {
	every c in [{"access": "everything"}, {"access": 1}, {}, "none", null] {
		inp := object.union(without_ctx(mem("READ", target, {}, "full")), {"context": {"memory": c}})
		r := decide.result with input as inp
		r.decision == "deny"
		r.rule_id == "POL-901"
	}
}

# --- access staging_only ----------------------------------------------------

test_staging_only_read_and_staged_write_allowed if {
	r := decide.result with input as mem("READ", target, {}, "staging_only")
	r.decision == "allow"
	r2 := decide.result with input as mem("REMEMBER", target, {}, "staging_only")
	r2.decision == "allow_reduced"
	r2.reduced_form.memory_staging == true
}

test_staging_only_delete_denied_pol802 if {
	r := decide.result with input as mem("DELETE", object.union(target, {"item_id": "mem_1"}), {}, "staging_only")
	r.decision == "deny"
	r.rule_id == "POL-902"
}

test_staging_only_mcp_write_denied_pol802 if {
	r := decide.result with input as mcp("memory", "create_entities", "REMEMBER", "staging_only")
	r.decision == "deny"
	r.rule_id == "POL-902"
	r2 := decide.result with input as mcp("memory", "read_graph", "READ", "staging_only")
	r2.decision == "allow"
}

# --- gates and control ladder -----------------------------------------------

test_control_gate_wins_over_memory_gate if {
	inp := object.union(mem("READ", target, {}, "none"), {"agent": object.union(agent, {"level": 5})})
	r := decide.result with input as inp
	r.rule_id == "POL-010"
}

test_supervised_write_waits_for_human if {
	inp := object.union(mem("REMEMBER", target, {}, "full"), {"agent": object.union(agent, {"level": 1})})
	r := decide.result with input as inp
	r.decision == "hold"
}

test_denials_only_for_memory_actions if {
	count(memory.denials) == 0 with input as mcp("filesystem", "write_file", "WRITE", "none")
}

test_memory_server_list_from_data if {
	memory.memory_mcp with input as mcp("vector-mem", "read_graph", "READ", "none")
		with data.fortik.memory.mcp_servers as ["vector-mem"]
	not memory.memory_mcp with input as mcp("memory", "read_graph", "READ", "none")
		with data.fortik.memory.mcp_servers as ["vector-mem"]
}
