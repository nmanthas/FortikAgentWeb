# Delegation chains: POL-601..604 through the full decision (fortik.decide).
package fortik.delegation_test

import data.fortik.decide
import data.fortik.delegation

# --- fixtures ------------------------------------------------------------------

http_none := {"external": "none", "allowed_domains": []}

http_any := {"external": "any", "allowed_domains": []}

acc(system, profile) := {"system": system, "version": 1, "profile": profile}

no_acc(system) := {"system": system, "version": 0, "profile": null}

hop(id, level, access) := {"agent_id": id, "registered": true, "level": level, "level_name": "X", "access": access}

# Executor agent_c fetching an external URL; its own http profile allows it.
egress := {
	"action": {
		"agent_id": "agent_c", "system": "http", "verb": "READ",
		"target": {"domain": "example.com", "external": true, "method": "GET"},
		"payload_summary": {}, "est_cost_usd": 0,
	},
	"agent": {"agent_id": "agent_c", "registered": true, "level": 0},
	"access": acc("http", http_any),
}

with_deleg(inp, d) := object.union(inp, {"context": {"delegation": d}})

token_ctx(chain, depth) := {"present": true, "source": "token", "delegation_id": "dlg_1", "depth": depth, "root": chain[0].agent_id, "chain": chain}

result(inp) := r if {
	r := decide.result with input as inp
}

denied(inp, rule) if {
	r := result(inp)
	r.decision == "deny"
	r.rule_id == rule
}

# --- no delegation ----------------------------------------------------------------

test_direct_action_allowed if {
	result(egress).decision == "allow"
	result(with_deleg(egress, {"present": false, "chain": []})).decision == "allow"
}

test_permitted_chain_allowed if {
	inp := with_deleg(egress, token_ctx([hop("agent_a", 0, acc("http", http_any))], 1))
	result(inp).decision == "allow"
}

# --- POL-601: UC1 and UC3 ---------------------------------------------------------

test_uc1_bypass_denied if {
	inp := with_deleg(egress, token_ctx([hop("agent_a", 0, acc("http", http_none))], 1))
	denied(inp, "POL-601")
	r := result(inp)
	contains(r.reason, "originating agent agent_a (hop 1 of 1)")
	contains(r.reason, "POL-028")
}

test_uc1_no_profile_origin_denied if {
	inp := with_deleg(egress, token_ctx([hop("agent_a", 0, no_acc("http"))], 1))
	denied(inp, "POL-601")
	contains(result(inp).reason, "POL-020")
}

test_uc3_transitive_names_root if {
	chain := [hop("agent_a", 0, acc("http", http_none)), hop("agent_b", 0, acc("http", http_none))]
	inp := with_deleg(egress, token_ctx(chain, 2))
	denied(inp, "POL-601")
	contains(result(inp).reason, "originating agent agent_a (hop 1 of 2)")
}

test_uc3_middle_hop_detected if {
	chain := [
		hop("agent_a", 0, acc("http", http_any)), hop("agent_b", 0, acc("http", http_none)),
		hop("agent_x", 0, acc("http", http_any)),
	]
	inp := with_deleg(egress, token_ctx(chain, 3))
	denied(inp, "POL-601")
	contains(result(inp).reason, "agent_b (hop 2 of 3)")
}

test_upstream_control_level_applies if {
	# agent_a is READ_ONLY: a delegated WRITE is refused even though agent_c may write.
	write := object.union(egress, {"action": object.union(egress.action, {"verb": "EXPORT"})})
	inp := with_deleg(write, token_ctx([hop("agent_a", 2, acc("http", http_any))], 1))
	denied(inp, "POL-601")
	contains(result(inp).reason, "POL-013")
}

test_upstream_unregistered_denied if {
	h := object.union(hop("ghost", 0, acc("http", http_any)), {"registered": false})
	denied(with_deleg(egress, token_ctx([h], 1)), "POL-601")
}

test_upstream_killed_denied if {
	denied(with_deleg(egress, token_ctx([hop("agent_a", 5, acc("http", http_any))], 1)), "POL-601")
}

test_inferred_chain_enforced if {
	d := {"present": true, "source": "inferred", "depth": 1, "chain": [hop("agent_b", 0, acc("http", http_none))]}
	denied(with_deleg(egress, d), "POL-601")
}

test_executor_gate_wins_over_bypass if {
	inp := object.union(with_deleg(egress, token_ctx([hop("agent_a", 0, acc("http", http_none))], 1)), {"access": acc("http", http_none)})
	denied(inp, "POL-028")
}

# --- POL-601: fail closed on malformed input ----------------------------------------

test_malformed_context_denied if {
	denied(with_deleg(egress, "yes"), "POL-601")
	denied(with_deleg(egress, {"present": true, "source": "token", "depth": 1, "chain": "agent_a"}), "POL-601")
	denied(with_deleg(egress, {"present": true, "source": "token", "depth": 1}), "POL-601")
	denied(with_deleg(egress, {"present": true, "source": "gossip", "depth": 1, "chain": []}), "POL-601")
}

test_malformed_hop_denied if {
	no_access := {"agent_id": "agent_a", "registered": true, "level": 0}
	denied(with_deleg(egress, token_ctx([no_access], 1)), "POL-601")
	bad_level := object.union(hop("agent_a", 0, acc("http", http_any)), {"level": "FULL"})
	denied(with_deleg(egress, token_ctx([bad_level], 1)), "POL-601")
}

# --- POL-604 ---------------------------------------------------------------------

test_token_error_denied if {
	inp := with_deleg(egress, {"present": true, "source": "token", "token_error": "expired delegation token", "chain": []})
	denied(inp, "POL-604")
	contains(result(inp).reason, "expired delegation token")
}

# --- POL-602 ---------------------------------------------------------------------

test_depth_beyond_max_denied if {
	chain := [hop("agent_a", 0, acc("http", http_any))]
	denied(with_deleg(egress, token_ctx(chain, 6)), "POL-602")
	result(with_deleg(egress, token_ctx(chain, 5))).decision == "allow"
}

test_depth_limit_from_data if {
	chain := [hop("agent_a", 0, acc("http", http_any))]
	r := decide.result with input as with_deleg(egress, token_ctx(chain, 3)) with data.fortik.delegation.max_depth as 2
	r.rule_id == "POL-602"
}

test_depth_limit_from_config_only_lowers if {
	chain := [hop("agent_a", 0, acc("http", http_any))]
	lowered := object.union(token_ctx(chain, 3), {"max_depth": 2})
	denied(with_deleg(egress, lowered), "POL-602")
	contains(result(with_deleg(egress, lowered)).reason, "max_depth 2")
	raised := object.union(token_ctx(chain, 6), {"max_depth": 9})
	denied(with_deleg(egress, raised), "POL-602")
	ignored := object.union(token_ctx(chain, 5), {"max_depth": "1"})
	result(with_deleg(egress, ignored)).decision == "allow"
}

test_delegate_depth_limit_from_config if {
	chain := [hop("agent_a", 0, acc("a2a", a2a_p(["*"], 9)))]
	d := object.union(token_ctx(chain, 1), {"max_depth": 1})
	denied(with_deleg(delegate("agent_b", "agent_c", a2a_p(["*"], 9)), d), "POL-602")
}

test_malformed_depth_denied if {
	d := object.union(token_ctx([hop("agent_a", 0, acc("http", http_any))], 1), {"depth": "1"})
	denied(with_deleg(egress, d), "POL-602")
}

# --- DELEGATE: POL-602 / POL-603 ----------------------------------------------------

a2a_p(to, depth) := {"may_delegate_to": to, "max_depth": depth}

delegate(from, to, profile) := {
	"action": {
		"agent_id": from, "system": "a2a", "verb": "DELEGATE",
		"target": {"to_agent": to, "channel": "a2a", "task_id": "t1"},
		"payload_summary": {}, "est_cost_usd": 0,
	},
	"agent": {"agent_id": from, "registered": true, "level": 0},
	"access": acc("a2a", profile),
}

test_delegate_listed_passes_gates if {
	inp := delegate("agent_a", "agent_b", a2a_p(["agent_b"], 2))
	count(delegation.denials) == 0 with input as inp
	count(delegation.denials) == 0 with input as delegate("agent_a", "agent_z", a2a_p(["*"], 1))
}

test_delegate_unlisted_denied if {
	inp := delegate("agent_a", "agent_c", a2a_p(["agent_b"], 2))
	denied(inp, "POL-603")
	contains(result(inp).reason, "agent_c")
}

test_delegate_no_target_denied if {
	inp := delegate("agent_a", "", a2a_p(["*"], 2))
	denied(inp, "POL-603")
}

test_delegate_beyond_profile_depth_denied if {
	inp := with_deleg(delegate("agent_b", "agent_c", a2a_p(["*"], 1)), token_ctx([hop("agent_a", 0, acc("a2a", a2a_p(["*"], 5)))], 1))
	denied(inp, "POL-603")
}

test_delegate_beyond_global_depth_denied if {
	chain := [hop("agent_a", 0, acc("a2a", a2a_p(["*"], 9)))]
	inp := with_deleg(delegate("agent_b", "agent_c", a2a_p(["*"], 9)), token_ctx(chain, 5))
	denied(inp, "POL-602")
	contains(result(inp).reason, "depth 6")
}

test_delegate_target_depth_counts if {
	inp := delegate("agent_a", "agent_b", a2a_p(["*"], 9))
	deep := object.union(inp, {"action": object.union(inp.action, {"target": object.union(inp.action.target, {"depth": 6})})})
	denied(deep, "POL-602")
	bad := object.union(inp, {"action": object.union(inp.action, {"target": object.union(inp.action.target, {"depth": "6"})})})
	denied(bad, "POL-602")
}

test_delegate_without_a2a_profile_denied if {
	inp := object.union(delegate("agent_a", "agent_b", {}), {"access": no_acc("a2a")})
	denied(inp, "POL-020")
	no_input_access := object.remove(inp, ["access"])
	"POL-603" in {d.rule_id | some d in delegation.denials} with input as no_input_access
}

test_self_delegation_exempt if {
	inp := object.union(delegate("agent_a", "agent_a", {}), {"access": no_acc("a2a")})
	count(delegation.denials) == 0 with input as inp
	not data.fortik.access.gate with input as inp
}

test_delegate_checked_against_upstream if {
	# UC3: agent_b may delegate, but agent_a (upstream) is READ_ONLY: DELEGATE is not READ.
	inp := with_deleg(delegate("agent_b", "agent_c", a2a_p(["*"], 3)), token_ctx([hop("agent_a", 2, acc("a2a", a2a_p(["*"], 3)))], 1))
	denied(inp, "POL-601")
}

test_delegate_upstream_without_a2a_profile_denied if {
	inp := with_deleg(delegate("agent_b", "agent_c", a2a_p(["*"], 3)), token_ctx([hop("agent_a", 0, no_acc("a2a"))], 1))
	denied(inp, "POL-601")
}
