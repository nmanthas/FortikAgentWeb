# Delegation chains (docs/PHASE3_DESIGN.md §1, manager use cases UC1 and UC3).
#
# The delegation enricher supplies input.context.delegation:
#   {"present": false}                                     not delegated, or
#   {"present": true, "source": "token" | "inferred", "delegation_id": "...",
#    "depth": N, "root": "agent_a", "max_depth": M (config; optional),
#    "chain": [{"agent_id", "registered", "level", "level_name", "access"}, ...]}
# chain lists the UPSTREAM agents only (root first, the executor excluded);
# each hop's access is that agent's profile for THIS action's system. A token
# that does not verify yields {"present": true, "token_error": "..."}.
#
#   POL-601 an upstream agent could not perform this action itself: the exact
#           control and access gates, evaluated as that agent (transitive, at
#           any depth), so "may not" means the same as for a direct action
#   POL-602 the delegation is deeper than max_depth (the action's own depth,
#           or the depth a DELEGATE would create)
#   POL-603 a DELEGATE to an agent the delegator's a2a profile does not list,
#           or deeper than the profile's max_depth (self-delegation exempt)
#   POL-604 the presented delegation token is invalid, expired or not the agent's
#
# Every rule fails closed: a malformed context, chain, hop or depth denies.
# The rules contribute to fortik.gates.deny (see gates.rego in this directory).
package fortik.delegation

import data.fortik.access
import data.fortik.control

act := input.action

tgt := object.get(act, "target", {})

verb := object.get(act, "verb", "")

deleg := object.get(object.get(input, "context", {}), "delegation", null)

present if deleg.present == true

token_error := e if {
	present
	e := object.get(deleg, "token_error", "")
	e != ""
}

chain := c if {
	c := deleg.chain
	is_array(c)
} else := []

# Policy limit (data.fortik.delegation.max_depth, default 5).
data_depth_limit := v if {
	v := data.fortik.delegation.max_depth
	is_number(v)
	v >= 1
} else := 5

# The enricher passes config delegation.max_depth (the limit the store also
# records hops under); it can only lower the policy limit, never raise it.
depth_limit := min({data_depth_limit, v}) if {
	is_object(deleg)
	v := deleg.max_depth
	is_number(v)
	v >= 1
} else := data_depth_limit

is_delegate if {
	act.system == "a2a"
	verb == "DELEGATE"
}

# --- POL-604: the token did not verify ----------------------------------------

denials contains {"rule_id": "POL-604", "reason": sprintf("delegation token refused: %v", [token_error])} if token_error

# --- POL-601: transitive enforcement -------------------------------------------

hop_ok(h) if {
	is_object(h)
	is_string(h.agent_id)
	h.agent_id != ""
	is_boolean(h.registered)
	is_number(h.level)
	is_object(h.access)
}

# The gate that would refuse this action were hop h performing it itself:
# its control level first, then its access profile, exactly as fortik.decide
# orders them for the executor.
hop_gate(h) := g if {
	g := control.gate with input.agent as h with input.access as h.access
} else := g if {
	g := access.gate with input.agent as h with input.access as h.access
}

malformed contains "delegation context is not an object" if {
	deleg != null
	not is_object(deleg)
}

malformed contains "delegation chain is not a list" if {
	present
	not token_error
	not is_array(object.get(deleg, "chain", null))
}

malformed contains sprintf("delegation chain entry %d is malformed", [i + 1]) if {
	present
	not token_error
	some i, h in chain
	not hop_ok(h)
}

malformed contains sprintf("unknown delegation source %v", [object.get(deleg, "source", null)]) if {
	present
	not token_error
	not object.get(deleg, "source", null) in {"token", "inferred"}
}

denials contains {"rule_id": "POL-601", "reason": sprintf("%s: fail closed", [m])} if {
	some m in malformed
}

bad_hops := {i |
	not token_error
	some i, h in chain
	hop_ok(h)
	hop_gate(h)
}

denials contains {"rule_id": "POL-601", "reason": msg} if {
	present
	count(bad_hops) > 0
	i := min(bad_hops)
	h := chain[i]
	g := hop_gate(h)
	msg := sprintf("delegation bypass: originating agent %s (hop %d of %d) may not %v on %v: %s (%s)", [
		h.agent_id, i + 1, count(chain), verb, act.system, g.reason, g.rule_id,
	])
}

# --- POL-602: depth --------------------------------------------------------------

ctx_depth := d if {
	present
	d := deleg.depth
	is_number(d)
} else := 0

denials contains {"rule_id": "POL-602", "reason": "malformed delegation depth: fail closed"} if {
	present
	not token_error
	not is_number(object.get(deleg, "depth", null))
}

denials contains {"rule_id": "POL-602", "reason": sprintf("delegation depth %v exceeds max_depth %v", [ctx_depth, depth_limit])} if {
	ctx_depth > depth_limit
}

target_depth := d if {
	d := tgt.depth
	is_number(d)
} else := 0

# The depth a DELEGATE creates: one below the delegator's own depth (a
# transport-supplied target.depth can only make it deeper).
new_depth := max({ctx_depth + 1, target_depth})

denials contains {"rule_id": "POL-602", "reason": "malformed target.depth (must be a number): fail closed"} if {
	is_delegate
	"depth" in object.keys(tgt)
	not is_number(tgt.depth)
}

denials contains {"rule_id": "POL-602", "reason": sprintf("delegating would create depth %v, beyond max_depth %v", [new_depth, depth_limit])} if {
	is_delegate
	new_depth > depth_limit
}

# --- POL-603: the delegator's a2a profile ----------------------------------------

to_agent := t if {
	t := tgt.to_agent
	is_string(t)
	t != ""
}

# A Claude Code Task subagent: the same agent, nothing new is granted.
self_delegation if to_agent == act.agent_id

a2a_profile := p if {
	object.get(input.access, "system", "") == "a2a"
	p := input.access.profile
	is_object(p)
}

may_delegate_to := l if {
	l := a2a_profile.may_delegate_to
	is_array(l)
} else := []

profile_max_depth := d if {
	d := a2a_profile.max_depth
	is_number(d)
} else := 0

delegate_listed if "*" in may_delegate_to

delegate_listed if to_agent in may_delegate_to

denials contains {"rule_id": "POL-603", "reason": "the delegation names no target agent (target.to_agent)"} if {
	is_delegate
	not to_agent
}

denials contains {"rule_id": "POL-603", "reason": "no a2a access profile: delegating to another agent is refused"} if {
	is_delegate
	to_agent
	not self_delegation
	not a2a_profile
}

denials contains {"rule_id": "POL-603", "reason": sprintf("a2a profile does not allow delegating to %s", [to_agent])} if {
	is_delegate
	to_agent
	not self_delegation
	a2a_profile
	not delegate_listed
}

denials contains {"rule_id": "POL-603", "reason": sprintf("delegating would create depth %v, beyond the a2a profile max_depth %v", [new_depth, profile_max_depth])} if {
	is_delegate
	to_agent
	not self_delegation
	a2a_profile
	new_depth > profile_max_depth
}
