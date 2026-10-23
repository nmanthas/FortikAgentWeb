# Control ladder gating. The agent's current level (read by Decide from
# control state on every call) restricts what may run regardless of class.
#   0 FULL         everything its scopes allow; yellow runs in reduced form
#   1 SUPERVISED   green runs; every yellow waits for a human
#   2 READ_ONLY    READ only
#   3 ISOLATED     internal reads only; no SEND, EXPORT or external egress
#   4 QUARANTINED  nothing; state frozen for review
#   5 KILLED       nothing
package fortik.control

act := input.action

agent := object.get(input, "agent", {})

level := object.get(agent, "level", 5)

tgt := object.get(act, "target", {})

external if tgt.external == true

external if object.get(tgt, "external_domains", 0) > 0

# gate: the control rule that refuses this action at the agent's level.
# At most one applies; the most restrictive level is checked first.
gate := {"rule_id": "POL-015", "reason": sprintf("agent %v is not registered with Fortik", [object.get(agent, "agent_id", "")])} if {
	not agent.registered == true
} else := {"rule_id": "POL-010", "reason": "agent is KILLED: no actions permitted"} if {
	level >= 5
} else := {"rule_id": "POL-016", "reason": sprintf("agent is SUSPENDED: no actions until resumed (%v)", [object.get(agent, "suspended_reason", "")])} if {
	agent.suspended == true
} else := {"rule_id": "POL-011", "reason": "agent is QUARANTINED: frozen for review"} if {
	level == 4
} else := {"rule_id": "POL-012", "reason": sprintf("agent is ISOLATED: internal reads only (%v refused)", [act.verb])} if {
	level == 3
	isolated_refuses
} else := {"rule_id": "POL-013", "reason": sprintf("agent is READ_ONLY: %v refused", [act.verb])} if {
	level == 2
	act.verb != "READ"
}

isolated_refuses if act.verb != "READ"

isolated_refuses if external

# Supervised agents: every yellow waits for a human (POL-014).
supervised if level == 1
