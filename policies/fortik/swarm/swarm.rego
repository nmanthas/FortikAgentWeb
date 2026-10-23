# Swarm controls (docs/PHASE5_DESIGN.md §1). The swarm enricher supplies
# input.context.swarm on every decision:
#
#   {"member_of": [swarm_id...],        active swarms the acting agent belongs to
#    "frozen": bool,                     one of them is frozen (kill-swarm step 1 onward)
#    "frozen_swarm_id": "...",
#    "delegatee_frozen": bool,           a DELEGATE names an agent of a frozen swarm
#    "breaker": {"tripped": bool,        this action's hash matches a tripped Max-5 breaker
#                "swarm_id": "...",      (or this call is the one that trips it: "pending")
#                "pending": bool}}
#
#   POL-651 yellow hold, approvals_required 2 (finding, rules.rego): the call
#           matches a tripped breaker; every matching call waits for two
#           distinct approvers
#   POL-652 deny (gate): a member of a frozen swarm may not DELEGATE (A2A,
#           subagent tasks, spawn registration = a new copy), and nobody may
#           delegate to a member of a frozen swarm
#   POL-653 deny (gate): a member of a frozen swarm may only READ, and is
#           issued no credentials (closes the gap between kill steps 3 and 6)
#   POL-659 deny (gate): malformed swarm context (fail closed)
#
# Without input.context.swarm (enricher not wired) no rule applies.
package fortik.swarm

cfg := s if {
	s := data.fortik.swarm.settings
	is_object(s)
} else := {}

breaker_approvals := n if {
	n := cfg.breaker_approvals
	is_number(n)
	n >= 2
} else := 2

read_verbs := {v | some v in object.get(cfg, "read_verbs", ["READ"])}

act := input.action

tgt := t if {
	t := act.target
	is_object(t)
} else := {}

raw := object.get(object.get(input, "context", {}), "swarm", null)

sw := raw if is_object(raw)

agent := object.get(act, "agent_id", "")

frozen if sw.frozen == true

frozen_id := id if {
	id := sw.frozen_swarm_id
	is_string(id)
	id != ""
} else := "unknown"

breaker := b if {
	b := sw.breaker
	is_object(b)
}

tripped if breaker.tripped == true

breaker_id := id if {
	id := breaker.swarm_id
	is_string(id)
	id != ""
} else := "pending"

delegate if act.verb == "DELEGATE"

spawn if {
	delegate
	act.system == "agents"
	object.get(tgt, "operation", "") == "spawn"
}

what := "new copy registration" if spawn

else := "delegation"

credential_request if tgt.credential_request == true

# --- POL-651: Max-5 breaker (finding; see rules.rego) ---------------------------

breaker_finding := {
	"rule_id": "POL-651",
	"class": "yellow",
	"reason": sprintf("swarm breaker tripped (swarm %s): this identical call was already made by more agents or copies than the breaker allows; held for %d distinct approvers", [breaker_id, breaker_approvals]),
	"hold": true,
	"approvals_required": breaker_approvals,
} if tripped

# --- POL-652: frozen swarm refuses DELEGATE and new copies -------------------------

denials contains {"rule_id": "POL-652", "reason": sprintf("swarm %s is frozen: %s by member %s refused", [frozen_id, what, agent])} if {
	frozen
	delegate
}

denials contains {"rule_id": "POL-652", "reason": sprintf("delegation to %v refused: it is a member of a frozen swarm", [object.get(tgt, "to_agent", "")])} if {
	delegate
	sw.delegatee_frozen == true
}

# --- POL-653: frozen members may only READ, and get no credentials -------------------

denials contains {"rule_id": "POL-653", "reason": sprintf("swarm %s is frozen: member %s may only READ (%s refused)", [frozen_id, agent, act.verb])} if {
	frozen
	not delegate
	not act.verb in read_verbs
}

denials contains {"rule_id": "POL-653", "reason": sprintf("swarm %s is frozen: no credentials are issued to member %s", [frozen_id, agent])} if {
	frozen
	credential_request
}

# --- POL-659: malformed context ------------------------------------------------------

malformed contains "not an object" if {
	raw != null
	not is_object(raw)
}

malformed contains "frozen" if {
	sw
	not is_boolean(sw.frozen)
}

malformed contains "member_of" if {
	sw
	not is_array(sw.member_of)
}

malformed contains "breaker" if {
	sw
	not breaker
}

malformed contains "breaker.tripped" if {
	breaker
	not is_boolean(breaker.tripped)
}

malformed contains "delegatee_frozen" if {
	sw
	v := sw.delegatee_frozen
	not is_boolean(v)
}

denials contains {"rule_id": "POL-659", "reason": sprintf("malformed swarm context (%s): fail closed", [concat(", ", sort(malformed))])} if {
	count(malformed) > 0
}
