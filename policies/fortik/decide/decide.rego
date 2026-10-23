# Aggregates rule findings and control gating into the single decision the
# interception point enforces:
#   {class, decision, reduced_form, ladder_change, reason, rule_id, matched}
package fortik.decide

import data.fortik.access
import data.fortik.control
import data.fortik.gates
import data.fortik.rules

# Escalation findings ("escalation": true, e.g. POL-660 above-normal volume)
# only ever make an action more restrictive, by one step:
#   - an otherwise-green action becomes a yellow hold;
#   - an otherwise-yellow action that would run in its reduced form
#     (allow_reduced) is held instead: a volume anomaly on the riskier paths
#     must not run unattended just because a reduced form exists;
#   - on anything already held, denied or red they are dropped, so they never
#     change another rule's decision or reported reason there.
escalation(f) if f.escalation == true

core_findings := {f | some f in rules.findings; not escalation(f)}

core_green if {
	not any_core_class("red")
	not any_core_class("yellow")
}

any_core_class(c) if {
	some f in core_findings
	f.class == c
}

core_yellows := [f | some f in core_findings; f.class == "yellow"]

core_reduced := {k: v |
	some f in core_yellows
	some k, v in object.get(f, "reduced_form", {})
}

# The core findings alone would run the action reduced (allow_reduced).
core_runs_reduced if {
	not any_core_class("red")
	count(core_yellows) > 0
	count(core_reduced) > 0
	not any_core_hold
	not any_core_deny
	not control.supervised
}

any_core_hold if {
	some f in core_yellows
	f.hold == true
}

any_core_deny if {
	some f in core_findings
	f.deny == true
}

findings := (core_findings | {f | some f in rules.findings; escalation(f); core_green}) | {object.union(f, {"hold": true}) |
	some f in rules.findings
	escalation(f)
	core_runs_reduced
}

levels := ["FULL", "SUPERVISED", "READ_ONLY", "ISOLATED", "QUARANTINED", "KILLED"]

level_index(name) := i if levels[i] == name

class := "red" if {
	some f in findings
	f.class == "red"
} else := "yellow" if {
	some f in findings
	f.class == "yellow"
} else := "green"

# The deciding finding: among findings of the worst class, a yellow that
# demands a hold comes first (it is why the action waits for a human, so its
# reason is the one shown and recorded); then the lowest rule id. Triples sort
# by priority and rule id first, so the pick is deterministic even when one
# rule id produced several findings.
hold_priority(f) := 0 if {
	f.class == "yellow"
	f.hold == true
} else := 1

ranked := sort([[hold_priority(f), f.rule_id, f] | some f in findings; f.class == class])

top := ranked[0][2] if count(ranked) > 0

yellows := [f | some f in findings; f.class == "yellow"]

reduced_form := {k: v |
	some f in yellows
	some k, v in object.get(f, "reduced_form", {})
}

# A yellow needs a human when any yellow finding says hold, when no reduced
# form exists to run it safely, or when the agent is Supervised (POL-014).
yellow_hold if {
	some f in yellows
	f.hold == true
}

yellow_hold if count(reduced_form) == 0

yellow_hold if control.supervised

any_deny if {
	some f in findings
	f.deny == true
}

core := "deny" if {
	any_deny
} else := "hold" if {
	class == "red"
} else := "hold" if {
	class == "yellow"
	yellow_hold
} else := "allow_reduced" if {
	class == "yellow"
} else := "allow"

# Gates refuse regardless of class: the control ladder first, then the
# agent's access profile (Phase 2). Neither gate adds a ladder change.
# Extension gates (fortik.gates.deny): the lowest rule id decides.
extra_ranked := sort([[g.rule_id, g] | some g in gates.deny])

extra_gate := extra_ranked[0][1] if count(extra_ranked) > 0

# A one-time approval grant (input.context.grant, supplied only when an
# unexpired, unused grant matches this agent and action hash) releases a held
# YELLOW action. It never overrides a gate and never releases red, and it
# carries the number of distinct approvers behind it: a grant approved by
# fewer people than this hold needs (e.g. one approval of a call held before
# the swarm breaker tripped, now needing two) releases nothing.
grant_approvals := n if {
	n := input.context.grant.approvals
	is_number(n)
} else := 1

granted if {
	not control.gate
	not access.gate
	not extra_gate
	class == "yellow"
	core == "hold"
	is_string(input.context.grant.grant_id)
	input.context.grant.grant_id != ""
	grant_approvals >= approvals_required
}

decision := "deny" if {
	control.gate
} else := "deny" if {
	access.gate
} else := "deny" if {
	extra_gate
} else := "allow" if {
	granted
} else := core

# Step-down target: the most restrictive level named by any red finding
# ("NONE" excluded, missing = configured default).
red_ladders := {l |
	some f in findings
	f.class == "red"
	l := object.get(f, "ladder", data.fortik.config.default_red_ladder)
	l != "NONE"
}

ladder_target := levels[max({level_index(l) | some l in red_ladders})] if count(red_ladders) > 0

ladder_change := {"to": ladder_target, "reason": sprintf("%s: %s", [top.rule_id, top.reason])} if ladder_target

rule_id := control.gate.rule_id if control.gate

else := access.gate.rule_id if access.gate

else := extra_gate.rule_id if extra_gate

else := top.rule_id if top

else := "POL-000"

supervised_note := " (agent SUPERVISED: POL-014 requires approval)" if {
	class == "yellow"
	control.supervised
} else := ""

reason := control.gate.reason if control.gate

else := access.gate.reason if access.gate

else := extra_gate.reason if extra_gate

else := sprintf("%s (approved: grant %s)", [top.reason, input.context.grant.grant_id]) if granted

else := concat("", [top.reason, supervised_note]) if top

else := "no rule matched: within policy"

matched := [{"rule_id": f.rule_id, "class": f.class, "reason": f.reason} |
	some id in sort({f.rule_id | some f in findings})
	some f in findings
	f.rule_id == id
]

base := {
	"class": class,
	"decision": decision,
	"rule_id": rule_id,
	"reason": reason,
	"matched": matched,
}

# A hold needs as many distinct approvers as the most demanding finding asks
# for (e.g. the swarm breaker: two); default one.
approvals_required := max({n |
	some f in findings
	n := object.get(f, "approvals_required", 1)
	is_number(n)
	n >= 1
} | {1})

with_approvals := object.union(base, {"approvals_required": approvals_required}) if {
	decision == "hold"
	approvals_required > 1
} else := base

with_reduced := object.union(base, {"reduced_form": reduced_form}) if decision == "allow_reduced"

else := object.union(base, {"grant_id": input.context.grant.grant_id}) if granted

else := with_approvals

result := object.union(with_reduced, {"ladder_change": ladder_change}) if ladder_change

else := with_reduced
