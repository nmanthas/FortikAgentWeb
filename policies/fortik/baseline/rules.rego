# Baseline findings (POL-660..669), contributed to the shared rule set.
#
# POL-660: an above-normal action that would otherwise be green becomes
# yellow and is held for one approver. It is an escalation finding: fortik.decide
# applies it only when no other finding makes the action yellow or red, so it
# never changes another rule's decision, reduced form or reported reason. It
# carries neither "hold" nor a reduced form, so as the only yellow it holds.
# A one-time approval grant for the action's hash releases it like any held
# yellow.
#
# POL-661: input.context.baseline present but malformed: fail closed (hold).
package fortik.rules

import data.fortik.baseline

findings contains {
	"rule_id": "POL-660",
	"class": "yellow",
	"escalation": true,
	"reason": sprintf(
		"unusual volume: %v %s calls by this agent this hour, above its normal (threshold %v by %v over %v days of history)",
		[baseline.ctx.current, input.action.verb, baseline.ctx.threshold, object.get(baseline.ctx, "method", "baseline"), object.get(baseline.ctx, "history_days", 0)],
	),
} if {
	baseline.above_normal
}

findings contains {
	"rule_id": "POL-661",
	"class": "yellow",
	"reason": "baseline context is malformed: fail closed, approval required",
	"hold": true,
} if {
	baseline.malformed
}
