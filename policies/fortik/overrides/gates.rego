# Deny gates contributed by timed app suspensions (see overrides.rego).
package fortik.gates

import data.fortik.overrides

deny contains {"rule_id": "POL-030", "reason": reason} if {
	o := overrides.winner(overrides.suspensions)
	reason := sprintf("%s suspended %s %s", [input.action.system, overrides.when(o), overrides.describe(o)])
}

deny contains {"rule_id": "POL-031", "reason": reason} if {
	not input.action.verb in overrides.read_verbs
	o := overrides.winner(overrides.read_onlys)
	reason := sprintf("%s is read-only %s %s: %v refused", [input.action.system, overrides.when(o), overrides.describe(o), input.action.verb])
}
