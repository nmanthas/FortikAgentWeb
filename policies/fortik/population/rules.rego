# Classification for system "agents" (docs/PHASE3_DESIGN.md §2.1). The only
# action Fortik defines on it is the spawn registration (verb DELEGATE,
# target.operation "spawn"), decided by the population gates. Any other
# "agents" action is unclassified: red and refused (fail closed), without a
# step-down, like POL-002.
package fortik.rules

import data.fortik.population

findings contains {
	"rule_id": "POL-706",
	"class": "red",
	"reason": sprintf("unclassified agents action (verb=%v, operation=%v): only spawn registrations are defined: fail closed", [input.action.verb, object.get(object.get(input.action, "target", {}), "operation", "")]),
	"ladder": "NONE",
	"deny": true,
} if {
	input.action.system == population.cfg.spawn_system
	not population.spawn
}
