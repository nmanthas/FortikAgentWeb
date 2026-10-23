# Extension point for deny gates contributed by Phase 3+ packages
# (delegation chains, timed suspensions, population/rate limits...).
#
# Any file may declare `package fortik.gates` and add
#   deny contains {"rule_id": "POL-xxx", "reason": "..."} if { ... }
# A gate refuses the action (decision deny, no ladder change of its own);
# the control and access gates are checked first, then these by lowest rule id.
package fortik.gates

# Never matches: makes data.fortik.gates.deny an (empty) set when no package
# contributes.
deny contains g if {
	false
	g := {"rule_id": "", "reason": ""}
}
