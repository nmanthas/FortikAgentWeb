# Contributes the shadow-agent denials (POL-680..689) to the shared deny-gate
# set; fortik.decide checks them after the control and access gates, lowest
# rule id first.
package fortik.gates

import data.fortik.shadow

deny contains d if {
	some d in shadow.denials
}
