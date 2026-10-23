# Contributes the population denials (POL-701..705) to the shared deny-gate
# set; fortik.decide checks them after the control and access gates, lowest
# rule id first.
package fortik.gates

import data.fortik.population

deny contains d if {
	some d in population.denials
}
