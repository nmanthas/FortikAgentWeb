# Contributes the memory access denials (POL-901, POL-902) to the shared
# deny-gate set; fortik.decide checks them after the control and access
# gates, lowest rule id first.
package fortik.gates

import data.fortik.memory

deny contains d if {
	some d in memory.denials
}
