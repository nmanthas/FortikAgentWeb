# Contributes the delegation rules (POL-601..604, package fortik.delegation)
# to the extension deny gates evaluated by fortik.decide.
package fortik.gates

deny contains d if {
	some d in data.fortik.delegation.denials
}
