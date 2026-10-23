# Contributes the swarm denials (POL-652, POL-653, POL-659; package
# fortik.swarm) to the extension deny gates evaluated by fortik.decide.
package fortik.gates

deny contains d if {
	some d in data.fortik.swarm.denials
}
