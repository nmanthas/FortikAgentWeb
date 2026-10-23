# The Max-5 breaker finding (POL-651, package fortik.swarm): a call whose
# action hash matches a tripped swarm breaker is yellow and held for two
# distinct approvers (approvals_required 2). A red finding on the same call
# still makes it red; the hold then still needs two approvers.
package fortik.rules

import data.fortik.swarm

findings contains swarm.breaker_finding if swarm.tripped
