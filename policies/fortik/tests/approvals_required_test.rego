package fortik.tests

import data.fortik.decide

two_approver_hold := {
	"rule_id": "POL-999",
	"class": "yellow",
	"reason": "test: needs two approvers",
	"hold": true,
	"approvals_required": 2,
}

test_hold_carries_highest_approvals_required if {
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": 1}, {"recipients": 1}, 0)
		with data.fortik.rules.findings as {two_approver_hold}
	r.decision == "hold"
	r.approvals_required == 2
}

test_single_approver_hold_omits_field if {
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 200}, 0)
	r.decision == "hold"
	not r.approvals_required
}

test_approvals_required_ignored_when_not_held if {
	f := object.union(two_approver_hold, {"hold": false, "reduced_form": {"delay_send_seconds": 120}})
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": 1}, {"recipients": 1}, 0)
		with data.fortik.rules.findings as {f}
	r.decision == "allow_reduced"
	not r.approvals_required
}
