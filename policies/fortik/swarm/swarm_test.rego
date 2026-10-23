package fortik.swarm_test

import data.fortik.decide
import data.fortik.swarm

agent := {"agent_id": "worker_6", "registered": true, "level": 0}

base(system, verb, target) := {
	"action": {
		"agent_id": "worker_6",
		"system": system,
		"verb": verb,
		"target": target,
		"payload_summary": {"recipients": 1},
		"est_cost_usd": 0,
	},
	"agent": agent,
}

send := base("gmail", "SEND", {"to": ["x@evil.example"], "external_domains": 1})

ctx(c) := object.union({"member_of": [], "frozen": false, "delegatee_frozen": false, "breaker": {"tripped": false, "swarm_id": ""}}, c)

with_ctx(inp, c) := object.union(inp, {"context": {"swarm": ctx(c)}})

tripped := {"member_of": ["swm_1"], "breaker": {"tripped": true, "swarm_id": "swm_1"}}

frozen := {"member_of": ["swm_1"], "frozen": true, "frozen_swarm_id": "swm_1"}

# An a2a delegation the delegation rules allow (profile may delegate to anyone).
a2a(to) := object.union(base("a2a", "DELEGATE", {"to_agent": to}), {"access": {"system": "a2a", "version": 1, "profile": {"may_delegate_to": ["*"], "max_depth": 3}}})

ids(inp) := {d.rule_id | some d in swarm.denials with input as inp}

test_no_context_no_rule if {
	r := decide.result with input as send
	r.decision == "allow_reduced"
	r.rule_id == "POL-202"
	count(ids(send)) == 0
}

test_breaker_not_tripped_is_normal if {
	r := decide.result with input as with_ctx(send, {})
	r.decision == "allow_reduced"
	not r.approvals_required
}

test_breaker_holds_for_two_approvers if {
	r := decide.result with input as with_ctx(send, tripped)
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == "POL-651"
	r.approvals_required == 2
	contains(r.reason, "swarm swm_1")
}

test_pending_trip_holds_too if {
	r := decide.result with input as with_ctx(send, {"breaker": {"tripped": true, "swarm_id": "", "pending": true}})
	r.decision == "hold"
	r.rule_id == "POL-651"
	r.approvals_required == 2
	contains(r.reason, "swarm pending")
}

test_breaker_on_green_read_still_holds if {
	inp := with_ctx(base("github", "READ", {"repo": "acme/api", "operation": "get_contents"}), tripped)
	r := decide.result with input as inp
	r.decision == "hold"
	r.class == "yellow"
	r.approvals_required == 2
}

test_breaker_with_red_finding_keeps_two_approvers if {
	inp := with_ctx(object.union(send, {"action": object.union(send.action, {"payload_summary": {"recipients": 1, "data_labels": ["customer_pii"]}})}), tripped)
	r := decide.result with input as inp
	r.class == "red"
	r.decision == "hold"
	r.approvals_required == 2
}

test_grant_releases_breaker_hold if {
	inp := object.union(with_ctx(send, tripped), {"context": {"swarm": ctx(tripped), "grant": {"grant_id": "grt_1", "approvals": 2}}})
	r := decide.result with input as inp
	r.decision == "allow"
	r.grant_id == "grt_1"
}

# Phase 5 review: a one-approver grant (e.g. for a call held before the
# breaker tripped) never releases a call the breaker holds for two.
test_one_approver_grant_does_not_release_breaker_hold if {
	inp := object.union(with_ctx(send, tripped), {"context": {"swarm": ctx(tripped), "grant": {"grant_id": "grt_1", "approvals": 1}}})
	r := decide.result with input as inp
	r.decision == "hold"
	r.rule_id == "POL-651"
	r.approvals_required == 2
	not r.grant_id
}

test_grant_without_approval_count_counts_as_one if {
	inp := object.union(with_ctx(send, tripped), {"context": {"swarm": ctx(tripped), "grant": {"grant_id": "grt_1"}}})
	r := decide.result with input as inp
	r.decision == "hold"
}

test_frozen_refuses_delegate if {
	inp := with_ctx(a2a("worker_7"), frozen)
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-652"
	contains(r.reason, "delegation by member worker_6")
}

test_frozen_refuses_new_copy if {
	inp := with_ctx(base("agents", "DELEGATE", {"operation": "spawn", "instance_id": "i-9", "host": "h", "new_host": false}), frozen)
	"POL-652" in ids(inp)
	some d in swarm.denials with input as inp
	contains(d.reason, "new copy registration")
}

test_delegation_to_frozen_member_refused if {
	inp := with_ctx(a2a("worker_7"), {"delegatee_frozen": true})
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-652"
}

test_frozen_member_may_read if {
	inp := with_ctx(base("github", "READ", {"repo": "acme/api", "operation": "get_contents"}), frozen)
	count(ids(inp)) == 0
}

test_frozen_member_may_not_send if {
	r := decide.result with input as with_ctx(send, frozen)
	r.decision == "deny"
	r.rule_id == "POL-653"
}

test_frozen_member_gets_no_credentials if {
	cred := base("github", "READ", {"repos": ["acme/api"], "permissions": {"contents": "read"}, "operation": "credential", "credential_request": true})
	"POL-653" in ids(with_ctx(cred, frozen))
}

test_not_frozen_delegate_allowed if {
	r := decide.result with input as with_ctx(a2a("worker_7"), {"member_of": ["swm_1"]})
	r.decision == "allow"
}

test_malformed_context_fails_closed if {
	"POL-659" in ids(object.union(send, {"context": {"swarm": "yes"}}))
	"POL-659" in ids(with_ctx(send, {"frozen": "no"}))
	"POL-659" in ids(with_ctx(send, {"breaker": {"tripped": 1}}))
	"POL-659" in ids(with_ctx(send, {"breaker": null}))
	"POL-659" in ids(with_ctx(send, {"member_of": "swm_1"}))
	r := decide.result with input as with_ctx(send, {"frozen": "no"})
	r.decision == "deny"
	r.rule_id == "POL-659"
}
