# Baselines: POL-660/661 through the full decision (fortik.decide).
package fortik.baseline_test

import data.fortik.decide

agent := {"agent_id": "agent_1", "registered": true, "level": 0}

act(system, verb, target, summary) := {
	"agent_id": "agent_1",
	"system": system,
	"verb": verb,
	"target": target,
	"payload_summary": summary,
	"est_cost_usd": 0,
}

ctx(above) := {
	"current": 120,
	"mean": 10.5,
	"stddev": 2.25,
	"median": 10,
	"history_days": 14,
	"threshold": 17.25,
	"above_normal": above,
	"method": "sigma",
	"min_count": 20,
}

with_ctx(a, c) := {"action": a, "agent": agent, "context": {"baseline": c}}

green_read := act("postgres", "READ", {"statement_type": "SELECT", "environment": "prod", "tables": ["public.orders"]}, {})

# memory REMEMBER: yellow with a reduced form (POL-903 staging).
staged_write := act("memory", "REMEMBER", {"store": "s", "namespace": "n"}, {})

# memory REMEMBER with sensitive data: yellow hold (POL-904).
sensitive_write := act("memory", "REMEMBER", {"store": "s", "namespace": "n"}, {"data_labels": ["customer_pii"]})

drop := act("postgres", "DELETE", {"statement_type": "DROP_TABLE", "environment": "prod", "tables": ["public.orders"]}, {})

ids(r) := {m.rule_id | some m in r.matched}

test_green_within_normal_stays_green if {
	r := decide.result with input as with_ctx(green_read, ctx(false))
	r.class == "green"
	r.decision == "allow"
	not "POL-660" in ids(r)
}

test_green_without_baseline_context_stays_green if {
	r := decide.result with input as {"action": green_read, "agent": agent}
	r.class == "green"
	r.decision == "allow"
}

test_above_normal_green_becomes_yellow_hold if {
	r := decide.result with input as with_ctx(green_read, ctx(true))
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-660"
	contains(r.reason, "unusual volume: 120 READ calls")
	contains(r.reason, "threshold 17.25")
	not r.approvals_required # one approver
	not r.ladder_change
}

# Phase 5 review L3: an above-normal burst of yellow actions that would run in
# their reduced form is held instead (POL-660 reported: it is why it waits).
test_above_normal_yellow_reduced_is_held if {
	plain := decide.result with input as {"action": staged_write, "agent": agent}
	r := decide.result with input as with_ctx(staged_write, ctx(true))
	plain.decision == "allow_reduced"
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-660"
	not r.reduced_form
	not r.approvals_required
	plain.rule_id in {m.rule_id | some m in r.matched}
}

test_within_normal_yellow_reduced_keeps_decision if {
	plain := decide.result with input as {"action": staged_write, "agent": agent}
	r := decide.result with input as with_ctx(staged_write, ctx(false))
	r.decision == "allow_reduced"
	r.rule_id == plain.rule_id
	r.reduced_form == plain.reduced_form
}

test_above_normal_yellow_hold_keeps_rule if {
	plain := decide.result with input as {"action": sensitive_write, "agent": agent}
	r := decide.result with input as with_ctx(sensitive_write, ctx(true))
	plain.decision == "hold"
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == plain.rule_id
	r.reason == plain.reason
}

test_above_normal_red_unchanged if {
	plain := decide.result with input as {"action": drop, "agent": agent}
	r := decide.result with input as with_ctx(drop, ctx(true))
	plain.class == "red"
	r.class == "red"
	r.decision == plain.decision
	r.rule_id == plain.rule_id
	r.reason == plain.reason
	r.ladder_change == plain.ladder_change
}

test_grant_releases_baseline_hold if {
	inp := object.union(with_ctx(green_read, ctx(true)), {"context": {"baseline": ctx(true), "grant": {"grant_id": "grt_1"}}})
	r := decide.result with input as inp
	r.decision == "allow"
	r.grant_id == "grt_1"
}

test_gate_still_refuses_above_normal if {
	inp := object.union(with_ctx(green_read, ctx(true)), {"agent": object.union(agent, {"level": 5})})
	r := decide.result with input as inp
	r.decision == "deny"
}

test_malformed_context_fails_closed if {
	every bad in [
		"yes",
		null,
		{"above_normal": "true", "current": 1, "threshold": 1},
		{"above_normal": true},
		{"above_normal": false, "current": "1", "threshold": 1},
	] {
		r := decide.result with input as with_ctx(green_read, bad)
		r.decision == "hold"
		r.rule_id == "POL-661"
	}
}

test_malformed_context_holds_reduced_yellow if {
	r := decide.result with input as with_ctx(staged_write, "garbage")
	r.decision == "hold"
	"POL-661" in ids(r)
}
