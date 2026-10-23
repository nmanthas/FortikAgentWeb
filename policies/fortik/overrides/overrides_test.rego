package fortik.overrides_test

import data.fortik.decide

gh_push := {
	"action": {
		"agent_id": "code_agent_12",
		"system": "github",
		"verb": "WRITE",
		"target": {"repo": "acme/api", "branch": "feat/x", "operation": "push"},
		"payload_summary": {},
		"est_cost_usd": 0,
	},
	"agent": {"agent_id": "code_agent_12", "registered": true, "level": 0},
}

gh_read := object.union(gh_push, {"action": object.union(gh_push.action, {"verb": "READ", "target": {"repo": "acme/api", "operation": "get_contents"}})})

ov(mode, status, expires) := o if {
	base := {
		"override_id": "ovr_01",
		"scope": "agent",
		"scope_id": "code_agent_12",
		"system": "github",
		"mode": mode,
		"status": status,
		"starts_at": "2026-10-11T11:25:00Z",
		"reason": "incident 42",
		"created_by": "user:sec@acme.com",
		"restore_profile_version": 0,
	}
	o := object.union(base, expires)
}

timed := {"expires_at": "2026-10-11T11:55:00Z"}

with_ovs(inp, list) := object.union(inp, {"context": {"overrides": {"active": list}}})

test_suspended_denies_with_restore_time if {
	r := decide.result with input as with_ovs(gh_push, [ov("suspended", "active", timed)])
	r.decision == "deny"
	r.rule_id == "POL-030"
	r.reason == "github suspended until 11:55 UTC on 2026-10-11 by user:sec@acme.com: incident 42 [override ovr_01]"
}

test_suspended_denies_reads_too if {
	r := decide.result with input as with_ovs(gh_read, [ov("suspended", "active", timed)])
	r.decision == "deny"
	r.rule_id == "POL-030"
}

test_suspended_until_released if {
	r := decide.result with input as with_ovs(gh_push, [ov("suspended", "active", {})])
	r.rule_id == "POL-030"
	contains(r.reason, "github suspended until released by user:sec@acme.com")
}

test_null_expiry_is_until_released if {
	r := decide.result with input as with_ovs(gh_push, [ov("suspended", "active", {"expires_at": null})])
	contains(r.reason, "until released")
}

test_blocked_override_still_enforced if {
	o := object.union(ov("suspended", "blocked", timed), {"blocked_reason": "red action act_9 (POL-301)"})
	r := decide.result with input as with_ovs(gh_push, [o])
	r.decision == "deny"
	r.rule_id == "POL-030"
	contains(r.reason, "until released (automatic restore was blocked: red action act_9 (POL-301))")
}

test_read_only_denies_writes if {
	r := decide.result with input as with_ovs(gh_push, [ov("read_only", "active", timed)])
	r.decision == "deny"
	r.rule_id == "POL-031"
	r.reason == "github is read-only until 11:55 UTC on 2026-10-11 by user:sec@acme.com: incident 42 [override ovr_01]: WRITE refused"
}

test_read_only_allows_reads if {
	r := decide.result with input as with_ovs(gh_read, [ov("read_only", "active", timed)])
	not r.rule_id in {"POL-030", "POL-031"}
	r.decision == "allow"
}

test_suspension_beats_read_only if {
	ro := object.union(ov("read_only", "active", {}), {"override_id": "ovr_00"})
	r := decide.result with input as with_ovs(gh_push, [ro, ov("suspended", "active", timed)])
	r.rule_id == "POL-030"
}

test_most_restrictive_suspension_named if {
	short := object.union(ov("suspended", "active", timed), {"override_id": "ovr_a"})
	later := object.union(ov("suspended", "active", {"expires_at": "2026-10-11T13:00:00.5Z"}), {"override_id": "ovr_b"})
	r := decide.result with input as with_ovs(gh_push, [short, later])
	contains(r.reason, "until 13:00 UTC")
	contains(r.reason, "ovr_b")
	forever := object.union(ov("suspended", "active", {}), {"override_id": "ovr_c"})
	r2 := decide.result with input as with_ovs(gh_push, [short, later, forever])
	contains(r2.reason, "until released")
	contains(r2.reason, "ovr_c")
}

test_other_system_unaffected if {
	o := object.union(ov("suspended", "active", timed), {"system": "drive"})
	r := decide.result with input as with_ovs(gh_push, [o])
	r.decision == "allow"
}

test_released_and_restored_ignored if {
	every st in ["restored", "released", "superseded"] {
		r := decide.result with input as with_ovs(gh_push, [ov("suspended", st, timed)])
		r.decision == "allow"
	}
}

test_unknown_mode_fails_closed if {
	r := decide.result with input as with_ovs(gh_read, [ov("frozen", "active", timed)])
	r.decision == "deny"
	r.rule_id == "POL-030"
}

test_missing_mode_fails_closed if {
	o := object.remove(ov("suspended", "active", timed), {"mode"})
	r := decide.result with input as with_ovs(gh_read, [o])
	r.rule_id == "POL-030"
}

test_no_context_no_gate if {
	r := decide.result with input as gh_push
	r.decision == "allow"
	r2 := decide.result with input as with_ovs(gh_push, [])
	r2.decision == "allow"
}

test_control_gate_first if {
	inp := object.union(with_ovs(gh_push, [ov("suspended", "active", timed)]), {"agent": {"agent_id": "code_agent_12", "registered": true, "level": 5}})
	r := decide.result with input as inp
	r.rule_id == "POL-010"
}

test_red_action_still_classified_red_while_suspended if {
	inp := object.union(gh_push, {"action": object.union(gh_push.action, {"target": {"repo": "acme/api", "branch": "main", "operation": "force_push"}})})
	r := decide.result with input as with_ovs(inp, [ov("suspended", "active", timed)])
	r.class == "red"
	r.decision == "deny"
	r.rule_id == "POL-030"
}
