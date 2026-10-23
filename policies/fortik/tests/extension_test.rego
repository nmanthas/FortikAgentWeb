package fortik.tests

import data.fortik.decide

copy_out := pg("COPY_TO_STDOUT", "EXPORT", "prod", {}) # POL-105 yellow hold

test_grant_releases_held_yellow if {
	inp := object.union(copy_out, {"context": {"grant": {"grant_id": "grt_1"}}})
	r := decide.result with input as inp
	r.class == "yellow"
	r.decision == "allow"
	r.grant_id == "grt_1"
	contains(r.reason, "grant grt_1")
}

test_grant_never_releases_red if {
	inp := object.union(pg("DROP_TABLE", "DELETE", "prod", {}), {"context": {"grant": {"grant_id": "grt_1"}}})
	r := decide.result with input as inp
	r.decision == "hold"
	not r.grant_id
}

test_grant_never_overrides_level_gate if {
	inp := object.union(with_level(copy_out, 2), {"context": {"grant": {"grant_id": "grt_1"}}})
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-013"
}

test_empty_grant_ignored if {
	inp := object.union(copy_out, {"context": {"grant": {"grant_id": ""}}})
	r := decide.result with input as inp
	r.decision == "hold"
}

test_extension_gate_denies_lowest_id_wins if {
	r := decide.result with input as read_internal
		with data.fortik.gates.deny as {{"rule_id": "POL-702", "reason": "b"}, {"rule_id": "POL-601", "reason": "a"}}
	r.decision == "deny"
	r.rule_id == "POL-601"
	r.reason == "a"
}

test_control_gate_before_extension_gate if {
	r := decide.result with input as with_level(write_internal, 2)
		with data.fortik.gates.deny as {{"rule_id": "POL-601", "reason": "a"}}
	r.rule_id == "POL-013"
}

test_grant_not_emitted_when_extension_gate_denies if {
	inp := object.union(copy_out, {"context": {"grant": {"grant_id": "grt_1"}}})
	r := decide.result with input as inp
		with data.fortik.gates.deny as {{"rule_id": "POL-601", "reason": "bypass"}}
	r.decision == "deny"
	r.rule_id == "POL-601"
	not r.grant_id
}
