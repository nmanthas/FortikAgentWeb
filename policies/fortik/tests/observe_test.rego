package fortik.tests

import data.fortik.decide

observing(inp) := object.union(inp, {"enforcement": "observe"})

drop_prod := pg("DROP_TABLE", "DELETE", "prod", {"safe_form": {"kind": "pg_rename"}})

# A red hold with a step-down becomes allow; the would-be decision is kept.
test_observe_red_hold_is_recorded_not_enforced if {
	enforced := decide.result with input as drop_prod
	enforced.decision == "hold"
	enforced.ladder_change
	r := decide.result with input as observing(drop_prod)
	r.decision == "allow"
	r.class == "red"
	r.rule_id == enforced.rule_id
	r.observed.decision == "hold"
	r.observed.ladder_change.to == enforced.ladder_change.to
	not r.ladder_change
	startswith(r.reason, "observe mode: would hold: ")
}

# A yellow reduced form is not applied.
test_observe_reduced_form_not_applied if {
	inp := pg("DELETE", "DELETE", "staging", {"has_where": true, "where_narrow": false, "undo_preparable": true})
	enforced := decide.result with input as inp
	enforced.decision == "allow_reduced"
	r := decide.result with input as observing(inp)
	r.decision == "allow"
	not r.reduced_form
	r.observed.decision == "allow_reduced"
	r.observed.reduced_form == enforced.reduced_form
}

# An access-profile denial (policy configuration) is observed.
test_observe_access_denial_observed if {
	inp := object.union(mk("github", "WRITE", {"repo": "acme/api"}, {}, 0), {"access": {"system": "github", "version": 1, "profile": {"repos": ["acme/other"], "permissions": {"contents": "write"}}}})
	enforced := decide.result with input as inp
	enforced.decision == "deny"
	r := decide.result with input as observing(inp)
	r.decision == "allow"
	r.observed.decision == "deny"
}

# Never relaxed: a level set by people (READ_ONLY write refused).
test_observe_keeps_control_level if {
	inp := with_level(pg("INSERT", "WRITE", "prod", {}), 2)
	r := decide.result with input as observing(inp)
	r.decision == "deny"
	r.rule_id == "POL-013"
	not r.observed
}

# Never relaxed: killed and unregistered agents.
test_observe_keeps_killed_and_unregistered if {
	k := decide.result with input as observing(with_level(pg("SELECT", "READ", "prod", {}), 5))
	k.decision == "deny"
	k.rule_id == "POL-010"
	u := decide.result with input as observing(object.union(pg("SELECT", "READ", "prod", {}), {"agent": {"agent_id": "agent_1", "registered": false, "level": 3}}))
	u.decision == "deny"
	u.rule_id == "POL-015"
}

# Never relaxed: unknown actions fail closed.
test_observe_keeps_unknown_action_refused if {
	r := decide.result with input as observing(mk("postgres", "TELEPORT", {}, {}, 0))
	r.decision == "deny"
	r.rule_id == "POL-002"
}

# Never relaxed: unclassified SQL.
test_observe_keeps_unclassified_sql_refused if {
	r := decide.result with input as observing(pg("UNKNOWN", "WRITE", "prod", {}))
	r.decision != "allow"
	r.rule_id == "POL-110"
}

# A green allow is unchanged and carries no observed block.
test_observe_green_unchanged if {
	inp := pg("SELECT", "READ", "prod", {})
	r := decide.result with input as observing(inp)
	r == decide.result with input as inp
	not r.observed
}

# Enforce mode (or no field) is unchanged.
test_enforce_mode_unchanged if {
	r1 := decide.result with input as object.union(drop_prod, {"enforcement": "enforce"})
	r2 := decide.result with input as drop_prod
	r1 == r2
}
