package fortik.tests

import data.fortik.decide

conn_target := {
	"connector_id": "con_1", "vendor": "chatgpt", "upstream": "google_workspace",
	"upstream_systems": ["gmail", "drive"], "scopes": ["https://www.googleapis.com/auth/gmail.readonly"],
	"write": false, "grant_type": "refresh_token", "grant_id": "cgr_1", "connector_status": "active",
}

conn(target, level) := mk("connector", "READ", target, {}, level)

conn_write(level) := mk("connector", "WRITE", object.union(conn_target, {"write": true}), {}, level)

test_connector_token_green_at_full if {
	r := decide.result with input as conn(conn_target, 0)
	r.class == "green"
	r.decision == "allow"
	w := decide.result with input as conn_write(0)
	w.decision == "allow"
}

# READ_ONLY: a read-only token is still issued, a write-capable one is not;
# KILLED: nothing.
test_connector_token_by_level if {
	ro := decide.result with input as conn_write(2)
	ro.decision == "deny"
	ro.rule_id == "POL-013"
	rr := decide.result with input as conn(conn_target, 2)
	rr.decision == "allow"
	k := decide.result with input as conn(conn_target, 5)
	k.decision == "deny"
	k.rule_id == "POL-010"
}

test_connector_disabled_refused if {
	r := decide.result with input as conn(object.union(conn_target, {"connector_status": "disabled"}), 0)
	r.decision == "deny"
	r.rule_id == "POL-690"
}

test_connector_malformed_fails_closed if {
	r := decide.result with input as conn(object.remove(conn_target, ["upstream_systems"]), 0)
	r.decision == "deny"
	r.rule_id == "POL-691"
	g := decide.result with input as mk("connector", "GRANT", conn_target, {}, 0)
	g.decision != "allow"
	l := decide.result with input as conn(object.union(conn_target, {"write": true}), 0)
	l.decision == "deny"
	l.rule_id == "POL-691"
}

suspended(system) := {"overrides": {"active": [{"override_id": "ovr_1", "system": system, "mode": "suspended", "status": "active", "expires_at": "2099-01-01T00:00:00Z"}]}}

# A timed suspension of an upstream system (Drive) stops the copilot's tokens;
# a suspension of an unrelated system does not.
test_connector_stopped_by_upstream_suspension if {
	r := decide.result with input as object.union(conn(conn_target, 0), {"context": suspended("drive")})
	r.decision == "deny"
	r.rule_id == "POL-030"
	o := decide.result with input as object.union(conn(conn_target, 0), {"context": suspended("github")})
	o.decision == "allow"
}

test_connector_observe_mode_keeps_disabled_refused if {
	r := decide.result with input as object.union(conn(object.union(conn_target, {"connector_status": "disabled"}), 0), {"enforcement": "observe"})
	r.decision == "deny"
	r.rule_id == "POL-690"
}
