package fortik.tests

import data.fortik.decide

read_internal := pg("SELECT", "READ", "prod", {})

write_internal := pg("INSERT", "WRITE", "prod", {"on_conflict_update": false})

test_unregistered_agent_denied if {
	inp := object.union(read_internal, {"agent": {"agent_id": "ghost", "registered": false, "level": 0}})
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-015"
}

test_missing_agent_fails_closed if {
	r := decide.result with input as {"action": read_internal.action}
	r.decision == "deny"
}

test_killed_denies_everything if {
	r := decide.result with input as with_level(read_internal, 5)
	r.decision == "deny"
	r.rule_id == "POL-010"
}

test_quarantined_denies_everything if {
	r := decide.result with input as with_level(read_internal, 4)
	r.decision == "deny"
	r.rule_id == "POL-011"
}

test_isolated_allows_internal_read if {
	r := decide.result with input as with_level(read_internal, 3)
	r.decision == "allow"
}

test_isolated_refuses_write if {
	r := decide.result with input as with_level(write_internal, 3)
	r.decision == "deny"
	r.rule_id == "POL-012"
}

test_isolated_refuses_external_read if {
	inp := with_level(mk("http", "READ", {"external": true, "domain": "pastebin.com"}, {}, 0), 3)
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-012"
}

test_isolated_refuses_send if {
	inp := with_level(mk("gmail", "SEND", {"external_domains": 0}, {"recipients": 1}, 0), 3)
	r := decide.result with input as inp
	r.decision == "deny"
}

test_read_only_allows_read if {
	r := decide.result with input as with_level(read_internal, 2)
	r.decision == "allow"
}

test_read_only_refuses_write if {
	r := decide.result with input as with_level(write_internal, 2)
	r.decision == "deny"
	r.rule_id == "POL-013"
	r.class == "green"
}

test_red_at_read_only_denied_and_still_classified_red if {
	r := decide.result with input as with_level(pg("DROP_TABLE", "DELETE", "prod", {}), 2)
	r.class == "red"
	r.decision == "deny"
	r.rule_id == "POL-013"
	"POL-101" in rule_ids(r)
	r.ladder_change.to == "READ_ONLY"
}

test_supervised_green_runs if {
	r := decide.result with input as with_level(write_internal, 1)
	r.decision == "allow"
}

test_supervised_yellow_waits_for_human if {
	inp := with_level(pg("DELETE", "DELETE", "staging", {"has_where": false, "where_narrow": false, "undo_preparable": true}), 1)
	r := decide.result with input as inp
	r.class == "yellow"
	r.decision == "hold"
	r.rule_id == "POL-102"
	contains(r.reason, "POL-014")
}

test_full_yellow_runs_reduced if {
	inp := pg("DELETE", "DELETE", "staging", {"has_where": false, "where_narrow": false, "undo_preparable": true})
	r := decide.result with input as inp
	r.decision == "allow_reduced"
}

test_most_restrictive_ladder_wins if {
	# GRANT (ISOLATED) combined with a configured QUARANTINED destructive ladder
	inp := object.union(
		mk("postgres", "GRANT", {"statement_type": "DROP_TABLE", "environment": "prod", "tables": ["public.t"]}, {}, 0),
		{"config": {"pg_destructive_ladder": "QUARANTINED"}},
	)
	r := decide.result with input as inp
	r.ladder_change.to == "QUARANTINED"
	r.rule_id == "POL-001"
}

test_matched_lists_every_rule_sorted if {
	r := decide.result with input as mk("gmail", "SEND", {"external_domains": 3}, {"recipients": 40, "data_labels": ["customer_pii"]}, 0)
	[m.rule_id | some m in r.matched] == ["POL-201", "POL-202", "POL-203"]
	r.rule_id == "POL-201"
}

test_suspended_agent_denied_everything if {
	inp := object.union(read_internal, {"agent": {"agent_id": "agent_1", "registered": true, "level": 0, "suspended": true, "suspended_reason": "investigation"}})
	r := decide.result with input as inp
	r.decision == "deny"
	r.rule_id == "POL-016"
	contains(r.reason, "investigation")
}

test_killed_takes_precedence_over_suspended if {
	inp := object.union(read_internal, {"agent": {"agent_id": "agent_1", "registered": true, "level": 5, "suspended": true}})
	r := decide.result with input as inp
	r.rule_id == "POL-010"
}
