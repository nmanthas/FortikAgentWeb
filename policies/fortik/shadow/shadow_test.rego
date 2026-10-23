package fortik.shadow_test

import data.fortik.decide
import data.fortik.shadow

discovered_agent(level) := {"agent_id": "shadow_postgres_0123456789", "registered": true, "level": level, "discovered": true}

owned_agent(level) := object.union(discovered_agent(level), {"sponsor": "alice@example.com"})

normal_agent(level) := {"agent_id": "coder_1", "registered": true, "level": level, "discovered": false, "sponsor": "bob@example.com"}

act(system, verb, target) := {
	"agent_id": "shadow_postgres_0123456789",
	"system": system,
	"verb": verb,
	"target": target,
	"payload_summary": {},
	"est_cost_usd": 0,
}

inp(agent, system, verb, target) := {"action": act(system, verb, target), "agent": agent}

with_ctx(i, c) := object.union(i, {"context": {"shadow": c}})

ids(i) := {d.rule_id | some d in shadow.denials with input as i}

# ---- POL-680 external egress ----

test_unowned_external_read_denied if {
	ids(inp(discovered_agent(0), "http", "READ", {"external": true, "host": "pastebin.com"})) == {"POL-680"}
}

test_unowned_external_domains_denied if {
	"POL-680" in ids(inp(discovered_agent(1), "gmail", "SEND", {"external_domains": 2}))
}

test_unowned_internal_read_allowed if {
	ids(inp(discovered_agent(0), "postgres", "READ", {"statement_type": "SELECT"})) == set()
}

test_owned_external_not_denied_by_shadow if {
	ids(inp(owned_agent(0), "http", "READ", {"external": true})) == set()
}

test_blank_sponsor_is_unowned if {
	a := object.union(discovered_agent(0), {"sponsor": "   "})
	ids(inp(a, "http", "READ", {"external": true})) == {"POL-680"}
}

test_not_discovered_never_denied if {
	ids(inp(normal_agent(0), "http", "READ", {"external": true})) == set()
	ids(inp(normal_agent(0), "aws", "GRANT", {})) == set()
}

# ---- POL-681 GRANT ----

test_unowned_grant_denied if {
	ids(inp(discovered_agent(0), "aws", "GRANT", {"action": "iam:AttachUserPolicy"})) == {"POL-681"}
}

test_owned_grant_not_denied if {
	ids(inp(owned_agent(0), "aws", "GRANT", {})) == set()
}

# ---- POL-682 DELEGATE ----

test_unowned_delegate_denied if {
	ids(inp(discovered_agent(0), "agents", "DELEGATE", {"operation": "spawn"})) == {"POL-682"}
}

# ---- POL-683 SEND / EXPORT / SPEND ----

test_unowned_send_export_spend_denied if {
	ids(inp(discovered_agent(0), "gmail", "SEND", {})) == {"POL-683"}
	ids(inp(discovered_agent(0), "drive", "EXPORT", {})) == {"POL-683"}
	ids(inp(discovered_agent(0), "aws", "SPEND", {})) == {"POL-683"}
}

test_unowned_write_not_denied_by_683 if {
	not "POL-683" in ids(inp(discovered_agent(0), "postgres", "WRITE", {}))
}

# ---- POL-684 flagged credential ----

test_flagged_only_read if {
	i := inp(owned_agent(0), "postgres", "WRITE", {})
	ids(with_ctx(i, {"discovered": true, "flagged": true})) == {"POL-684"}
}

test_flagged_read_allowed if {
	i := inp(owned_agent(0), "postgres", "READ", {})
	ids(with_ctx(i, {"discovered": true, "flagged": true})) == set()
}

test_not_flagged_no_684 if {
	i := inp(owned_agent(0), "postgres", "WRITE", {})
	ids(with_ctx(i, {"discovered": true, "flagged": false})) == set()
}

test_no_context_no_684 if {
	ids(inp(owned_agent(0), "postgres", "WRITE", {})) == set()
}

# ---- POL-689 malformed context ----

test_malformed_context_fails_closed if {
	i := inp(owned_agent(0), "postgres", "READ", {})
	ids(with_ctx(i, "yes")) == {"POL-689"}
	ids(with_ctx(i, {"flagged": "true"})) == {"POL-689"}
	ids(with_ctx(i, null)) == {"POL-689"}
}

# ---- through fortik.decide ----

test_decide_stepped_up_discovered_agent_cannot_send if {
	r := decide.result with input as inp(discovered_agent(0), "gmail", "SEND", {"to_domains": ["example.com"]})
	r.decision == "deny"
	r.rule_id == "POL-683"
}

test_decide_stepped_up_discovered_agent_cannot_grant if {
	r := decide.result with input as inp(discovered_agent(1), "github", "GRANT", {"repo": "acme/api", "operation": "add_collaborator"})
	r.decision == "deny"
	r.rule_id == "POL-681"
}

test_decide_isolated_discovered_agent_control_gate_first if {
	r := decide.result with input as inp(discovered_agent(3), "http", "READ", {"external": true})
	r.decision == "deny"
	r.rule_id == "POL-012"
}

test_decide_discovered_agent_internal_read_allowed_at_isolated if {
	r := decide.result with input as inp(discovered_agent(3), "postgres", "READ", {"statement_type": "SELECT", "environment": "dev", "tables": ["public.orders"]})
	r.decision != "deny"
}

test_decide_flagged_write_denied if {
	i := with_ctx(inp(owned_agent(0), "postgres", "WRITE", {"statement_type": "UPDATE", "environment": "dev", "tables": ["public.orders"]}), {"discovered": true, "flagged": true})
	r := decide.result with input as i
	r.decision == "deny"
	r.rule_id == "POL-684"
}
