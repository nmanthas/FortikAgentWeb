# Milestone 0 (cross-agent authority): the management use cases through the
# full decision (fortik.decide), plus POL-605 (delegated task scope).
#
#   Test 1  authority laundering: A may not email externally; B may; A's task
#           delegated to B cannot send customer data outside.
#   Test 2  multi-hop: A and B have no internet, C does; A -> B -> C; C may not
#           use its own permission for A's task. With depth limits 3 and 4,
#           and with missing or invalid delegation evidence.
#   POL-605 a task scope narrows what the delegatee may do even where every
#           agent's own profile would allow it.
package fortik.delegation_test

import data.fortik.decide

gmail_internal := {"send": "internal_only", "read": true, "max_recipients": 25}

gmail_any := {"send": "any", "read": true, "max_recipients": 25}

# Agent B sends a customer export to an outside address.
external_send := {
	"action": {
		"agent_id": "agent_b", "system": "gmail", "verb": "SEND",
		"target": {"endpoint": "gmail.users.messages.send", "user_id": "me", "to": ["partner@outside.example"], "cc": [], "bcc": [], "external_domains": 1, "attachment_bytes": 2048},
		"payload_summary": {"recipients": 1, "attachments": 1},
		"est_cost_usd": 0,
	},
	"agent": {"agent_id": "agent_b", "registered": true, "level": 0},
	"access": acc("gmail", gmail_any),
}

internal_send := json.patch(external_send, [
	{"op": "replace", "path": "/action/target/to", "value": ["colleague@acme.com"]},
	{"op": "replace", "path": "/action/target/external_domains", "value": 0},
])

ctx(d) := d

scoped(chain, depth, scopes) := object.union(token_ctx(chain, depth), {"task_scopes": scopes, "correlation_id": "act_root"})

# --- Test 1: authority laundering ---------------------------------------------------

test_t1_b_alone_may_send_externally if {
	result(external_send).decision != "deny"
}

test_t1_a_task_via_b_external_send_refused if {
	inp := with_deleg(external_send, token_ctx([hop("agent_a", 0, acc("gmail", gmail_internal))], 1))
	denied(inp, "POL-601")
	r := result(inp)
	contains(r.reason, "originating agent agent_a")
	contains(r.reason, "POL-022")
}

test_t1_a_task_via_b_internal_send_allowed if {
	inp := with_deleg(internal_send, token_ctx([hop("agent_a", 0, acc("gmail", gmail_internal))], 1))
	result(inp).decision != "deny"
}

# The same refusal when B presents no token but has an open inbound hop from
# A (the enricher infers the chain, fail closed).
test_t1_inferred_chain_refused if {
	d := object.union(token_ctx([hop("agent_a", 0, acc("gmail", gmail_internal))], 1), {"source": "inferred"})
	denied(with_deleg(external_send, d), "POL-601")
}

# --- Test 2: multi-hop A -> B -> C ------------------------------------------------

abc := [hop("agent_a", 0, acc("http", http_none)), hop("agent_b", 0, acc("http", http_none))]

test_t2_c_alone_allowed if {
	result(egress).decision == "allow"
}

test_t2_c_for_a_via_b_refused_at_hop_1 if {
	inp := with_deleg(egress, token_ctx(abc, 2))
	denied(inp, "POL-601")
	contains(result(inp).reason, "agent_a (hop 1 of 2)")
}

# Only the middle agent restricted: still refused, naming B.
test_t2_restriction_inherited_from_middle_hop if {
	inp := with_deleg(egress, token_ctx([hop("agent_a", 0, acc("http", http_any)), hop("agent_b", 0, acc("http", http_none))], 2))
	denied(inp, "POL-601")
	contains(result(inp).reason, "agent_b (hop 2 of 2)")
}

# Depth limits 3 and 4: a chain of depth 4 passes a limit of 4 and fails a
# limit of 3 (the delegation is refused for depth alone only by POL-602).
deep_any := [hop("a1", 0, acc("http", http_any)), hop("a2", 0, acc("http", http_any)), hop("a3", 0, acc("http", http_any)), hop("a4", 0, acc("http", http_any))]

test_t2_depth_limit_4_allows_depth_4 if {
	d := object.union(token_ctx(deep_any, 4), {"max_depth": 4})
	result(with_deleg(egress, d)).decision == "allow"
}

test_t2_depth_limit_3_refuses_depth_4 if {
	d := object.union(token_ctx(deep_any, 4), {"max_depth": 3})
	denied(with_deleg(egress, d), "POL-602")
}

# Invalid or missing evidence.
test_t2_invalid_token_refused if {
	denied(with_deleg(egress, {"present": true, "source": "token", "chain": [], "token_error": "invalid delegation token"}), "POL-604")
}

test_t2_expired_token_refused if {
	denied(with_deleg(egress, {"present": true, "source": "token", "chain": [], "token_error": "expired delegation token"}), "POL-604")
}

test_t2_unknown_origin_agent_refused if {
	unknown := {"agent_id": "ghost_agent", "registered": false, "level": 3, "level_name": "ISOLATED", "access": no_acc("http")}
	denied(with_deleg(egress, token_ctx([unknown], 1)), "POL-601")
}

test_t2_malformed_chain_fails_closed if {
	denied(with_deleg(egress, {"present": true, "source": "token", "depth": 1, "chain": [{"agent_id": "a"}]}), "POL-601")
	denied(with_deleg(egress, {"present": true, "source": "telepathy", "depth": 1, "chain": []}), "POL-601")
}

# --- POL-605: the delegated task's scope ------------------------------------------

open_chain := [hop("agent_a", 0, acc("http", http_any))]

test_scope_allows_matching_action if {
	inp := with_deleg(egress, scoped(open_chain, 1, [{"systems": ["http"], "verbs": ["READ"], "domains": ["example.com"]}]))
	result(inp).decision == "allow"
}

test_scope_subdomain_allowed if {
	inp := json.patch(egress, [{"op": "replace", "path": "/action/target/domain", "value": "docs.example.com"}])
	result(with_deleg(inp, scoped(open_chain, 1, [{"domains": ["example.com"]}]))).decision == "allow"
}

test_scope_wrong_system_refused if {
	inp := with_deleg(egress, scoped(open_chain, 1, [{"systems": ["postgres"]}]))
	denied(inp, "POL-605")
	contains(result(inp).reason, "correlation act_root")
}

test_scope_wrong_verb_refused if {
	inp := json.patch(egress, [{"op": "replace", "path": "/action/verb", "value": "WRITE"}])
	denied(with_deleg(inp, scoped(open_chain, 1, [{"verbs": ["READ"]}])), "POL-605")
}

test_scope_wrong_destination_refused if {
	denied(with_deleg(egress, scoped(open_chain, 1, [{"domains": ["acme-partner.example"]}])), "POL-605")

	# "badexample.com" is not a subdomain of "example.com".
	inp := json.patch(egress, [{"op": "replace", "path": "/action/target/domain", "value": "badexample.com"}])
	denied(with_deleg(inp, scoped(open_chain, 1, [{"domains": ["example.com"]}])), "POL-605")
}

test_scope_recipient_domains_checked if {
	ok := with_deleg(external_send, scoped([hop("agent_a", 0, acc("gmail", gmail_any))], 1, [{"domains": ["outside.example"]}]))
	result(ok).decision != "deny"
	bad := with_deleg(external_send, scoped([hop("agent_a", 0, acc("gmail", gmail_any))], 1, [{"domains": ["acme.com"]}]))
	denied(bad, "POL-605")
}

test_scope_unidentified_destination_fails_closed if {
	inp := json.patch(egress, [{"op": "remove", "path": "/action/target/domain"}])
	denied(with_deleg(inp, scoped(open_chain, 1, [{"domains": ["example.com"]}])), "POL-605")
}

# Every scope must allow the action (two delegated tasks: the stricter wins).
test_every_scope_must_allow if {
	inp := with_deleg(egress, scoped(open_chain, 1, [{"systems": ["http"]}, {"systems": ["postgres"]}]))
	denied(inp, "POL-605")
}

# The deny-all marker of an empty intersection matches nothing.
test_empty_intersection_denies if {
	denied(with_deleg(egress, scoped(open_chain, 1, [{"systems": ["-"]}])), "POL-605")
}

test_malformed_scope_fails_closed if {
	denied(with_deleg(egress, scoped(open_chain, 1, [{"systems": "http"}])), "POL-601")
	denied(with_deleg(egress, scoped(open_chain, 1, ["http"])), "POL-601")
}

# A DELEGATE onwards is not refused for the system/verb (the scope travels).
test_delegate_exempt_from_system_scope if {
	d := {
		"action": {"agent_id": "agent_b", "system": "a2a", "verb": "DELEGATE", "target": {"to_agent": "agent_c", "channel": "a2a", "route": "x"}, "payload_summary": {}, "est_cost_usd": 0},
		"agent": {"agent_id": "agent_b", "registered": true, "level": 0},
		"access": acc("a2a", {"may_delegate_to": ["agent_c"], "max_depth": 3}),
	}
	ch := [hop("agent_a", 0, acc("a2a", {"may_delegate_to": ["agent_b"], "max_depth": 3}))]
	result(with_deleg(d, scoped(ch, 1, [{"systems": ["http"], "verbs": ["READ"]}]))).decision == "allow"
}

# Observe mode never relaxes POL-605.
test_scope_enforced_in_observe_mode if {
	inp := object.union(with_deleg(egress, scoped(open_chain, 1, [{"systems": ["postgres"]}])), {"enforcement": "observe"})
	denied(inp, "POL-605")
}
