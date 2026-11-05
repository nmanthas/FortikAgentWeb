# Salesforce Agent API (Agentforce agents): POL-1213 (which agents, access
# profile agentforce_agents) and POL-1214 (messages held unless the profile
# sets agentforce_messages "allow").
package fortik.tests

agent_id := "0Xxg70000020uCOCAY"

af_profile(extra) := object.union({"mode": "read_write", "objects": ["account"], "agentforce_agents": [agent_id]}, extra)

af_start(profile) := saas_rest("salesforce", "READ", {"api": "agent_api", "operation": "agent_session_start", "object": "agentforce_agent", "agentforce_agent": agent_id}, profile)

af_msg(profile) := saas_rest(
	"salesforce", "EXECUTE", {
		"api": "agent_api", "operation": "agent_message", "object": "agentforce_agent", "agentforce_agent": agent_id,
		"session_id": "6e1f-session", "message_sha256": "abc", "message_preview": "hello",
	},
	profile,
)

test_agentforce_session_start_allowed_for_listed_agent if {
	r := sres(af_start(af_profile({})))
	r.decision == "allow"
	r.class == "green"
}

test_agentforce_objects_list_does_not_apply if {
	# objects ["account"] restricts records, not Agentforce agents
	sres(af_start(af_profile({}))).rule_id != "POL-1211"
}

test_agentforce_agent_not_listed_denied if {
	r := sres(af_start(af_profile({"agentforce_agents": ["0Xxg7000000OTHER1A"]})))
	r.decision == "deny"
	r.rule_id == "POL-1213"
}

test_agentforce_no_agents_key_denied if {
	r := sres(af_start({"mode": "read_write", "objects": ["*"]}))
	r.decision == "deny"
	r.rule_id == "POL-1213"
}

test_agentforce_wildcard_agents if {
	sres(af_start(af_profile({"agentforce_agents": ["*"]}))).decision == "allow"
}

test_agentforce_message_held_by_default if {
	r := sres(af_msg(af_profile({})))
	r.decision == "hold"
	r.class == "yellow"
	r.rule_id == "POL-1214"
}

test_agentforce_message_held_when_approval_set if {
	r := sres(af_msg(af_profile({"agentforce_messages": "approval"})))
	r.decision == "hold"
	r.rule_id == "POL-1214"
}

test_agentforce_message_allowed_when_profile_allows if {
	r := sres(af_msg(af_profile({"agentforce_messages": "allow"})))
	r.decision == "allow"
}

test_agentforce_message_approved_released_once if {
	inp := af_msg(af_profile({}))
	r := sres(object.union(inp, {"context": {"grant": {"grant_id": "g1", "approvals": 1}}}))
	r.decision == "allow"
	r.grant_id == "g1"
}

test_agentforce_message_read_only_profile_denied if {
	r := sres(af_msg(af_profile({"mode": "read_only", "agentforce_messages": "allow"})))
	r.decision == "deny"
	r.rule_id == "POL-021"
}

test_agentforce_message_wrong_verb_denied if {
	inp := saas_rest("salesforce", "READ", {"api": "agent_api", "operation": "agent_message", "object": "agentforce_agent", "agentforce_agent": agent_id}, af_profile({"agentforce_messages": "allow"}))
	r := sres(inp)
	r.decision == "deny"
	r.rule_id == "POL-1214"
}

test_agentforce_other_execute_still_pol1203 if {
	e := sres(saas_rest("salesforce", "EXECUTE", {"operation": "action", "object": "actions/standard/emailSimple"}, saas_rw))
	e.rule_id == "POL-1203"
}

test_agentforce_no_profile_denied if {
	inp := object.union(af_start(af_profile({})), {"access": {"system": "salesforce", "version": 0, "profile": null}})
	r := sres(inp)
	r.decision == "deny"
	r.rule_id == "POL-020"
}
