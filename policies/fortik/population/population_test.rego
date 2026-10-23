package fortik.population_test

import data.fortik.decide
import data.fortik.population

# A context well within every limit.
ok_ctx := {
	"instance_id": "",
	"require_instances": false,
	"agent_live": 1,
	"copy_cap": 3,
	"agent_type": "coding",
	"type_live": 1,
	"type_expected_max": 5,
	"spawns_last_minute": 1,
	"spawn_rate_limit": 10,
	"spawn_baseline_limit": 0,
	"actions_last_minute": 0,
	"action_rate_limit": 0,
	"spawn_throttled": false,
}

agent := {"agent_id": "coder_1", "registered": true, "level": 0}

spawn_with(ctx) := {
	"action": {
		"agent_id": "coder_1",
		"system": "agents",
		"verb": "DELEGATE",
		"target": {"operation": "spawn", "instance_id": "i-7", "host": "build-1", "new_host": false},
		"payload_summary": {},
		"est_cost_usd": 0,
	},
	"agent": agent,
	"context": {"population": object.union(ok_ctx, ctx)},
}

read_with(ctx) := {
	"action": {
		"agent_id": "coder_1",
		"instance_id": "i-1",
		"system": "memory",
		"verb": "READ",
		"target": {},
		"payload_summary": {},
		"est_cost_usd": 0,
	},
	"agent": agent,
	"context": {"population": object.union(ok_ctx, ctx)},
}

ids(inp) := {d.rule_id | some d in population.denials with input as inp}

# Until "agents" is a known system with its own rules (common.rego /
# data.json are owned elsewhere), decide-level spawn tests mock both.
known := ["gmail", "drive", "github", "aws", "postgres", "memory", "mcp", "a2a", "http", "shell", "agents"]

rule_sys := {"postgres", "gmail", "drive", "github", "aws", "agents"}

decide_spawn(inp) := r if {
	r := decide.result with input as inp
		with data.fortik.config.known_systems as known
		with data.fortik.rules.rule_systems as rule_sys
}

test_spawn_within_limits_no_denial if {
	count(ids(spawn_with({}))) == 0
	count(ids(read_with({}))) == 0
}

test_no_context_no_gate if {
	inp := object.remove(spawn_with({}), ["context"])
	count(ids(inp)) == 0
	count(ids(object.union(inp, {"context": {"population": null}}))) == 0
}

# --- POL-701 -----------------------------------------------------------------

test_pol701_at_cap if {
	ids(spawn_with({"agent_live": 3, "copy_cap": 3})) == {"POL-701"}
	ids(spawn_with({"agent_live": 9, "copy_cap": 3})) == {"POL-701"}
}

test_pol701_below_cap_allowed if {
	not "POL-701" in ids(spawn_with({"agent_live": 2, "copy_cap": 3}))
}

test_pol701_cap_zero_refuses_every_copy if {
	ids(spawn_with({"agent_live": 0, "copy_cap": 0})) == {"POL-701"}
}

test_pol701_reason_names_counts if {
	some d in population.denials with input as spawn_with({"agent_live": 6, "copy_cap": 6})
	d.rule_id == "POL-701"
	contains(d.reason, "6 live or suspended copies (copy_cap 6)")
	contains(d.reason, "no credentials")
}

test_pol701_only_for_spawns if {
	not "POL-701" in ids(read_with({"agent_live": 9, "copy_cap": 3}))
}

# --- POL-702 -----------------------------------------------------------------

test_pol702_type_population if {
	ids(spawn_with({"type_live": 5, "type_expected_max": 5})) == {"POL-702"}
}

test_pol702_below_or_unset_allowed if {
	not "POL-702" in ids(spawn_with({"type_live": 4, "type_expected_max": 5}))
	not "POL-702" in ids(spawn_with({"type_live": 100, "type_expected_max": 0}))
}

test_pol702_only_for_spawns if {
	not "POL-702" in ids(read_with({"type_live": 5, "type_expected_max": 5}))
}

# --- POL-703 -----------------------------------------------------------------

test_pol703_static_limit if {
	ids(spawn_with({"spawns_last_minute": 11, "spawn_rate_limit": 10})) == {"POL-703"}
	not "POL-703" in ids(spawn_with({"spawns_last_minute": 10, "spawn_rate_limit": 10}))
	not "POL-703" in ids(spawn_with({"spawns_last_minute": 500, "spawn_rate_limit": 0}))
}

test_pol703_baseline_limit if {
	ids(spawn_with({"spawns_last_minute": 3, "spawn_rate_limit": 0, "spawn_baseline_limit": 2.5})) == {"POL-703"}
	not "POL-703" in ids(spawn_with({"spawns_last_minute": 2, "spawn_rate_limit": 0, "spawn_baseline_limit": 2.5}))
}

test_pol703_cooldown_throttles_below_limit if {
	ids(spawn_with({"spawns_last_minute": 1, "spawn_throttled": true})) == {"POL-703"}
}

test_pol703_only_for_spawns if {
	not "POL-703" in ids(read_with({"spawns_last_minute": 99, "spawn_rate_limit": 10, "spawn_throttled": true}))
	other := json.patch(spawn_with({"spawns_last_minute": 99}), [{"op": "replace", "path": "/action/target/operation", "value": "list"}])
	not "POL-703" in ids(other)
	wrong_verb := json.patch(spawn_with({"spawns_last_minute": 99}), [{"op": "replace", "path": "/action/verb", "value": "READ"}])
	not "POL-703" in ids(wrong_verb)
	wrong_system := json.patch(spawn_with({"spawns_last_minute": 99}), [{"op": "replace", "path": "/action/system", "value": "a2a"}])
	not "POL-703" in ids(wrong_system)
}

test_pol703_reason_untyped_agent if {
	inp := json.patch(spawn_with({"spawns_last_minute": 11}), [{"op": "remove", "path": "/context/population/agent_type"}])
	some d in population.denials with input as inp
	d.rule_id == "POL-703"
	contains(d.reason, "agent coder_1")
}

# --- POL-704 -----------------------------------------------------------------

test_pol704_any_system if {
	ids(read_with({"actions_last_minute": 5, "action_rate_limit": 5})) == {"POL-704"}
	ids(spawn_with({"actions_last_minute": 5, "action_rate_limit": 5})) == {"POL-704"}
}

test_pol704_below_or_unlimited_allowed if {
	not "POL-704" in ids(read_with({"actions_last_minute": 4, "action_rate_limit": 5}))
	not "POL-704" in ids(read_with({"actions_last_minute": 10000, "action_rate_limit": 0}))
}

# --- POL-705 -----------------------------------------------------------------

test_pol705_requires_live_instance if {
	ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "paused"})) == {"POL-705"}
	ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "refused"})) == {"POL-705"}
	ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "stale"})) == {"POL-705"}
	ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "stopped"})) == {"POL-705"}
	ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "suspended"})) == {"POL-705"}
	ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "unregistered"})) == {"POL-705"}
	ids(read_with({"require_instances": true})) == {"POL-705"}
}

test_pol705_live_instance_allowed if {
	count(ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": "live"}))) == 0
}

test_pol705_not_required if {
	count(ids(read_with({"require_instances": false}))) == 0
	count(ids(read_with({"require_instances": false, "instance_id": "i-1", "instance_status": "live"}))) == 0
}

test_pol705_fortik_stopped_instance_denied_without_require_instances if {
	every st in ["paused", "refused", "stopped", "suspended"] {
		ids(read_with({"require_instances": false, "instance_id": "i-1", "instance_status": st})) == {"POL-705"}
	}

	# Without require_instances an instance id is only a label: unregistered or
	# stale ids are not refused.
	every st in ["stale", "unregistered"] {
		count(ids(read_with({"require_instances": false, "instance_id": "i-1", "instance_status": st}))) == 0
		ids(read_with({"require_instances": true, "instance_id": "i-1", "instance_status": st})) == {"POL-705"}
	}
	ids(read_with({"instance_id": "i-1", "instance_status": "paused"})) == {"POL-705"}
	"POL-705" in ids(read_with({"instance_status": 1}))
	count(ids(spawn_with({"require_instances": false, "instance_id": "i-7", "instance_status": "unregistered"}))) == 0
}

test_pol705_suspended_instance_reason if {
	some d in population.denials with input as read_with({"instance_id": "i-4", "instance_status": "suspended"})
	d.reason == "instance i-4 of agent coder_1 is suspended by Fortik: it may not act"
	count(population.denials) == 1 with input as read_with({"instance_id": "i-4", "instance_status": "suspended"})
}

test_pol705_spawn_registration_exempt if {
	count(ids(spawn_with({"require_instances": true, "instance_id": "i-7", "instance_status": "unregistered"}))) == 0
}

test_pol705_reason_names_instance if {
	some d in population.denials with input as read_with({"require_instances": true, "instance_id": "i-9", "instance_status": "paused"})
	d.reason == "instance i-9 of agent coder_1 is paused by Fortik: it may not act"
}

# --- fail closed on malformed context ------------------------------------------------

test_malformed_fields_fail_closed if {
	"POL-701" in ids(spawn_with({"agent_live": "3"}))
	"POL-702" in ids(spawn_with({"type_expected_max": null}))
	"POL-703" in ids(spawn_with({"spawn_baseline_limit": "high"}))
	"POL-703" in ids(spawn_with({"spawn_throttled": "yes"}))
	"POL-704" in ids(read_with({"action_rate_limit": "5"}))
	"POL-705" in ids(read_with({"require_instances": "true"}))
	"POL-705" in ids(read_with({"require_instances": true, "instance_status": 1}))
}

test_missing_field_fails_closed if {
	inp := json.patch(spawn_with({}), [{"op": "remove", "path": "/context/population/copy_cap"}])
	"POL-701" in ids(inp)
}

test_context_not_object_fails_closed if {
	inp := object.union(read_with({}), {"context": {"population": "lots"}})
	ids(inp) == {"POL-704"}
}

# --- through fortik.decide -----------------------------------------------------------

test_decide_rate_limit_denies if {
	r := decide.result with input as read_with({"actions_last_minute": 60, "action_rate_limit": 60})
	r.decision == "deny"
	r.rule_id == "POL-704"
	not r.ladder_change
}

test_decide_lowest_population_rule_wins if {
	r := decide.result with input as read_with({"actions_last_minute": 9, "action_rate_limit": 1, "require_instances": true})
	r.rule_id == "POL-704"
}

test_decide_spawn_allowed_within_limits if {
	r := decide_spawn(spawn_with({}))
	r.decision == "allow"
	r.class == "green"
}

test_decide_spawn_over_cap_denied_without_step_down if {
	r := decide_spawn(spawn_with({"agent_live": 6, "copy_cap": 6, "type_live": 5, "type_expected_max": 5}))
	r.decision == "deny"
	r.rule_id == "POL-701"
	not r.ladder_change
}

test_decide_control_gate_first if {
	inp := object.union(spawn_with({"agent_live": 6, "copy_cap": 6}), {"agent": {"agent_id": "coder_1", "registered": true, "level": 2}})
	r := decide_spawn(inp)
	r.rule_id == "POL-013"
}

test_decide_unregistered_agent_is_pol015 if {
	inp := object.union(spawn_with({}), {"agent": {"agent_id": "ghost", "registered": false, "level": 3}})
	r := decide_spawn(inp)
	r.rule_id == "POL-015"
}

# --- POL-706: only spawn registrations exist on system "agents" ---------------------

agents_action(verb, op) := object.union(spawn_with({}), {"action": {"verb": verb, "target": {"operation": op}}})

test_pol706_other_agents_actions_refused if {
	every c in [["DELEGATE", "kill"], ["WRITE", "spawn"], ["READ", ""]] {
		r := decide_spawn(agents_action(c[0], c[1]))
		r.decision == "deny"
		r.class == "red"
		r.rule_id == "POL-706"
		not r.ladder_change
	}
}

test_pol706_not_for_spawns_or_other_systems if {
	r := decide_spawn(spawn_with({}))
	not "POL-706" in {m.rule_id | some m in r.matched}
	r2 := decide.result with input as read_with({})
	not "POL-706" in {m.rule_id | some m in r2.matched}
}
