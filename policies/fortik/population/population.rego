# Population gates (docs/PHASE3_DESIGN.md §2.4): copy caps, agent-type
# populations, spawn spikes, action rate limits and instance liveness.
#
# Input: input.context.population, set by the population enricher on every
# decision (population.PolicyContext plus spawn_throttled, true while the
# agent type is in its spike cooldown). Spawn rules apply only to spawn
# registrations: system "agents", verb DELEGATE, target.operation "spawn"
# (data.fortik.population.settings).
#
#   POL-701 spawn: the agent's live copies are at or above copy_cap
#           (the new copy gets no credentials); "live" here (agent_live)
#           includes suspended copies, which keep their slot until resumed
#           or stopped
#   POL-702 spawn: the type's live total (suspended copies included) is at
#           or above type_expected_max (> 0)
#   POL-703 spawn: spawns in the last minute exceed spawn_rate_limit (> 0) or
#           spawn_baseline_limit (> 0), or the type is in its spike cooldown
#   POL-704 any system: actions in the last minute are at or above
#           action_rate_limit (> 0)
#   POL-705 the agent requires instances and the action's instance is
#           missing, unregistered or stale; or (whatever require_instances
#           says) the instance is paused, refused, stopped or suspended by
#           Fortik (the spawn registration itself is exempt: it is how an
#           instance becomes live)
#
# Without input.context.population (enricher not wired) no rule applies. A
# present but malformed field refuses under the rule that reads it (fail
# closed). The rules contribute deny gates (fortik.gates.deny, see gates.rego).
package fortik.population

cfg := data.fortik.population.settings

act := input.action

tgt := object.get(act, "target", {})

raw := object.get(object.get(input, "context", {}), "population", null)

pop := raw if is_object(raw)

spawn if {
	act.system == cfg.spawn_system
	act.verb == cfg.spawn_verb
	object.get(tgt, "operation", "") == cfg.spawn_operation
}

# num(k): a numeric field of the context; bad(k): present context, field
# missing or not a number.
num(k) := v if {
	v := pop[k]
	is_number(v)
}

bad(k) if {
	pop
	not num(k)
}

agent := object.get(act, "agent_id", "")

type_name := t if {
	t := pop.agent_type
	is_string(t)
	t != ""
}

# What spawn counts and limits apply to: the agent type, or the agent itself.
scope := sprintf("agent type %s", [type_name]) if type_name

else := sprintf("agent %s", [agent])

throttled if pop.spawn_throttled == true

requires if pop.require_instances == true

inst_status := s if {
	s := pop.instance_status
	is_string(s)
} else := ""

inst_id := s if {
	s := pop.instance_id
	is_string(s)
	s != ""
} else := ""

# --- POL-701: copy cap ---------------------------------------------------------

denials contains {"rule_id": "POL-701", "reason": sprintf("copy cap: agent %s already has %v live or suspended copies (copy_cap %v): new copy refused, no credentials", [agent, num("agent_live"), num("copy_cap")])} if {
	spawn
	num("agent_live") >= num("copy_cap")
}

denials contains {"rule_id": "POL-701", "reason": "malformed population context (agent_live, copy_cap): fail closed"} if {
	spawn
	some k in ["agent_live", "copy_cap"]
	bad(k)
}

# --- POL-702: agent-type population ----------------------------------------------

denials contains {"rule_id": "POL-702", "reason": sprintf("population: %s already has %v live or suspended instances (expected max %v): new copy refused", [scope, num("type_live"), num("type_expected_max")])} if {
	spawn
	num("type_expected_max") > 0
	num("type_live") >= num("type_expected_max")
}

denials contains {"rule_id": "POL-702", "reason": "malformed population context (type_live, type_expected_max): fail closed"} if {
	spawn
	some k in ["type_live", "type_expected_max"]
	bad(k)
}

# --- POL-703: spawn rate (static limit, baseline, spike cooldown) -------------------

denials contains {"rule_id": "POL-703", "reason": sprintf("spawn spike: %v spawns of %s in the last minute exceed the limit of %v per minute: throttled", [num("spawns_last_minute"), scope, num("spawn_rate_limit")])} if {
	spawn
	num("spawn_rate_limit") > 0
	num("spawns_last_minute") > num("spawn_rate_limit")
}

denials contains {"rule_id": "POL-703", "reason": sprintf("spawn spike: %v spawns of %s in the last minute exceed the baseline of %v per minute: throttled", [num("spawns_last_minute"), scope, num("spawn_baseline_limit")])} if {
	spawn
	num("spawn_baseline_limit") > 0
	num("spawns_last_minute") > num("spawn_baseline_limit")
}

denials contains {"rule_id": "POL-703", "reason": sprintf("spawn spike cooldown: spawns of %s are throttled after a recent spike", [scope])} if {
	spawn
	throttled
}

denials contains {"rule_id": "POL-703", "reason": "malformed population context (spawns_last_minute, spawn_rate_limit, spawn_baseline_limit): fail closed"} if {
	spawn
	some k in ["spawns_last_minute", "spawn_rate_limit", "spawn_baseline_limit"]
	bad(k)
}

denials contains {"rule_id": "POL-703", "reason": "malformed population context (spawn_throttled): fail closed"} if {
	spawn
	v := pop.spawn_throttled
	not is_boolean(v)
}

# --- POL-704: action rate limit (any system) ---------------------------------------

denials contains {"rule_id": "POL-704", "reason": sprintf("rate limit: agent %s made %v actions in the last minute (limit %v per minute)", [agent, num("actions_last_minute"), num("action_rate_limit")])} if {
	num("action_rate_limit") > 0
	num("actions_last_minute") >= num("action_rate_limit")
}

denials contains {"rule_id": "POL-704", "reason": "malformed population context (actions_last_minute, action_rate_limit): fail closed"} if {
	some k in ["actions_last_minute", "action_rate_limit"]
	bad(k)
}

denials contains {"rule_id": "POL-704", "reason": "malformed population context (not an object): fail closed"} if {
	raw != null
	not is_object(raw)
}

# --- POL-705: instance liveness ---------------------------------------------------

denials contains {"rule_id": "POL-705", "reason": sprintf("agent %s requires a registered instance: this action names none (X-Fortik-Instance-Id)", [agent])} if {
	requires
	not spawn
	inst_status == ""
}

# Statuses Fortik itself put a copy in: paused by pause-extra, refused over
# the cap, stopped, or suspended by containment (resumable).
halted_statuses := {"paused", "refused", "stopped", "suspended"}

# A copy Fortik halted is denied whatever require_instances says: those
# decisions must stop the copy acting, not only its heartbeats.
denials contains {"rule_id": "POL-705", "reason": sprintf("instance %s of agent %s is %s by Fortik: it may not act", [inst_id, agent, inst_status])} if {
	not spawn
	inst_status in halted_statuses
}

# Agents that require registration: any named instance that is not live
# (unregistered, stale) is denied too. For other agents an instance id is only
# a label and an unregistered or stale one is not refused.
denials contains {"rule_id": "POL-705", "reason": sprintf("agent %s requires a live instance: instance %s is %s", [agent, inst_id, inst_status])} if {
	requires
	not spawn
	inst_status != ""
	inst_status != "live"
	not inst_status in halted_statuses
}

denials contains {"rule_id": "POL-705", "reason": "malformed population context (require_instances): fail closed"} if {
	v := pop.require_instances
	not is_boolean(v)
}

denials contains {"rule_id": "POL-705", "reason": "malformed population context (instance_status): fail closed"} if {
	v := pop.instance_status
	not is_string(v)
}
