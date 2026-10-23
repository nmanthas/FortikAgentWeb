package fortik.tests

agent_at(level) := {"agent_id": "agent_1", "registered": true, "level": level}

mk(system, verb, target, summary, level) := {
	"action": {
		"agent_id": "agent_1",
		"system": system,
		"verb": verb,
		"target": target,
		"payload_summary": summary,
		"est_cost_usd": 0,
	},
	"agent": agent_at(level),
}

pg(stype, verb, env, extra) := mk(
	"postgres", verb,
	object.union({"statement_type": stype, "environment": env, "tables": ["public.orders"]}, extra),
	{}, 0,
)

with_level(inp, level) := object.union(inp, {"agent": agent_at(level)})

with_summary(inp, summary) := object.union(inp, {"action": object.union(inp.action, {"payload_summary": summary})})

rule_ids(result) := {m.rule_id | some m in result.matched}
