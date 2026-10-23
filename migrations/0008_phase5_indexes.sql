-- Phase 5 lookup indexes (added after 0007 was first applied in dev).

-- Diary lookup by action (the console's action page lists every event that
-- names an action) and by swarm (swarm detail and the sealed bundle).
CREATE INDEX diary_action_id ON diary (((body_json::jsonb -> 'data' ->> 'action_id')));
CREATE INDEX diary_swarm_id ON diary (((body_json::jsonb -> 'data' ->> 'swarm_id')));

-- Shadow enricher: findings of a discovered agent.
CREATE INDEX shadow_findings_agent ON shadow_findings (agent_id) WHERE agent_id IS NOT NULL;

-- Communication map rollup cursors walk actions and delegations by (ts, id).
CREATE INDEX actions_ts_id ON actions (ts, action_id);
CREATE INDEX delegations_created ON delegations (created_at, delegation_id);
