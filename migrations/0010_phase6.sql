-- Phase 6: pilot-ready (docs/PHASE6_DESIGN.md).

-- Observe mode: per-agent override of the deployment's enforcement mode
-- ('default' follows enforcement.mode in the config). Changes are Diary events.
ALTER TABLE agents ADD COLUMN enforcement text NOT NULL DEFAULT 'default'
    CHECK (enforcement IN ('default', 'observe', 'enforce'));
-- An action decided in observe mode whose enforced decision would have differed.
ALTER TABLE actions ADD COLUMN observed boolean NOT NULL DEFAULT false;
CREATE INDEX actions_observed ON actions (ts DESC) WHERE observed;

-- Map telemetry: rollup batches for /v1/map/live, outside the hash-chained
-- Diary (pruned with the edges, map.retention).
CREATE TABLE map_events (
    id          bigserial PRIMARY KEY,
    ts          timestamptz NOT NULL DEFAULT now(),
    event_type  text NOT NULL,
    payload     jsonb NOT NULL
);
CREATE INDEX map_events_ts ON map_events (ts);

-- Startup records the deployment's enforcement mode when it changes (looked
-- up by event type).
CREATE INDEX diary_event_type_seq ON diary (event_type, seq DESC);
