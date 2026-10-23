-- Phase 4: containment (suspend/resume, isolate, kill, fleet stop), memory
-- protection, queue control. See docs/PHASE4_DESIGN.md.

-- Suspension is a reversible state beside the ladder level: every action is
-- refused, live credentials revoked, queued jobs paused, copies told to pause;
-- memory and state are kept so Resume continues where the agent stopped.
ALTER TABLE agents ADD COLUMN suspended_at     timestamptz;
ALTER TABLE agents ADD COLUMN suspended_by     text;
ALTER TABLE agents ADD COLUMN suspended_reason text;

ALTER TABLE instances DROP CONSTRAINT instances_status_check;
ALTER TABLE instances ADD CONSTRAINT instances_status_check
    CHECK (status IN ('live', 'paused', 'stopped', 'refused', 'suspended'));

-- New integration kinds: queue systems and the memory (vector) store.
ALTER TABLE integrations DROP CONSTRAINT integrations_key_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_key_check
    CHECK (key ~ '^(google_workspace|github|aws|postgres:[a-z][a-z0-9_]{0,62}|temporal|celery|queue_webhook|memory:[a-z][a-z0-9_]{0,62})$');
ALTER TABLE integrations DROP CONSTRAINT integrations_system_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_system_check
    CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'temporal', 'celery', 'queue_webhook', 'memory'));

ALTER TABLE access_profiles DROP CONSTRAINT access_profiles_system_check;
ALTER TABLE access_profiles ADD CONSTRAINT access_profiles_system_check
    CHECK (system IN ('gmail', 'drive', 'github', 'aws', 'postgres', 'a2a', 'http', 'mcp', 'memory'));

-- Per-agent memory access state (remove / restore memory access).
CREATE TABLE memory_access (
    agent_id   text PRIMARY KEY REFERENCES agents (agent_id),
    mode       text NOT NULL CHECK (mode IN ('full', 'staging_only', 'none')),
    reason     text NOT NULL,
    changed_by text NOT NULL,
    changed_at timestamptz NOT NULL DEFAULT now()
);

-- Memory snapshots (pointers: the data stays in the customer's store).
CREATE TABLE memory_snapshots (
    snapshot_id text PRIMARY KEY,
    store_key   text NOT NULL,          -- memory:<name> integration
    namespace   text NOT NULL,
    item_count  integer NOT NULL DEFAULT 0,
    clean       boolean NOT NULL DEFAULT true,  -- false once someone flags it
    location    text NOT NULL,          -- pointer inside the customer's store
    created_by  text NOT NULL,
    reason      text NOT NULL DEFAULT '',
    created_at  timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    purged_at   timestamptz
);
CREATE INDEX memory_snapshots_ns ON memory_snapshots (store_key, namespace, created_at DESC);

-- Containment operations: one row per suspend/resume/isolate/kill/estop with
-- per-step results, for idempotency and the console.
CREATE TABLE containment_ops (
    op_id       text PRIMARY KEY,
    op          text NOT NULL CHECK (op IN ('suspend', 'resume', 'isolate', 'kill', 'estop', 'estop_release', 'memory_remove', 'memory_restore', 'cancel_queue', 'quarantine')),
    target_type text NOT NULL CHECK (target_type IN ('instance', 'agent', 'team', 'fleet')),
    target_id   text NOT NULL,
    actor       text NOT NULL,
    reason      text NOT NULL,
    status      text NOT NULL DEFAULT 'running' CHECK (status IN ('running', 'done', 'partial', 'failed')),
    steps       jsonb NOT NULL DEFAULT '[]',
    created_at  timestamptz NOT NULL DEFAULT now(),
    finished_at timestamptz
);
CREATE INDEX containment_ops_target ON containment_ops (target_type, target_id, created_at DESC);
