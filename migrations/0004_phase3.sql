-- Phase 3: delegation chains, instances/population, alerts, timed
-- suspensions (access_overrides), approval grants. See docs/PHASE3_DESIGN.md.

ALTER TABLE agents ADD COLUMN require_instances boolean NOT NULL DEFAULT false;
ALTER TABLE agents ADD COLUMN delegation_strict boolean NOT NULL DEFAULT true;

-- New access-profile systems: a2a (who may be delegated to), http (external
-- egress), mcp (servers/tools).
ALTER TABLE access_profiles DROP CONSTRAINT access_profiles_system_check;
ALTER TABLE access_profiles ADD CONSTRAINT access_profiles_system_check
    CHECK (system IN ('gmail', 'drive', 'github', 'aws', 'postgres', 'a2a', 'http', 'mcp'));

CREATE TABLE delegations (
    delegation_id text PRIMARY KEY,
    parent_id     text REFERENCES delegations (delegation_id),
    root_agent    text NOT NULL,
    from_agent    text NOT NULL,
    to_agent      text NOT NULL,
    chain         text[] NOT NULL,          -- root ... to_agent
    depth         integer NOT NULL CHECK (depth >= 1),
    task_id       text,
    channel       text NOT NULL CHECK (channel IN ('a2a', 'mcp', 'spawn', 'hook_task')),
    action_id     text REFERENCES actions (action_id),
    status        text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'closed', 'expired', 'refused')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    expires_at    timestamptz NOT NULL,
    closed_at     timestamptz,
    close_reason  text
);
CREATE INDEX delegations_inbound_open ON delegations (to_agent, expires_at) WHERE status = 'open';
CREATE INDEX delegations_root ON delegations (root_agent, created_at DESC);

CREATE TABLE agent_types (
    type                   text PRIMARY KEY,
    expected_max_instances integer NOT NULL DEFAULT 0 CHECK (expected_max_instances >= 0),
    max_agents             integer NOT NULL DEFAULT 0 CHECK (max_agents >= 0),
    spawn_rate_per_min     integer NOT NULL DEFAULT 0 CHECK (spawn_rate_per_min >= 0),
    action_rate_per_min    integer NOT NULL DEFAULT 0 CHECK (action_rate_per_min >= 0),
    updated_by             text NOT NULL DEFAULT '',
    updated_at             timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE instances (
    instance_id        text PRIMARY KEY CHECK (instance_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    agent_id           text NOT NULL REFERENCES agents (agent_id),
    host               text NOT NULL DEFAULT '',
    parent_instance_id text,
    started_at         timestamptz NOT NULL DEFAULT now(),
    last_heartbeat     timestamptz NOT NULL DEFAULT now(),
    status             text NOT NULL DEFAULT 'live' CHECK (status IN ('live', 'paused', 'stopped', 'refused')),
    reason             text,
    new_host           boolean NOT NULL DEFAULT false
);
CREATE INDEX instances_agent_live ON instances (agent_id, last_heartbeat) WHERE status = 'live';

-- Hourly spawn counts per agent type (14-day rolling baseline, plan §baselines).
CREATE TABLE spawn_stats (
    hour       timestamptz NOT NULL,
    agent_type text NOT NULL,
    count      integer NOT NULL DEFAULT 0,
    PRIMARY KEY (hour, agent_type)
);

CREATE TABLE alerts (
    alert_id   text PRIMARY KEY,
    kind       text NOT NULL,
    severity   text NOT NULL CHECK (severity IN ('info', 'warning', 'high', 'critical')),
    agent_id   text,
    agent_type text,
    action_id  text,
    summary    text NOT NULL,
    details    jsonb NOT NULL DEFAULT '{}',
    dedup_key  text,
    count      integer NOT NULL DEFAULT 1,
    status     text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'resolved')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    acked_by   text
);
CREATE UNIQUE INDEX alerts_open_dedup ON alerts (dedup_key) WHERE status = 'open' AND dedup_key IS NOT NULL;
CREATE INDEX alerts_status_created ON alerts (status, created_at DESC);

CREATE TABLE access_overrides (
    override_id             text PRIMARY KEY,
    scope                   text NOT NULL CHECK (scope IN ('agent', 'team')),
    scope_id                text NOT NULL,
    system                  text NOT NULL,
    mode                    text NOT NULL CHECK (mode IN ('suspended', 'read_only')),
    starts_at               timestamptz NOT NULL DEFAULT now(),
    expires_at              timestamptz,               -- NULL = until released
    restore_profile_version integer NOT NULL DEFAULT 0,
    reason                  text NOT NULL,
    created_by              text NOT NULL,
    status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'restored', 'released', 'blocked', 'superseded')),
    restored_at             timestamptz,
    revoke_result           jsonb,
    blocked_reason          text,
    created_at              timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX access_overrides_active ON access_overrides (scope, scope_id, system) WHERE status IN ('active', 'blocked');
CREATE INDEX access_overrides_due ON access_overrides (expires_at) WHERE status = 'active' AND expires_at IS NOT NULL;

CREATE TABLE approval_grants (
    grant_id       text PRIMARY KEY,
    action_id      text NOT NULL REFERENCES actions (action_id),
    agent_id       text NOT NULL,
    action_hash    text NOT NULL,
    approved_by    text NOT NULL,
    reason         text NOT NULL,
    expires_at     timestamptz NOT NULL,
    used_at        timestamptz,
    used_by_action text,
    created_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX approval_grants_usable ON approval_grants (agent_id, action_hash, expires_at) WHERE used_at IS NULL;

-- Two-person rule groundwork: approvals recorded per held action.
CREATE TABLE held_approvals (
    action_id   text NOT NULL REFERENCES held_actions (action_id),
    approver    text NOT NULL,
    decision    text NOT NULL CHECK (decision IN ('approve', 'deny')),
    reason      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (action_id, approver)
);
