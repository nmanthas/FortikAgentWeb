-- Phase 5: swarms, communication map, shadow-agent discovery, baselines and
-- the full approval queue (docs/PHASE5_DESIGN.md).

-- A swarm: agents and copies acting together (an orchestrator and its
-- workers, or many copies of one agent). Treated as one object so security
-- can stop it in one action; release needs two distinct security approvers.
CREATE TABLE swarms (
    swarm_id       text PRIMARY KEY,                 -- root delegation id, or swm_<ulid> cluster id
    root_agent_id  text,                             -- NULL when there is no common root
    detected_by    text NOT NULL CHECK (detected_by IN ('action_hash', 'spawn_tree', 'copy_surge', 'converging_targets', 'manual')),
    signal         jsonb NOT NULL DEFAULT '{}',      -- what found it (hash, counts, window, target)
    action_hash    text,                             -- the breaker hash for action_hash swarms
    member_count   integer NOT NULL DEFAULT 0,
    state          text NOT NULL DEFAULT 'detected' CHECK (state IN ('detected', 'breaker_tripped', 'suspended', 'isolated', 'killed', 'released')),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now(),
    released_at    timestamptz
);
CREATE INDEX swarms_active ON swarms (created_at DESC) WHERE state <> 'released';
CREATE INDEX swarms_hash ON swarms (action_hash) WHERE action_hash IS NOT NULL;

CREATE TABLE swarm_members (
    swarm_id     text NOT NULL REFERENCES swarms (swarm_id),
    agent_id     text NOT NULL,
    instance_id  text NOT NULL DEFAULT '',           -- '' = the whole agent
    role         text NOT NULL DEFAULT 'member' CHECK (role IN ('root', 'member')),
    added_at     timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (swarm_id, agent_id, instance_id)
);
CREATE INDEX swarm_members_agent ON swarm_members (agent_id);

-- Max-5 breaker: once tripped for an action hash, every matching call is held
-- (two approvers to release) until the breaker is released.
CREATE TABLE swarm_breakers (
    action_hash  text PRIMARY KEY,
    swarm_id     text NOT NULL REFERENCES swarms (swarm_id),
    tripped_at   timestamptz NOT NULL DEFAULT now(),
    state        text NOT NULL DEFAULT 'tripped' CHECK (state IN ('tripped', 'released')),
    released_at  timestamptz
);

-- Two-approver release of a swarm (distinct approvers; the second vote releases).
CREATE TABLE swarm_release_votes (
    swarm_id    text NOT NULL REFERENCES swarms (swarm_id),
    approver    text NOT NULL,
    reason      text NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (swarm_id, approver)
);

-- Actions already carry swarm_id (Phase 1 column); holds carry it too so the
-- approval queue can group a swarm's held calls.
ALTER TABLE held_actions ADD COLUMN swarm_id text;
ALTER TABLE held_actions ADD COLUMN assigned_to text;
CREATE INDEX held_actions_swarm ON held_actions (swarm_id) WHERE swarm_id IS NOT NULL;

-- Communication map: calls rolled up per 5-minute window. Node ids are typed:
-- agent:<id>, instance:<id>, user:<email>, app:<system>, store:<system>:<name>,
-- memory:<store>/<namespace>, mcp:<server>, domain:<host>.
CREATE TABLE edges (
    window_start  timestamptz NOT NULL,
    from_node     text NOT NULL,
    to_node       text NOT NULL,
    verb          text NOT NULL,
    count         bigint NOT NULL DEFAULT 0,
    bytes         bigint NOT NULL DEFAULT 0,
    data_labels   text[] NOT NULL DEFAULT '{}',
    worst_class   text NOT NULL CHECK (worst_class IN ('green', 'yellow', 'red', 'hidden')),
    sample_action_ids text[] NOT NULL DEFAULT '{}',  -- up to 5, for the Diary link per hop
    PRIMARY KEY (window_start, from_node, to_node, verb)
);
CREATE INDEX edges_from ON edges (from_node, window_start DESC);
CREATE INDEX edges_to ON edges (to_node, window_start DESC);
CREATE INDEX edges_window ON edges (window_start DESC);

-- Rollup cursor: the last action/delegation folded into edges (exactly-once).
CREATE TABLE edge_rollup_state (
    source      text PRIMARY KEY,                    -- 'actions' | 'delegations' | 'credentials'
    last_ts     timestamptz NOT NULL DEFAULT 'epoch',
    last_id     text NOT NULL DEFAULT ''
);

-- Shadow-agent discovery: standing credentials and unknown callers found per
-- system. A finding used by software becomes a discovered agent (no owner,
-- starts ISOLATED) and its credential is flagged for revocation.
CREATE TABLE shadow_findings (
    finding_id      text PRIMARY KEY,
    system          text NOT NULL CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'traffic')),
    kind            text NOT NULL,                   -- oauth_grant | pat | app_installation | iam_user_key | db_role | unknown_host | unknown_oauth_client | unknown_token
    credential_ref  text NOT NULL,                   -- an identifier, never the secret (key id, role name, token id, client id)
    holder          text NOT NULL DEFAULT '',        -- user/role the credential belongs to, if known
    used_by_software boolean NOT NULL DEFAULT false,
    evidence        jsonb NOT NULL DEFAULT '{}',     -- why: user agent, host, application_name, last used
    agent_id        text,                            -- the discovered agent, once created
    status          text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'flagged_for_revocation', 'revoked', 'dismissed', 'registered')),
    first_seen      timestamptz NOT NULL DEFAULT now(),
    last_seen       timestamptz NOT NULL DEFAULT now(),
    updated_by      text,
    UNIQUE (system, kind, credential_ref)
);
CREATE INDEX shadow_findings_open ON shadow_findings (last_seen DESC) WHERE status IN ('open', 'flagged_for_revocation');

-- Baselines: durable hourly counts per agent and verb (the hot copy lives in
-- Redis when configured; this table is the fallback and the backfill source).
CREATE TABLE baseline_hourly (
    agent_id  text NOT NULL,
    verb      text NOT NULL,
    hour      timestamptz NOT NULL,
    count     bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (agent_id, verb, hour)
);
CREATE INDEX baseline_hourly_hour ON baseline_hourly (hour);

-- Containment history also covers swarm operations.
ALTER TABLE containment_ops DROP CONSTRAINT containment_ops_target_type_check;
ALTER TABLE containment_ops ADD CONSTRAINT containment_ops_target_type_check
    CHECK (target_type IN ('instance', 'agent', 'team', 'fleet', 'swarm'));
ALTER TABLE containment_ops DROP CONSTRAINT containment_ops_op_check;
ALTER TABLE containment_ops ADD CONSTRAINT containment_ops_op_check
    CHECK (op IN ('suspend', 'resume', 'isolate', 'kill', 'estop', 'estop_release', 'memory_remove', 'memory_restore', 'cancel_queue', 'quarantine',
                  'trip_breaker', 'kill_swarm', 'release_swarm'));

