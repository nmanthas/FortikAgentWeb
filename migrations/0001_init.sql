-- Fortik Phase 1 schema: agents, actions, held actions, undo handles, Diary.
-- Later phases add instances, access_profiles, access_overrides, swarms, edges
-- in their own migrations.

CREATE TABLE agents (
    agent_id               text PRIMARY KEY CHECK (agent_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$'),
    name                   text NOT NULL DEFAULT '',
    type                   text NOT NULL DEFAULT '',
    platform               text NOT NULL DEFAULT '',
    sponsor                text NOT NULL DEFAULT '',
    business_unit          text NOT NULL DEFAULT '',
    copy_cap               integer NOT NULL DEFAULT 1 CHECK (copy_cap >= 0),
    level                  smallint NOT NULL DEFAULT 0 CHECK (level BETWEEN 0 AND 5),
    level_changed_at       timestamptz NOT NULL DEFAULT now(),
    access_profile_version integer NOT NULL DEFAULT 0,
    discovered             boolean NOT NULL DEFAULT false,
    created_at             timestamptz NOT NULL DEFAULT now(),
    updated_at             timestamptz NOT NULL DEFAULT now()
);

-- Every decided action, including refused attempts by unregistered agents.
-- agent_id intentionally has no FK: attempts by unknown/shadow agents must be
-- recorded too (they feed shadow-agent discovery in a later phase).
CREATE TABLE actions (
    action_id       text PRIMARY KEY,
    agent_id        text NOT NULL,
    instance_id     text,
    swarm_id        text,
    system          text NOT NULL,
    verb            text NOT NULL,
    action_hash     text NOT NULL,
    class           text NOT NULL CHECK (class IN ('green', 'yellow', 'red')),
    decision        text NOT NULL CHECK (decision IN ('allow', 'allow_reduced', 'hold', 'deny')),
    rule_id         text NOT NULL,
    reason          text NOT NULL,
    reversible      boolean NOT NULL DEFAULT false,
    source          text NOT NULL DEFAULT '',
    target          jsonb NOT NULL DEFAULT '{}',
    payload_summary jsonb NOT NULL DEFAULT '{}',
    decision_json   jsonb NOT NULL DEFAULT '{}', -- matched rules, reduced form, ladder change, levels, policy version
    fail_closed     boolean NOT NULL DEFAULT false,
    latency_us      bigint NOT NULL DEFAULT 0,
    ts              timestamptz NOT NULL
);
CREATE INDEX actions_agent_ts ON actions (agent_id, ts DESC);
CREATE INDEX actions_class_ts ON actions (class, ts DESC) WHERE class <> 'green';
CREATE INDEX actions_hash_ts ON actions (action_hash, ts DESC);

CREATE TABLE held_actions (
    action_id          text PRIMARY KEY REFERENCES actions (action_id),
    agent_id           text NOT NULL,
    rule_id            text NOT NULL,
    reason             text NOT NULL,
    approvals_required integer NOT NULL DEFAULT 1 CHECK (approvals_required >= 1),
    approver_role      text NOT NULL DEFAULT 'security',
    safe_form          jsonb,          -- e.g. rename-based form offered for DROP TABLE
    expires_at         timestamptz NOT NULL,
    outcome            text NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending', 'approved', 'denied', 'expired')),
    decided_by         text,
    decided_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX held_actions_pending ON held_actions (created_at) WHERE outcome = 'pending';

CREATE TABLE undo_handles (
    action_id   text PRIMARY KEY REFERENCES actions (action_id),
    agent_id    text NOT NULL,
    kind        text NOT NULL,
    handle_json jsonb NOT NULL,
    status      text NOT NULL CHECK (status IN ('prepared', 'active', 'failed', 'undoing', 'used', 'expired')),
    expires_at  timestamptz NOT NULL,
    used_at     timestamptz,
    used_by     text,
    error       text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX undo_handles_agent ON undo_handles (agent_id, created_at DESC);

-- Agent Diary: append-only, hash-chained.
--   hash = sha256(prev_hash || body_json), body_json is the exact canonical
--   JSON that was hashed (stored as text so verification is byte-exact).
CREATE TABLE diary (
    seq        bigint PRIMARY KEY,
    ts         timestamptz NOT NULL,
    agent_id   text,
    event_type text NOT NULL,
    actor      text NOT NULL,
    body_json  text NOT NULL,
    prev_hash  text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
    hash       text NOT NULL UNIQUE CHECK (hash ~ '^[0-9a-f]{64}$')
);
CREATE INDEX diary_agent_ts ON diary (agent_id, ts);
CREATE INDEX diary_ts ON diary (ts);

-- Single-row chain head; appends lock this row, which serialises the chain
-- and makes seq gapless.
CREATE TABLE diary_head (
    id   boolean PRIMARY KEY DEFAULT true CHECK (id),
    seq  bigint NOT NULL,
    hash text NOT NULL
);
INSERT INTO diary_head (id, seq, hash) VALUES (true, 0, repeat('0', 64));

-- Daily signed root hashes (the chain head at the end of each UTC day).
CREATE TABLE diary_roots (
    day       date PRIMARY KEY,
    last_seq  bigint NOT NULL,
    root_hash text NOT NULL,
    signature text NOT NULL,
    key_id    text NOT NULL,
    sealed_at timestamptz NOT NULL DEFAULT now()
);

-- Append-only enforcement. (A superuser or table owner can still disable
-- triggers; production deployments run the app as a non-owner role — see
-- SECURITY.md — and rely on exported signed roots to detect tampering.)
CREATE FUNCTION fortik_forbid_mutation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'fortik: % on % is forbidden (append-only)', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege';
END;
$$;

CREATE TRIGGER diary_no_update BEFORE UPDATE OR DELETE ON diary
    FOR EACH ROW EXECUTE FUNCTION fortik_forbid_mutation();
CREATE TRIGGER diary_no_truncate BEFORE TRUNCATE ON diary
    FOR EACH STATEMENT EXECUTE FUNCTION fortik_forbid_mutation();
CREATE TRIGGER diary_roots_no_update BEFORE UPDATE OR DELETE ON diary_roots
    FOR EACH ROW EXECUTE FUNCTION fortik_forbid_mutation();
CREATE TRIGGER diary_roots_no_truncate BEFORE TRUNCATE ON diary_roots
    FOR EACH STATEMENT EXECUTE FUNCTION fortik_forbid_mutation();
