-- Phase 2: access profiles, integrations, credential issuances, delayed
-- sends, console sessions. See docs/PHASE2_DESIGN.md §13.

ALTER TABLE agents ADD COLUMN workspace_user text NOT NULL DEFAULT '';

CREATE TABLE access_profiles (
    agent_id     text NOT NULL REFERENCES agents (agent_id),
    system       text NOT NULL CHECK (system IN ('gmail', 'drive', 'github', 'aws', 'postgres')),
    version      integer NOT NULL CHECK (version >= 1),
    profile_json jsonb NOT NULL,
    changed_by   text NOT NULL,
    changed_at   timestamptz NOT NULL DEFAULT now(),
    reason       text NOT NULL,
    PRIMARY KEY (agent_id, system, version)
);
-- Versions are append-only (revert = new version).
CREATE TRIGGER access_profiles_no_update BEFORE UPDATE OR DELETE ON access_profiles
    FOR EACH ROW EXECUTE FUNCTION fortik_forbid_mutation();

CREATE TABLE integrations (
    key            text PRIMARY KEY CHECK (key ~ '^(google_workspace|github|aws|postgres:[a-z][a-z0-9_]{0,62})$'),
    system         text NOT NULL CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres')),
    config_json    jsonb NOT NULL DEFAULT '{}',
    secret_fields  text[] NOT NULL DEFAULT '{}',   -- names only, never values
    status         text NOT NULL DEFAULT 'configured' CHECK (status IN ('unconfigured', 'configured', 'ok', 'error')),
    last_tested_at timestamptz,
    last_error     text,
    updated_by     text NOT NULL,
    updated_at     timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE credential_issuances (
    issuance_id   text PRIMARY KEY,
    action_id     text REFERENCES actions (action_id),
    agent_id      text NOT NULL,
    instance_id   text,
    system        text NOT NULL,
    scope_json    jsonb NOT NULL DEFAULT '{}',   -- non-secret description only
    expires_at    timestamptz NOT NULL,
    revoked_at    timestamptz,
    revoke_method text,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX credential_issuances_live ON credential_issuances (agent_id, system, expires_at) WHERE revoked_at IS NULL;

CREATE TABLE delayed_sends (
    action_id   text PRIMARY KEY REFERENCES actions (action_id),
    agent_id    text NOT NULL,
    send_at     timestamptz NOT NULL,
    status      text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'sending', 'sent', 'cancelled', 'failed')),
    payload_enc bytea NOT NULL,       -- AES-256-GCM; key in the secret store
    nonce       bytea NOT NULL,
    key_id      text NOT NULL,
    meta_json   jsonb NOT NULL DEFAULT '{}',  -- recipients count, sizes: no content
    sent_at     timestamptz,
    error       text,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX delayed_sends_due ON delayed_sends (send_at) WHERE status = 'pending';

CREATE TABLE console_sessions (
    id_sha256    text PRIMARY KEY,
    email        text NOT NULL,
    name         text NOT NULL DEFAULT '',
    roles        text[] NOT NULL DEFAULT '{}',
    auth_method  text NOT NULL CHECK (auth_method IN ('oidc', 'dev')),
    csrf         text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX console_sessions_expiry ON console_sessions (expires_at);

-- Index for the LADDER-3Y rule (held yellow actions per agent in a window).
CREATE INDEX held_actions_agent_created ON held_actions (agent_id, created_at DESC);
