-- Phase 6 (continued): the SaaS copilot connector broker.

-- SaaS copilot connector broker (docs/PHASE6_DESIGN.md §6). A copilot's
-- Workspace / GitHub connector uses a Fortik-issued OAuth client; Fortik is
-- its authorization server and holds the upstream grant. Secrets never live
-- here: client secrets and Fortik refresh tokens are stored as SHA-256
-- hashes; upstream refresh tokens live in the secret store.
CREATE TABLE connectors (
    connector_id         text PRIMARY KEY,                 -- con_<ulid>
    agent_id             text NOT NULL REFERENCES agents (agent_id),
    vendor               text NOT NULL CHECK (vendor ~ '^[a-z0-9_]{1,32}$'),
    upstream             text NOT NULL CHECK (upstream IN ('google_workspace', 'github')),
    client_id            text NOT NULL UNIQUE,
    client_secret_sha256 text NOT NULL,
    redirect_uris        text[] NOT NULL,
    scopes               text[] NOT NULL,
    status               text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_by           text NOT NULL,
    created_at           timestamptz NOT NULL DEFAULT now(),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    disabled_reason      text
);
CREATE INDEX connectors_agent ON connectors (agent_id);

-- Browser authorization in progress (state handed to the upstream).
CREATE TABLE connector_pending (
    txn_sha256            text PRIMARY KEY,
    connector_id          text NOT NULL REFERENCES connectors (connector_id),
    redirect_uri          text NOT NULL,
    client_state          text NOT NULL DEFAULT '',
    scopes                text[] NOT NULL,
    code_challenge        text NOT NULL DEFAULT '',
    code_challenge_method text NOT NULL DEFAULT '',
    expires_at            timestamptz NOT NULL
);

-- A consented connection: one per user consent. The upstream refresh token
-- is in the secret store under upstream_secret.
CREATE TABLE connector_grants (
    grant_id                text PRIMARY KEY,               -- cgr_<ulid>
    connector_id            text NOT NULL REFERENCES connectors (connector_id),
    agent_id                text NOT NULL,
    scopes                  text[] NOT NULL,
    subject                 text NOT NULL DEFAULT '',       -- upstream account, when known
    upstream_secret         text NOT NULL,
    refresh_sha256          text UNIQUE,                    -- current Fortik refresh token
    previous_refresh_sha256 text,                           -- rotated-out token (reuse = theft: revoke)
    status                  text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    created_at              timestamptz NOT NULL DEFAULT now(),
    last_issued_at          timestamptz,
    revoked_at              timestamptz,
    revoke_reason           text
);
CREATE INDEX connector_grants_agent ON connector_grants (agent_id) WHERE status = 'active';

-- One-time Fortik authorization codes (RFC 6749 §4.1), hashed.
CREATE TABLE connector_codes (
    code_sha256           text PRIMARY KEY,
    grant_id              text NOT NULL REFERENCES connector_grants (grant_id),
    connector_id          text NOT NULL,
    redirect_uri          text NOT NULL,
    code_challenge        text NOT NULL DEFAULT '',
    code_challenge_method text NOT NULL DEFAULT '',
    expires_at            timestamptz NOT NULL,
    used_at               timestamptz
);

-- Vendor audit-log events already recorded (dedup).
CREATE TABLE connector_audit_seen (
    connector_id text NOT NULL,
    event_id     text NOT NULL,
    seen_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (connector_id, event_id)
);
