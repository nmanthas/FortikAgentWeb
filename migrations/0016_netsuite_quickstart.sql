-- NetSuite QuickStart MCP integration (Milestone 1 of the QuickStart brief):
-- the integration key, and what Fortik last learned from the MCP server.
ALTER TABLE integrations DROP CONSTRAINT integrations_key_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_key_check
    CHECK (key ~ '^(google_workspace|github|aws|postgres:[a-z][a-z0-9_]{0,62}|temporal|celery|queue_webhook|memory:[a-z][a-z0-9_]{0,62}|notify_slack|netsuite|netsuite_quickstart)$');
ALTER TABLE integrations DROP CONSTRAINT integrations_system_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_system_check
    CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'temporal', 'celery', 'queue_webhook', 'memory', 'notify_slack', 'netsuite', 'netsuite_quickstart'));

-- One row per upstream MCP connection: the outcome of the last live check
-- (initialize + tools/list) and the tools from the last successful one. No
-- credential is stored here; the token stays in the secret store.
CREATE TABLE mcp_connections (
    integration_key    text PRIMARY KEY,
    -- integrations.updated_at of the settings that were last checked: a
    -- different value means the settings (or the token) changed since.
    config_version     timestamptz NOT NULL,
    state              text NOT NULL CHECK (state IN ('connected', 'connected_limited', 'auth_failed', 'token_expired',
                           'permission_denied', 'mcp_init_failed', 'tool_discovery_failed', 'unavailable', 'endpoint_not_permitted')),
    detail             text NOT NULL DEFAULT '',
    http_status        int,
    endpoint           text NOT NULL,
    protocol_version   text NOT NULL DEFAULT '',
    server_name        text NOT NULL DEFAULT '',
    server_version     text NOT NULL DEFAULT '',
    server_instructions text NOT NULL DEFAULT '',
    capabilities       jsonb NOT NULL DEFAULT '{}',
    tools              jsonb NOT NULL DEFAULT '[]',
    rejected_tools     jsonb NOT NULL DEFAULT '[]',
    tools_hash         text NOT NULL DEFAULT '',
    permission_mode    text NOT NULL DEFAULT 'unknown' CHECK (permission_mode IN ('read_only', 'read_write', 'unverified', 'unknown')),
    permission_basis   text NOT NULL DEFAULT '',
    duration_ms        int NOT NULL DEFAULT 0,
    last_attempt_at    timestamptz NOT NULL,
    last_success_at    timestamptz,
    last_tools_sync_at timestamptz
);
