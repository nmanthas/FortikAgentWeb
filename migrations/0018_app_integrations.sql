-- Unified integration model (integration platform Milestone 1).
--
-- An application integration ("logical integration") is one tenant/account
-- of one provider, e.g. netsuite:acme. Its transport connections are the
-- existing integrations rows, each now tagged with the logical integration
-- it belongs to and its transport (rest_api | mcp | native). A logical
-- integration has at most one connection per transport, and an account id
-- (tenant_ref of a full NetSuite account) belongs to one integration only,
-- so adding a second transport never creates a second integration for the
-- same account. A QuickStart company label is a display name, not an
-- identity, and is not unique.
--
-- Existing rows are preserved: each is linked to a logical integration whose
-- id is derived from its key exactly as integrations.LogicalID does
-- (provider:instance, or provider:default / netsuite:quickstart for the
-- single-instance keys).

CREATE TABLE app_integrations (
    integration_id     text PRIMARY KEY CHECK (integration_id ~ '^[a-z][a-z0-9_]{0,31}:[a-z][a-z0-9_]{0,62}$'),
    provider           text NOT NULL CHECK (provider ~ '^[a-z][a-z0-9_]{0,31}$'),
    environment        text NOT NULL DEFAULT '',
    tenant_ref         text NOT NULL DEFAULT '',
    display_name       text NOT NULL,
    -- true when an administrator created it (kept when its last connection
    -- is removed); false when it was created implicitly with a connection
    created_explicitly boolean NOT NULL DEFAULT false,
    created_by         text NOT NULL,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_by         text NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CHECK (split_part(integration_id, ':', 1) = provider)
);
CREATE UNIQUE INDEX app_integrations_tenant ON app_integrations (provider, environment, lower(tenant_ref))
    WHERE tenant_ref <> '' AND environment <> 'quickstart';

ALTER TABLE integrations DROP CONSTRAINT integrations_key_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_key_check
    CHECK (key ~ '^(google_workspace|github|aws|temporal|celery|queue_webhook|notify_slack|netsuite|netsuite_quickstart|(postgres|memory|netsuite|netsuite_quickstart|netsuite_mcp):[a-z][a-z0-9_]{0,62})$');
ALTER TABLE integrations DROP CONSTRAINT integrations_system_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_system_check
    CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'temporal', 'celery', 'queue_webhook', 'memory', 'notify_slack', 'netsuite', 'netsuite_quickstart', 'netsuite_mcp'));

ALTER TABLE integrations ADD COLUMN app_integration_id text REFERENCES app_integrations (integration_id);
ALTER TABLE integrations ADD COLUMN transport text CHECK (transport IN ('rest_api', 'mcp', 'native'));
CREATE UNIQUE INDEX integrations_one_transport ON integrations (app_integration_id, transport) WHERE app_integration_id IS NOT NULL;

-- Backfill: one logical integration per existing connection.
WITH src AS (
    SELECT key, system, config_json, updated_by,
        CASE WHEN system IN ('netsuite_quickstart', 'netsuite_mcp') THEN 'netsuite' ELSE system END AS provider,
        COALESCE(NULLIF(split_part(key, ':', 2), ''), CASE system WHEN 'netsuite_quickstart' THEN 'quickstart' ELSE 'default' END) AS slug,
        CASE system WHEN 'netsuite' THEN 'full' WHEN 'netsuite_mcp' THEN 'full' WHEN 'netsuite_quickstart' THEN 'quickstart' ELSE '' END AS environment,
        CASE system WHEN 'netsuite' THEN COALESCE(config_json ->> 'account_id', '')
                    WHEN 'netsuite_mcp' THEN COALESCE(config_json ->> 'account_id', '')
                    WHEN 'netsuite_quickstart' THEN COALESCE(config_json ->> 'tenant_label', '')
                    ELSE '' END AS tenant_ref,
        CASE system WHEN 'netsuite_quickstart' THEN 'mcp' WHEN 'netsuite_mcp' THEN 'mcp'
                    WHEN 'postgres' THEN 'native' WHEN 'memory' THEN 'native' WHEN 'temporal' THEN 'native' WHEN 'celery' THEN 'native'
                    ELSE 'rest_api' END AS transport
    FROM integrations
)
INSERT INTO app_integrations (integration_id, provider, environment, tenant_ref, display_name, created_by, updated_by)
SELECT provider || ':' || slug, provider, environment, tenant_ref,
    CASE WHEN tenant_ref <> '' THEN tenant_ref ELSE key END, 'migration:0018', COALESCE(updated_by, 'migration:0018')
FROM src
ON CONFLICT (integration_id) DO NOTHING;

UPDATE integrations i SET
    app_integration_id = (CASE WHEN i.system IN ('netsuite_quickstart', 'netsuite_mcp') THEN 'netsuite' ELSE i.system END) || ':' ||
        COALESCE(NULLIF(split_part(i.key, ':', 2), ''), CASE i.system WHEN 'netsuite_quickstart' THEN 'quickstart' ELSE 'default' END),
    transport = CASE i.system WHEN 'netsuite_quickstart' THEN 'mcp' WHEN 'netsuite_mcp' THEN 'mcp'
                    WHEN 'postgres' THEN 'native' WHEN 'memory' THEN 'native' WHEN 'temporal' THEN 'native' WHEN 'celery' THEN 'native'
                    ELSE 'rest_api' END;

-- The MCP connection states gain authorization_required (OAuth connections
-- that are configured but not yet authorized by a NetSuite user).
ALTER TABLE mcp_connections DROP CONSTRAINT mcp_connections_state_check;
ALTER TABLE mcp_connections ADD CONSTRAINT mcp_connections_state_check
    CHECK (state IN ('connected', 'connected_limited', 'auth_failed', 'token_expired', 'authorization_required',
        'permission_denied', 'mcp_init_failed', 'tool_discovery_failed', 'unavailable', 'endpoint_not_permitted'));

-- Actions of one logical integration across its transports (the unified card).
CREATE INDEX actions_app_integration_ts ON actions ((target ->> 'integration_id'), ts DESC)
    WHERE target ->> 'integration_id' IS NOT NULL;
