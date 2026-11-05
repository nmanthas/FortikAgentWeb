-- Salesforce, ServiceNow and SAP connections (unified REST / MCP
-- integrations). Each provider has a REST connection type and an MCP
-- connection type, keyed <type> (the provider's default tenant) or
-- <type>:<tenant>, linked to one logical integration per tenant like
-- NetSuite's (migration 0018).
--
-- rest_connections keeps the last live check of each REST connection: the
-- state, what the provider said, and the capabilities it discovered (API
-- versions, objects or tables readable, OData entity sets). MCP connections
-- keep theirs in mcp_connections.

ALTER TABLE integrations DROP CONSTRAINT integrations_key_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_key_check
    CHECK (key ~ '^(google_workspace|github|aws|temporal|celery|queue_webhook|notify_slack|netsuite|netsuite_quickstart|salesforce|salesforce_mcp|servicenow|servicenow_mcp|sap|sap_mcp|(postgres|memory|netsuite|netsuite_quickstart|netsuite_mcp|salesforce|salesforce_mcp|servicenow|servicenow_mcp|sap|sap_mcp):[a-z][a-z0-9_]{0,62})$');
ALTER TABLE integrations DROP CONSTRAINT integrations_system_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_system_check
    CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'temporal', 'celery', 'queue_webhook', 'memory', 'notify_slack',
        'netsuite', 'netsuite_quickstart', 'netsuite_mcp', 'salesforce', 'salesforce_mcp', 'servicenow', 'servicenow_mcp', 'sap', 'sap_mcp'));

-- Access profiles for the three business systems (one profile per system,
-- applied to both transports).
ALTER TABLE access_profiles DROP CONSTRAINT access_profiles_system_check;
ALTER TABLE access_profiles ADD CONSTRAINT access_profiles_system_check
    CHECK (system IN ('gmail', 'drive', 'github', 'aws', 'postgres', 'a2a', 'http', 'mcp', 'memory', 'netsuite', 'salesforce', 'servicenow', 'sap'));

CREATE TABLE rest_connections (
    integration_key text PRIMARY KEY,
    -- integrations.updated_at of the settings that were checked: a different
    -- value means the settings or a credential changed since.
    config_version  timestamptz NOT NULL,
    state           text NOT NULL CHECK (state IN ('connected', 'auth_failed', 'permission_denied', 'not_found', 'unavailable',
                        'endpoint_not_permitted', 'invalid_settings')),
    detail          text NOT NULL DEFAULT '',
    http_status     int,
    endpoint        text NOT NULL DEFAULT '',
    identity        jsonb NOT NULL DEFAULT '{}', -- who the credentials act as (user, org), as the provider reported it
    capabilities    jsonb NOT NULL DEFAULT '{}',
    duration_ms     int NOT NULL DEFAULT 0,
    last_attempt_at timestamptz NOT NULL,
    last_success_at timestamptz
);
