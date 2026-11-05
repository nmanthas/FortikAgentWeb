-- Milestone 1 (NetSuite): the integration and access-profile system, and the
-- SaaS activity ingestion state shared by every SaaS connector.
ALTER TABLE integrations DROP CONSTRAINT integrations_key_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_key_check
    CHECK (key ~ '^(google_workspace|github|aws|postgres:[a-z][a-z0-9_]{0,62}|temporal|celery|queue_webhook|memory:[a-z][a-z0-9_]{0,62}|notify_slack|netsuite)$');
ALTER TABLE integrations DROP CONSTRAINT integrations_system_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_system_check
    CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'temporal', 'celery', 'queue_webhook', 'memory', 'notify_slack', 'netsuite'));
ALTER TABLE access_profiles DROP CONSTRAINT access_profiles_system_check;
ALTER TABLE access_profiles ADD CONSTRAINT access_profiles_system_check
    CHECK (system IN ('gmail', 'drive', 'github', 'aws', 'postgres', 'a2a', 'http', 'mcp', 'memory', 'netsuite'));

-- Per connector and tenant: where activity ingestion stopped, and whether
-- the last pass worked (stale data is shown as stale).
CREATE TABLE saas_sync_state (
    system          text NOT NULL,
    tenant          text NOT NULL,
    cursor          text NOT NULL DEFAULT '',
    last_attempt_at timestamptz,
    last_success_at timestamptz,
    last_error      text,
    PRIMARY KEY (system, tenant)
);

-- Platform events already recorded (dedup).
CREATE TABLE saas_events_seen (
    system   text NOT NULL,
    tenant   text NOT NULL,
    event_id text NOT NULL,
    seen_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (system, tenant, event_id)
);
