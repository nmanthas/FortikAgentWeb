-- Owner notifications (the plan: a restore "notifies the owner (console,
-- plus Slack or email)"). Security alerts are sent once to a Slack-compatible
-- incoming webhook (integration notify_slack) by internal/notify.
ALTER TABLE alerts ADD COLUMN notified_at timestamptz;
ALTER TABLE alerts ADD COLUMN notify_attempts integer NOT NULL DEFAULT 0;
ALTER TABLE alerts ADD COLUMN notify_status text;
CREATE INDEX alerts_unnotified ON alerts (created_at) WHERE notified_at IS NULL;

ALTER TABLE integrations DROP CONSTRAINT integrations_key_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_key_check
    CHECK (key ~ '^(google_workspace|github|aws|postgres:[a-z][a-z0-9_]{0,62}|temporal|celery|queue_webhook|memory:[a-z][a-z0-9_]{0,62}|notify_slack)$');
ALTER TABLE integrations DROP CONSTRAINT integrations_system_check;
ALTER TABLE integrations ADD CONSTRAINT integrations_system_check
    CHECK (system IN ('google_workspace', 'github', 'aws', 'postgres', 'temporal', 'celery', 'queue_webhook', 'memory', 'notify_slack'));
