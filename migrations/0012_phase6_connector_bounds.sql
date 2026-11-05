-- Phase 6 security review: the public authorize endpoint prunes and caps
-- open authorizations per connector, and old codes are pruned per connector
-- (internal/connector, maxOpenAuthorizations / codeReplayWindow).
CREATE INDEX connector_pending_connector ON connector_pending (connector_id, expires_at);
CREATE INDEX connector_codes_connector ON connector_codes (connector_id, expires_at);
