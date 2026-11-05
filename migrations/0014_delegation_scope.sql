-- Delegated task scope and correlation (cross-agent authority, POL-605): the
-- scope a delegator declared for the task (narrowed by every ancestor's), and
-- the root DELEGATE's action id shared by every hop of one delegated task.
ALTER TABLE delegations ADD COLUMN scope jsonb;
ALTER TABLE delegations ADD COLUMN correlation_id text;
CREATE INDEX delegations_correlation ON delegations (correlation_id) WHERE correlation_id IS NOT NULL;
