-- Delegation observer looks hops up by the action that opened them.
CREATE INDEX delegations_action ON delegations (action_id) WHERE status = 'open';
