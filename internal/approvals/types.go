// Package approvals lets a security approver approve or deny held actions.
//
// Approving a held RED action never runs it unchanged: if the interception
// point offered a safe form (e.g. DROP TABLE -> rename), Fortik executes the
// safe form itself and records an undo handle. Approving a held YELLOW action
// issues a one-time grant bound to the agent and the exact action hash; the
// agent's retry within the grant TTL is allowed once (input.context.grant).
package approvals

import "time"

type Grant struct {
	GrantID    string     `json:"grant_id"`
	ActionID   string     `json:"action_id"` // the held action that was approved
	AgentID    string     `json:"agent_id"`
	ActionHash string     `json:"action_hash"`
	ApprovedBy string     `json:"approved_by"`
	Reason     string     `json:"reason"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at,omitempty"`
	UsedBy     string     `json:"used_by_action,omitempty"`
}

// PolicyContext is input.context.grant (present only when a usable grant matches).
type PolicyContext struct {
	GrantID   string    `json:"grant_id"`
	ExpiresAt time.Time `json:"expires_at"`
	// Approvals is the number of distinct approvers of the held action the
	// grant was issued for: policy releases a hold only with a grant carrying
	// at least the hold's approvals_required.
	Approvals int `json:"approvals"`
}
