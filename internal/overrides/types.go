// Package overrides implements time-limited per-app suspensions (plan:
// "GitHub suspended for 30 minutes", "Drive suspended until released") with
// automatic, safety-checked restore.
package overrides

import (
	"encoding/json"
	"time"
)

// Modes.
const (
	ModeSuspended = "suspended" // no access to the system
	ModeReadOnly  = "read_only" // reads only on the system
)

type Override struct {
	OverrideID            string          `json:"override_id"`
	Scope                 string          `json:"scope"` // agent | team
	ScopeID               string          `json:"scope_id"`
	System                string          `json:"system"`
	Mode                  string          `json:"mode"`
	StartsAt              time.Time       `json:"starts_at"`
	ExpiresAt             *time.Time      `json:"expires_at,omitempty"` // nil = until released
	RestoreProfileVersion int             `json:"restore_profile_version"`
	Reason                string          `json:"reason"`
	CreatedBy             string          `json:"created_by"`
	Status                string          `json:"status"` // active | restored | released | blocked | superseded
	RestoredAt            *time.Time      `json:"restored_at,omitempty"`
	RevokeResult          json.RawMessage `json:"revoke_result,omitempty"`
	BlockedReason         string          `json:"blocked_reason,omitempty"`
}

// PolicyContext is input.context.overrides: active overrides that apply to
// the acting agent (directly or via its team) for the action's system.
type PolicyContext struct {
	Active []Override `json:"active"`
}
