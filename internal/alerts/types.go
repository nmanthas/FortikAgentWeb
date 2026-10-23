// Package alerts records security alerts for investigation (spawn spikes,
// delegation bypass attempts, copy-cap breaches...). Every alert is also a
// Diary event (alert.raised) and is pushed to the console live.
package alerts

import (
	"context"
	"encoding/json"
	"time"
)

const (
	SevInfo     = "info"
	SevWarning  = "warning"
	SevHigh     = "high"
	SevCritical = "critical"
)

// Kinds raised in Phase 3.
const (
	KindDelegationBypass  = "delegation_bypass"
	KindDelegationDepth   = "delegation_depth"
	KindSpawnSpike        = "spawn_spike"
	KindCopyCap           = "copy_cap"
	KindPopulation        = "population_exceeded"
	KindRateLimited       = "rate_limited"
	KindAgentSurge        = "agent_registration_surge"
	KindUnregisteredSurge = "unregistered_agent_surge"
	KindRestoreBlocked    = "override_restore_blocked"

	// Phase 5
	KindSwarmDetected = "swarm_detected"
	KindShadowAgent   = "shadow_agent"
	KindHiddenSignal  = "hidden_signal"
)

type Alert struct {
	ID        string          `json:"alert_id"`
	Kind      string          `json:"kind"`
	Severity  string          `json:"severity"`
	AgentID   string          `json:"agent_id,omitempty"`
	AgentType string          `json:"agent_type,omitempty"`
	ActionID  string          `json:"action_id,omitempty"`
	Summary   string          `json:"summary"`
	Details   json.RawMessage `json:"details"`
	DedupKey  string          `json:"dedup_key,omitempty"` // same open key within the window bumps count instead of a new alert
	Count     int             `json:"count"`
	Status    string          `json:"status"` // open | acknowledged | resolved
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
	AckedBy   string          `json:"acked_by,omitempty"`
}

// Raiser is what subsystems use. Raise must be safe to call inside a decision
// transaction (RaiseTx) so the alert commits with the decision.
type Raiser interface {
	Raise(ctx context.Context, a Alert) (Alert, error)
}
