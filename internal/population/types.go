// Package population controls how many copies of each agent (and agents of
// each type) may run, detects spawn spikes against a baseline, and rate-limits
// actions. Copies register on start and heartbeat; copies over the cap get no
// credentials.
package population

import "time"

// Instance is one running copy of an agent.
type Instance struct {
	InstanceID       string    `json:"instance_id"`
	AgentID          string    `json:"agent_id"`
	Host             string    `json:"host"`
	ParentInstanceID string    `json:"parent_instance_id,omitempty"`
	StartedAt        time.Time `json:"started_at"`
	LastHeartbeat    time.Time `json:"last_heartbeat"`
	Status           string    `json:"status"` // live | paused | suspended | stopped | refused | stale
	Reason           string    `json:"reason,omitempty"`
	NewHost          bool      `json:"new_host"` // first time this agent was seen on this host
}

// AgentType is the expected operating envelope for a class of agents.
type AgentType struct {
	Type                 string `json:"type"`
	ExpectedMaxInstances int    `json:"expected_max_instances"` // across all agents of the type
	MaxAgents            int    `json:"max_agents"`             // registered agents of the type
	SpawnRatePerMin      int    `json:"spawn_rate_per_min"`     // static ceiling (0 = baseline only)
	ActionRatePerMin     int    `json:"action_rate_per_min"`    // per agent (0 = unlimited)
}

// PolicyContext is input.context.population.
type PolicyContext struct {
	InstanceID         string  `json:"instance_id,omitempty"`
	InstanceStatus     string  `json:"instance_status,omitempty"` // live|paused|refused|unregistered|"" (no instance id)
	RequireInstances   bool    `json:"require_instances"`
	AgentLive          int     `json:"agent_live"`
	CopyCap            int     `json:"copy_cap"`
	AgentType          string  `json:"agent_type,omitempty"`
	TypeLive           int     `json:"type_live"`
	TypeExpectedMax    int     `json:"type_expected_max"`
	SpawnsLastMinute   int     `json:"spawns_last_minute"`
	SpawnRateLimit     int     `json:"spawn_rate_limit"`
	SpawnBaselineLimit float64 `json:"spawn_baseline_limit"` // mean+3σ (or 5×median with < 3 days of history) per minute; 0 = no baseline yet
	ActionsLastMinute  int     `json:"actions_last_minute"`
	ActionRateLimit    int     `json:"action_rate_limit"`
}
