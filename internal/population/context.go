package population

import (
	"fortik/internal/action"
)

// Spawn actions: what POST /v1/instances/register decides.
const (
	SystemAgents   = "agents"
	OperationSpawn = "spawn"
	// ContextKey is the enricher's key (input.context.population).
	ContextKey = "population"
)

// Rule ids of package fortik.population (policies/fortik/population).
const (
	RuleCopyCap    = "POL-701"
	RuleTypeMax    = "POL-702"
	RuleSpawnRate  = "POL-703"
	RuleActionRate = "POL-704"
	RuleInstance   = "POL-705"
	// RuleUnregistered is the control gate for unknown agents (counted for
	// the unregistered-agent surge alert).
	RuleUnregistered = "POL-015"
)

// Instance statuses as policy sees them (InstanceStatus). "stale" is a live
// row whose heartbeat is older than stale_after; "unregistered" is an
// instance id Fortik does not know for this agent.
const (
	StatusLive    = "live"
	StatusPaused  = "paused"
	StatusStopped = "stopped"
	StatusRefused = "refused"
	StatusStale   = "stale"
	// StatusSuspended: a copy paused by containment (suspend); heartbeats
	// answer 423 {"action":"pause"} and its actions are refused (POL-705).
	StatusSuspended    = "suspended"
	StatusUnregistered = "unregistered"
)

// EnrichedContext is what the enricher puts under input.context.population:
// the contract PolicyContext plus the spike-cooldown flag POL-703 needs
// ("throttled for spike_cooldown"), which PolicyContext has no field for.
type EnrichedContext struct {
	PolicyContext
	// SpawnThrottled: a spawn spike was detected for this agent type (or
	// untyped agent) within the last spike_cooldown.
	SpawnThrottled bool `json:"spawn_throttled"`
}

// IsSpawn reports whether a is a spawn registration (system "agents",
// verb DELEGATE, target.operation "spawn").
func IsSpawn(a action.Action) bool {
	if a.System != SystemAgents || a.Verb != action.VerbDelegate {
		return false
	}
	op, _ := a.Target["operation"].(string)
	return op == OperationSpawn
}

// Conditions mirror the Rego rules of fortik.population on a context. They
// are used only to raise alerts for refused actions (the policy decides);
// keeping them here lets an alert name every condition that held even when
// another gate had the lowest rule id.
func (c EnrichedContext) copyCapReached() bool { return c.AgentLive >= c.CopyCap }

func (c EnrichedContext) typeMaxReached() bool {
	return c.TypeExpectedMax > 0 && c.TypeLive >= c.TypeExpectedMax
}

func (c EnrichedContext) spawnRateExceeded() bool {
	n := c.SpawnsLastMinute
	return (c.SpawnRateLimit > 0 && n > c.SpawnRateLimit) ||
		(c.SpawnBaselineLimit > 0 && float64(n) > c.SpawnBaselineLimit)
}

func (c EnrichedContext) actionRateReached() bool {
	return c.ActionRateLimit > 0 && c.ActionsLastMinute >= c.ActionRateLimit
}

// spawnKey is the counter scope for spawns: the agent type, or the agent
// itself when it has no type.
func spawnScope(agentID, agentType string) string {
	if agentType != "" {
		return "type:" + agentType
	}
	return "agent:" + agentID
}

func spawnCounterKey(scope string) string  { return "spawn:" + scope }
func spikeCounterKey(scope string) string  { return "spike:" + scope }
func actionCounterKey(agent string) string { return "act:agent:" + agent }

const unregisteredDenialsKey = "deny:unregistered"
