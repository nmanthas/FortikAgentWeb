// Package containment orchestrates the plan's containment actions
// (suspend/resume, isolate, remove/restore memory access, cancel queued
// work, kill, single-tenant fleet stop) over a target: one copy, one agent,
// a team or the fleet. Each operation runs ordered steps, records each
// step's honest result, is idempotent, and is written to the Diary.
package containment

import (
	"context"
	"time"
)

// Ops and target types (match containment_ops CHECK constraints).
const (
	OpSuspend       = "suspend"
	OpResume        = "resume"
	OpIsolate       = "isolate"
	OpKill          = "kill"
	OpEStop         = "estop"
	OpEStopRelease  = "estop_release"
	OpMemoryRemove  = "memory_remove"
	OpMemoryRestore = "memory_restore"
	OpCancelQueue   = "cancel_queue"
	// OpQuarantine is recorded when the level API sets QUARANTINED; it is
	// not requested through Run.
	OpQuarantine = "quarantine"

	TargetInstance = "instance"
	TargetAgent    = "agent"
	TargetTeam     = "team"
	TargetFleet    = "fleet"
)

// Step is one ordered step of an operation and what it actually achieved.
type Step struct {
	Name     string `json:"name"` // e.g. "revoke_credentials", "pause_queues"
	AgentID  string `json:"agent_id,omitempty"`
	Status   string `json:"status"`           // done | skipped | failed
	Detail   string `json:"detail,omitempty"` // honest semantics ("STS tokens not recallable; deny-by-issue-time attached")
	Duration int64  `json:"duration_ms"`
	// Phase numbers the ordered steps of a swarm kill (1..7); 0 elsewhere.
	Phase int `json:"phase,omitempty"`
}

// Op is one containment operation (a containment_ops row).
type Op struct {
	OpID       string     `json:"op_id"`
	Op         string     `json:"op"`
	TargetType string     `json:"target_type"`
	TargetID   string     `json:"target_id"`
	Actor      string     `json:"actor"`
	Reason     string     `json:"reason"`
	Status     string     `json:"status"` // running | done | partial | failed
	Steps      []Step     `json:"steps"`
	CreatedAt  time.Time  `json:"created_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// Request asks for one operation.
type Request struct {
	Op         string `json:"op"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	Reason     string `json:"reason"`
	// Memory options (memory_remove): "none" (no access) or "staging_only"
	// (reads allowed, writes go to staging and are not promoted).
	MemoryMode string `json:"memory_mode,omitempty"`
	// memory_restore: roll the namespace back to this clean snapshot first.
	RollbackSnapshotID string `json:"rollback_snapshot_id,omitempty"`
}

// Service runs operations. Actor comes from the authenticated principal.
type Service interface {
	Run(ctx context.Context, req Request, actor string) (Op, error)
}
