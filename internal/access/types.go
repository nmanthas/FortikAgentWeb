// Package access holds per-agent, per-system access profiles. Profiles are
// versioned data passed to policy as input.access and used by the broker to
// narrow every credential it issues. No profile = no access (POL-020).
package access

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Systems that have access profiles: the Phase 2 apps, plus (Phase 3) a2a
// (who an agent may delegate to), http (external egress) and mcp (servers
// and tools). New systems are appended so existing orderings stay stable.
var Systems = []string{"gmail", "drive", "github", "aws", "postgres", "a2a", "http", "mcp"}

// Profile is one version of an agent's access to one system. Profile JSON
// shapes are defined in docs/PHASE2_DESIGN.md §5 and validated by Validate.
type Profile struct {
	AgentID   string          `json:"agent_id"`
	System    string          `json:"system"`
	Version   int             `json:"version"`
	Profile   json.RawMessage `json:"profile"`
	ChangedBy string          `json:"changed_by"`
	ChangedAt time.Time       `json:"changed_at"`
	Reason    string          `json:"reason"`
}

// PolicyInput is what Decide puts in input.access for the action's system.
type PolicyInput struct {
	System  string          `json:"system"`
	Version int             `json:"version"`
	Profile json.RawMessage `json:"profile"` // JSON null when absent
}

var (
	ErrInvalidProfile = errors.New("invalid access profile")
	ErrNotFound       = errors.New("access profile not found")
)

// Store persists profile versions (append-only) and writes Diary events.
type Store interface {
	// Current returns the newest version, or ErrNotFound.
	Current(ctx context.Context, agentID, system string) (Profile, error)
	All(ctx context.Context, agentID string) ([]Profile, error)
	History(ctx context.Context, agentID, system string, limit int) ([]Profile, error)
	// Put validates and appends a new version; returns it.
	Put(ctx context.Context, agentID, system string, profile json.RawMessage, actor, reason string) (Profile, error)
	// Revert appends a new version copying `version`.
	Revert(ctx context.Context, agentID, system string, version int, actor, reason string) (Profile, error)
	// PolicyInput returns input.access for Decide (Profile null when none).
	PolicyInput(ctx context.Context, agentID, system string) (PolicyInput, error)
}

// Widens reports whether `next` grants anything `prev` did not (owners may
// only narrow; widening needs the security role). Implemented per system.
type WideningChecker func(system string, prev, next json.RawMessage) (bool, error)
