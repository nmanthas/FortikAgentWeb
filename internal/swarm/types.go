// Package swarm detects swarms (agents and copies acting together: an
// orchestrator and its workers, many copies of one agent, many agents
// converging on one target) and lets security contain one as a single
// object (docs/PHASE5_DESIGN.md §1).
//
// Detection:
//   - the Max-5 breaker, counted inside the decision transaction (Observer):
//     an action hash repeated by more than breaker_n distinct agents or
//     copies within breaker_window trips the breaker; the tripping call and
//     every later matching call are held for two approvers (POL-651);
//   - a background sweep (Sweeper) for spawn trees, copy surges and
//     converging targets.
//
// Actions (security, reason required): trip_breaker, suspend, isolate, kill
// (7 ordered steps, each in parallel across members) and a two-approver
// release that never un-kills.
package swarm

import (
	"encoding/json"
	"errors"
	"time"

	"fortik/internal/containment"
)

// ContextKey is the enricher key: input.context.swarm.
const ContextKey = "swarm"

// Rule ids (policies/fortik/swarm).
const (
	RuleBreaker   = "POL-651"
	RuleFrozen    = "POL-652"
	RuleFrozenAct = "POL-653"
)

// Detection signals (swarms.detected_by).
const (
	DetectedActionHash = "action_hash"
	DetectedSpawnTree  = "spawn_tree"
	DetectedCopySurge  = "copy_surge"
	DetectedConverging = "converging_targets"
)

// Swarm states (swarms.state). Containment never moves a swarm to a less
// strict state; released is final.
const (
	StateDetected       = "detected"
	StateBreakerTripped = "breaker_tripped"
	StateSuspended      = "suspended"
	StateIsolated       = "isolated"
	StateKilled         = "killed"
	StateReleased       = "released"
)

var stateRank = map[string]int{StateDetected: 0, StateBreakerTripped: 1, StateSuspended: 2, StateIsolated: 3, StateKilled: 4}

// Member roles.
const (
	RoleRoot   = "root"
	RoleMember = "member"
)

// Diary events.
const (
	EventDetected       = "swarm.detected"
	EventMemberAdded    = "swarm.member_added"
	EventBreakerTripped = "swarm.breaker_tripped"
	EventFrozen         = "swarm.frozen"
	EventSuspended      = "swarm.suspended"
	EventIsolated       = "swarm.isolated"
	EventVotesCleared   = "swarm.release_votes_cleared"
	EventReleaseVote    = "swarm.release_vote"
	EventReleased       = "swarm.released"
	EventSealed         = "swarm.sealed"
	EventBundleExported = "swarm.bundle_exported"
)

// AlertKind is the alert raised when a swarm is detected.
const AlertKind = "swarm_detected"

// ReleaseApprovals is the number of distinct security approvers a release needs.
const ReleaseApprovals = 2

// BreakerApprovals is approvals_required of a breaker hold (POL-651).
const BreakerApprovals = 2

var (
	ErrInvalid  = errors.New("invalid swarm request")
	ErrNotFound = errors.New("swarm not found")
	// ErrConflict: the action does not apply to the swarm's current state
	// (a released swarm, a breaker tripped for another swarm...).
	ErrConflict = errors.New("swarm conflict")
	// ErrAlreadyVoted: the approver already voted to release this swarm.
	ErrAlreadyVoted = errors.New("this approver already voted to release the swarm: a second, different security approver is required")
	// ErrTwoPerson: the release already has a vote from an API token and this
	// vote is from another token (see Options.AllowTokenPairs).
	ErrTwoPerson = errors.New("two-person rule: this release already has a vote from an API token; the second vote must come from a signed-in person, not another token")
	// ErrNotSealed: the swarm has no sealed bundle (it was never killed).
	ErrNotSealed = errors.New("swarm has no sealed bundle: kill-swarm step 7 seals it")
	// ErrNoSigner: bundle export needs the Diary signing key.
	ErrNoSigner = errors.New("no Diary signing key configured: bundles cannot be signed")
	// ErrBusy: another operation on the swarm did not finish in time.
	ErrBusy = errors.New("swarm busy")
)

// Swarm is a swarms row.
type Swarm struct {
	SwarmID     string          `json:"swarm_id"`
	RootAgentID string          `json:"root_agent_id,omitempty"`
	DetectedBy  string          `json:"detected_by"`
	Signal      json.RawMessage `json:"signal"`
	ActionHash  string          `json:"action_hash,omitempty"`
	MemberCount int             `json:"member_count"`
	State       string          `json:"state"`
	// Frozen: spawning is frozen (kill-swarm step 1): POL-652/653 apply to
	// the members until the swarm is released.
	Frozen     bool       `json:"frozen"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
}

// Member is one swarm_members row (instance_id "" = the whole agent).
type Member struct {
	AgentID    string    `json:"agent_id"`
	InstanceID string    `json:"instance_id,omitempty"`
	Role       string    `json:"role"`
	AddedAt    time.Time `json:"joined_at"`
	Level      string    `json:"level_name,omitempty"`
	Suspended  bool      `json:"suspended"`
}

// Breaker is a swarm_breakers row.
type Breaker struct {
	ActionHash string     `json:"action_hash"`
	SwarmID    string     `json:"swarm_id"`
	State      string     `json:"state"`
	TrippedAt  time.Time  `json:"tripped_at"`
	ReleasedAt *time.Time `json:"released_at,omitempty"`
	// Matched: held calls of this swarm matching the breaker's hash.
	Matched int `json:"matched"`
}

// ReleaseVote is one swarm_release_votes row.
type ReleaseVote struct {
	Approver  string    `json:"approver"`
	Reason    string    `json:"reason"`
	CreatedAt time.Time `json:"at"`
}

// TreeHop is one delegation of the swarm's spawn tree (parent -> child).
type TreeHop struct {
	DelegationID string    `json:"delegation_id"`
	ParentID     string    `json:"parent_delegation_id,omitempty"`
	From         string    `json:"parent"`
	To           string    `json:"child"`
	Depth        int       `json:"depth"`
	Channel      string    `json:"channel"`
	Status       string    `json:"status"`
	TaskID       string    `json:"task_id,omitempty"`
	ActionID     string    `json:"action_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
}

// Detail is GET /v1/swarms/{id}. Held rows have the GET /v1/held row shape
// plus approvals (distinct approve votes so far) and swarm_id.
type Detail struct {
	Swarm
	Members         []Member          `json:"members"`
	Breakers        []Breaker         `json:"breakers"`
	Held            []json.RawMessage `json:"held"`
	HeldTruncated   bool              `json:"held_truncated,omitempty"`
	ReleaseVotes    []ReleaseVote     `json:"release_votes"`
	ReleaseRequired int               `json:"release_required"`
	SpawnTree       []TreeHop         `json:"spawn_tree"`
	Ops             []Op              `json:"ops"`
}

// PolicyContext is input.context.swarm.
type PolicyContext struct {
	MemberOf        []string       `json:"member_of"`
	Frozen          bool           `json:"frozen"`
	FrozenSwarmID   string         `json:"frozen_swarm_id,omitempty"`
	DelegateeFrozen bool           `json:"delegatee_frozen"`
	Breaker         BreakerContext `json:"breaker"`
}

// BreakerContext is input.context.swarm.breaker for this action's hash.
type BreakerContext struct {
	Tripped bool   `json:"tripped"`
	SwarmID string `json:"swarm_id"`
	// Pending: no breaker is tripped yet, but this call is the one that
	// pushes the hash past breaker_n distinct agents or copies; the observer
	// trips the breaker in the same decision transaction.
	Pending bool `json:"pending,omitempty"`
	// DistinctOthers: distinct other agents/copies that made this call in
	// the breaker window (counted only while no breaker is tripped).
	DistinctOthers int `json:"distinct_others,omitempty"`
	Threshold      int `json:"threshold,omitempty"`
}

// Op is the result of a swarm action: the shape of a containment op.
type Op = containment.Op

// Step is one step of a swarm operation.
type Step = containment.Step

// ReleaseResult is POST /v1/swarms/{id}/release.
type ReleaseResult struct {
	Released bool `json:"released"`
	Votes    int  `json:"votes"`
	Required int  `json:"required"`
	Op       *Op  `json:"op,omitempty"`
}
