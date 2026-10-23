// Package delegation tracks agent-to-agent delegation chains (A asks B, B asks
// C...) so that every action is evaluated against the permissions of EVERY
// agent in the chain, not only the agent that executes it.
//
// A hop is recorded when one agent delegates to another (A2A message, task,
// spawn). The delegatee receives a signed delegation token (header
// X-Fortik-Delegation) carrying the chain; interception points forward it.
// If a delegatee acts WITHOUT a token while it has open inbound delegations,
// the chain is inferred conservatively from all of them (fail closed).
package delegation

import (
	"context"
	"errors"
	"time"

	"fortik/internal/access"
)

// Header carries the signed delegation token between agents.
const Header = "X-Fortik-Delegation"

// Claims is the signed payload of a delegation token.
type Claims struct {
	DelegationID string    `json:"did"`
	Root         string    `json:"root"`  // originating agent
	Chain        []string  `json:"chain"` // agents in order: root ... current holder (the delegatee)
	Depth        int       `json:"depth"` // len(Chain)-1
	TaskID       string    `json:"task,omitempty"`
	IssuedAt     time.Time `json:"iat"`
	ExpiresAt    time.Time `json:"exp"`
}

// Hop is one stored delegation (from -> to).
type Hop struct {
	DelegationID string     `json:"delegation_id"`
	ParentID     string     `json:"parent_id,omitempty"`
	Root         string     `json:"root_agent"`
	From         string     `json:"from_agent"`
	To           string     `json:"to_agent"`
	Chain        []string   `json:"chain"`
	Depth        int        `json:"depth"`
	TaskID       string     `json:"task_id,omitempty"`
	Channel      string     `json:"channel"` // a2a | mcp | spawn | hook_task
	ActionID     string     `json:"action_id"`
	Status       string     `json:"status"` // open | closed | expired | refused
	CreatedAt    time.Time  `json:"created_at"`
	ExpiresAt    time.Time  `json:"expires_at"`
	ClosedAt     *time.Time `json:"closed_at,omitempty"`
}

// HopState is one upstream agent as policy sees it (input.context.delegation.chain[i]).
type HopState struct {
	AgentID    string              `json:"agent_id"`
	Registered bool                `json:"registered"`
	Level      int                 `json:"level"`
	LevelName  string              `json:"level_name"`
	Access     *access.PolicyInput `json:"access"` // profile for the ACTION's system
}

// PolicyContext is input.context.delegation.
type PolicyContext struct {
	Present      bool       `json:"present"`
	Source       string     `json:"source"` // token | inferred
	DelegationID string     `json:"delegation_id,omitempty"`
	Depth        int        `json:"depth"`
	Root         string     `json:"root,omitempty"`
	Chain        []HopState `json:"chain"` // UPSTREAM agents only (root first), excluding the executor
}

var (
	ErrInvalidToken = errors.New("invalid delegation token")
	ErrExpiredToken = errors.New("expired delegation token")
	ErrTokenAgent   = errors.New("delegation token was issued to a different agent")
	// ErrRevokedToken: the signature is valid but the token's hop is no
	// longer open (closed, expired, refused) or unknown.
	ErrRevokedToken = errors.New("delegation token's hop is no longer open")
)

// Store records hops and resolves chains.
type Store interface {
	// Open records a hop from -> to (parent = the delegation the delegator
	// itself acts under, if any) and returns it with a signed token for the delegatee.
	Open(ctx context.Context, h Hop) (Hop, string, error)
	Close(ctx context.Context, delegationID, reason string) error
	// Verify checks a token presented by `holder` (must be the last chain element).
	Verify(ctx context.Context, token, holder string) (Claims, error)
	// OpenInbound lists unexpired open hops delegated TO agent (for inference).
	OpenInbound(ctx context.Context, agent string) ([]Hop, error)
}
