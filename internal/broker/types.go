// Package broker is the authority broker: the only component that issues
// credentials that make an agent action run. Every issuance is decided first
// (decide.Service), narrowed by the agent's access profile, short-lived,
// recorded in credential_issuances and the Diary (never the secret itself).
package broker

import (
	"context"
	"errors"
	"time"

	"fortik/internal/decide"
)

// IssueRequest is the body of POST /v1/credentials/issue (agent-authenticated).
type IssueRequest struct {
	AgentID    string      `json:"-"` // from the authenticated agent, never the body
	InstanceID string      `json:"-"`
	System     string      `json:"system"` // aws | github | postgres
	AWS        *AWSRequest `json:"aws,omitempty"`
	GitHub     *GHRequest  `json:"github,omitempty"`
}

type AWSRequest struct {
	Service    string  `json:"service"`  // e.g. "s3"
	Action     string  `json:"action"`   // e.g. "GetObject"
	Resource   string  `json:"resource"` // ARN or "*"
	Region     string  `json:"region,omitempty"`
	EstCostUSD float64 `json:"est_cost_usd,omitempty"`
}

type GHRequest struct {
	Repos       []string          `json:"repos"`       // "org/repo"
	Permissions map[string]string `json:"permissions"` // e.g. {"contents":"read"}
}

// Credential is returned to the agent (AWS, GitHub direct mode) or used
// internally (Google, GitHub gateway mode, Postgres). Secret fields are never
// logged or stored in Postgres.
type Credential struct {
	IssuanceID string            `json:"issuance_id"`
	ActionID   string            `json:"action_id"`
	System     string            `json:"system"`
	ExpiresAt  time.Time         `json:"expires_at"`
	Scope      map[string]any    `json:"scope"`  // non-secret description of what it allows
	Secret     map[string]string `json:"secret"` // e.g. AWS keys/session token, GitHub token
}

// Refusal is returned when Decide did not allow the issuance.
type Refusal struct {
	Outcome decide.Outcome
}

func (r *Refusal) Error() string {
	return "credential refused: " + string(r.Outcome.Result.Decision) + " by " + r.Outcome.Result.RuleID + ": " + r.Outcome.Result.Reason
}

var (
	ErrNotConfigured = errors.New("integration not configured")
	ErrUnsupported   = errors.New("system does not support direct credentials (use the gateway)")
)

// Adapter mints and revokes credentials for one system.
type Adapter interface {
	System() string
	// Mint issues a credential narrowed to scope (already intersected with
	// the access profile by the adapter). Must be short-lived.
	Mint(ctx context.Context, agentID string, scope map[string]any, ttl time.Duration) (Credential, error)
	// RevokeAgent revokes every live credential for the agent using the
	// system's real semantics and returns a human description of what was
	// actually achieved (e.g. "tokens not recallable; deny-by-issue-time attached").
	RevokeAgent(ctx context.Context, agentID string) (string, error)
}

// Broker is the façade used by the API, the gateway and pgproxy.
type Broker interface {
	Issue(ctx context.Context, req IssueRequest) (Credential, error) // *Refusal or ErrNotConfigured on refusal
	// RecordIssuance stores a credential issued by an in-process adapter
	// (gateway/pgproxy) and writes credential.issued to the Diary.
	RecordIssuance(ctx context.Context, c Credential, agentID, instanceID string) error
	RevokeAll(ctx context.Context, agentID, actor, reason string) (map[string]string, error)
}
