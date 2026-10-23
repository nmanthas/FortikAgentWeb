// Package queues controls an agent's queued work in the customer's job
// system (plan: "pause the agent's queued jobs", "cancel queued jobs and
// retries"). Adapters: Temporal, Celery (Redis broker), generic webhook.
package queues

import (
	"context"
	"errors"
)

// Result is what an adapter honestly achieved for one agent.
type Result struct {
	System   string `json:"system"`   // temporal | celery | queue_webhook
	Affected int    `json:"affected"` // workflows/tasks paused, resumed or cancelled
	Detail   string `json:"detail"`   // human description of the real semantics
}

var (
	// ErrNotConfigured: no integration row for the system, or the row is
	// unconfigured (containment records the step as skipped).
	ErrNotConfigured = errors.New("queue integration not configured")
	// ErrSecretMissing: the integration is configured but a required
	// secret is missing from the secret store. Deliberately NOT
	// ErrNotConfigured: the customer uses this queue system, so nothing was
	// paused or cancelled and the step must be recorded as failed.
	ErrSecretMissing = errors.New("queue integration is configured but a required secret is missing from the secret store")
	ErrUnsupported   = errors.New("operation not supported by this queue system")
	// ErrTruncated: an operation stopped at a safety cap, so part of the
	// agent's work was not touched (the step must not be recorded as done).
	ErrTruncated = errors.New("queue operation stopped at a limit: some of the agent's work was not processed")
)

// Adapter manages one queue system. Work is attributed to an agent by a
// tag the customer's producers set (Temporal search attribute FortikAgentId,
// Celery header fortik_agent_id, webhook payload agent_id).
type Adapter interface {
	System() string
	// Pause stops the agent's queued work from starting (paused, not cancelled).
	Pause(ctx context.Context, agentID, reason string) (Result, error)
	// Resume releases work held by Pause.
	Resume(ctx context.Context, agentID, reason string) (Result, error)
	// Cancel cancels queued jobs, retries and scheduled work (not reversible).
	Cancel(ctx context.Context, agentID, reason string) (Result, error)
}
