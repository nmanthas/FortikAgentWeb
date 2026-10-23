package agentgw

import (
	"context"

	"fortik/internal/delegation"
)

// DelegationStore is the part of internal/delegation the callout calls
// directly; *delegation.PGStore implements it.
//
//   - Verify re-checks a presented token (no DB round trip), so a bad token
//     can never pass even if the delegation enricher were not wired.
//   - Close and CloseTask close hops when the A2A response observer sees the
//     delegated task end (each writes delegation.closed).
//
// Tokens travel to and from Decide through the request context
// (delegation.WithToken, delegation.WithTokenSink / Sink.TokenFor); they are
// never put in the Action, logged or stored by the callout.
type DelegationStore interface {
	Verify(ctx context.Context, token, holder string) (delegation.Claims, error)
	Close(ctx context.Context, delegationID, reason string) error
	CloseTask(ctx context.Context, from, to, taskID, reason string) (int, error)
}

var _ DelegationStore = (*delegation.PGStore)(nil)
