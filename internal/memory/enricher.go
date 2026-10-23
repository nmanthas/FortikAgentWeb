package memory

import (
	"context"
	"errors"

	"fortik/internal/action"
	"fortik/internal/control"
)

// EnricherKey is the input.context key the enricher fills.
const EnricherKey = "memory"

// Enricher supplies input.context.memory = {"access": mode} for memory
// actions and for MCP actions (which may address a memory server; the policy
// decides which servers are memory). Other systems get no memory context. A
// store error fails the decision closed.
type Enricher struct {
	svc *Service
}

// NewEnricher returns the decide.Enricher for memory access.
func NewEnricher(svc *Service) *Enricher { return &Enricher{svc: svc} }

func (e *Enricher) Key() string { return EnricherKey }

func (e *Enricher) Enrich(ctx context.Context, a action.Action, _ control.State) (any, error) {
	if a.System != action.SystemMemory && a.System != action.SystemMCP {
		return nil, nil
	}
	if e == nil || e.svc == nil {
		return nil, errors.New("memory enricher: no service")
	}
	st, err := e.svc.Access(ctx, a.AgentID)
	if err != nil {
		return nil, err
	}
	return PolicyContext{Access: st.Mode}, nil
}
