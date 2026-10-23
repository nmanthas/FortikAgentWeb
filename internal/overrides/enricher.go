package overrides

import (
	"context"
	"fmt"

	"fortik/internal/action"
	"fortik/internal/control"
)

// EnricherKey is the input.context key the enricher fills.
const EnricherKey = "overrides"

// Enricher supplies input.context.overrides: the overrides in force (active
// or blocked) for the acting agent, directly or through its team
// (agents.business_unit), on the action's system. It always returns a
// PolicyContext (an empty list when nothing applies); a store error fails
// the decision closed.
type Enricher struct {
	store *PGStore
}

// NewEnricher returns the decide.Enricher for overrides.
func NewEnricher(store *PGStore) *Enricher { return &Enricher{store: store} }

func (e *Enricher) Key() string { return EnricherKey }

func (e *Enricher) Enrich(ctx context.Context, a action.Action, st control.State) (any, error) {
	if e == nil || e.store == nil {
		return nil, fmt.Errorf("overrides enricher: no store")
	}
	team := ""
	if st.Registered {
		team = st.Team
	}
	active, err := e.store.InForce(ctx, a.AgentID, team, a.System)
	if err != nil {
		return nil, fmt.Errorf("overrides: %w", err)
	}
	return PolicyContext{Active: active}, nil
}
