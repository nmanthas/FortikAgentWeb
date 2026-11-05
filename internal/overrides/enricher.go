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
	// An action can reach other systems: a copilot connector's token reaches
	// its upstream's systems (Phase 6), and a shell command reaches GitHub
	// (gh, git push/fetch/clone) or AWS (the aws CLI). Their suspensions
	// apply to it too. Extra systems only ever add overrides, so a caller
	// cannot use them to escape one.
	if extra := reachedSystems(a); len(extra) > 0 {
		for _, sys := range extra {
			more, err := e.store.InForce(ctx, a.AgentID, team, sys)
			if err != nil {
				return nil, fmt.Errorf("overrides: %w", err)
			}
			active = append(active, more...)
		}
		SortMostRestrictive(active)
	}
	return PolicyContext{Active: active}, nil
}

// reachedSystems: the other systems an action reaches (deduplicated, the
// action's own system excluded, at most 8).
func reachedSystems(a action.Action) []string {
	var raw []string
	if a.System == "connector" {
		raw = append(raw, upstreamSystems(a.Target["upstream_systems"])...)
	}
	raw = append(raw, upstreamSystems(a.Target["reaches"])...)
	seen := map[string]bool{a.System: true}
	var out []string
	for _, s := range raw {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
		if len(out) == 8 {
			break
		}
	}
	return out
}

func upstreamSystems(v any) []string {
	var out []string
	switch xs := v.(type) {
	case []string:
		out = xs
	case []any:
		for _, x := range xs {
			if s, ok := x.(string); ok {
				out = append(out, s)
			}
		}
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}
