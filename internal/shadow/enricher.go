package shadow

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/control"
)

// Enricher supplies input.context.shadow to the policy (decide.Enricher)
// for DISCOVERED agents only; every other agent costs nothing and gets no
// key. Value:
//
//	{"discovered": true, "flagged": bool, "statuses": [...], "finding_ids": [...]}
//
// flagged is true while any of the agent's findings is still open or
// flagged for revocation (not yet revoked, dismissed or registered). An
// error fails the decision closed.
type Enricher struct{ pool *pgxpool.Pool }

// NewEnricher returns the enricher.
func NewEnricher(pool *pgxpool.Pool) *Enricher { return &Enricher{pool: pool} }

// Key implements decide.Enricher.
func (e *Enricher) Key() string { return "shadow" }

// Enrich implements decide.Enricher.
func (e *Enricher) Enrich(ctx context.Context, _ action.Action, st control.State) (any, error) {
	if !st.Discovered {
		return nil, nil
	}
	if e == nil || e.pool == nil {
		return nil, fmt.Errorf("shadow enricher: no database")
	}
	rows, err := e.pool.Query(ctx, `SELECT finding_id, status FROM shadow_findings WHERE agent_id = $1 ORDER BY finding_id LIMIT 50`, st.AgentID)
	if err != nil {
		return nil, fmt.Errorf("shadow enricher: %w", err)
	}
	defer rows.Close()
	ids, statuses := []string{}, []string{}
	flagged := false
	for rows.Next() {
		var id, status string
		if err := rows.Scan(&id, &status); err != nil {
			return nil, fmt.Errorf("shadow enricher: %w", err)
		}
		ids = append(ids, id)
		statuses = append(statuses, status)
		if status == StatusOpen || status == StatusFlagged {
			flagged = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("shadow enricher: %w", err)
	}
	return map[string]any{"discovered": true, "flagged": flagged, "statuses": statuses, "finding_ids": ids}, nil
}
