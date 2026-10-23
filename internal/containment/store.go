package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// MaxListLimit bounds List.
const MaxListLimit = 500

const opCols = `op_id, op, target_type, target_id, actor, reason, status, steps, created_at, finished_at`

func scanOp(row pgx.Row) (Op, error) {
	var op Op
	var steps []byte
	var fin *time.Time
	if err := row.Scan(&op.OpID, &op.Op, &op.TargetType, &op.TargetID, &op.Actor, &op.Reason, &op.Status, &steps, &op.CreatedAt, &fin); err != nil {
		return Op{}, err
	}
	op.CreatedAt = op.CreatedAt.UTC()
	if fin != nil {
		t := fin.UTC()
		op.FinishedAt = &t
	}
	op.Steps = []Step{}
	if err := json.Unmarshal(steps, &op.Steps); err != nil {
		return Op{}, fmt.Errorf("containment op %s: steps: %w", op.OpID, err)
	}
	return op, nil
}

// List returns operations, newest first, optionally filtered by target type
// and id. An agent's history also includes the team and fleet operations
// whose steps covered it, and its instances' operations.
func (m *Manager) List(ctx context.Context, targetType, targetID string, limit int) ([]Op, error) {
	if limit <= 0 || limit > MaxListLimit {
		limit = 50
	}
	if targetType != "" {
		if _, ok := map[string]bool{TargetInstance: true, TargetAgent: true, TargetTeam: true, TargetFleet: true, TargetSwarm: true}[targetType]; !ok {
			return nil, fmt.Errorf("%w: target_type must be instance, agent, team, fleet or swarm", ErrInvalid)
		}
	}
	if targetID != "" && targetType == "" {
		return nil, fmt.Errorf("%w: target_id needs target_type", ErrInvalid)
	}
	var (
		rows pgx.Rows
		err  error
	)
	switch {
	case targetType == TargetAgent && targetID != "":
		rows, err = m.pool.Query(ctx, `SELECT `+opCols+` FROM containment_ops
			WHERE (target_type = 'agent' AND target_id = $1)
				OR steps @> jsonb_build_array(jsonb_build_object('agent_id', $1::text))
			ORDER BY created_at DESC, op_id DESC LIMIT $2`, targetID, limit)
	default:
		rows, err = m.pool.Query(ctx, `SELECT `+opCols+` FROM containment_ops
			WHERE ($1 = '' OR target_type = $1) AND ($2 = '' OR target_id = $2)
			ORDER BY created_at DESC, op_id DESC LIMIT $3`, targetType, targetID, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Op{}
	for rows.Next() {
		op, err := scanOp(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, op)
	}
	return out, rows.Err()
}

// Get returns one operation.
func (m *Manager) Get(ctx context.Context, opID string) (Op, error) {
	op, err := scanOp(m.pool.QueryRow(ctx, `SELECT `+opCols+` FROM containment_ops WHERE op_id = $1`, opID))
	if errors.Is(err, pgx.ErrNoRows) {
		return Op{}, fmt.Errorf("%w: operation %s", ErrNotFound, opID)
	}
	return op, err
}
