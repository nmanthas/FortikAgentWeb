package approvals

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/diary"
)

// Worker marks pending holds past expires_at as expired (Diary
// action.hold_expired). Rows locked by an in-flight approval are skipped and
// picked up on a later sweep.
type Worker struct {
	svc      *Service
	interval time.Duration
	batch    int
}

// ExpiryWorker returns the held-action expiry sweep (default interval 30s).
func (s *Service) ExpiryWorker(interval time.Duration) *Worker {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Worker{svc: s, interval: interval, batch: 200}
}

// Run sweeps immediately and then every interval until ctx is cancelled.
// Sweep errors are logged and retried on the next tick.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		if n, err := w.Sweep(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			w.svc.log.Error("held expiry sweep failed", "err", err)
		} else if n > 0 {
			w.svc.log.Info("held actions expired", "count", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep expires every due pending hold (in batches) and returns how many it
// expired.
func (w *Worker) Sweep(ctx context.Context) (int, error) {
	total := 0
	for {
		n, err := w.sweepBatch(ctx)
		total += n
		if err != nil {
			return total, err
		}
		if n < w.batch {
			return total, nil
		}
	}
}

func (w *Worker) sweepBatch(ctx context.Context) (int, error) {
	s := w.svc
	now := s.now().UTC()
	n := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		n = 0
		rows, err := tx.Query(ctx, `
			SELECT action_id, agent_id, rule_id, expires_at FROM held_actions
			WHERE outcome = 'pending' AND expires_at <= $1
			ORDER BY expires_at LIMIT $2
			FOR UPDATE SKIP LOCKED`, now, w.batch)
		if err != nil {
			return err
		}
		type due struct {
			actionID, agentID, ruleID string
			expiresAt                 time.Time
		}
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.actionID, &d.agentID, &d.ruleID, &d.expiresAt); err != nil {
				rows.Close()
				return err
			}
			list = append(list, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(list) == 0 {
			return nil
		}
		events := make([]diary.Event, 0, len(list))
		for _, d := range list {
			tag, err := tx.Exec(ctx, `UPDATE held_actions SET outcome = 'expired', decided_by = $2, decided_at = $3
				WHERE action_id = $1 AND outcome = 'pending'`, d.actionID, expiryActor, now)
			if err != nil {
				return fmt.Errorf("expire held action: %w", err)
			}
			if tag.RowsAffected() != 1 {
				continue
			}
			events = append(events, diary.Event{AgentID: d.agentID, EventType: EventHoldExpired, Actor: expiryActor, Data: map[string]any{
				"action_id": d.actionID, "rule_id": d.ruleID, "expired_at": d.expiresAt.UTC().Format(time.RFC3339),
			}})
		}
		if len(events) > 0 {
			if _, err := s.diary.AppendTx(ctx, tx, events...); err != nil {
				return err
			}
		}
		// Count what was actually expired: a row that could not be updated is
		// never re-selected forever by the batch loop in Sweep.
		n = len(events)
		return nil
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}

const expiryActor = "system:approvals"
