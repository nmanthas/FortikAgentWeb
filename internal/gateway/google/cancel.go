package google

import (
	"context"
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
	"fortik/internal/undo"
)

// SendCancellation says, for one agent, what CancelPendingSends actually
// achieved. Only Cancelled messages are known not to have been sent.
type SendCancellation struct {
	// Cancelled: pending delayed sends cancelled now; they were never sent
	// and never will be.
	Cancelled []string `json:"cancelled"`
	// InFlight: sends the delayed sender had already claimed (status
	// "sending") before the cancel: they could not be stopped and may have
	// been delivered.
	InFlight []string `json:"in_flight"`
	// SentSince: delayed sends of the agent delivered at or after `since`.
	SentSince int `json:"sent_since"`
}

// CancelPendingSends cancels every pending delayed Gmail send of the given
// agents (containment: e.g. step 2 of a swarm kill), so none of them is
// delivered, and reports honestly per agent what was cancelled, what was
// already in flight (claimed by the sender: may have been delivered) and how
// many sends were delivered since `since`.
//
// The cancel is one transaction: each cancelled row, its undo handle (now
// failed: there is nothing left to undo) and a gmail.delayed_send.cancelled
// Diary event commit together. A row the sender worker is claiming at that
// moment is locked by it; the update waits and, once the claim commits, no
// longer matches "pending" and is reported in flight instead. reason is
// recorded (single-line, clipped); never message content.
func CancelPendingSends(ctx context.Context, pool *pgxpool.Pool, d *diary.Diary, agentIDs []string, since time.Time, actor, reason string) (map[string]SendCancellation, error) {
	if pool == nil || d == nil {
		return nil, errors.New("cancel delayed sends: pool and diary are required")
	}
	if strings.TrimSpace(actor) == "" {
		return nil, errors.New("cancel delayed sends: actor is required")
	}
	out := map[string]SendCancellation{}
	agents := slices.Compact(slices.Sorted(slices.Values(agentIDs)))
	if len(agents) == 0 {
		return out, nil
	}
	for _, a := range agents {
		out[a] = SendCancellation{Cancelled: []string{}, InFlight: []string{}}
	}
	note := clipLine(reason, 300)
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		for _, a := range agents {
			out[a] = SendCancellation{Cancelled: []string{}, InFlight: []string{}}
		}
		rows, err := tx.Query(ctx, `
			UPDATE delayed_sends SET status = 'cancelled', error = $2
			WHERE agent_id = ANY($1) AND status = 'pending'
			RETURNING action_id, agent_id, COALESCE((meta_json->>'recipients')::int, 0)`,
			agents, "cancelled before sending by "+actor+": "+note)
		if err != nil {
			return err
		}
		type cancelled struct {
			actionID, agentID string
			recipients        int
		}
		var done []cancelled
		for rows.Next() {
			var c cancelled
			if err := rows.Scan(&c.actionID, &c.agentID, &c.recipients); err != nil {
				rows.Close()
				return err
			}
			done = append(done, c)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		slices.SortFunc(done, func(x, y cancelled) int { return strings.Compare(x.actionID, y.actionID) })
		events := make([]diary.Event, 0, len(done))
		for _, c := range done {
			ct, err := tx.Exec(ctx, `UPDATE undo_handles SET status = $2, error = $3
				WHERE action_id = $1 AND status IN ('prepared', 'active')`, c.actionID, undo.StatusFailed,
				"cancelled before sending: nothing was sent")
			if err != nil {
				return err
			}
			r := out[c.agentID]
			r.Cancelled = append(r.Cancelled, c.actionID)
			out[c.agentID] = r
			events = append(events, diary.Event{AgentID: c.agentID, EventType: EventDelayedCancelled, Actor: actor, Data: map[string]any{
				"action_id": c.actionID, "status": "cancelled", "by": "containment", "reason": note,
				"undo_handle": undo.StatusFailed, "undo_note": "cancelled before sending: nothing was sent",
				"handle_updated": ct.RowsAffected() == 1, "recipients": c.recipients,
			}})
		}
		if _, err := d.AppendTx(ctx, tx, events...); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT action_id, agent_id FROM delayed_sends WHERE agent_id = ANY($1) AND status = 'sending' ORDER BY action_id`, agents)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id, agent string
			if err := rows.Scan(&id, &agent); err != nil {
				rows.Close()
				return err
			}
			r := out[agent]
			r.InFlight = append(r.InFlight, id)
			out[agent] = r
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		rows, err = tx.Query(ctx, `SELECT agent_id, count(*) FROM delayed_sends
			WHERE agent_id = ANY($1) AND status = 'sent' AND sent_at >= $2 GROUP BY agent_id`, agents, since)
		if err != nil {
			return err
		}
		for rows.Next() {
			var agent string
			var n int
			if err := rows.Scan(&agent, &n); err != nil {
				rows.Close()
				return err
			}
			r := out[agent]
			r.SentSince = n
			out[agent] = r
		}
		rows.Close()
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// clipLine keeps s on one line and at most n bytes.
func clipLine(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		s = s[:n] + "..."
	}
	return s
}
