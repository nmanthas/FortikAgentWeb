package undo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// DelayedSendState is the live delayed_sends row behind a gmail_delayed_send
// handle. The handle's send_at is only the time recorded when the email was
// queued; the row is authoritative (retries move send_at, and the row stays
// pending while the sender is late or the agent is suspended).
type DelayedSendState struct {
	Status string    // pending | sending | sent | cancelled | failed
	SendAt time.Time // current send time
}

// Delayed send row statuses (delayed_sends.status).
const (
	delayedPending   = "pending"
	delayedSending   = "sending"
	delayedSent      = "sent"
	delayedCancelled = "cancelled"
	delayedFailed    = "failed"
)

// rowQuerier is the subset of pgx used to read delayed_sends.
type rowQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// LoadDelayedSends reads the delayed_sends rows of the given action ids.
// Ids without a row are absent from the map.
func LoadDelayedSends(ctx context.Context, q rowQuerier, actionIDs []string) (map[string]DelayedSendState, error) {
	out := make(map[string]DelayedSendState, len(actionIDs))
	if len(actionIDs) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT action_id, status, send_at FROM delayed_sends WHERE action_id = ANY($1)`, actionIDs)
	if err != nil {
		return nil, fmt.Errorf("undo: read delayed sends: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var st DelayedSendState
		if err := rows.Scan(&id, &st.Status, &st.SendAt); err != nil {
			return nil, fmt.Errorf("undo: read delayed sends: %w", err)
		}
		out[id] = st
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("undo: read delayed sends: %w", err)
	}
	return out, nil
}

// AssessDelayedSendAt assesses a gmail_delayed_send handle against its live
// delayed_sends row (nil when the row could not be read: the handle-only
// assessment is returned, which keeps Undo offered and lets the executor
// decide). Handles that are not active (used, expired, ...) keep their
// handle assessment.
func AssessDelayedSendAt(h Handle, row *DelayedSendState, now time.Time) Assessment {
	a := UndoabilityAt(h, now)
	if h.Kind != KindGmailDelayedSend || row == nil || h.Status != StatusActive {
		return a
	}
	if a.WhyNot != "" && a.WhyNot != WhyNotMalformed {
		return a // e.g. the handle expired
	}
	at := row.SendAt.UTC().Format(time.RFC3339)
	a.WhyNot = ""
	switch row.Status {
	case delayedPending:
		if now.Before(row.SendAt) {
			a.Description = fmt.Sprintf("Cancel the delayed email (not sent yet; it goes out at %s)", at)
		} else {
			a.Description = fmt.Sprintf("Cancel the delayed email (not sent yet: still queued although its send time %s has passed; the sender may pick it up at any moment)", at)
		}
	case delayedSending:
		a.Description = "Cancel the delayed email (only before it is sent)"
		a.WhyNot = WhyNotSending
	case delayedSent:
		a.Description = "Cancel the delayed email (only before it is sent)"
		a.WhyNot = WhyNotSent
	case delayedCancelled:
		a.Description = "Cancel the delayed email (only before it is sent)"
		a.WhyNot = WhyNotSendCancelled
	case delayedFailed:
		a.Description = "Cancel the delayed email (only before it is sent)"
		a.WhyNot = WhyNotSendIncomplete
	default:
		a.WhyNot = WhyNotUnsupported
	}
	a.Undoable = a.WhyNot == ""
	return a
}
