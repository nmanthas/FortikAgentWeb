package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/broker"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/undo"
)

// UndoExecutor reverses gmail_delayed_send (cancel before sending) and
// drive_permission (delete the recorded permission) handles. Register it in
// api.Server.Executors under both kinds.
type UndoExecutor struct{ a *Adapter }

// UndoExecutor returns the executor for this adapter's handle kinds.
func (a *Adapter) UndoExecutor() *UndoExecutor { return &UndoExecutor{a: a} }

var _ undo.Executor = (*UndoExecutor)(nil)

func (e *UndoExecutor) Kinds() []string { return []string{KindGmailDelayedSend, KindDrivePermission} }

func (e *UndoExecutor) Undo(ctx context.Context, h undo.Handle) (map[string]any, error) {
	switch h.Kind {
	case KindGmailDelayedSend:
		return e.cancelDelayed(ctx, h)
	case KindDrivePermission:
		return e.deletePermission(ctx, h)
	}
	return nil, fmt.Errorf("%w: %s", undo.ErrUnsupported, h.Kind)
}

// notUndoableError is a terminal "cannot undo" answer (the API maps it to 409).
type notUndoableError struct{ msg string }

func (e *notUndoableError) Error() string { return e.msg }
func (e *notUndoableError) Unwrap() []error {
	return []error{undo.ErrNotUndoable, undo.ErrNothingToUndo}
}

// cancelDelayed cancels a pending send atomically: a row the worker has
// already claimed ("sending") or sent cannot be cancelled.
func (e *UndoExecutor) cancelDelayed(ctx context.Context, h undo.Handle) (map[string]any, error) {
	actor := h.UsedBy
	if actor == "" {
		actor = "system:undo"
	}
	var status string
	err := pgx.BeginFunc(ctx, e.a.pool, func(tx pgx.Tx) error {
		var agentID string
		err := tx.QueryRow(ctx, `UPDATE delayed_sends SET status = 'cancelled', error = 'cancelled by undo'
			WHERE action_id = $1 AND status = 'pending' RETURNING agent_id`, h.ActionID).Scan(&agentID)
		if errors.Is(err, pgx.ErrNoRows) {
			if err := tx.QueryRow(ctx, `SELECT status FROM delayed_sends WHERE action_id = $1`, h.ActionID).Scan(&status); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					status = "missing"
					return nil
				}
				return err
			}
			return nil
		}
		if err != nil {
			return err
		}
		status = "cancelled_now"
		_, err = e.a.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventDelayedCancelled, Actor: actor,
			Data: map[string]any{"action_id": h.ActionID, "status": "cancelled", "by": "undo"}})
		return err
	})
	if err != nil {
		return nil, err
	}
	switch status {
	case "cancelled_now":
		return map[string]any{"cancelled": true, "note": "the message was not sent"}, nil
	case "sent", "sending":
		return nil, &notUndoableError{"already sent: NOT undoable"}
	case "cancelled":
		return nil, &notUndoableError{"already cancelled: nothing to undo"}
	case "failed":
		return nil, &notUndoableError{"the send failed earlier: nothing was sent, nothing to undo"}
	default:
		return nil, fmt.Errorf("%w: no queued message for this action", undo.ErrNothingToUndo)
	}
}

// deletePermission removes the Drive permission recorded at share time,
// acting as the same workspace user.
func (e *UndoExecutor) deletePermission(ctx context.Context, h undo.Handle) (map[string]any, error) {
	var d struct {
		FileID       string `json:"file_id"`
		PermissionID string `json:"permission_id"`
		Subject      string `json:"subject"`
	}
	if err := json.Unmarshal(h.Data, &d); err != nil || !segPattern.MatchString(d.FileID) || !segPattern.MatchString(d.PermissionID) || d.Subject == "" {
		return nil, errors.New("drive_permission handle is malformed")
	}
	s, err := e.a.settings(ctx)
	if err != nil {
		return nil, err
	}
	tok, err := e.a.tokens.token(ctx, s, mintRequest{agentID: h.AgentID, actionID: h.ActionID, subject: d.Subject, system: "drive",
		scopes: []string{ScopeDrive}})
	if err != nil {
		return nil, err
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	resp, err := gateway.Do(rctx, gateway.ProxyRequest{Client: e.a.client, Method: http.MethodDelete,
		URL: e.a.driveBase + "/drive/v3/files/" + url.PathEscape(d.FileID) + "/permissions/" + url.PathEscape(d.PermissionID) +
			"?supportsAllDrives=true",
		ForwardHeaders: []string{}, Authorization: "Bearer " + tok})
	if err != nil {
		// DELETE is idempotent: the handle is released and may be retried.
		return nil, err
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	resp.Body.Close()
	switch {
	case resp.StatusCode/100 == 2:
		return map[string]any{"deleted_permission": d.PermissionID, "file_id": d.FileID}, nil
	case resp.StatusCode == http.StatusNotFound:
		return nil, fmt.Errorf("%w: the permission no longer exists", undo.ErrNothingToUndo)
	default:
		return nil, fmt.Errorf("drive permissions.delete returned HTTP %d", resp.StatusCode)
	}
}

// BrokerAdapters exposes the gateway-held Google credentials to
// broker.RevokeAll, keyed by the systems their issuances are recorded under
// ("gmail" and "drive", the access-profile systems). Pass them in the broker's
// adapters map. Mint is unsupported: Google tokens never leave the gateway.
func (a *Adapter) BrokerAdapters() map[string]broker.Adapter {
	return map[string]broker.Adapter{"gmail": brokerAdapter{a, "gmail"}, "drive": brokerAdapter{a, "drive"}}
}

type brokerAdapter struct {
	a      *Adapter
	system string
}

func (b brokerAdapter) System() string { return b.system }

func (b brokerAdapter) Mint(context.Context, string, map[string]any, time.Duration) (broker.Credential, error) {
	return broker.Credential{}, broker.ErrUnsupported
}

// RevokeAgent drops the agent's cached tokens for this system. The tokens
// were never released to the agent, so nothing outside the gateway can use them.
func (b brokerAdapter) RevokeAgent(_ context.Context, agentID string) (string, error) {
	n := b.a.tokens.dropAgent(agentID, b.system)
	return fmt.Sprintf("%s: gateway-held Google tokens dropped (%d); tokens were never released to the agent", b.system, n), nil
}
