package undo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
)

// PGStore is the Postgres implementation of Store.
type PGStore struct {
	pool  *pgxpool.Pool
	diary *diary.Diary
}

func NewPGStore(pool *pgxpool.Pool, d *diary.Diary) *PGStore { return &PGStore{pool: pool, diary: d} }

var _ Store = (*PGStore)(nil)

func (s *PGStore) Prepare(ctx context.Context, h Handle, actor string) error {
	if h.ActionID == "" || h.Kind == "" || len(h.Data) == 0 || h.ExpiresAt.IsZero() {
		return errors.New("undo prepare: action_id, kind, handle_json and expires_at are required")
	}
	if !json.Valid(h.Data) {
		return errors.New("undo prepare: handle_json is not valid JSON")
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			INSERT INTO undo_handles (action_id, agent_id, kind, handle_json, status, expires_at)
			VALUES ($1, $2, $3, $4, 'prepared', $5)`, h.ActionID, h.AgentID, h.Kind, h.Data, h.ExpiresAt); err != nil {
			return fmt.Errorf("undo prepare: %w", err)
		}
		var data map[string]any
		_ = json.Unmarshal(h.Data, &data)
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: h.AgentID, EventType: diary.EventUndoPrepared, Actor: actor,
			Data: map[string]any{"action_id": h.ActionID, "kind": h.Kind, "handle": data, "expires_at": h.ExpiresAt.UTC().Format(time.RFC3339)}})
		return err
	})
}

// transition moves one handle between states and writes a Diary event.
// usedBy: "" leaves used_by alone, "set" records actor as the (claiming or
// completing) user, "clear" resets it (a released claim).
func (s *PGStore) transition(ctx context.Context, actionID, from, to, eventType, actor string, extra map[string]any, setUsed bool, errText string, usedBy string) error {
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var agentID string
		q := `UPDATE undo_handles SET status = $3, error = NULLIF($4, '')`
		args := []any{actionID, from, to, errText}
		switch {
		case setUsed:
			q += `, used_at = now(), used_by = $5`
			args = append(args, actor)
		case usedBy == "set":
			q += `, used_by = $5`
			args = append(args, actor)
		case usedBy == "clear":
			q += `, used_by = NULL`
		}
		q += ` WHERE action_id = $1 AND status = $2 RETURNING agent_id`
		err := tx.QueryRow(ctx, q, args...).Scan(&agentID)
		if errors.Is(err, pgx.ErrNoRows) {
			return s.stateError(ctx, tx, actionID, from)
		}
		if err != nil {
			return err
		}
		data := map[string]any{"action_id": actionID, "from": from, "to": to}
		if errText != "" {
			data["error"] = errText
		}
		for k, v := range extra {
			data[k] = v
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: eventType, Actor: actor, Data: data})
		return err
	})
}

func (s *PGStore) stateError(ctx context.Context, tx pgx.Tx, actionID, want string) error {
	var status string
	err := tx.QueryRow(ctx, `SELECT status FROM undo_handles WHERE action_id = $1`, actionID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%w: status is %q, want %q", ErrNotUndoable, status, want)
}

func (s *PGStore) Activate(ctx context.Context, actionID string) error {
	return s.transition(ctx, actionID, StatusPrepared, StatusActive, diary.EventUndoActivated, "system:undo", nil, false, "", "")
}

func (s *PGStore) Fail(ctx context.Context, actionID, reason string) error {
	if reason == "" {
		reason = "action did not complete"
	}
	return s.transition(ctx, actionID, StatusPrepared, StatusFailed, diary.EventUndoVoided, "system:undo", nil, false, reason, "")
}

func (s *PGStore) Get(ctx context.Context, actionID string) (Handle, error) {
	var h Handle
	var usedBy, errText *string
	err := s.pool.QueryRow(ctx, `
		SELECT action_id, agent_id, kind, handle_json, status, expires_at, used_at, used_by, error, created_at
		FROM undo_handles WHERE action_id = $1`, actionID).
		Scan(&h.ActionID, &h.AgentID, &h.Kind, &h.Data, &h.Status, &h.ExpiresAt, &h.UsedAt, &usedBy, &errText, &h.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return Handle{}, ErrNotFound
	}
	if usedBy != nil {
		h.UsedBy = *usedBy
	}
	if errText != nil {
		h.Error = *errText
	}
	return h, err
}

func (s *PGStore) Claim(ctx context.Context, actionID, actor string) (Handle, error) {
	h, err := s.Get(ctx, actionID)
	if err != nil {
		return Handle{}, err
	}
	if h.Status == StatusActive && time.Now().After(h.ExpiresAt) {
		_ = s.transition(ctx, actionID, StatusActive, StatusExpired, diary.EventUndoExpired, actor, map[string]any{"expired": true}, false, "retention elapsed", "")
		return Handle{}, ErrExpired
	}
	if err := s.transition(ctx, actionID, StatusActive, StatusUndoing, diary.EventUndoClaimed, actor, nil, false, "", "set"); err != nil {
		return Handle{}, err
	}
	h.Status = StatusUndoing
	return h, nil
}

func (s *PGStore) Complete(ctx context.Context, actionID, actor string, result map[string]any) error {
	return s.transition(ctx, actionID, StatusUndoing, StatusUsed, diary.EventUndoExecuted, actor, map[string]any{"result": result}, true, "", "")
}

func (s *PGStore) Release(ctx context.Context, actionID, actor, reason string) error {
	return s.transition(ctx, actionID, StatusUndoing, StatusActive, diary.EventUndoFailed, actor, nil, false, reason, "clear")
}

// List returns recent handles (newest first) for the Undo list.
func (s *PGStore) List(ctx context.Context, agentID string, limit int) ([]Handle, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT action_id, agent_id, kind, handle_json, status, expires_at, used_at, COALESCE(used_by,''), COALESCE(error,''), created_at
		FROM undo_handles WHERE ($1 = '' OR agent_id = $1) ORDER BY created_at DESC LIMIT $2`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Handle
	for rows.Next() {
		var h Handle
		if err := rows.Scan(&h.ActionID, &h.AgentID, &h.Kind, &h.Data, &h.Status, &h.ExpiresAt, &h.UsedAt, &h.UsedBy, &h.Error, &h.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}
