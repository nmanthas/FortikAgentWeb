// Package undo models undo handles. An undo handle is recorded BEFORE the
// action it reverses runs; Fortik never claims an undo it did not prepare.
package undo

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// Kinds supported in Phase 1 (the two Postgres kinds the proxy prepares).
// Later phases add drive_permission, gmail_delayed_send, github_ref, memory_staging.
const (
	KindPGRows   = "pg_rows_snapshot" // DELETE/UPDATE: affected rows copied to fortik_undo.* in the same transaction
	KindPGRename = "pg_rename"        // DROP/TRUNCATE rewritten to ALTER TABLE ... RENAME TO fortik_trash_*
)

// Status lifecycle: prepared -> active (action committed) | failed (action
// did not run / rolled back); active -> undoing (claimed by one undo request)
// -> used (undo succeeded) | active again (undo failed, error recorded);
// active -> expired (retention elapsed).
const (
	StatusPrepared = "prepared"
	StatusActive   = "active"
	StatusFailed   = "failed"
	StatusUndoing  = "undoing"
	StatusUsed     = "used"
	StatusExpired  = "expired"
)

// Handle is one row of undo_handles.
type Handle struct {
	ActionID  string          `json:"action_id"`
	AgentID   string          `json:"agent_id"`
	Kind      string          `json:"kind"`
	Data      json.RawMessage `json:"handle_json"`
	Status    string          `json:"status"`
	ExpiresAt time.Time       `json:"expires_at"`
	UsedAt    *time.Time      `json:"used_at,omitempty"`
	UsedBy    string          `json:"used_by,omitempty"`
	Error     string          `json:"error,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// PGRowsData is handle_json for KindPGRows.
type PGRowsData struct {
	Upstream       string   `json:"upstream"` // pgproxy upstream name (config key)
	Database       string   `json:"database"`
	Schema         string   `json:"schema"`
	Table          string   `json:"table"`
	SnapshotSchema string   `json:"snapshot_schema"` // always "fortik_undo"
	SnapshotTable  string   `json:"snapshot_table"`
	Op             string   `json:"op"`         // DELETE | UPDATE
	PKColumns      []string `json:"pk_columns"` // required to re-apply an UPDATE
	Statement      string   `json:"statement_fingerprint,omitempty"`
}

// PGRenameData is handle_json for KindPGRename.
type PGRenameData struct {
	Upstream   string `json:"upstream"`
	Database   string `json:"database"`
	Schema     string `json:"schema"`
	Table      string `json:"table"`
	TrashTable string `json:"trash_table"` // fortik_trash_<table>_<ts>
	Op         string `json:"op"`          // DROP | TRUNCATE
}

var (
	ErrNotFound    = errors.New("undo handle not found")
	ErrNotUndoable = errors.New("undo handle is not in an undoable state")
	ErrExpired     = errors.New("undo handle expired")
	ErrUnsupported = errors.New("undo kind not supported")
	// ErrOutcomeUnknown: the executor cannot tell whether its change committed
	// (e.g. the connection dropped during COMMIT). The handle must stay in
	// "undoing" for manual review — never retried automatically.
	ErrOutcomeUnknown = errors.New("undo outcome unknown")
	ErrNothingToUndo  = errors.New("nothing to undo: prepared state no longer exists (transaction rolled back or purged)")
)

// Store persists handles. Every state change also writes a Diary event.
type Store interface {
	Prepare(ctx context.Context, h Handle, actor string) error
	Activate(ctx context.Context, actionID string) error
	Fail(ctx context.Context, actionID, reason string) error
	Get(ctx context.Context, actionID string) (Handle, error)
	// Claim atomically moves active -> undoing and returns the handle. It
	// returns ErrNotUndoable if the handle is not active (so concurrent or
	// repeated undo requests cannot both run) and ErrExpired past expires_at.
	Claim(ctx context.Context, actionID, actor string) (Handle, error)
	// Complete moves undoing -> used and records the result in the Diary.
	Complete(ctx context.Context, actionID, actor string, result map[string]any) error
	// Release moves undoing -> active after a failed undo, recording the error.
	Release(ctx context.Context, actionID, actor, reason string) error
}

// Executor reverses one kind of handle against the real system.
type Executor interface {
	Kinds() []string
	Undo(ctx context.Context, h Handle) (map[string]any, error)
}
