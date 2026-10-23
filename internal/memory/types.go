// Package memory protects agents' long-term (vector) memory (plan: "Remove
// memory access", undo #6 "memory write -> staging namespace, promoted after
// 10 minutes if no flag; drop staged vectors or restore the namespace
// snapshot"). Agents reach memory through Fortik's memory gateway (REST under
// /gw/memory/... and MCP memory tools via agentgateway); every read/write is
// decided. Data stays in the customer's store (Postgres + pgvector in the
// MVP); Fortik keeps pointers and metadata only.
package memory

import (
	"context"
	"time"
)

// Access modes per agent (memory_access table; default full).
const (
	AccessFull        = "full"
	AccessStagingOnly = "staging_only" // reads allowed; writes staged, held for review and never promoted while in this mode
	AccessNone        = "none"         // no memory reads or writes; memory frozen, not deleted
)

// Item is one memory record.
type Item struct {
	ID        string            `json:"id"`
	Namespace string            `json:"namespace"`
	Content   string            `json:"content"`
	Embedding []float32         `json:"embedding,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
	AgentID   string            `json:"agent_id"`
	Staged    bool              `json:"staged"`
	Flagged   bool              `json:"flagged"`
	CreatedAt time.Time         `json:"created_at"`
	PromoteAt *time.Time        `json:"promote_at,omitempty"`
	// HoldReason is set on a staged item that is held for review: it was
	// written while its writer's access was not full, or it came back
	// through a snapshot restore. A held item has no promote_at until the
	// promotion worker opens a fresh review window for it (once the writer
	// is back at full access).
	HoldReason string `json:"hold_reason,omitempty"`
	// ActionID is the gateway write that staged the item (internal: never
	// returned to agents).
	ActionID string `json:"-"`
}

// PolicyContext is input.context.memory.
type PolicyContext struct {
	Access string `json:"access"` // full | staging_only | none
}

// Store is the customer's vector store as Fortik uses it.
type Store interface {
	Write(ctx context.Context, it Item) (Item, error) // always into staging (Staged=true)
	Query(ctx context.Context, namespace string, embedding []float32, text string, limit int, includeStaged bool) ([]Item, error)
	Delete(ctx context.Context, namespace, id string) error
	Promote(ctx context.Context, now time.Time) (int, error)      // staged, unflagged, due -> live
	Flag(ctx context.Context, namespace, id, reason string) error // stop promotion
	DropStaged(ctx context.Context, namespace, id string) error   // undo of a staged write
	Snapshot(ctx context.Context, namespace string) (location string, count int, err error)
	Restore(ctx context.Context, namespace, location string) (int, error)
}
