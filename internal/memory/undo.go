package memory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"fortik/internal/undo"
)

// UndoExecutor reverses a staged memory write (undo kind memory_staging,
// plan undo #6): it drops the staged item. Once the item was promoted to
// long-term memory it is NOT undoable this way and the executor says so
// (restore a snapshot instead). Register it in api.Server.Executors under
// undo.KindMemoryStaging.
type UndoExecutor struct {
	stores StoreResolver
}

var _ undo.Executor = (*UndoExecutor)(nil)

// NewUndoExecutor builds the executor over the memory stores.
func NewUndoExecutor(stores StoreResolver) *UndoExecutor { return &UndoExecutor{stores: stores} }

func (e *UndoExecutor) Kinds() []string { return []string{undo.KindMemoryStaging} }

// Undo drops the staged item the handle's write staged (and tombstones it,
// so restoring a snapshot does not bring it back).
func (e *UndoExecutor) Undo(ctx context.Context, h undo.Handle) (map[string]any, error) {
	if h.Kind != undo.KindMemoryStaging {
		return nil, fmt.Errorf("%w: %s", undo.ErrUnsupported, h.Kind)
	}
	var d StagingUndo
	if err := json.Unmarshal(h.Data, &d); err != nil || d.Store == "" || d.Namespace == "" || d.ItemID == "" {
		return nil, fmt.Errorf("%w: memory_staging handle is incomplete", undo.ErrNothingToUndo)
	}
	st, err := e.stores.Store(ctx, d.Store)
	if err != nil {
		return nil, fmt.Errorf("memory store %s: %w", IntegrationKey(d.Store), err)
	}
	// The undo is bound to its own write: an item with the same id that a
	// different write staged (after a drop, DELETE or restore) is not touched.
	if d.ActionID != "" && d.ActionID != h.ActionID {
		return nil, fmt.Errorf("%w: memory_staging handle data names write %s, not %s", undo.ErrNothingToUndo, d.ActionID, h.ActionID)
	}
	it, err := st.DropStagedWrite(ctx, d.Namespace, d.ItemID, h.ActionID)
	switch {
	case errors.Is(err, ErrItemReplaced):
		return nil, fmt.Errorf("%w: memory item %s in %s/%s was staged by a different write, not by %s: nothing to undo (left untouched)", undo.ErrNothingToUndo, d.ItemID, d.Store, d.Namespace, h.ActionID)
	case errors.Is(err, ErrAlreadyPromoted):
		return nil, fmt.Errorf("%w: memory item %s was already promoted to long-term memory: NOT undoable by dropping staging (restore a snapshot instead)", undo.ErrNothingToUndo, d.ItemID)
	case errors.Is(err, ErrItemNotFound):
		return nil, fmt.Errorf("%w: staged memory item %s no longer exists in %s/%s (already dropped, deleted or replaced by a restore)", undo.ErrNothingToUndo, d.ItemID, d.Store, d.Namespace)
	case err != nil:
		return nil, err
	}
	return map[string]any{"dropped": true, "store": d.Store, "namespace": it.Namespace, "item_id": it.ID,
		"was_flagged": it.Flagged, "tombstoned": true,
		"note": "the staged memory write was dropped before promotion; restoring a snapshot does not bring it back"}, nil
}

// SnapshotPurger deletes memory snapshot tables from the customer's store for
// the retention worker (it satisfies retention.SnapshotPurger; pass it with
// retention.WithSnapshotPurger). A snapshot whose table is already gone is
// not an error; a store that cannot be reached is.
type SnapshotPurger struct {
	stores StoreResolver
}

// NewSnapshotPurger builds the purger over the memory stores.
func NewSnapshotPurger(stores StoreResolver) *SnapshotPurger { return &SnapshotPurger{stores: stores} }

// PurgeSnapshot drops the snapshot table at location in store memory:<name>.
func (p *SnapshotPurger) PurgeSnapshot(ctx context.Context, storeKey, _, location string) error {
	name, err := StoreNameFromKey(storeKey)
	if err != nil {
		return err
	}
	st, err := p.stores.Store(ctx, name)
	if err != nil {
		return err
	}
	return st.DropSnapshot(ctx, location)
}
