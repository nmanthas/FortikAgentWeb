package memory

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/undo"
)

// Diary event types written by the memory package.
const (
	EventAccessChanged   = "memory.access_changed"
	EventSnapshotCreated = "memory.snapshot_created"
	EventRestored        = "memory.restored"
	EventItemFlagged     = "memory.item_flagged"
	EventItemDropped     = "memory.item_dropped"
	EventItemDeleted     = "memory.item_deleted"
	EventPromoted        = "memory.promoted"
	EventReviewWindow    = "memory.review_window_opened"
	EventSnapshotUnclean = "memory.snapshot_marked_unclean"
)

// SystemActor is the Diary actor of the memory workers.
const SystemActor = "system:memory"

var (
	ErrAgentNotFound    = errors.New("agent not registered")
	ErrSnapshotNotFound = errors.New("memory snapshot not found")
	ErrSnapshotPurged   = errors.New("memory snapshot was purged (retention elapsed)")
	ErrSnapshotNotClean = errors.New("memory snapshot is not clean (it contains a flagged or an unreviewed staged item, or is a pre-restore copy)")
	// ErrNotRecorded: a change was applied in the customer's store but its
	// Diary record could not be written (retried once). The change stands.
	ErrNotRecorded = errors.New("applied but not recorded in the Diary")
)

// Forbidden is an authorization refusal raised by an Authorize callback.
type Forbidden string

func (f Forbidden) Error() string { return string(f) }

// Authorize decides whether the caller may act on an item written by
// writerAgentID (security, or the writer's owner). It runs before anything
// changes.
type Authorize func(ctx context.Context, writerAgentID string) error

// AccessState is an agent's memory access (memory_access; default full).
type AccessState struct {
	AgentID   string     `json:"agent_id"`
	Mode      string     `json:"mode"`
	Reason    string     `json:"reason,omitempty"`
	ChangedBy string     `json:"changed_by,omitempty"`
	ChangedAt *time.Time `json:"changed_at,omitempty"`
}

// AccessChange is what SetAccess actually did.
type AccessChange struct {
	AgentID string `json:"agent_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Changed bool   `json:"changed"` // false: the agent already had this mode (idempotent no-op)
	// HeldForReview (back to full only): the agent's staged items held for
	// review (written while its access was not full, or restored from a
	// snapshot). They are NOT promoted at once: the next promotion pass gives
	// each a fresh review window of promotion_delay.
	HeldForReview []StagedItem `json:"held_for_review,omitempty"`
	// HeldCheckError says why HeldForReview may be incomplete.
	HeldCheckError string `json:"held_check_error,omitempty"`
}

// Snapshot is a memory_snapshots row: a pointer to a snapshot table in the
// customer's store.
type Snapshot struct {
	SnapshotID string     `json:"snapshot_id"`
	Store      string     `json:"store"`
	StoreKey   string     `json:"store_key"`
	Namespace  string     `json:"namespace"`
	ItemCount  int        `json:"item_count"`
	Clean      bool       `json:"clean"`
	Location   string     `json:"location"`
	CreatedBy  string     `json:"created_by"`
	Reason     string     `json:"reason"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	PurgedAt   *time.Time `json:"purged_at,omitempty"`
}

// RestoreResult is what a restore did.
type RestoreResult struct {
	Snapshot Snapshot `json:"snapshot"`
	// PreRestore is the namespace as it stood right before the restore
	// (restore it to undo this restore). It is never clean.
	PreRestore Snapshot `json:"pre_restore_snapshot"`
	Restored   int      `json:"restored"`
	// SkippedRemoved are items of the snapshot removed on purpose since
	// (staging undo, drop, DELETE): not restored.
	SkippedRemoved []string `json:"skipped_removed_items"`
	// HeldForReview are restored staged items: held, not promoted, until a
	// fresh review window opens for them (see PromoteDue).
	HeldForReview []Held `json:"held_for_review"`
	// UndoHandlesClosed are staging undo handles of writes the restore removed.
	UndoHandlesClosed []string `json:"undo_handles_closed"`
}

// Service is Fortik's side of memory protection: per-agent access modes,
// snapshot pointers, flags, promotion and the Diary. Item data stays in the
// customer's stores (StoreResolver).
type Service struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	stores StoreResolver
	cfg    config.MemoryConfig
	log    *slog.Logger
	Now    func() time.Time
	// StoreTimeout bounds each call into a customer store from the workers
	// (default 30s).
	StoreTimeout time.Duration
}

// NewService builds the memory service. cfg is config.Config.Memory.
func NewService(pool *pgxpool.Pool, d *diary.Diary, stores StoreResolver, cfg config.MemoryConfig, log *slog.Logger) (*Service, error) {
	if pool == nil || d == nil || stores == nil {
		return nil, errors.New("memory: pool, diary and stores are required")
	}
	if cfg.PromotionDelay <= 0 {
		cfg.PromotionDelay = 10 * time.Minute
	}
	if cfg.SnapshotRetention <= 0 {
		cfg.SnapshotRetention = 30 * 24 * time.Hour
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: pool, diary: d, stores: stores, cfg: cfg, log: log, StoreTimeout: 30 * time.Second}, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Stores returns the store resolver.
func (s *Service) Stores() StoreResolver { return s.stores }

// Config returns the memory configuration in force.
func (s *Service) Config() config.MemoryConfig { return s.cfg }

// ---- access ------------------------------------------------------------------

// accessLock serialises access changes against promotion passes: a pass holds
// it shared while it reads the blocked writers and promotes, a change takes
// it exclusively. Once SetAccess returns, no pass can promote with the old mode.
const accessLock = `SELECT pg_catalog.pg_advisory_xact_lock%s(pg_catalog.hashtextextended('fortik.memory.access', 0))`

// ValidMode reports whether mode is full, staging_only or none.
func ValidMode(mode string) bool {
	return mode == AccessFull || mode == AccessStagingOnly || mode == AccessNone
}

// Access returns an agent's memory access (full when never changed).
func (s *Service) Access(ctx context.Context, agentID string) (AccessState, error) {
	return accessOf(ctx, s.pool, agentID)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func accessOf(ctx context.Context, q querier, agentID string) (AccessState, error) {
	st := AccessState{AgentID: agentID, Mode: AccessFull}
	var at time.Time
	err := q.QueryRow(ctx, `SELECT mode, reason, changed_by, changed_at FROM memory_access WHERE agent_id = $1`, agentID).
		Scan(&st.Mode, &st.Reason, &st.ChangedBy, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		return st, nil
	}
	if err != nil {
		return AccessState{}, fmt.Errorf("memory access for %s: %w", agentID, err)
	}
	st.ChangedAt = &at
	return st, nil
}

// SetAccess sets an agent's memory access mode (containment memory_remove /
// memory_restore; it implements containment.MemoryAccess). With a non-nil tx
// the change and its memory.access_changed Diary event are made inside the
// caller's transaction (the caller commits); with a nil tx in their own.
// Setting the mode an agent already has is a no-op.
func (s *Service) SetAccess(ctx context.Context, tx pgx.Tx, agentID, mode, actor, reason string) error {
	_, err := s.changeAccess(ctx, tx, agentID, mode, actor, reason)
	return err
}

// ChangeAccess is SetAccess in its own transaction, reporting what changed.
func (s *Service) ChangeAccess(ctx context.Context, agentID, mode, actor, reason string) (AccessChange, error) {
	return s.changeAccess(ctx, nil, agentID, mode, actor, reason)
}

func (s *Service) changeAccess(ctx context.Context, tx pgx.Tx, agentID, mode, actor, reason string) (AccessChange, error) {
	if !ValidMode(mode) {
		return AccessChange{}, invalidf("memory access mode must be full, staging_only or none")
	}
	if agentID == "" || actor == "" {
		return AccessChange{}, invalidf("agent and actor are required")
	}
	if strings.TrimSpace(reason) == "" {
		return AccessChange{}, invalidf("a reason is required to change memory access")
	}
	ch := AccessChange{AgentID: agentID, To: mode}
	apply := func(tx pgx.Tx) error {
		// Lock order (same as containment's memory step): the agent's
		// memory_access row, then the promotion lock, then agents, then the
		// Diary head. A first change has no row to lock; the promotion lock
		// serialises concurrent first changes.
		if _, err := tx.Exec(ctx, `SELECT 1 FROM memory_access WHERE agent_id = $1 FOR UPDATE`, agentID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, fmt.Sprintf(accessLock, "")); err != nil {
			return err
		}
		var one int
		err := tx.QueryRow(ctx, `SELECT 1 FROM agents WHERE agent_id = $1 FOR KEY SHARE`, agentID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrAgentNotFound
		}
		if err != nil {
			return err
		}
		cur, err := accessOf(ctx, tx, agentID)
		if err != nil {
			return err
		}
		ch.From = cur.Mode
		if cur.Mode == mode {
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO memory_access (agent_id, mode, reason, changed_by, changed_at)
			VALUES ($1, $2, $3, $4, now())
			ON CONFLICT (agent_id) DO UPDATE SET mode = EXCLUDED.mode, reason = EXCLUDED.reason,
				changed_by = EXCLUDED.changed_by, changed_at = EXCLUDED.changed_at`, agentID, mode, reason, actor); err != nil {
			return err
		}
		ch.Changed = true
		data := map[string]any{"from": cur.Mode, "to": mode, "reason": reason, "promotion": promotionNote(mode)}
		if mode == AccessFull {
			// Writes made while access was not full are held for review, not
			// promoted at once: report them so the operator can flag or drop.
			hctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			held, herr := s.PendingReview(hctx, agentID)
			cancel()
			ch.HeldForReview = held
			ids := make([]string, 0, min(len(held), 100))
			for i, h := range held {
				if i < 100 {
					ids = append(ids, h.Store+"/"+h.Namespace+"/"+h.ID)
				}
			}
			data["held_for_review"] = ids
			data["held_for_review_count"] = len(held)
			if herr != nil {
				ch.HeldCheckError = sanitize(herr)
				data["held_check_error"] = ch.HeldCheckError
			}
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventAccessChanged, Actor: actor, Data: data})
		return err
	}
	var err error
	if tx != nil {
		err = apply(tx)
	} else {
		err = pgx.BeginFunc(ctx, s.pool, apply)
	}
	if err != nil {
		return AccessChange{}, err
	}
	return ch, nil
}

func promotionNote(mode string) string {
	switch mode {
	case AccessNone:
		return "no memory reads or writes; staged items are not promoted; existing memory is frozen, not deleted"
	case AccessStagingOnly:
		return "reads allowed; writes are staged and held for review: not promoted while in this mode, and given a fresh review window (not promoted at once) when access returns to full"
	default:
		return "reads and staged writes; due unflagged items are promoted; items held for review get a fresh review window first"
	}
}

// PendingReview lists the agent's unflagged staged items that are held for
// review (written while its access was not full, or restored from a
// snapshot), in every store. Unreachable stores are reported in the error;
// the items of the others are still returned.
func (s *Service) PendingReview(ctx context.Context, agentID string) ([]StagedItem, error) {
	names, err := s.stores.Names(ctx)
	if err != nil {
		return []StagedItem{}, err
	}
	out := []StagedItem{}
	var errs []error
	for _, name := range names {
		st, err := s.stores.Store(ctx, name)
		var items []Item
		if err == nil {
			items, err = st.HeldBy(ctx, agentID, 500)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", IntegrationKey(name), err))
			continue
		}
		for _, it := range items {
			out = append(out, stagedItem(name, it))
		}
	}
	return out, errors.Join(errs...)
}

// recordApplied writes the record of a change already applied in a customer
// store, in one Fortik transaction, retrying once on a fresh context so a
// cancelled request cannot leave the change unrecorded.
func (s *Service) recordApplied(ctx context.Context, what string, fn func(ctx context.Context, tx pgx.Tx) error) error {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error { return fn(ctx, tx) })
	if err == nil {
		return nil
	}
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err2 := pgx.BeginFunc(rctx, s.pool, func(tx pgx.Tx) error { return fn(rctx, tx) }); err2 != nil {
		s.log.Error("memory change APPLIED but not recorded in the Diary", "what", what, "err", err2, "first_err", err)
		return fmt.Errorf("%s: %w: %v", what, ErrNotRecorded, err2)
	}
	return nil
}

// expireStagingUndoTx marks the active memory_staging undo handles of the
// given writes expired (their staged item is gone, so there is nothing left
// to undo) and records an undo.expired event for each, in tx.
func (s *Service) expireStagingUndoTx(ctx context.Context, tx pgx.Tx, actionIDs []string, note, actor string) ([]string, error) {
	closed := []string{}
	if len(actionIDs) == 0 {
		return closed, nil
	}
	rows, err := tx.Query(ctx, `UPDATE undo_handles SET status = $3, error = $4
		WHERE action_id = ANY($1) AND kind = $2 AND status = $5 RETURNING action_id, agent_id`,
		actionIDs, undo.KindMemoryStaging, undo.StatusExpired, note, undo.StatusActive)
	if err != nil {
		return nil, err
	}
	type handle struct{ action, agent string }
	hs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (handle, error) {
		var h handle
		return h, r.Scan(&h.action, &h.agent)
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(hs, func(i, j int) bool { return hs[i].action < hs[j].action })
	events := make([]diary.Event, 0, len(hs))
	for _, h := range hs {
		closed = append(closed, h.action)
		events = append(events, diary.Event{AgentID: h.agent, EventType: diary.EventUndoExpired, Actor: actor, Data: map[string]any{
			"action_id": h.action, "kind": undo.KindMemoryStaging, "from": undo.StatusActive, "to": undo.StatusExpired,
			"error": note, "expired": true}})
	}
	if _, err := s.diary.AppendTx(ctx, tx, events...); err != nil {
		return nil, err
	}
	return closed, nil
}

// ---- snapshots -----------------------------------------------------------------

const snapCols = `snapshot_id, store_key, namespace, item_count, clean, location, created_by, reason, created_at, expires_at, purged_at`

func scanSnapshot(row pgx.Row) (Snapshot, error) {
	var sn Snapshot
	if err := row.Scan(&sn.SnapshotID, &sn.StoreKey, &sn.Namespace, &sn.ItemCount, &sn.Clean, &sn.Location, &sn.CreatedBy,
		&sn.Reason, &sn.CreatedAt, &sn.ExpiresAt, &sn.PurgedAt); err != nil {
		return Snapshot{}, err
	}
	sn.Store = strings.TrimPrefix(sn.StoreKey, KeyPrefix)
	return sn, nil
}

func newSnapshotID() (id, location string) {
	id = action.NewID("msnap")
	location, _ = SnapshotLocation(strings.ToLower(strings.TrimPrefix(id, "msnap_")))
	return id, location
}

// CreateSnapshot copies a namespace into a new snapshot table in the store
// and records the pointer. It is clean (a rollback target) only when no item
// in the namespace is flagged and none is staged (unreviewed).
func (s *Service) CreateSnapshot(ctx context.Context, store, namespace, actor, reason string) (Snapshot, error) {
	if actor == "" {
		return Snapshot{}, invalidf("actor is required")
	}
	if !ValidNamespace(namespace) {
		return Snapshot{}, invalidf("namespace must match %s", namespacePattern)
	}
	st, err := s.stores.Store(ctx, store)
	if err != nil {
		return Snapshot{}, err
	}
	id, loc := newSnapshotID()
	info, err := st.SnapshotTo(ctx, namespace, loc)
	if err != nil {
		return Snapshot{}, err
	}
	sn, err := s.recordSnapshot(ctx, id, st.Key(), namespace, info, actor, reason)
	if err != nil {
		// Do not leave an untracked copy of the data behind.
		dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		if derr := st.DropSnapshot(dctx, loc); derr != nil {
			s.log.Error("memory: snapshot taken but not recorded, and dropping it failed; drop it manually",
				"store", st.Key(), "location", loc, "err", derr)
		}
		return Snapshot{}, err
	}
	return sn, nil
}

func (s *Service) recordSnapshot(ctx context.Context, id, storeKey, namespace string, info SnapshotInfo, actor, reason string) (Snapshot, error) {
	var sn Snapshot
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		sn, err = s.insertSnapshotTx(ctx, tx, id, storeKey, namespace, info, info.Clean(), "", actor, reason)
		return err
	})
	return sn, err
}

// insertSnapshotTx records a snapshot pointer and its Diary event in tx.
// kind is "" or "pre_restore" (never clean).
func (s *Service) insertSnapshotTx(ctx context.Context, tx pgx.Tx, id, storeKey, namespace string, info SnapshotInfo, clean bool, kind, actor, reason string) (Snapshot, error) {
	sn, err := scanSnapshot(tx.QueryRow(ctx, `INSERT INTO memory_snapshots
		(snapshot_id, store_key, namespace, item_count, clean, location, created_by, reason, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING `+snapCols,
		id, storeKey, namespace, info.Count, clean, info.Location, actor, reason, s.now().Add(s.cfg.SnapshotRetention)))
	if err != nil {
		return Snapshot{}, err
	}
	data := map[string]any{
		"snapshot_id": sn.SnapshotID, "store": storeKey, "namespace": namespace, "item_count": info.Count,
		"clean": sn.Clean, "flagged_items": info.Flagged, "staged_items": info.Staged, "location": info.Location, "reason": reason,
		"expires_at": sn.ExpiresAt.UTC().Format(time.RFC3339)}
	if kind != "" {
		data["kind"] = kind
	}
	if !sn.Clean {
		data["unclean_because"] = uncleanBecause(info, kind)
	}
	_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventSnapshotCreated, Actor: actor, Data: data})
	return sn, err
}

func uncleanBecause(info SnapshotInfo, kind string) string {
	var why []string
	if kind == "pre_restore" {
		why = append(why, "pre-restore copy (the state being rolled back)")
	}
	if info.Flagged > 0 {
		why = append(why, fmt.Sprintf("%d flagged item(s)", info.Flagged))
	}
	if info.Staged > 0 {
		why = append(why, fmt.Sprintf("%d staged item(s) not yet reviewed", info.Staged))
	}
	return strings.Join(why, "; ")
}

// SnapshotFilter narrows ListSnapshots.
type SnapshotFilter struct {
	Store         string
	Namespace     string
	CleanOnly     bool
	IncludePurged bool
	Limit         int
}

// ListSnapshots returns snapshot pointers, newest first.
func (s *Service) ListSnapshots(ctx context.Context, f SnapshotFilter) ([]Snapshot, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	key := ""
	if f.Store != "" {
		if !ValidStoreName(f.Store) {
			return nil, invalidf("store name must match %s", storeName)
		}
		key = IntegrationKey(f.Store)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+snapCols+` FROM memory_snapshots
		WHERE ($1 = '' OR store_key = $1) AND ($2 = '' OR namespace = $2) AND (NOT $3 OR clean) AND ($4 OR purged_at IS NULL)
		ORDER BY created_at DESC, snapshot_id DESC LIMIT $5`, key, f.Namespace, f.CleanOnly, f.IncludePurged, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Snapshot{}
	for rows.Next() {
		sn, err := scanSnapshot(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sn)
	}
	return out, rows.Err()
}

// GetSnapshot returns one snapshot pointer.
func (s *Service) GetSnapshot(ctx context.Context, id string) (Snapshot, error) {
	sn, err := scanSnapshot(s.pool.QueryRow(ctx, `SELECT `+snapCols+` FROM memory_snapshots WHERE snapshot_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Snapshot{}, ErrSnapshotNotFound
	}
	return sn, err
}

// LastCleanSnapshot returns the newest clean, unpurged snapshot of a namespace.
func (s *Service) LastCleanSnapshot(ctx context.Context, store, namespace string) (Snapshot, error) {
	list, err := s.ListSnapshots(ctx, SnapshotFilter{Store: store, Namespace: namespace, CleanOnly: true, Limit: 1})
	if err != nil {
		return Snapshot{}, err
	}
	if len(list) == 0 {
		return Snapshot{}, ErrSnapshotNotFound
	}
	return list[0], nil
}

// RestoreSnapshot replaces the snapshot's namespace with its contents. A
// pre-restore snapshot is taken first (restoring it undoes this restore).
// Clean or not: security decides (e.g. undoing a restore).
func (s *Service) RestoreSnapshot(ctx context.Context, snapshotID, actor, reason string) (RestoreResult, error) {
	return s.restore(ctx, snapshotID, actor, reason, false)
}

// RollbackToSnapshot rolls a namespace back to a clean snapshot (containment
// memory_restore with rollback_snapshot_id). A snapshot that contains a
// flagged item is refused (ErrSnapshotNotClean).
func (s *Service) RollbackToSnapshot(ctx context.Context, snapshotID, actor, reason string) error {
	_, err := s.restore(ctx, snapshotID, actor, reason, true)
	return err
}

// Rollback is RollbackToSnapshot reporting what was restored.
func (s *Service) Rollback(ctx context.Context, snapshotID, actor, reason string) (RestoreResult, error) {
	return s.restore(ctx, snapshotID, actor, reason, true)
}

func (s *Service) restore(ctx context.Context, snapshotID, actor, reason string, cleanOnly bool) (RestoreResult, error) {
	if actor == "" {
		return RestoreResult{}, invalidf("actor is required")
	}
	if strings.TrimSpace(reason) == "" {
		return RestoreResult{}, invalidf("a reason is required to restore memory")
	}
	sn, err := s.GetSnapshot(ctx, snapshotID)
	if err != nil {
		return RestoreResult{}, err
	}
	if sn.PurgedAt != nil {
		return RestoreResult{}, ErrSnapshotPurged
	}
	if cleanOnly && !sn.Clean {
		return RestoreResult{}, ErrSnapshotNotClean
	}
	st, err := s.stores.Store(ctx, sn.Store)
	if err != nil {
		return RestoreResult{}, err
	}
	// The pre-restore copy, the replacement and the hold of restored staged
	// items are one transaction in the customer's store under the exclusive
	// namespace lock: no write lands in between, and a failure leaves
	// nothing behind (no orphan pre-restore copy).
	preID, preLoc := newSnapshotID()
	out, err := st.RestoreNamespace(ctx, RestoreSpec{Namespace: sn.Namespace, Location: sn.Location, BackupLocation: preLoc,
		CleanOnly: cleanOnly, HoldReason: "restored from snapshot " + sn.SnapshotID + ": held for review"})
	switch {
	case errors.Is(err, ErrSnapshotMissing):
		return RestoreResult{}, fmt.Errorf("%w (%s); nothing was restored", err, sn.Location)
	case errors.Is(err, ErrSnapshotNotClean):
		if sn.Clean {
			s.markUnclean(ctx, sn, actor, err.Error())
		}
		return RestoreResult{}, fmt.Errorf("%w; nothing was restored", err)
	case errors.Is(err, ErrInvalid):
		return RestoreResult{}, fmt.Errorf("%w; nothing was restored", err)
	case err != nil:
		return RestoreResult{}, err // the store's transaction failed (it rolls back as a whole)
	}
	res := RestoreResult{Snapshot: sn, Restored: out.Restored, SkippedRemoved: nonNilStrings(out.Skipped),
		HeldForReview: out.Held, UndoHandlesClosed: []string{}}
	if res.HeldForReview == nil {
		res.HeldForReview = []Held{}
	}
	heldIDs := make([]string, 0, min(len(out.Held), 100))
	for i, h := range out.Held {
		if i < 100 {
			heldIDs = append(heldIDs, h.ID)
		}
	}
	// The restore committed in the customer's store; record the pre-restore
	// pointer (never clean: it is the state being rolled back), the undo
	// handles it voided and the restore itself, in one Fortik transaction.
	err = s.recordApplied(ctx, "memory restore of "+sn.SnapshotID, func(ctx context.Context, tx pgx.Tx) error {
		pre, err := s.insertSnapshotTx(ctx, tx, preID, sn.StoreKey, sn.Namespace, out.Backup, false, "pre_restore", actor,
			"pre-restore of "+sn.SnapshotID+": "+reason)
		if err != nil {
			return err
		}
		closed, err := s.expireStagingUndoTx(ctx, tx, out.RemovedWrites,
			"staged item removed by the restore of memory snapshot "+sn.SnapshotID+": nothing left to undo", actor)
		if err != nil {
			return err
		}
		res.PreRestore, res.UndoHandlesClosed = pre, closed
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventRestored, Actor: actor, Data: map[string]any{
			"snapshot_id": sn.SnapshotID, "store": sn.StoreKey, "namespace": sn.Namespace, "restored_items": out.Restored,
			"replaced_items": out.Backup.Count, "pre_restore_snapshot_id": pre.SnapshotID, "clean": sn.Clean, "clean_only": cleanOnly,
			"skipped_removed_items": res.SkippedRemoved, "held_for_review": heldIDs, "held_for_review_count": len(out.Held),
			"undo_handles_closed": closed, "reason": reason}})
		return err
	})
	if err != nil {
		// The pre-restore copy exists in the store; keep its location in the
		// error so it can be found.
		return res, fmt.Errorf("memory restore was applied (pre-restore copy at %s): %w", preLoc, err)
	}
	return res, nil
}

// markUnclean corrects a snapshot pointer recorded clean whose data is not
// (a pointer written by an earlier version). Best effort: the restore was
// refused either way.
func (s *Service) markUnclean(ctx context.Context, sn Snapshot, actor, why string) {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE memory_snapshots SET clean = false WHERE snapshot_id = $1 AND clean`, sn.SnapshotID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventSnapshotUnclean, Actor: actor, Data: map[string]any{
			"snapshot_ids": []string{sn.SnapshotID}, "store": sn.StoreKey, "namespace": sn.Namespace, "reason": why}})
		return err
	})
	if err != nil {
		s.log.Error("memory: could not mark a snapshot unclean", "snapshot_id", sn.SnapshotID, "err", err)
	}
}

func nonNilStrings(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// ---- items ---------------------------------------------------------------------

// FlagResult is what flagging an item did.
type FlagResult struct {
	Item             Item     `json:"item"`
	SnapshotsUnclean []string `json:"snapshots_marked_unclean"`
	PromotionStopped bool     `json:"promotion_stopped"`
	AlreadyPromoted  bool     `json:"already_promoted"`
	// SnapshotCheckError: the snapshots holding the item could not be
	// determined, so every candidate snapshot was marked unclean.
	SnapshotCheckError string `json:"snapshot_check_error,omitempty"`
}

// FlagItem flags an item: it is never promoted, agents stop seeing it, and
// every snapshot that contains it is marked not clean.
func (s *Service) FlagItem(ctx context.Context, store, namespace, id, actor, reason string, authorize Authorize) (FlagResult, error) {
	if strings.TrimSpace(reason) == "" {
		return FlagResult{}, invalidf("a reason is required to flag a memory item")
	}
	st, err := s.stores.Store(ctx, store)
	if err != nil {
		return FlagResult{}, err
	}
	cur, err := st.Get(ctx, namespace, id)
	if err != nil {
		return FlagResult{}, err
	}
	if authorize != nil {
		if err := authorize(ctx, cur.AgentID); err != nil {
			return FlagResult{}, err
		}
	}
	it, err := st.FlagItem(ctx, namespace, id, reason)
	if err != nil {
		return FlagResult{}, err
	}
	// The flag is applied from here on: it is always recorded, whatever
	// happens while looking for the snapshots that contain the item.
	res := FlagResult{Item: redact(it), PromotionStopped: it.Staged, AlreadyPromoted: !it.Staged, SnapshotsUnclean: []string{}}
	since := it.CreatedAt.Add(-time.Hour)
	contain, checkErr := s.snapshotsWith(ctx, st, namespace, id, since)
	err = s.recordApplied(ctx, "memory flag of "+namespace+"/"+id, func(ctx context.Context, tx pgx.Tx) error {
		res.SnapshotsUnclean = []string{}
		var rows pgx.Rows
		var err error
		switch {
		case checkErr != nil:
			// Could not tell which snapshots hold the item: mark every
			// candidate unclean (fail closed).
			rows, err = tx.Query(ctx, `UPDATE memory_snapshots SET clean = false
				WHERE store_key = $1 AND namespace = $2 AND clean AND purged_at IS NULL AND created_at >= $3 RETURNING snapshot_id`,
				st.Key(), namespace, since)
		case len(contain) > 0:
			rows, err = tx.Query(ctx, `UPDATE memory_snapshots SET clean = false WHERE snapshot_id = ANY($1) AND clean RETURNING snapshot_id`, contain)
		}
		if err != nil {
			return err
		}
		if rows != nil {
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			sort.Strings(ids)
			res.SnapshotsUnclean = append(res.SnapshotsUnclean, ids...)
		}
		data := map[string]any{
			"store": st.Key(), "namespace": namespace, "item_id": id, "writer": it.AgentID, "staged": it.Staged,
			"promotion_stopped": it.Staged, "snapshots_marked_unclean": res.SnapshotsUnclean, "reason": reason}
		if checkErr != nil {
			res.SnapshotCheckError = sanitize(checkErr)
			data["snapshot_check_error"] = res.SnapshotCheckError
			data["snapshots_marked_unclean_pessimistically"] = true
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: it.AgentID, EventType: EventItemFlagged, Actor: actor, Data: data})
		return err
	})
	if err != nil {
		return res, fmt.Errorf("the item was flagged (promotion stopped, hidden from agents) but %w", err)
	}
	return res, nil
}

// snapshotsWith returns the clean, unpurged snapshots of the namespace taken
// since since that hold item id: candidates by time (with margin for clock
// skew between Fortik and the store), confirmed in each snapshot table.
func (s *Service) snapshotsWith(ctx context.Context, st *PGStore, namespace, id string, since time.Time) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT snapshot_id, location FROM memory_snapshots
		WHERE store_key = $1 AND namespace = $2 AND clean AND purged_at IS NULL AND created_at >= $3`, st.Key(), namespace, since)
	if err != nil {
		return nil, err
	}
	type cand struct{ id, loc string }
	list, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cand, error) {
		var c cand
		return c, r.Scan(&c.id, &c.loc)
	})
	if err != nil {
		return nil, err
	}
	var contain []string
	for _, c := range list {
		ok, err := st.SnapshotContains(ctx, c.loc, id)
		if err != nil {
			return nil, fmt.Errorf("snapshot %s: %w", c.id, err)
		}
		if ok {
			contain = append(contain, c.id)
		}
	}
	return contain, nil
}

// DropItem removes a staged item (security or the writer's owner). A
// promoted item is refused with ErrAlreadyPromoted.
func (s *Service) DropItem(ctx context.Context, store, namespace, id, actor, reason string, authorize Authorize) (Item, error) {
	if strings.TrimSpace(reason) == "" {
		return Item{}, invalidf("a reason is required to drop a memory item")
	}
	st, err := s.stores.Store(ctx, store)
	if err != nil {
		return Item{}, err
	}
	cur, err := st.Get(ctx, namespace, id)
	if err != nil {
		return Item{}, err
	}
	if authorize != nil {
		if err := authorize(ctx, cur.AgentID); err != nil {
			return Item{}, err
		}
	}
	it, err := st.DropStagedItem(ctx, namespace, id)
	if err != nil {
		return Item{}, err
	}
	// Dropped and tombstoned (a snapshot restore does not bring it back).
	// The write's staging undo handle has nothing left to undo: close it with
	// the drop's Diary event.
	err = s.recordApplied(ctx, "memory drop of "+namespace+"/"+id, func(ctx context.Context, tx pgx.Tx) error {
		closed, err := s.expireStagingUndoTx(ctx, tx, nonEmpty(it.ActionID), "staged item dropped via the memory API: nothing left to undo", actor)
		if err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: it.AgentID, EventType: EventItemDropped, Actor: actor, Data: map[string]any{
			"store": st.Key(), "namespace": namespace, "item_id": id, "writer": it.AgentID, "flagged": it.Flagged,
			"write_action_id": it.ActionID, "undo_handles_closed": closed, "tombstoned": true, "reason": reason}})
		return err
	})
	if err != nil {
		return redact(it), fmt.Errorf("staged item was dropped but %w", err)
	}
	return redact(it), nil
}

// RecordDeleted records a gateway DELETE that removed it (and tombstoned it)
// and closes the staging undo handle of the write that staged it, in one
// transaction.
func (s *Service) RecordDeleted(ctx context.Context, storeKey string, it Item, deleteActionID, agentID, actor string) error {
	return s.recordApplied(ctx, "memory delete of "+it.Namespace+"/"+it.ID, func(ctx context.Context, tx pgx.Tx) error {
		var closed []string
		if it.Staged {
			var err error
			if closed, err = s.expireStagingUndoTx(ctx, tx, nonEmpty(it.ActionID), "staged item deleted through the memory gateway (action "+deleteActionID+"): nothing left to undo", actor); err != nil {
				return err
			}
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventItemDeleted, Actor: actor, Data: map[string]any{
			"store": storeKey, "namespace": it.Namespace, "item_id": it.ID, "writer": it.AgentID, "was_staged": it.Staged,
			"action_id": deleteActionID, "write_action_id": it.ActionID, "undo_handles_closed": nonNilStrings(closed), "tombstoned": true}})
		return err
	})
}

func nonEmpty(ids ...string) []string {
	out := []string{}
	for _, id := range ids {
		if id != "" {
			out = append(out, id)
		}
	}
	return out
}

// redact drops the embedding (never returned by management APIs).
func redact(it Item) Item {
	it.Embedding = nil
	return it
}

// StagedItem summarises a staged item for the console (content is a preview).
type StagedItem struct {
	Store     string     `json:"store"`
	ID        string     `json:"id"`
	Namespace string     `json:"namespace"`
	Preview   string     `json:"content_preview"`
	Bytes     int        `json:"bytes"`
	Labels    []string   `json:"labels,omitempty"`
	Flagged   bool       `json:"flagged"`
	CreatedAt time.Time  `json:"created_at"`
	PromoteAt *time.Time `json:"promote_at,omitempty"`
	// HoldReason: held for review (no promote_at until a review window opens).
	HoldReason string `json:"hold_reason,omitempty"`
}

func stagedItem(store string, it Item) StagedItem {
	return StagedItem{Store: store, ID: it.ID, Namespace: it.Namespace, Preview: preview(it.Content), Bytes: len(it.Content),
		Labels: Labels(it.Metadata), Flagged: it.Flagged, CreatedAt: it.CreatedAt, PromoteAt: it.PromoteAt, HoldReason: it.HoldReason}
}

// AgentMemory is the agent detail memory panel.
type AgentMemory struct {
	AgentID     string            `json:"agent_id"`
	Access      AccessState       `json:"access"`
	Staged      []StagedItem      `json:"staged"`
	StoreErrors map[string]string `json:"store_errors,omitempty"`
}

const previewRunes = 280

func preview(s string) string {
	if r := []rune(s); len(r) > previewRunes {
		return string(r[:previewRunes]) + "…"
	}
	return s
}

// AgentView returns an agent's access mode and its recent staged items in
// every configured store. An unreachable store is reported, not hidden.
func (s *Service) AgentView(ctx context.Context, agentID string, limit int) (AgentMemory, error) {
	acc, err := s.Access(ctx, agentID)
	if err != nil {
		return AgentMemory{}, err
	}
	view := AgentMemory{AgentID: agentID, Access: acc, Staged: []StagedItem{}}
	names, err := s.stores.Names(ctx)
	if err != nil {
		view.StoreErrors = map[string]string{"*": "could not list memory stores: " + sanitize(err)}
		return view, nil
	}
	for _, name := range names {
		st, err := s.stores.Store(ctx, name)
		var items []Item
		if err == nil {
			items, err = st.StagedBy(ctx, agentID, limit)
		}
		if err != nil {
			if view.StoreErrors == nil {
				view.StoreErrors = map[string]string{}
			}
			view.StoreErrors[name] = sanitize(err)
			continue
		}
		for _, it := range items {
			view.Staged = append(view.Staged, stagedItem(name, it))
		}
	}
	sort.Slice(view.Staged, func(i, j int) bool { return view.Staged[i].CreatedAt.After(view.Staged[j].CreatedAt) })
	return view, nil
}

// Labels returns the data labels in metadata["labels"] (comma-separated),
// lower-cased, de-duplicated and sorted.
func Labels(meta map[string]string) []string {
	raw, ok := meta["labels"]
	if !ok {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, l := range strings.Split(raw, ",") {
		l = strings.ToLower(strings.TrimSpace(l))
		if l != "" && !seen[l] {
			seen[l] = true
			out = append(out, l)
		}
	}
	sort.Strings(out)
	return out
}

// ---- workers' passes -------------------------------------------------------------

// PromotionResult counts one promotion pass.
type PromotionResult struct {
	Promoted int `json:"promoted"`
	// Held counts the agents whose staged items were kept back because their
	// access is staging_only or none.
	HeldAgents int `json:"held_agents"`
	// ReviewWindows counts held items that got a fresh review window.
	ReviewWindows int `json:"review_windows"`
}

// PromoteDue promotes due, unflagged staged items in every store, except
// items written by agents whose access is staging_only or none. Access
// changes wait for a running pass (see accessLock). Each promotion is
// recorded per agent (memory.promoted) in the pass's transaction.
func (s *Service) PromoteDue(ctx context.Context) (PromotionResult, error) {
	names, err := s.stores.Names(ctx)
	if err != nil {
		return PromotionResult{}, err
	}
	if len(names) == 0 {
		return PromotionResult{}, nil
	}
	var res PromotionResult
	var errs []error
	now := s.now()
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, fmt.Sprintf(accessLock, "_shared")); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT agent_id FROM memory_access WHERE mode <> 'full' ORDER BY agent_id`)
		if err != nil {
			return err
		}
		blocked, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		res.HeldAgents = len(blocked)
		for _, name := range names {
			sctx, cancel := context.WithTimeout(ctx, s.StoreTimeout)
			st, err := s.stores.Store(sctx, name)
			var promoted []Promoted
			var opened []Held
			if err == nil {
				promoted, err = st.PromoteDue(sctx, now, blocked)
			}
			if err == nil {
				// Held items (written while access was not full, or restored
				// from a snapshot) of writers now at full access: a fresh
				// review window, never an immediate promotion.
				opened, err = st.OpenReviewWindows(sctx, now.Add(s.cfg.PromotionDelay), blocked)
			}
			cancel()
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", IntegrationKey(name), err))
			}
			if len(opened) > 0 {
				res.ReviewWindows += len(opened)
				if err := s.recordReviewWindows(ctx, tx, st.Key(), opened); err != nil {
					return err
				}
			}
			if len(promoted) == 0 {
				continue
			}
			res.Promoted += len(promoted)
			byAgent := map[string][]Promoted{}
			for _, p := range promoted {
				byAgent[p.AgentID] = append(byAgent[p.AgentID], p)
			}
			agents := make([]string, 0, len(byAgent))
			for a := range byAgent {
				agents = append(agents, a)
			}
			sort.Strings(agents)
			for _, a := range agents {
				ps := byAgent[a]
				ids := make([]string, 0, min(len(ps), 100))
				actionIDs := make([]string, 0, len(ps))
				for i, p := range ps {
					if i < 100 {
						ids = append(ids, p.Namespace+"/"+p.ID)
					}
					if p.ActionID != "" {
						actionIDs = append(actionIDs, p.ActionID)
					}
				}
				closed, err := closeStagingUndo(ctx, tx, actionIDs)
				if err != nil {
					return err
				}
				events := []diary.Event{{AgentID: a, EventType: EventPromoted, Actor: SystemActor, Data: map[string]any{
					"store": st.Key(), "count": len(ps), "items": ids, "truncated": len(ps) > len(ids),
					"undo_handles_closed": len(closed),
					"note":                "promoted to long-term memory: staging undo no longer possible (restore a snapshot instead)"}}}
				for _, id := range closed {
					events = append(events, diary.Event{AgentID: a, EventType: diary.EventUndoExpired, Actor: SystemActor, Data: map[string]any{
						"action_id": id, "kind": undo.KindMemoryStaging, "from": undo.StatusActive, "to": undo.StatusExpired,
						"error": promotedUndoNote, "expired": true}})
				}
				if _, err := s.diary.AppendTx(ctx, tx, events...); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		if res.Promoted > 0 {
			s.log.Error("memory items were PROMOTED but the pass could not be recorded", "promoted", res.Promoted, "err", err)
		}
		return res, err
	}
	return res, errors.Join(errs...)
}

// recordReviewWindows records, per writer, the held items that got a review
// window.
func (s *Service) recordReviewWindows(ctx context.Context, tx pgx.Tx, storeKey string, opened []Held) error {
	byAgent := map[string][]Held{}
	for _, h := range opened {
		byAgent[h.AgentID] = append(byAgent[h.AgentID], h)
	}
	agents := make([]string, 0, len(byAgent))
	for a := range byAgent {
		agents = append(agents, a)
	}
	sort.Strings(agents)
	events := make([]diary.Event, 0, len(agents))
	for _, a := range agents {
		hs := byAgent[a]
		items := make([]map[string]any, 0, min(len(hs), 100))
		for i, h := range hs {
			if i < 100 {
				items = append(items, map[string]any{"namespace": h.Namespace, "item_id": h.ID, "hold_reason": h.HoldReason})
			}
		}
		var promoteAt string
		if hs[0].PromoteAt != nil {
			promoteAt = hs[0].PromoteAt.UTC().Format(time.RFC3339)
		}
		events = append(events, diary.Event{AgentID: a, EventType: EventReviewWindow, Actor: SystemActor, Data: map[string]any{
			"store": storeKey, "count": len(hs), "items": items, "truncated": len(hs) > len(items), "promote_at": promoteAt,
			"note": "held items get a fresh review window: flag or drop them before promote_at, otherwise they are promoted"}})
	}
	_, err := s.diary.AppendTx(ctx, tx, events...)
	return err
}

// promotedUndoNote is the undo handle error of a promoted staged write.
const promotedUndoNote = "promoted to long-term memory: NOT undoable by dropping staging (restore a snapshot instead)"

// closeStagingUndo marks the active memory_staging undo handles of promoted
// writes expired (the item left staging, so dropping it is no longer
// possible) and returns the action ids it changed. Handles in another state
// (prepared, undoing, used...) are left alone; the executor refuses a
// promoted item anyway.
func closeStagingUndo(ctx context.Context, tx pgx.Tx, actionIDs []string) ([]string, error) {
	if len(actionIDs) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, `UPDATE undo_handles SET status = $3, error = $4
		WHERE action_id = ANY($1) AND kind = $2 AND status = $5 RETURNING action_id`,
		actionIDs, undo.KindMemoryStaging, undo.StatusExpired, promotedUndoNote, undo.StatusActive)
	if err != nil {
		return nil, err
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	sort.Strings(ids)
	return ids, nil
}

// AutoSnapshot takes a snapshot of every namespace of every store whose
// newest snapshot is older than every and whose contents changed since.
// Only one process runs a pass at a time (session advisory lock).
func (s *Service) AutoSnapshot(ctx context.Context, every time.Duration) (int, error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return 0, err
	}
	defer conn.Release()
	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_lock(pg_catalog.hashtextextended('fortik.memory.autosnapshot', 0))`).Scan(&got); err != nil {
		return 0, err
	}
	if !got {
		return 0, nil // another process is running a pass
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(uctx, `SELECT pg_catalog.pg_advisory_unlock(pg_catalog.hashtextextended('fortik.memory.autosnapshot', 0))`); err != nil {
			// A lock we cannot release must not outlive this connection.
			conn.Conn().Close(uctx) //nolint:errcheck
		}
	}()

	names, err := s.stores.Names(ctx)
	if err != nil {
		return 0, err
	}
	taken := 0
	var errs []error
	for _, name := range names {
		if ctx.Err() != nil {
			return taken, ctx.Err()
		}
		n, err := s.autoSnapshotStore(ctx, name, every)
		taken += n
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", IntegrationKey(name), err))
		}
	}
	return taken, errors.Join(errs...)
}

func (s *Service) autoSnapshotStore(ctx context.Context, name string, every time.Duration) (int, error) {
	sctx, cancel := context.WithTimeout(ctx, s.StoreTimeout)
	defer cancel()
	st, err := s.stores.Store(sctx, name)
	if err != nil {
		return 0, err
	}
	nss, err := st.Namespaces(sctx)
	if err != nil {
		return 0, err
	}
	taken := 0
	var errs []error
	for _, ns := range nss {
		last, err := s.ListSnapshots(ctx, SnapshotFilter{Store: name, Namespace: ns, Limit: 1})
		if err != nil {
			return taken, err
		}
		if len(last) == 1 {
			if s.now().Sub(last[0].CreatedAt) < every {
				continue
			}
			same, err := st.SameContents(sctx, ns, last[0].Location)
			if err != nil {
				errs = append(errs, fmt.Errorf("%s: %w", ns, err))
				continue
			}
			if same {
				continue
			}
		}
		if _, err := s.CreateSnapshot(sctx, name, ns, SystemActor, "automatic snapshot"); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", ns, err))
			continue
		}
		taken++
	}
	return taken, errors.Join(errs...)
}
