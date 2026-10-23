// Package retention purges what Fortik prepared for undo once it can no
// longer be used (docs/PHASE4_DESIGN.md §4):
//
//   - fortik_undo.* row-snapshot tables whose undo handle has expired, or was
//     used / failed and is older than undo.snapshot_retention, and orphan
//     snapshot tables (no handle) older than the same retention;
//   - fortik_trash_<table>_<ts> tables older than undo.trash_retention whose
//     pg_rename handle is expired, used or absent;
//   - memory snapshot pointers past memory.snapshot_retention (and, through
//     an optional SnapshotPurger, the snapshot data in the customer's store);
//   - active undo handles past expires_at are marked expired.
//
// The sweep runs under a Postgres advisory lock so only one Fortik process
// sweeps at a time. It only ever drops relations whose name follows a
// Fortik pattern AND that are either referenced by a Fortik undo handle or
// carry a timestamp in their name proving their age; it never uses CASCADE.
// Each purge writes a Diary event "retention.purged" with names and counts,
// never data.
package retention

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"

	"fortik/internal/broker/pgroles"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/pgsql"
	"fortik/internal/undo"
)

// EventPurged is the Diary event written for every purge.
const EventPurged = "retention.purged"

// Actor is the Diary actor of the retention worker.
const Actor = "system:retention"

// LockClass and LockID form the session-level advisory lock
// (pg_try_advisory_lock(LockClass, LockID)) on Fortik's database that
// serialises sweeps across processes.
const (
	LockClass int32 = 0x46726574 // "Fret"
	LockID    int32 = 1
)

// Plan defaults, used when a config value is zero.
const (
	defaultSweepInterval     = time.Hour
	defaultSnapshotRetention = 30 * 24 * time.Hour
	defaultTrashRetention    = 7 * 24 * time.Hour
	defaultMemoryRetention   = 30 * 24 * time.Hour
)

const (
	expireBatch   = 500
	memoryBatch   = 200
	tablesPerKind = 1000 // per upstream per sweep; the rest waits for the next sweep
	lockTimeout   = "5s"
	stmtTimeout   = "60s"
	maxErrLen     = 300
)

var (
	// snapshotName: pgsql.SnapshotTableName = <table>_<lower-cased ULID>.
	snapshotName = regexp.MustCompile(`^.+_([0-9a-z]{26})$`)
	// trashName: pgsql.TrashTableName = fortik_trash_<table>_<yyyymmddhhmmss>.
	trashName = regexp.MustCompile(`^fortik_trash_.+_([0-9]{14})$`)
)

// SnapshotPurger deletes a memory snapshot's data from the customer's store
// (the memory package's store provides it). It must return nil when the data
// is already gone, and an error whenever it could not confirm the deletion.
type SnapshotPurger interface {
	PurgeSnapshot(ctx context.Context, storeKey, namespace, location string) error
}

// Option configures optional Worker behaviour.
type Option func(*Worker)

// WithSnapshotPurger deletes memory snapshot data through p before the
// pointer is marked purged. Without it only the pointer is purged and the
// Diary event says the data was left in the store (data_purged=false).
func WithSnapshotPurger(p SnapshotPurger) Option { return func(w *Worker) { w.purger = p } }

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(w *Worker) { w.now = now } }

// Worker is the retention sweep.
type Worker struct {
	pool      *pgxpool.Pool
	diary     *diary.Diary
	src       integrations.Source
	undoCfg   config.UndoConfig
	interval  time.Duration
	memRetain time.Duration
	log       *slog.Logger
	purger    SnapshotPurger
	now       func() time.Time
}

// New builds the worker. Zero durations take the plan defaults (sweep every
// hour, snapshots 30 days, trash 7 days, memory snapshots 30 days).
func New(pool *pgxpool.Pool, d *diary.Diary, src integrations.Source, undoCfg config.UndoConfig,
	retCfg config.RetentionConfig, memCfg config.MemoryConfig, log *slog.Logger, opts ...Option) *Worker {
	if undoCfg.SnapshotRetention <= 0 {
		undoCfg.SnapshotRetention = defaultSnapshotRetention
	}
	if undoCfg.TrashRetention <= 0 {
		undoCfg.TrashRetention = defaultTrashRetention
	}
	if retCfg.SweepInterval <= 0 {
		retCfg.SweepInterval = defaultSweepInterval
	}
	if memCfg.SnapshotRetention <= 0 {
		memCfg.SnapshotRetention = defaultMemoryRetention
	}
	if log == nil {
		log = slog.Default()
	}
	w := &Worker{pool: pool, diary: d, src: src, undoCfg: undoCfg, interval: retCfg.SweepInterval,
		memRetain: memCfg.SnapshotRetention, log: log.With("component", "retention"), now: time.Now}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Dropped is one relation the sweep dropped.
type Dropped struct {
	Table    string `json:"table"` // schema.table
	Reason   string `json:"reason"`
	ActionID string `json:"action_id,omitempty"`
}

// Failure is one relation the sweep tried and failed to drop (it still exists).
type Failure struct {
	Table string `json:"table"`
	Error string `json:"error"`
}

// UpstreamReport is the outcome for one postgres:<name> integration.
type UpstreamReport struct {
	Upstream       string    `json:"upstream"`
	Database       string    `json:"database,omitempty"`
	SnapshotTables []Dropped `json:"snapshot_tables"`
	TrashTables    []Dropped `json:"trash_tables"`
	Failed         []Failure `json:"failed,omitempty"`
	Error          string    `json:"error,omitempty"` // the upstream could not be swept at all
}

// MemoryReport is the outcome for one memory store's snapshots.
type MemoryReport struct {
	StoreKey string           `json:"store_key"`
	Purged   []MemorySnapshot `json:"purged"`
	Failed   []MemoryFailure  `json:"failed,omitempty"`
}

// MemorySnapshot is one purged memory snapshot pointer.
type MemorySnapshot struct {
	SnapshotID string `json:"snapshot_id"`
	Namespace  string `json:"namespace"`
	ItemCount  int    `json:"item_count"`
	Location   string `json:"location"`
	DataPurged bool   `json:"data_purged"`
}

// MemoryFailure is a snapshot whose data could not be purged (its pointer is kept).
type MemoryFailure struct {
	SnapshotID string `json:"snapshot_id"`
	Error      string `json:"error"`
}

// Report summarises one sweep.
type Report struct {
	// Locked: another process holds the sweep lock; this sweep did nothing.
	Locked         bool             `json:"locked"`
	ExpiredHandles int              `json:"expired_handles"`
	Upstreams      []UpstreamReport `json:"upstreams"`
	Memory         []MemoryReport   `json:"memory"`
}

// Run sweeps immediately and then every sweep interval until ctx is
// cancelled. Errors are logged and retried on the next tick.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		rep, err := w.Sweep(ctx)
		switch {
		case ctx.Err() != nil:
			return
		case err != nil:
			w.log.Error("retention sweep finished with errors", "err", err)
		case rep.Locked:
			w.log.Debug("retention sweep skipped: another process holds the lock")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Sweep runs one full retention pass under the advisory lock. When another
// process holds the lock it returns Report{Locked: true} and a nil error.
// Per-upstream and per-store failures do not stop the rest of the sweep; they
// are reported and joined into the returned error.
func (w *Worker) Sweep(ctx context.Context) (Report, error) {
	conn, err := w.pool.Acquire(ctx)
	if err != nil {
		return Report{}, fmt.Errorf("retention: acquire lock connection: %w", err)
	}
	var locked bool
	if err := conn.QueryRow(ctx, `SELECT pg_catalog.pg_try_advisory_lock($1, $2)`, LockClass, LockID).Scan(&locked); err != nil {
		conn.Release()
		return Report{}, fmt.Errorf("retention: advisory lock: %w", err)
	}
	if !locked {
		conn.Release()
		return Report{Locked: true}, nil
	}
	defer func() {
		uctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
		defer cancel()
		var ok bool
		if err := conn.QueryRow(uctx, `SELECT pg_catalog.pg_advisory_unlock($1, $2)`, LockClass, LockID).Scan(&ok); err != nil || !ok {
			// Closing the session is the only other way to free the lock.
			w.log.Warn("retention lock release failed; closing its connection", "err", err)
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}()

	var rep Report
	var errs []error
	n, err := w.expireHandles(ctx)
	rep.ExpiredHandles = n
	if err != nil {
		errs = append(errs, fmt.Errorf("expire undo handles: %w", err))
	}
	ups, err := w.sweepUpstreams(ctx)
	rep.Upstreams = ups
	if err != nil {
		errs = append(errs, err)
	}
	mem, err := w.purgeMemorySnapshots(ctx)
	rep.Memory = mem
	if err != nil {
		errs = append(errs, err)
	}
	if n > 0 {
		w.log.Info("undo handles expired", "count", n)
	}
	return rep, errors.Join(errs...)
}

// ---- undo handles -----------------------------------------------------------

// expireHandles moves active handles past expires_at to expired, with the
// same undo.expired Diary event undo.PGStore writes, in the same transaction.
// Handles locked by an in-flight claim are skipped until the next sweep.
func (w *Worker) expireHandles(ctx context.Context) (int, error) {
	total := 0
	for {
		n, more, err := w.expireBatch(ctx)
		total += n
		if err != nil || !more {
			return total, err
		}
	}
}

// expireBatch expires up to expireBatch handles; more reports whether a full
// batch was selected (another may be due).
func (w *Worker) expireBatch(ctx context.Context) (n int, more bool, err error) {
	err = pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		n, more = 0, false
		rows, err := tx.Query(ctx, `
			SELECT action_id, agent_id, kind FROM undo_handles
			WHERE status = $1 AND expires_at <= $2
			ORDER BY expires_at LIMIT $3
			FOR UPDATE SKIP LOCKED`, undo.StatusActive, w.now().UTC(), expireBatch)
		if err != nil {
			return err
		}
		type due struct{ actionID, agentID, kind string }
		var list []due
		for rows.Next() {
			var d due
			if err := rows.Scan(&d.actionID, &d.agentID, &d.kind); err != nil {
				rows.Close()
				return err
			}
			list = append(list, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		events := make([]diary.Event, 0, len(list))
		for _, d := range list {
			tag, err := tx.Exec(ctx, `UPDATE undo_handles SET status = $2, error = 'retention elapsed'
				WHERE action_id = $1 AND status = $3`, d.actionID, undo.StatusExpired, undo.StatusActive)
			if err != nil {
				return err
			}
			if tag.RowsAffected() != 1 {
				continue
			}
			events = append(events, diary.Event{AgentID: d.agentID, EventType: diary.EventUndoExpired, Actor: Actor,
				Data: map[string]any{"action_id": d.actionID, "kind": d.kind, "from": undo.StatusActive, "to": undo.StatusExpired,
					"error": "retention elapsed", "expired": true}})
		}
		if _, err := w.diary.AppendTx(ctx, tx, events...); err != nil {
			return err
		}
		n, more = len(events), len(list) == expireBatch
		return nil
	})
	if err != nil {
		return 0, false, err
	}
	return n, more, nil
}

// ---- Postgres upstreams -----------------------------------------------------

type handleRef struct {
	actionID  string
	status    string
	createdAt time.Time
}

type candidate struct {
	schema, name string
	ts           time.Time // age from the name (zero if it has no parsable timestamp)
}

func (c candidate) qualified() string { return c.schema + "." + c.name }

func (w *Worker) sweepUpstreams(ctx context.Context) ([]UpstreamReport, error) {
	if w.src == nil {
		return nil, nil
	}
	list, err := w.src.List(ctx, pgroles.System)
	if err != nil {
		return nil, fmt.Errorf("list postgres integrations: %w", err)
	}
	slices.SortFunc(list, func(a, b integrations.Resolved) int { return strings.Compare(a.Key, b.Key) })
	var out []UpstreamReport
	var errs []error
	for _, r := range list {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		if !strings.HasPrefix(r.Key, pgroles.KeyPrefix) {
			continue
		}
		rep := w.sweepUpstream(ctx, r)
		if rep.Error != "" {
			errs = append(errs, fmt.Errorf("%s: %s", r.Key, rep.Error))
		}
		for _, f := range rep.Failed {
			w.log.Warn("retention could not drop a table", "upstream", rep.Upstream, "table", f.Table, "err", f.Error)
		}
		out = append(out, rep)
	}
	return out, errors.Join(errs...)
}

func (w *Worker) sweepUpstream(ctx context.Context, r integrations.Resolved) UpstreamReport {
	rep := UpstreamReport{Upstream: strings.TrimPrefix(r.Key, pgroles.KeyPrefix), SnapshotTables: []Dropped{}, TrashTables: []Dropped{}}
	u, err := pgroles.ParseUpstream(r)
	if err != nil {
		rep.Error = truncate(err.Error())
		return rep
	}
	rep.Upstream, rep.Database = u.Name, u.Database
	pc, err := u.AdminConnConfig(map[string]string{"application_name": "fortik:retention",
		"lock_timeout": lockTimeout, "statement_timeout": stmtTimeout})
	if err != nil {
		rep.Error = truncate(err.Error())
		return rep
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		rep.Error = truncate(err.Error())
		return rep
	}
	cc.Config = *pc
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		rep.Error = truncate("connect: " + err.Error())
		return rep
	}
	defer conn.Close(context.WithoutCancel(ctx))

	now := w.now().UTC()
	snaps, err := w.snapshotDrops(ctx, conn, u.Name, now)
	if err != nil {
		rep.Error = truncate("snapshot tables: " + err.Error())
	}
	trash, err := w.trashDrops(ctx, conn, u.Name, now)
	if err != nil && rep.Error == "" {
		rep.Error = truncate("trash tables: " + err.Error())
	}
	for _, d := range snaps {
		if err := dropTable(ctx, conn, d.schema, d.name); err != nil {
			rep.Failed = append(rep.Failed, Failure{Table: d.qualified(), Error: truncate(err.Error())})
			continue
		}
		rep.SnapshotTables = append(rep.SnapshotTables, d.Dropped)
	}
	for _, d := range trash {
		if err := dropTable(ctx, conn, d.schema, d.name); err != nil {
			rep.Failed = append(rep.Failed, Failure{Table: d.qualified(), Error: truncate(err.Error())})
			continue
		}
		rep.TrashTables = append(rep.TrashTables, d.Dropped)
	}
	if len(rep.SnapshotTables)+len(rep.TrashTables) > 0 {
		if err := w.recordUpstream(ctx, rep); err != nil {
			// The tables are gone; the record of it is not. Say so loudly.
			w.log.Error("retention dropped tables but could not record it in the Diary", "upstream", u.Name,
				"snapshot_tables", len(rep.SnapshotTables), "trash_tables", len(rep.TrashTables), "err", err)
			if rep.Error == "" {
				rep.Error = truncate("diary: " + err.Error())
			}
		} else {
			w.log.Info("retention purged tables", "upstream", u.Name,
				"snapshot_tables", len(rep.SnapshotTables), "trash_tables", len(rep.TrashTables))
		}
	}
	return rep
}

type drop struct {
	candidate
	Dropped
}

// snapshotDrops lists ordinary tables in fortik_undo and decides which to drop.
func (w *Worker) snapshotDrops(ctx context.Context, conn *pgx.Conn, upstream string, now time.Time) ([]drop, error) {
	rows, err := conn.Query(ctx, `
		SELECT c.relname FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relkind = 'r' AND c.relpersistence = 'p' AND NOT c.relispartition
		ORDER BY c.relname`, pgsql.SnapshotSchema)
	if err != nil {
		return nil, err
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	handles, err := w.handles(ctx, `
		SELECT action_id, status, created_at, handle_json->>'snapshot_table' FROM undo_handles
		WHERE kind = $1 AND handle_json->>'upstream' = $2
		  AND COALESCE(NULLIF(handle_json->>'snapshot_schema', ''), $3) = $3
		  AND handle_json->>'snapshot_table' = ANY($4)`, undo.KindPGRows, upstream, pgsql.SnapshotSchema, names)
	if err != nil {
		return nil, err
	}
	retain := w.undoCfg.SnapshotRetention
	var out []drop
	for _, name := range names {
		c := candidate{schema: pgsql.SnapshotSchema, name: name}
		if hs, ok := handles[name]; ok {
			if reason, id, ok := terminalDrop(hs, now, retain, true); ok {
				out = append(out, drop{c, Dropped{Table: c.qualified(), Reason: reason, ActionID: id}})
			}
		} else if ts, ok := snapshotTime(name); ok && now.Sub(ts) >= retain {
			// No handle references it: an orphan, aged by its action's ULID.
			out = append(out, drop{c, Dropped{Table: c.qualified(), Reason: "orphan snapshot older than " + retain.String()}})
		}
		if len(out) >= tablesPerKind {
			break
		}
	}
	return out, nil
}

// trashDrops lists fortik_trash_<table>_<ts> tables in user schemas and
// decides which to drop.
func (w *Worker) trashDrops(ctx context.Context, conn *pgx.Conn, upstream string, now time.Time) ([]drop, error) {
	rows, err := conn.Query(ctx, `
		SELECT n.nspname, c.relname FROM pg_catalog.pg_class c
		JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind IN ('r', 'p') AND c.relpersistence = 'p' AND NOT c.relispartition
		  AND c.relname LIKE 'fortik\_trash\_%'
		  AND n.nspname <> 'information_schema' AND n.nspname NOT LIKE 'pg\_%' AND n.nspname <> $1
		ORDER BY n.nspname, c.relname`, pgsql.SnapshotSchema)
	if err != nil {
		return nil, err
	}
	var cands []candidate
	var names []string
	for rows.Next() {
		var c candidate
		if err := rows.Scan(&c.schema, &c.name); err != nil {
			rows.Close()
			return nil, err
		}
		ts, ok := trashTime(c.name)
		if !ok {
			continue // not a Fortik trash name: never touched
		}
		c.ts = ts
		cands = append(cands, c)
		names = append(names, c.name)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(cands) == 0 {
		return nil, nil
	}
	// A handle without a schema matches the trash name in every schema
	// (conservative: it can only keep a table, never cause a drop).
	handles, err := w.handles(ctx, `
		SELECT action_id, status, created_at, COALESCE(handle_json->>'schema', '') || '.' || (handle_json->>'trash_table') FROM undo_handles
		WHERE kind = $1 AND handle_json->>'upstream' = $2 AND handle_json->>'trash_table' = ANY($3)`,
		undo.KindPGRename, upstream, names)
	if err != nil {
		return nil, err
	}
	retain := w.undoCfg.TrashRetention
	var out []drop
	for _, c := range cands {
		if now.Sub(c.ts) < retain {
			continue
		}
		hs := append(slices.Clone(handles[c.qualified()]), handles["."+c.name]...)
		ok := len(hs) > 0
		if !ok {
			out = append(out, drop{c, Dropped{Table: c.qualified(), Reason: "trash table older than " + retain.String() + " without an undo handle"}})
		} else if reason, id, ok := terminalDrop(hs, now, retain, false); ok {
			out = append(out, drop{c, Dropped{Table: c.qualified(), Reason: reason, ActionID: id}})
		}
		if len(out) >= tablesPerKind {
			break
		}
	}
	return out, nil
}

// handles runs q (returning action_id, status, created_at, key) and groups
// the handles by key.
func (w *Worker) handles(ctx context.Context, q string, args ...any) (map[string][]handleRef, error) {
	rows, err := w.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]handleRef{}
	for rows.Next() {
		var h handleRef
		var key *string
		if err := rows.Scan(&h.actionID, &h.status, &h.createdAt, &key); err != nil {
			return nil, err
		}
		if key != nil {
			out[*key] = append(out[*key], h)
		}
	}
	return out, rows.Err()
}

// terminalDrop decides from the handles referencing a table whether it may
// be dropped. Any handle that may still be undone (prepared, active,
// undoing) keeps the table. Expired handles allow the drop; used handles
// (and, for snapshots, failed ones) allow it once older than retain.
func terminalDrop(hs []handleRef, now time.Time, retain time.Duration, failedDrops bool) (reason, actionID string, ok bool) {
	for _, h := range hs {
		switch h.status {
		case undo.StatusExpired:
		case undo.StatusUsed:
			if now.Sub(h.createdAt) < retain {
				return "", "", false
			}
		case undo.StatusFailed:
			if !failedDrops || now.Sub(h.createdAt) < retain {
				return "", "", false
			}
		default:
			return "", "", false
		}
	}
	h := hs[0]
	switch h.status {
	case undo.StatusExpired:
		return "undo handle expired", h.actionID, true
	case undo.StatusUsed:
		return "undo handle used, older than " + retain.String(), h.actionID, true
	default:
		return "undo handle " + h.status + ", older than " + retain.String(), h.actionID, true
	}
}

// snapshotTime returns the creation time encoded in a snapshot table name's
// ULID suffix.
func snapshotTime(name string) (time.Time, bool) {
	m := snapshotName.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	id, err := ulid.ParseStrict(strings.ToUpper(m[1]))
	if err != nil {
		return time.Time{}, false
	}
	return ulid.Time(id.Time()).UTC(), true
}

// trashTime returns the UTC rename time encoded in a trash table name.
func trashTime(name string) (time.Time, bool) {
	m := trashName.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	ts, err := time.ParseInLocation("20060102150405", m[1], time.UTC)
	if err != nil {
		return time.Time{}, false
	}
	return ts, true
}

// dropTable drops schema.name in its own transaction (plain DROP TABLE, never
// CASCADE: anything depending on it makes the drop fail and the table stay).
// If the table belongs to a role the admin may SET ROLE to but not inherit
// (a Fortik per-agent role), the drop runs as that owner.
func dropTable(ctx context.Context, conn *pgx.Conn, schema, name string) error {
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit
	qualified := pgsql.QuoteQualified(schema, name)
	var usage, canSet bool
	var owner string
	err = tx.QueryRow(ctx, `
		SELECT pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE'), pg_catalog.pg_has_role(current_user, c.relowner, 'SET'),
		       pg_catalog.pg_get_userbyid(c.relowner)
		FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = $1 AND c.relname = $2 AND c.relkind IN ('r', 'p')`, schema, name).Scan(&usage, &canSet, &owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return errors.New("table no longer exists")
	}
	if err != nil {
		return err
	}
	if !usage && canSet {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgsql.QuoteIdent(owner)); err != nil {
			return fmt.Errorf("set role to the table owner: %w", err)
		}
	}
	if _, err := tx.Exec(ctx, "DROP TABLE "+qualified); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (w *Worker) recordUpstream(ctx context.Context, rep UpstreamReport) error {
	data := map[string]any{
		"upstream":                rep.Upstream,
		"database":                rep.Database,
		"snapshot_tables":         rep.SnapshotTables,
		"trash_tables":            rep.TrashTables,
		"snapshot_tables_dropped": len(rep.SnapshotTables),
		"trash_tables_dropped":    len(rep.TrashTables),
		"snapshot_retention":      w.undoCfg.SnapshotRetention.String(),
		"trash_retention":         w.undoCfg.TrashRetention.String(),
	}
	if len(rep.Failed) > 0 {
		data["failed"] = rep.Failed
	}
	return w.appendEvent(ctx, nil, data)
}

// appendEvent writes one retention.purged event (inside tx when given).
// Report structs are converted to plain JSON values so the canonical body is
// stable.
func (w *Worker) appendEvent(ctx context.Context, tx pgx.Tx, data map[string]any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var plain map[string]any
	if err := json.Unmarshal(b, &plain); err != nil {
		return err
	}
	ev := diary.Event{EventType: EventPurged, Actor: Actor, Data: plain}
	if tx != nil {
		_, err = w.diary.AppendTx(ctx, tx, ev)
	} else {
		_, err = w.diary.Append(ctx, ev)
	}
	return err
}

// ---- memory snapshots -------------------------------------------------------

type memSnap struct {
	id, store, namespace, location string
	items                          int
}

// purgeMemorySnapshots purges memory snapshot pointers past retention, per
// store: the rows are locked, the data is deleted through the purger (when
// configured), and the pointers whose data is gone are marked purged with
// one Diary event per store, in the same transaction.
func (w *Worker) purgeMemorySnapshots(ctx context.Context) ([]MemoryReport, error) {
	now := w.now().UTC()
	cutoff := now.Add(-w.memRetain)
	rows, err := w.pool.Query(ctx, `
		SELECT DISTINCT store_key FROM memory_snapshots
		WHERE purged_at IS NULL AND (expires_at <= $1 OR created_at <= $2) ORDER BY store_key`, now, cutoff)
	if err != nil {
		return nil, fmt.Errorf("memory snapshots: %w", err)
	}
	stores, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("memory snapshots: %w", err)
	}
	var out []MemoryReport
	var errs []error
	for _, store := range stores {
		if ctx.Err() != nil {
			errs = append(errs, ctx.Err())
			break
		}
		rep, err := w.purgeStore(ctx, store, now, cutoff)
		if err != nil {
			errs = append(errs, fmt.Errorf("memory snapshots of %s: %w", store, err))
		}
		for _, f := range rep.Failed {
			w.log.Warn("retention could not purge a memory snapshot", "store", store, "snapshot_id", f.SnapshotID, "err", f.Error)
		}
		if len(rep.Purged) > 0 || len(rep.Failed) > 0 {
			out = append(out, rep)
		}
	}
	return out, errors.Join(errs...)
}

func (w *Worker) purgeStore(ctx context.Context, store string, now, cutoff time.Time) (MemoryReport, error) {
	rep := MemoryReport{StoreKey: store, Purged: []MemorySnapshot{}}
	err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		rep.Purged, rep.Failed = []MemorySnapshot{}, nil
		rows, err := tx.Query(ctx, `
			SELECT snapshot_id, store_key, namespace, location, item_count FROM memory_snapshots
			WHERE store_key = $1 AND purged_at IS NULL AND (expires_at <= $2 OR created_at <= $3)
			ORDER BY created_at LIMIT $4
			FOR UPDATE SKIP LOCKED`, store, now, cutoff, memoryBatch)
		if err != nil {
			return err
		}
		var snaps []memSnap
		for rows.Next() {
			var s memSnap
			if err := rows.Scan(&s.id, &s.store, &s.namespace, &s.location, &s.items); err != nil {
				rows.Close()
				return err
			}
			snaps = append(snaps, s)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		var purged []string
		for _, s := range snaps {
			dataPurged := false
			if w.purger != nil {
				if err := w.purger.PurgeSnapshot(ctx, s.store, s.namespace, s.location); err != nil {
					rep.Failed = append(rep.Failed, MemoryFailure{SnapshotID: s.id, Error: truncate(err.Error())})
					continue
				}
				dataPurged = true
			}
			purged = append(purged, s.id)
			rep.Purged = append(rep.Purged, MemorySnapshot{SnapshotID: s.id, Namespace: s.namespace, ItemCount: s.items,
				Location: s.location, DataPurged: dataPurged})
		}
		if len(purged) == 0 {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE memory_snapshots SET purged_at = $2 WHERE snapshot_id = ANY($1) AND purged_at IS NULL`,
			purged, now); err != nil {
			return err
		}
		data := map[string]any{
			"memory_store":       store,
			"memory_snapshots":   rep.Purged,
			"snapshots_purged":   len(rep.Purged),
			"snapshot_retention": w.memRetain.String(),
		}
		if w.purger == nil {
			data["note"] = "no memory store purger configured: pointers purged, snapshot data left in the customer's store"
		}
		if len(rep.Failed) > 0 {
			data["failed"] = rep.Failed
		}
		return w.appendEvent(ctx, tx, data)
	})
	if err != nil {
		return MemoryReport{StoreKey: store, Purged: []MemorySnapshot{}}, err
	}
	if len(rep.Purged) > 0 {
		w.log.Info("retention purged memory snapshots", "store", store, "count", len(rep.Purged))
	}
	return rep, nil
}

func truncate(s string) string {
	if len(s) <= maxErrLen {
		return s
	}
	return s[:maxErrLen] + "..."
}
