// Package pgundo reverses the Postgres undo handles prepared by the proxy:
// row snapshots (undo.KindPGRows) and rename-based safe forms
// (undo.KindPGRename). Every undo runs in one transaction; on any failure
// the transaction rolls back, so an undo never destroys data.
package pgundo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/broker/pgroles"
	"fortik/internal/config"
	"fortik/internal/integrations"
	"fortik/internal/pgproxy"
	"fortik/internal/pgsql"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

// Executor implements undo.Executor for the Postgres handle kinds.
type Executor struct {
	cfg config.PGProxyConfig
	sec secrets.Provider
	src integrations.Source // nil: YAML upstreams only
}

var _ undo.Executor = (*Executor)(nil)

// Option configures optional Executor behaviour.
type Option func(*Executor)

// WithIntegrations makes undo of an integration-backed upstream
// (postgres:<name>, which wins over a YAML upstream of the same name) run as
// the integration's admin user. Agents' own roles never run undo.
func WithIntegrations(src integrations.Source) Option { return func(e *Executor) { e.src = src } }

// NewExecutor builds an executor that connects to upstreams like the proxy:
// integration-backed upstreams as their admin user, YAML upstreams as their
// static user.
func NewExecutor(cfg config.PGProxyConfig, sec secrets.Provider, opts ...Option) *Executor {
	e := &Executor{cfg: cfg, sec: sec}
	for _, o := range opts {
		o(e)
	}
	return e
}

// Kinds lists the handle kinds this executor reverses.
func (e *Executor) Kinds() []string { return []string{undo.KindPGRows, undo.KindPGRename} }

// Undo reverses one handle.
func (e *Executor) Undo(ctx context.Context, h undo.Handle) (map[string]any, error) {
	switch h.Kind {
	case undo.KindPGRows:
		var d undo.PGRowsData
		if err := json.Unmarshal(h.Data, &d); err != nil {
			return nil, fmt.Errorf("pgundo: bad handle_json: %w", err)
		}
		return e.undoRows(ctx, d)
	case undo.KindPGRename:
		var d undo.PGRenameData
		if err := json.Unmarshal(h.Data, &d); err != nil {
			return nil, fmt.Errorf("pgundo: bad handle_json: %w", err)
		}
		return e.undoRename(ctx, d)
	}
	return nil, fmt.Errorf("%w: %s", undo.ErrUnsupported, h.Kind)
}

func (e *Executor) connect(ctx context.Context, upstream, database string) (*pgx.Conn, error) {
	pc, err := e.connConfig(ctx, upstream, database)
	if err != nil {
		return nil, err
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		return nil, err
	}
	cc.Config = *pc
	return pgx.ConnectConfig(ctx, cc)
}

// connConfig resolves the upstream: the postgres:<name> integration first
// (as its admin user), else the YAML upstream. Any integration error other
// than "not configured" fails the undo (no fallback to YAML).
func (e *Executor) connConfig(ctx context.Context, upstream, database string) (*pgconn.Config, error) {
	runtime := map[string]string{"application_name": "fortik:undo"}
	if e.src != nil {
		u, err := pgroles.Resolve(ctx, e.src, upstream)
		switch {
		case err == nil:
			if database != "" && database != u.Database {
				return nil, fmt.Errorf("pgundo: handle database %q does not match integration postgres:%s database %q", database, upstream, u.Database)
			}
			return u.AdminConnConfig(runtime)
		case !errors.Is(err, pgroles.ErrUpstreamNotManaged):
			return nil, fmt.Errorf("pgundo: upstream %q: %w", upstream, err)
		}
	}
	up, ok := e.cfg.Upstreams[upstream]
	if !ok {
		return nil, fmt.Errorf("pgundo: upstream %q is not configured", upstream)
	}
	if up.Database == "" {
		up.Database = upstream
	}
	if database != "" && database != up.Database {
		return nil, fmt.Errorf("pgundo: handle database %q does not match upstream %q database %q", database, upstream, up.Database)
	}
	return pgproxy.ConnConfig(ctx, up, e.sec, runtime)
}

type column struct {
	name      string
	generated bool
	identity  byte // 'a' always, 'd' by default, 0 none
}

func columns(ctx context.Context, tx pgx.Tx, regclass string) ([]column, error) {
	rows, err := tx.Query(ctx, `SELECT attname, attgenerated <> '', attidentity::text
FROM pg_catalog.pg_attribute
WHERE attrelid = $1::regclass AND attnum > 0 AND NOT attisdropped ORDER BY attnum`, regclass)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []column
	for rows.Next() {
		var c column
		var ident string
		if err := rows.Scan(&c.name, &c.generated, &ident); err != nil {
			return nil, err
		}
		if ident != "" {
			c.identity = ident[0]
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func relExists(ctx context.Context, tx pgx.Tx, schema, table string) (bool, error) {
	var ok bool
	err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, pgsql.QuoteQualified(schema, table)).Scan(&ok)
	return ok, err
}

func quoteCols(cols []string, prefix string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = prefix + pgsql.QuoteIdent(c)
	}
	return strings.Join(q, ", ")
}

func (e *Executor) undoRows(ctx context.Context, d undo.PGRowsData) (map[string]any, error) {
	if d.SnapshotSchema == "" {
		d.SnapshotSchema = pgsql.SnapshotSchema
	}
	if d.Schema == "" || d.Table == "" || d.SnapshotTable == "" {
		return nil, errors.New("pgundo: handle is missing table or snapshot names")
	}
	conn, err := e.connect(ctx, d.Upstream, d.Database)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit

	if ok, err := relExists(ctx, tx, d.SnapshotSchema, d.SnapshotTable); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w: snapshot %s.%s does not exist", undo.ErrNothingToUndo, d.SnapshotSchema, d.SnapshotTable)
	}
	if ok, err := relExists(ctx, tx, d.Schema, d.Table); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("pgundo: target table %s.%s does not exist", d.Schema, d.Table)
	}
	target := pgsql.QuoteQualified(d.Schema, d.Table)
	snap := pgsql.QuoteQualified(d.SnapshotSchema, d.SnapshotTable)
	// Lock the target so concurrent writers cannot interleave with the restore.
	if _, err := tx.Exec(ctx, "LOCK TABLE "+target+" IN SHARE ROW EXCLUSIVE MODE"); err != nil {
		return nil, err
	}
	tcols, err := columns(ctx, tx, target)
	if err != nil {
		return nil, err
	}
	scols, err := columns(ctx, tx, snap)
	if err != nil {
		return nil, err
	}
	inSnap := map[string]bool{}
	for _, c := range scols {
		inSnap[c.name] = true
	}
	var snapRows int64
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+snap).Scan(&snapRows); err != nil {
		return nil, err
	}
	res := map[string]any{
		"op": d.Op, "table": d.Schema + "." + d.Table,
		"snapshot_table": d.SnapshotSchema + "." + d.SnapshotTable, "snapshot_rows": snapRows,
	}

	switch strings.ToUpper(d.Op) {
	case "DELETE":
		var cols []string
		overriding := false
		for _, c := range tcols {
			if c.generated || !inSnap[c.name] {
				continue
			}
			cols = append(cols, c.name)
			if c.identity == 'a' {
				overriding = true
			}
		}
		if len(cols) == 0 {
			return nil, errors.New("pgundo: no columns in common between table and snapshot")
		}
		var hasKey bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_catalog.pg_index WHERE indrelid = $1::regclass AND (indisprimary OR indisunique))`, target).Scan(&hasKey); err != nil {
			return nil, err
		}
		q := "INSERT INTO " + target + " (" + quoteCols(cols, "") + ")"
		if overriding {
			q += " OVERRIDING SYSTEM VALUE"
		}
		q += " SELECT " + quoteCols(cols, "") + " FROM " + snap
		if hasKey {
			q += " ON CONFLICT DO NOTHING"
		}
		tag, err := tx.Exec(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("pgundo: restore rows: %w", err)
		}
		res["rows_restored"] = tag.RowsAffected()
		res["rows_skipped"] = snapRows - tag.RowsAffected()
		res["on_conflict_do_nothing"] = hasKey
	case "UPDATE":
		if len(d.PKColumns) == 0 {
			return nil, errors.New("pgundo: UPDATE undo requires pk_columns")
		}
		pk := map[string]bool{}
		inTarget := map[string]column{}
		for _, c := range tcols {
			inTarget[c.name] = c
		}
		var conds []string
		for _, c := range d.PKColumns {
			if _, ok := inTarget[c]; !ok || !inSnap[c] {
				return nil, fmt.Errorf("pgundo: primary key column %q missing from table or snapshot", c)
			}
			pk[c] = true
			conds = append(conds, "fortik_t."+pgsql.QuoteIdent(c)+" = fortik_s."+pgsql.QuoteIdent(c))
		}
		var sets []string
		for _, c := range tcols {
			if pk[c.name] || c.generated || c.identity == 'a' || !inSnap[c.name] {
				continue
			}
			sets = append(sets, pgsql.QuoteIdent(c.name)+" = fortik_s."+pgsql.QuoteIdent(c.name))
		}
		if len(sets) == 0 {
			res["rows_restored"] = int64(0)
			break
		}
		q := "UPDATE " + target + " AS fortik_t SET " + strings.Join(sets, ", ") +
			" FROM " + snap + " AS fortik_s WHERE " + strings.Join(conds, " AND ")
		tag, err := tx.Exec(ctx, q)
		if err != nil {
			return nil, fmt.Errorf("pgundo: restore values: %w", err)
		}
		res["rows_restored"] = tag.RowsAffected()
		res["rows_unmatched"] = snapRows - tag.RowsAffected()
	default:
		return nil, fmt.Errorf("pgundo: unsupported pg_rows op %q", d.Op)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}

func (e *Executor) undoRename(ctx context.Context, d undo.PGRenameData) (map[string]any, error) {
	if d.Schema == "" || d.Table == "" || d.TrashTable == "" {
		return nil, errors.New("pgundo: handle is missing table or trash names")
	}
	conn, err := e.connect(ctx, d.Upstream, d.Database)
	if err != nil {
		return nil, err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit

	if ok, err := relExists(ctx, tx, d.Schema, d.TrashTable); err != nil {
		return nil, err
	} else if !ok {
		return nil, fmt.Errorf("%w: trash table %s.%s does not exist", undo.ErrNothingToUndo, d.Schema, d.TrashTable)
	}
	target := pgsql.QuoteQualified(d.Schema, d.Table)
	trash := pgsql.QuoteQualified(d.Schema, d.TrashTable)
	// If the trash table belongs to a role the admin may SET ROLE to (a
	// per-agent role) but not inherit, act as that owner for this transaction.
	var owner, canSet bool
	var ownerName string
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE'), pg_catalog.pg_has_role(current_user, c.relowner, 'SET'),
		pg_catalog.pg_get_userbyid(c.relowner) FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass($1)`, trash).Scan(&owner, &canSet, &ownerName); err != nil {
		return nil, err
	}
	if !owner && canSet {
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgsql.QuoteIdent(ownerName)); err != nil {
			return nil, fmt.Errorf("pgundo: set role %s: %w", ownerName, err)
		}
	}
	exists, err := relExists(ctx, tx, d.Schema, d.Table)
	if err != nil {
		return nil, err
	}
	res := map[string]any{"op": d.Op, "table": d.Schema + "." + d.Table, "trash_table": d.Schema + "." + d.TrashTable}
	if exists {
		if !strings.EqualFold(d.Op, "TRUNCATE") {
			return nil, fmt.Errorf("pgundo: %s.%s exists again; refusing to overwrite it", d.Schema, d.Table)
		}
		if _, err := tx.Exec(ctx, "LOCK TABLE "+target+" IN ACCESS EXCLUSIVE MODE"); err != nil {
			return nil, err
		}
		var nonEmpty bool
		if err := tx.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM "+target+")").Scan(&nonEmpty); err != nil {
			return nil, err
		}
		if nonEmpty {
			return nil, fmt.Errorf("pgundo: recreated table %s.%s is not empty; refusing to drop it", d.Schema, d.Table)
		}
		if _, err := tx.Exec(ctx, "DROP TABLE "+target); err != nil {
			return nil, fmt.Errorf("pgundo: drop empty recreated table: %w", err)
		}
		res["dropped_empty_recreated_table"] = true
	}
	if _, err := tx.Exec(ctx, "ALTER TABLE "+trash+" RENAME TO "+pgsql.QuoteIdent(d.Table)); err != nil {
		return nil, fmt.Errorf("pgundo: rename trash back: %w", err)
	}
	var rows int64
	if err := tx.QueryRow(ctx, "SELECT count(*) FROM "+target).Scan(&rows); err != nil {
		return nil, err
	}
	res["rows_restored"] = rows
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return res, nil
}
