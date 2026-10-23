package approvals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/broker/pgroles"
	"fortik/internal/diary"
	"fortik/internal/pgsql"
	"fortik/internal/undo"
)

// renameTarget is the part of a held Postgres action's target the pg_rename
// safe form is rebuilt from. The stored safe_form SQL text is never run:
// the statement is regenerated from these identifiers with proper quoting.
type renameTarget struct {
	Upstream string
	Database string
	Schema   string
	Table    string
	Op       string // DROP | TRUNCATE
}

func validIdent(s string) bool {
	return s != "" && len(s) <= pgsql.MaxIdentLen && utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// parseRenameTarget validates the held action's target for a pg_rename safe
// form: a single-table DROP TABLE or TRUNCATE on a named upstream.
func parseRenameTarget(system string, t map[string]any) (renameTarget, error) {
	if system != action.SystemPostgres {
		return renameTarget{}, fmt.Errorf("pg_rename safe form on system %q", system)
	}
	str := func(k string) string { v, _ := t[k].(string); return v }
	rt := renameTarget{Upstream: str("upstream"), Database: str("database"), Schema: str("schema"), Table: str("table")}
	switch str("statement_type") {
	case pgsql.TypeDropTable:
		rt.Op = "DROP"
	case pgsql.TypeTruncate:
		rt.Op = "TRUNCATE"
	default:
		return renameTarget{}, fmt.Errorf("pg_rename safe form for statement type %q", str("statement_type"))
	}
	if !pgroles.ValidName(rt.Upstream) {
		return renameTarget{}, fmt.Errorf("target upstream %q is not a valid integration name", rt.Upstream)
	}
	if rt.Schema == "" {
		rt.Schema = "public"
	}
	if !validIdent(rt.Schema) || !validIdent(rt.Table) {
		return renameTarget{}, errors.New("target schema/table are missing or not valid identifiers")
	}
	if tables, ok := t["tables"]; ok {
		list, ok := tables.([]any)
		if !ok || len(list) != 1 {
			return renameTarget{}, errors.New("pg_rename safe form needs exactly one target table")
		}
	}
	return rt, nil
}

// executeRename runs the pg_rename safe form on the upstream as the
// integration's admin user:
//
//	DROP:     ALTER TABLE s.t RENAME TO fortik_trash_t_<ts>
//	TRUNCATE: the same, then CREATE TABLE s.t (LIKE s.fortik_trash_t_<ts> INCLUDING ALL)
//
// Every precondition is checked (and the table locked) before the undo
// handle is recorded; the handle is recorded before the change runs and is
// activated after the upstream commit, so the result is always undoable by
// pgundo (or the handle is failed when the change did not happen).
func (s *Service) executeRename(ctx context.Context, h *hold, t renameTarget, actor string) (SafeFormResult, error) {
	if s.src == nil || s.undo == nil {
		return SafeFormResult{}, fmt.Errorf("%w: no integration source or undo store is configured", ErrSafeFormState)
	}
	ctx, cancel := context.WithTimeout(ctx, s.cfg.ExecTimeout)
	defer cancel()

	// A handle may already exist from an earlier attempt whose outcome was
	// unclear; never overwrite or reuse it.
	if prev, err := s.undo.Get(ctx, h.actionID); err == nil {
		return SafeFormResult{}, fmt.Errorf("%w: an undo record already exists for this action (status %s); deny the hold and let the agent retry",
			ErrSafeFormState, prev.Status)
	} else if !errors.Is(err, undo.ErrNotFound) {
		return SafeFormResult{}, fmt.Errorf("check undo record: %w", err)
	}

	up, err := pgroles.Resolve(ctx, s.src, t.Upstream)
	if errors.Is(err, pgroles.ErrUpstreamNotManaged) {
		return SafeFormResult{}, fmt.Errorf("%w: upstream %q is not a postgres integration", ErrSafeFormState, t.Upstream)
	}
	if err != nil {
		return SafeFormResult{}, fmt.Errorf("%w: %v", ErrSafeFormState, err)
	}
	if t.Database != "" && t.Database != up.Database {
		return SafeFormResult{}, fmt.Errorf("%w: the held action targets database %q but integration postgres:%s now points at %q",
			ErrSafeFormState, t.Database, t.Upstream, up.Database)
	}
	t.Database = up.Database
	pc, err := up.AdminConnConfig(map[string]string{"application_name": "fortik:approvals"})
	if err != nil {
		return SafeFormResult{}, fmt.Errorf("%w: %v", ErrSafeFormState, err)
	}
	cc, err := pgx.ParseConfig("")
	if err != nil {
		return SafeFormResult{}, err
	}
	cc.Config = *pc
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return SafeFormResult{}, fmt.Errorf("%w: connect to postgres:%s: %v", ErrSafeFormRun, t.Upstream, err)
	}
	defer conn.Close(context.WithoutCancel(ctx))

	tx, err := conn.Begin(ctx)
	if err != nil {
		return SafeFormResult{}, fmt.Errorf("%w: %v", ErrSafeFormRun, err)
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after commit

	target := pgsql.QuoteQualified(t.Schema, t.Table)
	trash := pgsql.TrashTableName(t.Table, s.now())
	res := SafeFormResult{Kind: SafeFormPGRename, Op: t.Op, Upstream: t.Upstream, Database: t.Database,
		Schema: t.Schema, Table: t.Table, TrashTable: trash, UndoKind: undo.KindPGRename}

	if err := s.renamePreconditions(ctx, tx, t, target, trash); err != nil {
		return SafeFormResult{}, err
	}

	data, err := json.Marshal(undo.PGRenameData{Upstream: t.Upstream, Database: t.Database, Schema: t.Schema,
		Table: t.Table, TrashTable: trash, Op: t.Op})
	if err != nil {
		return SafeFormResult{}, err
	}
	now := s.now().UTC()
	if err := s.undo.Prepare(ctx, undo.Handle{ActionID: h.actionID, AgentID: h.agentID, Kind: undo.KindPGRename, Data: data,
		Status: undo.StatusPrepared, ExpiresAt: now.Add(s.cfg.TrashRetention), CreatedAt: now}, actor); err != nil {
		return SafeFormResult{}, fmt.Errorf("%w: the undo handle could not be recorded, nothing was changed: %v", ErrSafeFormState, err)
	}

	fail := func(cause error) error {
		fctx, fcancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
		defer fcancel()
		if err := s.undo.Fail(fctx, h.actionID, "safe form did not run: "+cause.Error()); err != nil {
			s.log.Error("undo handle could not be failed", "action_id", h.actionID, "err", err)
		}
		s.recordFailure(fctx, h, res, actor, cause.Error())
		return fmt.Errorf("%w: %v", ErrSafeFormRun, cause)
	}

	if _, err := tx.Exec(ctx, "ALTER TABLE "+target+" RENAME TO "+pgsql.QuoteIdent(trash)); err != nil {
		return SafeFormResult{}, fail(fmt.Errorf("rename: %w", err))
	}
	if t.Op == "TRUNCATE" {
		if _, err := tx.Exec(ctx, "CREATE TABLE "+target+" (LIKE "+pgsql.QuoteQualified(t.Schema, trash)+" INCLUDING ALL)"); err != nil {
			return SafeFormResult{}, fail(fmt.Errorf("recreate empty table: %w", err))
		}
		res.Recreated = true
	}
	if err := tx.Commit(ctx); err != nil {
		// The commit may or may not have happened: look before deciding.
		renamed, verr := s.verifyRenamed(context.WithoutCancel(ctx), cc, t, trash)
		switch {
		case verr != nil:
			s.log.Error("safe form commit outcome unknown; undo handle left 'prepared' for manual review",
				"action_id", h.actionID, "trash_table", trash, "err", err, "verify_err", verr)
			return SafeFormResult{}, fmt.Errorf("%w: commit failed (%v) and the result could not be verified; the undo handle is left prepared for manual review",
				ErrOutcomeUnsure, err)
		case !renamed:
			return SafeFormResult{}, fail(fmt.Errorf("commit: %w", err))
		}
	}
	actx, acancel := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer acancel()
	if err := s.undo.Activate(actx, h.actionID); err != nil {
		s.log.Error("safe form EXECUTED but its undo handle could not be activated; manual review needed",
			"action_id", h.actionID, "trash_table", trash, "err", err)
		return SafeFormResult{}, fmt.Errorf("safe form executed (trash table %s) but its undo handle could not be activated: %w", trash, err)
	}
	return res, nil
}

// renamePreconditions checks, inside the upstream transaction, everything the
// rename needs, and takes the table lock so nothing changes before it runs.
func (s *Service) renamePreconditions(ctx context.Context, tx pgx.Tx, t renameTarget, target, trash string) error {
	lockMS := strconv.FormatInt(s.cfg.LockTimeout.Milliseconds(), 10)
	stmtMS := strconv.FormatInt(s.cfg.ExecTimeout.Milliseconds(), 10)
	for _, q := range []string{"SET LOCAL lock_timeout = " + lockMS, "SET LOCAL statement_timeout = " + stmtMS} {
		if _, err := tx.Exec(ctx, q); err != nil {
			return fmt.Errorf("%w: %v", ErrSafeFormRun, err)
		}
	}
	var (
		exists, owner, canCreate, canSet bool
		kind, ownerName                  string
	)
	err := tx.QueryRow(ctx, `
		SELECT c.relkind::text, pg_catalog.pg_has_role(current_user, c.relowner, 'USAGE'),
		       pg_catalog.has_schema_privilege(current_user, c.relnamespace, 'CREATE'),
		       pg_catalog.pg_has_role(current_user, c.relowner, 'SET'), pg_catalog.pg_get_userbyid(c.relowner)
		FROM pg_catalog.pg_class c WHERE c.oid = pg_catalog.to_regclass($1)`, target).Scan(&kind, &owner, &canCreate, &canSet, &ownerName)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return fmt.Errorf("%w: %v", ErrSafeFormRun, err)
	default:
		exists = true
	}
	if !exists {
		return fmt.Errorf("%w: table %s.%s no longer exists on postgres:%s", ErrSafeFormState, t.Schema, t.Table, t.Upstream)
	}
	if kind != "r" && kind != "p" {
		return fmt.Errorf("%w: %s.%s is not a table (relkind %s)", ErrSafeFormState, t.Schema, t.Table, kind)
	}
	if !owner && canSet {
		// Tables an agent created belong to its per-agent role; Fortik's admin
		// was granted SET (not INHERIT) on that role when it was created, so it
		// can act as the owner for this one transaction.
		if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+pgsql.QuoteIdent(ownerName)); err != nil {
			return fmt.Errorf("%w: set role %s: %v", ErrSafeFormRun, ownerName, err)
		}
		owner = true
		if err := tx.QueryRow(ctx, `SELECT pg_catalog.has_schema_privilege(current_user, $1, 'CREATE')`, t.Schema).Scan(&canCreate); err != nil {
			return fmt.Errorf("%w: %v", ErrSafeFormRun, err)
		}
	}
	if !owner {
		return fmt.Errorf("%w: the integration admin does not own %s.%s and cannot rename it", ErrSafeFormState, t.Schema, t.Table)
	}
	// ALTER TABLE ... RENAME needs CREATE on the table's schema (and the
	// TRUNCATE form creates the empty copy there too).
	if !canCreate {
		return fmt.Errorf("%w: the integration admin lacks CREATE on schema %s and cannot rename tables in it", ErrSafeFormState, t.Schema)
	}
	var trashTaken bool
	if err := tx.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL`, pgsql.QuoteQualified(t.Schema, trash)).Scan(&trashTaken); err != nil {
		return fmt.Errorf("%w: %v", ErrSafeFormRun, err)
	}
	if trashTaken {
		return fmt.Errorf("%w: trash table %s.%s already exists; retry in a second", ErrSafeFormState, t.Schema, trash)
	}
	if _, err := tx.Exec(ctx, "LOCK TABLE "+target+" IN ACCESS EXCLUSIVE MODE"); err != nil {
		return fmt.Errorf("%w: lock %s.%s: %v", ErrSafeFormRun, t.Schema, t.Table, err)
	}
	return nil
}

// verifyRenamed reports whether the trash table exists after an uncertain
// commit (DROP: and the original name is gone).
func (s *Service) verifyRenamed(ctx context.Context, cc *pgx.ConnConfig, t renameTarget, trash string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := pgx.ConnectConfig(ctx, cc)
	if err != nil {
		return false, err
	}
	defer conn.Close(ctx)
	var trashExists, targetExists bool
	err = conn.QueryRow(ctx, `SELECT pg_catalog.to_regclass($1) IS NOT NULL, pg_catalog.to_regclass($2) IS NOT NULL`,
		pgsql.QuoteQualified(t.Schema, trash), pgsql.QuoteQualified(t.Schema, t.Table)).Scan(&trashExists, &targetExists)
	if err != nil {
		return false, err
	}
	if t.Op == "DROP" {
		return trashExists && !targetExists, nil
	}
	return trashExists, nil
}

// recordFailure writes safe_form.failed (best effort, own transaction: the
// approval transaction rolls back).
func (s *Service) recordFailure(ctx context.Context, h *hold, res SafeFormResult, actor, cause string) {
	if _, err := s.diary.Append(ctx, diary.Event{AgentID: h.agentID, EventType: EventSafeFormFailed, Actor: actor, Data: map[string]any{
		"action_id": h.actionID, "kind": res.Kind, "op": res.Op, "upstream": res.Upstream, "database": res.Database,
		"schema": res.Schema, "table": res.Table, "trash_table": res.TrashTable, "error": cause,
	}}); err != nil {
		s.log.Error("could not record safe form failure", "action_id", h.actionID, "err", err)
	}
}
