package pgsql

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// MaxIdentLen is PostgreSQL's NAMEDATALEN-1.
const MaxIdentLen = 63

// SnapshotSchema is where row snapshots are written.
const SnapshotSchema = "fortik_undo"

// ErrNotPreparable means Fortik cannot prepare undo for the statement.
var ErrNotPreparable = errors.New("pgsql: undo cannot be prepared for this statement")

// QuoteIdent double-quotes an identifier (always, so case and keywords are preserved).
func QuoteIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

// QuoteQualified quotes schema.table.
func QuoteQualified(schema, table string) string {
	return QuoteIdent(schema) + "." + QuoteIdent(table)
}

// QuoteLiteral returns an escape-string literal (E'...') that is correct
// regardless of standard_conforming_strings.
func QuoteLiteral(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `''`)
	return "E'" + s + "'"
}

// truncIdent truncates s to at most n bytes on a UTF-8 boundary.
func truncIdent(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[:n]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

// SnapshotTableName returns a deterministic snapshot table name for an
// action: <table truncated>_<lower-cased ULID of the action id>, <= 63 bytes.
func SnapshotTableName(table, actionID string) string {
	id := actionID
	if i := strings.LastIndexByte(id, '_'); i >= 0 {
		id = id[i+1:]
	}
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	id = b.String()
	if len(id) > 26 {
		id = id[len(id)-26:]
	}
	if id == "" {
		id = "x"
	}
	return truncIdent(table, MaxIdentLen-1-len(id)) + "_" + id
}

// SnapshotSQL returns
//
//	CREATE TABLE <schema>.<snap> AS SELECT * FROM <relation [alias]> WHERE <where>
//
// built from the statement's own parse tree, so the snapshot selects exactly
// the rows the DELETE/UPDATE matches (same relation, alias, ONLY, WHERE).
func SnapshotSQL(st *Statement, snapshotSchema, snapshotTable string) (string, error) {
	if st == nil || !st.SnapshotPreparable() || st.DML == nil {
		return "", ErrNotPreparable
	}
	var rel *pg_query.RangeVar
	var where *pg_query.Node
	switch {
	case st.DML.GetDeleteStmt() != nil:
		rel, where = st.DML.GetDeleteStmt().Relation, st.DML.GetDeleteStmt().WhereClause
	case st.DML.GetUpdateStmt() != nil:
		rel, where = st.DML.GetUpdateStmt().Relation, st.DML.GetUpdateStmt().WhereClause
	default:
		return "", ErrNotPreparable
	}
	if rel == nil || snapshotSchema == "" || snapshotTable == "" || len(snapshotTable) > MaxIdentLen {
		return "", ErrNotPreparable
	}
	sel := &pg_query.SelectStmt{
		TargetList: []*pg_query.Node{{Node: &pg_query.Node_ResTarget{ResTarget: &pg_query.ResTarget{
			Val: pg_query.MakeColumnRefNode([]*pg_query.Node{pg_query.MakeAStarNode()}, -1),
		}}}},
		FromClause:  []*pg_query.Node{{Node: &pg_query.Node_RangeVar{RangeVar: rel}}},
		WhereClause: where,
		LimitOption: pg_query.LimitOption_LIMIT_OPTION_DEFAULT,
		Op:          pg_query.SetOperation_SETOP_NONE,
	}
	ctas := &pg_query.CreateTableAsStmt{
		Query: &pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: sel}},
		Into: &pg_query.IntoClause{
			Rel: &pg_query.RangeVar{
				Schemaname: snapshotSchema, Relname: snapshotTable,
				Inh: true, Relpersistence: "p", Location: -1,
			},
			OnCommit: pg_query.OnCommitAction_ONCOMMIT_NOOP,
		},
		Objtype: pg_query.ObjectType_OBJECT_TABLE,
	}
	out, err := pg_query.Deparse(&pg_query.ParseResult{Version: st.version, Stmts: []*pg_query.RawStmt{{
		Stmt: &pg_query.Node{Node: &pg_query.Node_CreateTableAsStmt{CreateTableAsStmt: ctas}},
	}}})
	if err != nil {
		return "", fmt.Errorf("pgsql: deparse snapshot: %w", err)
	}
	return out, nil
}

// TrashTableName returns fortik_trash_<table>_<yyyymmddhhmmss> (<= 63 bytes).
func TrashTableName(table string, now time.Time) string {
	ts := now.UTC().Format("20060102150405")
	const prefix = "fortik_trash_"
	return prefix + truncIdent(table, MaxIdentLen-len(prefix)-1-len(ts)) + "_" + ts
}

// SafeRenameSQL returns the rename-based safe form for a single-table DROP
// TABLE (rename to trash) or TRUNCATE (rename to trash, then recreate an empty
// table LIKE the trash table), plus the trash table name.
func SafeRenameSQL(st *Statement, now time.Time) (sql, trash string, err error) {
	if st == nil || !st.SingleRelation() || st.Table == "" {
		return "", "", ErrNotPreparable
	}
	trash = TrashTableName(st.Table, now)
	rename := fmt.Sprintf("ALTER TABLE %s RENAME TO %s", QuoteQualified(st.Schema, st.Table), QuoteIdent(trash))
	switch st.StatementType {
	case TypeDropTable:
		return rename, trash, nil
	case TypeTruncate:
		return rename + "; " + fmt.Sprintf("CREATE TABLE %s (LIKE %s INCLUDING ALL)",
			QuoteQualified(st.Schema, st.Table), QuoteQualified(st.Schema, trash)), trash, nil
	}
	return "", "", ErrNotPreparable
}
