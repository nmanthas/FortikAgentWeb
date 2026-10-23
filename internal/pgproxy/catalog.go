package pgproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"fortik/internal/pgsql"
)

// tableInfo is what the proxy knows about a relation from the catalog.
type tableInfo struct {
	exists  bool
	schema  string     // resolved schema (via the session's search_path when unqualified)
	pk      []string   // primary key columns
	uniques [][]string // key columns of every valid, non-partial, non-expression unique index (incl. PK)
}

// narrow reports whether equality on cols pins at most one row.
func (t *tableInfo) narrow(cols []string) bool {
	if t == nil || len(cols) == 0 {
		return false
	}
	have := map[string]bool{}
	for _, c := range cols {
		have[c] = true
	}
	for _, u := range t.uniques {
		if len(u) == 0 {
			continue
		}
		all := true
		for _, c := range u {
			if !have[c] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}

func relationLiteral(st *pgsql.Statement) string {
	if st.SchemaQualified {
		return pgsql.QuoteLiteral(pgsql.QuoteQualified(st.Schema, st.Table))
	}
	return pgsql.QuoteLiteral(pgsql.QuoteIdent(st.Table))
}

// tableInfo looks up (and caches per session) key information for the
// statement's primary relation. Callers must ensure the session is idle.
func (s *session) tableInfo(st *pgsql.Statement) (*tableInfo, error) {
	key := fmt.Sprintf("%t\x00%s\x00%s", st.SchemaQualified, st.Schema, st.Table)
	if ti, ok := s.tables[key]; ok {
		return ti, nil
	}
	q := `SELECT n.nspname, i.indexrelid::text, i.indisprimary::text, a.attname
FROM pg_catalog.pg_class c
JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
LEFT JOIN pg_catalog.pg_index i ON i.indrelid = c.oid AND (i.indisprimary OR i.indisunique)
     AND i.indisvalid AND i.indpred IS NULL AND i.indexprs IS NULL
LEFT JOIN LATERAL unnest(i.indkey::pg_catalog.int2[]) WITH ORDINALITY AS k(attnum, ord) ON k.ord <= i.indnkeyatts
LEFT JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attnum = k.attnum
WHERE c.oid = pg_catalog.to_regclass(` + relationLiteral(st) + `)
ORDER BY i.indexrelid, k.ord`
	r, err := s.preQuery(q, false)
	if err != nil {
		return nil, err
	}
	ti := &tableInfo{}
	var cur string
	var curPK bool
	var cols []string
	flush := func() {
		if cur != "" && len(cols) > 0 {
			ti.uniques = append(ti.uniques, cols)
			if curPK {
				ti.pk = cols
			}
		}
	}
	for _, row := range r.rows {
		if len(row) != 4 {
			return nil, errors.New("unexpected catalog result shape")
		}
		ti.exists = true
		ti.schema = string(row[0])
		if row[1] == nil || row[3] == nil {
			continue
		}
		idx := string(row[1])
		if idx != cur {
			flush()
			cur, curPK, cols = idx, string(row[2]) == "true", nil
		}
		cols = append(cols, string(row[3]))
	}
	flush()
	if !ti.exists {
		ti.schema = st.Schema
	}
	s.tables[key] = ti
	return ti, nil
}

// explainRows returns the planner's row estimate for a DELETE/UPDATE using
// plain EXPLAIN (which never executes the statement).
func (s *session) explainRows(st *pgsql.Statement) (int64, error) {
	opts := "FORMAT JSON"
	if st.HasParams {
		if s.serverMajor < 16 {
			return 0, errors.New("parameterised statement and server < 16 (no GENERIC_PLAN)")
		}
		opts += ", GENERIC_PLAN"
	}
	q := "EXPLAIN (" + opts + ") " + st.SQL + "\n"
	// Defence in depth: the composed text must be exactly one plain EXPLAIN.
	chk, err := pgsql.Classify(q)
	if err != nil || len(chk) != 1 || chk[0].StatementType != pgsql.TypeExplain {
		return 0, errors.New("refusing to run composed EXPLAIN")
	}
	// $n placeholders only work with GENERIC_PLAN in a simple Query (over
	// the extended protocol they would become parameters of the Parse).
	r, err := s.preQuery(q, st.HasParams)
	if err != nil {
		return 0, err
	}
	if len(r.rows) != 1 || len(r.rows[0]) != 1 {
		return 0, errors.New("unexpected EXPLAIN result shape")
	}
	var plan []struct {
		Plan explainNode `json:"Plan"`
	}
	if err := json.Unmarshal(r.rows[0][0], &plan); err != nil || len(plan) == 0 {
		return 0, errors.New("unparseable EXPLAIN output")
	}
	top := plan[0].Plan
	// A read is sized by the rows it reads, not the rows it returns: an
	// aggregate over a whole table (json_agg, string_agg, count...) returns
	// one row but reads them all. The largest estimate anywhere in the plan
	// (scans, joins, sub-plans) bounds that.
	if st.StatementType == pgsql.TypeSelect {
		return int64(top.maxRows()), nil
	}
	// Since PG 14 a ModifyTable node without RETURNING reports 0 rows; the
	// rows it will modify are its input's estimate.
	if top.NodeType == "ModifyTable" && len(top.Plans) > 0 {
		return int64(top.Plans[0].Rows), nil
	}
	return int64(top.Rows), nil
}

type explainNode struct {
	NodeType string        `json:"Node Type"`
	Rows     float64       `json:"Plan Rows"`
	Plans    []explainNode `json:"Plans"`
}

// maxRows is the largest row estimate of n and every node under it.
func (n explainNode) maxRows() float64 {
	m := n.Rows
	for _, c := range n.Plans {
		if r := c.maxRows(); r > m {
			m = r
		}
	}
	return m
}

// relFacts describes the relations a statement references, from the catalog.
type relFacts struct {
	plain     bool  // every relation exists and is a plain or partitioned table
	maxTuples int64 // the largest pg_class.reltuples
	analysed  bool  // every relation has a planner row count (reltuples >= 0)
}

// relationFacts looks up every relation in tables (as "schema.table"). A view,
// materialized view, foreign table or anything else is not plain: planning a
// statement over it can run user code (a function inside the view folded at
// plan time), so no EXPLAIN may run before the decision. Callers must ensure
// the session is idle.
func (s *session) relationFacts(tables []string) (relFacts, error) {
	if len(tables) == 0 {
		return relFacts{plain: true, analysed: true}, nil
	}
	lits := make([]string, 0, len(tables))
	for _, t := range tables {
		schema, table, ok := strings.Cut(t, ".")
		if !ok || schema == "" || table == "" || table == "*" {
			return relFacts{}, fmt.Errorf("relation %q is not schema.table", t)
		}
		lits = append(lits, "pg_catalog.to_regclass("+pgsql.QuoteLiteral(pgsql.QuoteQualified(schema, table))+")")
	}
	q := `SELECT count(c.oid)::text, coalesce(bool_and(c.relkind IN ('r', 'p')), false)::text,
       coalesce(max(c.reltuples), -1)::bigint::text, coalesce(min(c.reltuples), -1)::bigint::text
FROM unnest(ARRAY[` + strings.Join(lits, ", ") + `]::pg_catalog.regclass[]) AS t(r)
LEFT JOIN pg_catalog.pg_class c ON c.oid = t.r`
	r, err := s.preQuery(q, false)
	if err != nil {
		return relFacts{}, err
	}
	if len(r.rows) != 1 || len(r.rows[0]) != 4 {
		return relFacts{}, errors.New("unexpected catalog result shape")
	}
	row := r.rows[0]
	var n, maxT, minT int64
	if _, err := fmt.Sscan(string(row[0])+" "+string(row[2])+" "+string(row[3]), &n, &maxT, &minT); err != nil {
		return relFacts{}, fmt.Errorf("unparseable catalog result: %w", err)
	}
	return relFacts{
		plain:     n == int64(len(tables)) && string(row[1]) == "true",
		maxTuples: maxT,
		analysed:  minT >= 0,
	}, nil
}

// preQuery runs a read-only internal query with the configured timeout,
// without disturbing the client's transaction: inside a transaction block it
// runs in a savepoint that is always rolled back.
//
// While the client may still use an unnamed statement or portal, the query
// runs over the extended protocol on proxy-owned names (a simple Query would
// make Postgres drop them). needSimple queries are then refused.
func (s *session) preQuery(q string, needSimple bool) (*result, error) {
	timeout := s.srv.cfg.PreQueryTimeout
	ms := timeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}
	guard := timeout + 5*time.Second
	setTimeout := fmt.Sprintf("SET LOCAL statement_timeout = %d", ms)
	ext := s.unnamedLive()
	if ext && needSimple {
		return nil, errors.New("query needs the simple protocol while the client holds an unnamed statement or portal")
	}
	run := func(steps ...string) (*result, error) {
		if ext {
			// SET LOCAL applies until the Sync ends the implicit transaction.
			return s.internalExt(steps, guard)
		}
		// A multi-statement simple query is one implicit transaction, so
		// SET LOCAL ends with it.
		return s.internalQuery(strings.Join(steps, ";\n"), guard)
	}
	var r *result
	var err error
	switch s.status() {
	case 'I':
		r, err = run(setTimeout, q)
	case 'T':
		r, err = run("SAVEPOINT fortik_pre", setTimeout, q)
		if err == nil {
			rb, rerr := run("ROLLBACK TO SAVEPOINT fortik_pre", "RELEASE SAVEPOINT fortik_pre")
			if rerr != nil {
				return nil, rerr
			}
			if rb.failed() || rb.txStatus != 'T' {
				return nil, fmt.Errorf("could not restore client transaction after pre-query: %s", rb.errText())
			}
		}
	default:
		return nil, errors.New("transaction is in failed state")
	}
	if err != nil {
		return nil, err
	}
	if r.failed() {
		return nil, fmt.Errorf("pre-query failed: %s", strings.TrimSpace(r.errText()))
	}
	return r, nil
}
