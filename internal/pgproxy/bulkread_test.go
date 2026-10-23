package pgproxy

import (
	"testing"

	"github.com/jackc/pgx/v5"
)

// Phase 5 review (POL-113/POL-114): a read of a labelled table is sized by
// the rows it reads, a parameterised read cannot shrink its estimate with
// default selectivities, and nothing is planned over a view before the
// decision.
func TestBulkReadEstimateResistsEvasion(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE customers (id int PRIMARY KEY, email text)")
	h.exec("INSERT INTO customers SELECT g, 'u' || g || '@example.com' FROM generate_series(1, 20000) g")
	h.exec("ANALYZE customers")
	h.dec.set("SELECT", denyRule("pg.inspect")) // nothing runs: only the action is inspected

	est := func(t *testing.T) int64 {
		t.Helper()
		e := h.dec.last(t).PayloadSummary.RowsEstimate
		if e == nil {
			t.Fatal("no rows_estimate")
		}
		return *e
	}
	simple := h.connect(pgx.QueryExecModeSimpleProtocol)

	// H1: an aggregate returns one row but reads the whole table.
	for _, q := range []string{
		"SELECT json_agg(c) FROM customers c",
		"SELECT string_agg(email, ',') FROM customers",
		"SELECT count(*) FROM customers",
	} {
		_, _ = simple.Exec(bg, q)
		if n := est(t); n < 15000 {
			t.Errorf("%s: estimate %d, want the rows read (~20000)", q, n)
		}
	}

	// H2: random() is never evaluated by the planner, so it no longer
	// removes the estimate.
	_, _ = simple.Exec(bg, "SELECT * FROM customers WHERE id > 0 AND random() >= 0")
	if n := est(t); n < 5000 {
		t.Errorf("random() read: estimate %d", n)
	}

	// H3: generic-plan selectivities ("id > $1" = 1/3, BETWEEN = 0.5%) are
	// bounded below by the table size; a unique-key lookup stays small.
	ext := h.connect(pgx.QueryExecModeCacheDescribe)
	for _, q := range []string{
		"SELECT * FROM customers WHERE id > $1",
		"SELECT * FROM customers WHERE id BETWEEN $1 AND $1 + 100000",
	} {
		_, _ = ext.Exec(bg, q, 0)
		if n := est(t); n < 15000 {
			t.Errorf("%s: estimate %d, want the table size", q, n)
		}
	}
	_, _ = ext.Exec(bg, "SELECT * FROM customers WHERE id = $1", 7)
	if n := est(t); n > 5 {
		t.Errorf("unique-key lookup: estimate %d", n)
	}
}

// M1: a function reached through a view is not in the statement text; the
// proxy must not plan the statement before the decision (planning would
// constant-fold the IMMUTABLE function and run it), and so reports no
// estimate (POL-114 then holds a sensitive read).
func TestNoPreDecisionPlanOverViews(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE customers (id int PRIMARY KEY, email text)")
	h.exec("INSERT INTO customers SELECT g, 'x' FROM generate_series(1, 100) g")
	h.exec("ANALYZE customers")
	h.exec("CREATE SEQUENCE probe_seq")
	h.exec(`CREATE FUNCTION probe(int) RETURNS int LANGUAGE plpgsql IMMUTABLE AS $$ BEGIN PERFORM nextval('probe_seq'); RETURN $1; END $$`)
	h.exec("CREATE VIEW probe_v AS SELECT probe(1) AS p")
	h.dec.set("SELECT", denyRule("pg.inspect"))
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	if _, err := c.Exec(bg, "SELECT c.*, v.p FROM customers c CROSS JOIN probe_v v"); err == nil {
		t.Fatal("the denied read ran")
	}
	if e := h.dec.last(t).PayloadSummary.RowsEstimate; e != nil {
		t.Fatalf("estimate %d computed by planning over a view", *e)
	}
	if n := h.count("SELECT count(*) FROM pg_sequences WHERE sequencename = 'probe_seq' AND last_value IS NOT NULL"); n != 0 {
		t.Fatal("the view's function ran before the decision")
	}
}
