package pgproxy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/pgsql"
	"fortik/internal/policy"
	"fortik/internal/undo"
)

var bg = context.Background()

func TestAuth(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	var one int
	if err := c.QueryRow(bg, "SELECT 1").Scan(&one); err != nil || one != 1 {
		t.Fatalf("select through proxy: %v", err)
	}

	_, err := h.connectErr(testAgent, "wrong-token", upName, pgx.QueryExecModeSimpleProtocol)
	if pe := pgErr(t, err); pe.Code != "28P01" {
		t.Fatalf("bad token: got %s", pe.Code)
	}
	_, err = h.connectErr("ghost-agent", testToken, upName, pgx.QueryExecModeSimpleProtocol)
	if pe := pgErr(t, err); pe.Code != "28P01" {
		t.Fatalf("unknown agent: got %s", pe.Code)
	}

	// Token rotation without restart.
	toks, _ := json.Marshal(map[string]string{testAgent: sha("rotated")})
	h.sec.set("agent_tokens", toks)
	if _, err := h.connectErr(testAgent, testToken, upName, pgx.QueryExecModeSimpleProtocol); err == nil {
		t.Fatal("old token still accepted after rotation")
	}
	c2, err := h.connectErr(testAgent, "rotated", upName, pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatalf("rotated token rejected: %v", err)
	}
	c2.Close(bg)

	// The upstream backend carries the agent marker in application_name.
	var app string
	if err := c.QueryRow(bg, "SELECT current_setting('application_name')").Scan(&app); err != nil {
		t.Fatal(err)
	}
	if app != "fortik:agent-1:inst-7" {
		t.Fatalf("upstream application_name = %q", app)
	}
	a := h.dec.last(t)
	if a.AgentID != testAgent || a.InstanceID != "inst-7" {
		t.Fatalf("agent/instance = %q/%q", a.AgentID, a.InstanceID)
	}
}

func TestUnknownDatabase(t *testing.T) {
	h := newHarness(t)
	_, err := h.connectErr(testAgent, testToken, "nope", pgx.QueryExecModeSimpleProtocol)
	pe := pgErr(t, err)
	if pe.Code != "3D000" || pe.Severity != "FATAL" {
		t.Fatalf("got %s %s %s", pe.Severity, pe.Code, pe.Message)
	}
}

func TestSelectAllowedAndTarget(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE customers (id int PRIMARY KEY, email text UNIQUE, name text)")
	h.exec("INSERT INTO customers VALUES (1,'a@x','A'),(2,'b@x','B'),(3,'c@x','C')")
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			h.dec.reset()
			c := h.connect(m.mode)
			rows, err := c.Query(bg, "SELECT id, name FROM customers WHERE id >= $1 ORDER BY id", 2)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for rows.Next() {
				var id int
				var name string
				if err := rows.Scan(&id, &name); err != nil {
					t.Fatal(err)
				}
				got = append(got, fmt.Sprintf("%d:%s", id, name))
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if strings.Join(got, ",") != "2:B,3:C" {
				t.Fatalf("rows = %v", got)
			}
			a := h.dec.last(t)
			wantKeys := []string{"database", "dangerous_functions", "environment", "fingerprint", "has_where",
				"normalized_sql", "protocol", "schema", "statement_count", "statement_type", "table", "tables",
				"undo_preparable", "upstream", "where_narrow", "on_conflict_update", "merge_has_delete", "volatile_where"}
			var keys []string
			for k := range a.Target {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			sort.Strings(wantKeys)
			if strings.Join(keys, ",") != strings.Join(wantKeys, ",") {
				t.Fatalf("target keys = %v", keys)
			}
			if a.Verb != "READ" || !a.Reversible || a.System != "postgres" || a.Source != "pgproxy" {
				t.Fatalf("action = %+v", a)
			}
			if a.Target["statement_type"] != "SELECT" || a.Target["upstream"] != upName ||
				a.Target["database"] != h.dbName || a.Target["environment"] != "dev" || a.Target["table"] != "customers" {
				t.Fatalf("target = %+v", a.Target)
			}
			if a.Target["protocol"] != m.name {
				t.Fatalf("protocol = %v", a.Target["protocol"])
			}
			if len(a.PayloadSummary.DataLabels) != 1 || a.PayloadSummary.DataLabels[0] != "customer_pii" {
				t.Fatalf("labels = %v", a.PayloadSummary.DataLabels)
			}
			if !strings.HasPrefix(a.ActionID, "act_") {
				t.Fatalf("action id %q", a.ActionID)
			}
			if ns := a.Target["normalized_sql"].(string); strings.Contains(ns, "'") {
				t.Fatalf("normalized sql has literals: %s", ns)
			}
		})
	}
}

func TestLargeSelectStreams(t *testing.T) {
	h := newHarness(t)
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			c := h.connect(m.mode)
			start := time.Now()
			rows, err := c.Query(bg, "SELECT g, md5(g::text) FROM generate_series(1, 50000) g")
			if err != nil {
				t.Fatal(err)
			}
			var n, sum int64
			for rows.Next() {
				var g int64
				var s string
				if err := rows.Scan(&g, &s); err != nil {
					t.Fatal(err)
				}
				n++
				sum += g
			}
			if err := rows.Err(); err != nil {
				t.Fatal(err)
			}
			if n != 50000 || sum != 50000*50001/2 {
				t.Fatalf("n=%d sum=%d", n, sum)
			}
			if d := time.Since(start); d > 10*time.Second {
				t.Fatalf("50k rows took %v", d)
			}
			t.Logf("%s: 50k rows in %v", m.name, time.Since(start))
		})
	}
}

func TestRefusedDropTable(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE important (id int)")
	h.dec.set("DROP_TABLE", holdRule("pg.drop_table"))
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			c := h.connect(m.mode)
			var err error
			if m.mode == pgx.QueryExecModeSimpleProtocol {
				_, err = c.Exec(bg, "DROP TABLE important")
			} else {
				err = c.PgConn().ExecParams(bg, "DROP TABLE important", nil, nil, nil, nil).Read().Err
			}
			pe := pgErr(t, err)
			a := h.dec.last(t)
			if pe.Code != "42501" || !strings.HasPrefix(pe.Message, "fortik: hold (red) by pg.drop_table: needs approval") {
				t.Fatalf("error = %s %s", pe.Code, pe.Message)
			}
			if pe.Detail != "action_id="+a.ActionID {
				t.Fatalf("detail = %q", pe.Detail)
			}
			if !strings.Contains(pe.Hint, `A security approver can approve the safe form: ALTER TABLE "public"."important" RENAME TO "fortik_trash_important_`) {
				t.Fatalf("hint = %q", pe.Hint)
			}
			if pe.Where != "" {
				t.Fatalf("internal context leaked: %q", pe.Where)
			}
			sf, ok := a.Target["safe_form"].(map[string]any)
			if !ok || sf["kind"] != "pg_rename" || !strings.HasPrefix(sf["trash_table"].(string), "fortik_trash_important_") {
				t.Fatalf("safe_form = %#v", a.Target["safe_form"])
			}
			if h.count("SELECT count(*) FROM pg_tables WHERE tablename = 'important'") != 1 {
				t.Fatal("table was dropped")
			}
			// Connection remains usable.
			var one int
			if err := c.QueryRow(bg, "SELECT 1").Scan(&one); err != nil {
				t.Fatalf("connection unusable after refusal: %v", err)
			}
		})
	}
}

func TestRefusalInsideTransactionAborts(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int PRIMARY KEY, v text)")
	h.dec.set("DROP_TABLE", denyRule("pg.drop"))
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			h.exec("TRUNCATE t")
			h.exec("INSERT INTO t VALUES (1,'a'),(2,'b')")
			c := h.connect(m.mode)
			tx, err := c.Begin(bg)
			if err != nil {
				t.Fatal(err)
			}
			if m.mode == pgx.QueryExecModeSimpleProtocol {
				if _, err := tx.Exec(bg, "DELETE FROM t WHERE id = 1"); err != nil {
					t.Fatal(err)
				}
				_, err = tx.Exec(bg, "DROP TABLE t")
			} else {
				if _, err := tx.Exec(bg, "DELETE FROM t WHERE id = $1", 1); err != nil {
					t.Fatal(err)
				}
				err = c.PgConn().ExecParams(bg, "DROP TABLE t", nil, nil, nil, nil).Read().Err
			}
			if pe := pgErr(t, err); pe.Code != "42501" {
				t.Fatalf("got %s", pe.Code)
			}
			// Later statements fail like after any Postgres error.
			_, err = tx.Exec(bg, "SELECT 1")
			if pe := pgErr(t, err); pe.Code != "25P02" {
				t.Fatalf("expected 25P02 in aborted tx, got %s", pe.Code)
			}
			if err := tx.Commit(bg); !errors.Is(err, pgx.ErrTxCommitRollback) {
				t.Fatalf("commit: expected rollback, got %v", err)
			}
			if n := h.count("SELECT count(*) FROM t WHERE id = 1"); n != 1 {
				t.Fatal("DELETE before the refused statement was committed")
			}
		})
	}
}

func TestMultiStatementRefusalRunsNothing(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int)")
	h.dec.set("DROP_TABLE", denyRule("pg.drop"))
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	_, err := c.PgConn().Exec(bg, "INSERT INTO t VALUES (100); DROP TABLE t; INSERT INTO t VALUES (101)").ReadAll()
	if pe := pgErr(t, err); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
	if n := h.count("SELECT count(*) FROM t"); n != 0 {
		t.Fatalf("%d rows inserted", n)
	}
	for _, a := range h.dec.calls() {
		if a.Target["statement_count"] != 3 {
			t.Fatalf("statement_count = %v", a.Target["statement_count"])
		}
	}
	// An all-allowed multi-statement query runs as is.
	h.dec.set("DROP_TABLE", policy.Result{Decision: policy.Allow, RuleID: "x"})
	if _, err := c.PgConn().Exec(bg, "INSERT INTO t VALUES (1); INSERT INTO t VALUES (2)").ReadAll(); err != nil {
		t.Fatal(err)
	}
	if n := h.count("SELECT count(*) FROM t"); n != 2 {
		t.Fatalf("got %d rows", n)
	}
}

func setupOrders(h *harness) {
	h.exec("DROP TABLE IF EXISTS orders")
	h.exec("CREATE TABLE orders (id int PRIMARY KEY, grp text NOT NULL, amount numeric, note text)")
	h.exec("INSERT INTO orders SELECT g, CASE WHEN g % 4 = 0 THEN 'a' ELSE 'b' END, g * 1.5, 'n' || g FROM generate_series(1, 20) g")
}

func handleFor(t *testing.T, h *harness, actionID string) (undo.Handle, undo.PGRowsData) {
	t.Helper()
	hd, err := h.us.Get(bg, actionID)
	if err != nil {
		t.Fatalf("handle %s: %v", actionID, err)
	}
	var d undo.PGRowsData
	if err := json.Unmarshal(hd.Data, &d); err != nil {
		t.Fatal(err)
	}
	return hd, d
}

func TestSnapshotDeleteIdle(t *testing.T) {
	h := newHarness(t)
	setupOrders(h)
	h.dec.set("DELETE", snapshotRule())
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	tag, err := c.Exec(bg, "DELETE FROM orders WHERE grp = 'a'")
	if err != nil {
		t.Fatal(err)
	}
	if tag.String() != "DELETE 5" {
		t.Fatalf("tag = %q", tag)
	}
	a := h.dec.last(t)
	if a.Target["undo_preparable"] != true || a.Target["where_narrow"] != false {
		t.Fatalf("target = %+v", a.Target)
	}
	if a.PayloadSummary.RowsEstimate == nil {
		t.Fatal("rows_estimate not computed")
	}
	hd, d := handleFor(t, h, a.ActionID)
	if hd.Status != undo.StatusActive || strings.Join(h.us.history[a.ActionID], ">") != "prepared>active" {
		t.Fatalf("handle status %s history %v", hd.Status, h.us.history[a.ActionID])
	}
	if d.SnapshotSchema != "fortik_undo" || d.SnapshotTable != pgsql.SnapshotTableName("orders", a.ActionID) ||
		d.Op != "DELETE" || d.Schema != "public" || d.Table != "orders" || strings.Join(d.PKColumns, ",") != "id" ||
		d.Upstream != upName || d.Database != h.dbName {
		t.Fatalf("handle data = %+v", d)
	}
	snap := `fortik_undo."` + d.SnapshotTable + `"`
	if n := h.count("SELECT count(*) FROM " + snap); n != 5 {
		t.Fatalf("snapshot has %d rows", n)
	}
	if n := h.count("SELECT count(*) FROM " + snap + " WHERE grp <> 'a'"); n != 0 {
		t.Fatal("snapshot has rows that were not deleted")
	}
	if n := h.count("SELECT count(*) FROM orders WHERE grp = 'a'"); n != 0 {
		t.Fatal("rows not deleted")
	}
	// Session is idle and usable afterwards.
	var st string
	if err := c.QueryRow(bg, "SELECT 'ok'").Scan(&st); err != nil || st != "ok" {
		t.Fatalf("after snapshot: %v", err)
	}
	if c.PgConn().TxStatus() != 'I' {
		t.Fatalf("tx status %c", c.PgConn().TxStatus())
	}
}

func TestSnapshotDeleteInsideTransaction(t *testing.T) {
	h := newHarness(t)
	setupOrders(h)
	h.dec.set("DELETE", snapshotRule())
	h.dec.set("UPDATE", snapshotRule())
	c := h.connect(pgx.QueryExecModeSimpleProtocol)

	tx, err := c.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	tag, err := tx.Exec(bg, "DELETE FROM orders WHERE id = 4")
	if err != nil {
		t.Fatal(err)
	}
	if tag.String() != "DELETE 1" {
		t.Fatalf("tag %q", tag)
	}
	a := h.dec.last(t)
	if a.Target["where_narrow"] != true {
		t.Fatalf("where_narrow = %v", a.Target["where_narrow"])
	}
	if hd, _ := handleFor(t, h, a.ActionID); hd.Status != undo.StatusPrepared {
		t.Fatalf("status before commit = %s", hd.Status)
	}
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	hd, d := handleFor(t, h, a.ActionID)
	if hd.Status != undo.StatusActive {
		t.Fatalf("status after commit = %s", hd.Status)
	}
	if n := h.count(`SELECT count(*) FROM fortik_undo."` + d.SnapshotTable + `" WHERE id = 4`); n != 1 {
		t.Fatal("snapshot missing the deleted row")
	}

	// Rolled back transaction: handle fails, snapshot gone, row back.
	tx, _ = c.Begin(bg)
	if _, err := tx.Exec(bg, "UPDATE orders SET note = 'changed' WHERE grp = 'b'"); err != nil {
		t.Fatal(err)
	}
	a2 := h.dec.last(t)
	if a2.Target["undo_preparable"] != true {
		t.Fatal("UPDATE with PK should be undo_preparable")
	}
	if err := tx.Rollback(bg); err != nil {
		t.Fatal(err)
	}
	hd2, d2 := handleFor(t, h, a2.ActionID)
	if hd2.Status != undo.StatusFailed {
		t.Fatalf("status after rollback = %s", hd2.Status)
	}
	if n := h.count(`SELECT count(*) FROM pg_tables WHERE schemaname = 'fortik_undo' AND tablename = '` + d2.SnapshotTable + `'`); n != 0 {
		t.Fatal("snapshot survived rollback")
	}
	if n := h.count("SELECT count(*) FROM orders WHERE note = 'changed'"); n != 0 {
		t.Fatal("update survived rollback")
	}
}

func TestSnapshotFailingStatement(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE parent (id int PRIMARY KEY)")
	h.exec("CREATE TABLE child (id int PRIMARY KEY, parent_id int REFERENCES parent(id))")
	h.exec("INSERT INTO parent VALUES (1),(2)")
	h.exec("INSERT INTO child VALUES (10, 1)")
	h.dec.set("DELETE", snapshotRule())
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	_, err := c.Exec(bg, "DELETE FROM parent")
	if pe := pgErr(t, err); pe.Code != "23503" {
		t.Fatalf("expected FK violation, got %s %s", pe.Code, pe.Message)
	}
	a := h.dec.last(t)
	hd, d := handleFor(t, h, a.ActionID)
	if hd.Status != undo.StatusFailed {
		t.Fatalf("status = %s", hd.Status)
	}
	if n := h.count("SELECT count(*) FROM parent"); n != 2 {
		t.Fatal("rows deleted")
	}
	if n := h.count(`SELECT count(*) FROM pg_tables WHERE tablename = '` + d.SnapshotTable + `'`); n != 0 {
		t.Fatal("snapshot left behind")
	}
	if c.PgConn().TxStatus() != 'I' {
		t.Fatalf("tx status %c", c.PgConn().TxStatus())
	}
	// Snapshot itself failing: the statement must not run.
	h.exec("CREATE TABLE victims (id int PRIMARY KEY)")
	h.exec("INSERT INTO victims VALUES (1),(2),(3)")
	// Volatile failure in the WHERE clause evaluated during the snapshot.
	_, err = c.Exec(bg, "DELETE FROM victims WHERE id = 1/0")
	pe := pgErr(t, err)
	if pe.Code != "22012" || !strings.HasPrefix(pe.Message, "fortik: undo snapshot failed; statement not executed") {
		t.Fatalf("got %s %s", pe.Code, pe.Message)
	}
	a = h.dec.last(t)
	if hd, _ := handleFor(t, h, a.ActionID); hd.Status != undo.StatusFailed {
		t.Fatalf("status = %s", hd.Status)
	}
	if n := h.count("SELECT count(*) FROM victims"); n != 3 {
		t.Fatal("statement ran despite snapshot failure")
	}
}

func TestReducedFormNotHonoured(t *testing.T) {
	h := newHarness(t)
	setupOrders(h)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	h.dec.set("DELETE", policy.Result{Class: policy.Yellow, Decision: policy.AllowReduced, RuleID: "pg.reduce",
		ReducedForm: map[string]any{"snapshot_rows": true, "max_rows": 10}})
	_, err := c.Exec(bg, "DELETE FROM orders WHERE grp = 'a'")
	pe := pgErr(t, err)
	if pe.Code != "42501" || !strings.Contains(pe.Message, "max_rows") {
		t.Fatalf("got %s %s", pe.Code, pe.Message)
	}
	if n := h.count("SELECT count(*) FROM orders"); n != 20 {
		t.Fatal("rows deleted")
	}
	if len(h.us.all()) != 0 {
		t.Fatal("undo handle prepared for a refused statement")
	}
	// Not preparable (USING) => refused.
	h.dec.set("DELETE", snapshotRule())
	_, err = c.Exec(bg, "DELETE FROM orders o USING orders p WHERE o.id = p.id AND p.grp = 'a'")
	if pe := pgErr(t, err); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
	// Extended protocol cannot snapshot => refused, connection usable.
	ce := h.connect(pgx.QueryExecModeCacheStatement)
	_, err = ce.Exec(bg, "DELETE FROM orders WHERE id = $1", 1)
	if pe := pgErr(t, err); pe.Code != "42501" || !strings.Contains(pe.Message, "extended") {
		t.Fatalf("got %s %s", pe.Code, pe.Message)
	}
	if n := h.count("SELECT count(*) FROM orders"); n != 20 {
		t.Fatal("rows deleted")
	}
	var one int
	if err := ce.QueryRow(bg, "SELECT $1::int", 1).Scan(&one); err != nil {
		t.Fatal(err)
	}
}

func TestExtendedRefusedParse(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int)")
	h.dec.set("TRUNCATE", denyRule("pg.truncate"))
	c := h.connect(pgx.QueryExecModeCacheStatement)
	// Named prepared statement refused: never created upstream.
	_, err := c.PgConn().Prepare(bg, "trunc_stmt", "TRUNCATE t", nil)
	if pe := pgErr(t, err); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
	var n int
	if err := c.QueryRow(bg, "SELECT count(*) FROM pg_prepared_statements WHERE name = $1", "trunc_stmt").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("refused statement exists upstream")
	}
	// Unnamed via Query, then the connection is still usable.
	rows, _ := c.Query(bg, "TRUNCATE t")
	rows.Close()
	if pe := pgErr(t, rows.Err()); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
	var v int
	if err := c.QueryRow(bg, "SELECT $1::int + 1", 41).Scan(&v); err != nil || v != 42 {
		t.Fatalf("connection unusable: %v", err)
	}

	// Pipeline: an allowed INSERT before a refused statement in the same
	// implicit transaction is rolled back (as if Postgres raised the error).
	h.dec.set("TRUNCATE", denyRule("pg.truncate"))
	p := c.PgConn().StartPipeline(bg)
	p.SendQueryParams("INSERT INTO t VALUES ($1)", [][]byte{[]byte("5")}, nil, nil, nil)
	p.SendQueryParams("TRUNCATE t", nil, nil, nil, nil)
	if err := p.Sync(); err != nil {
		t.Fatal(err)
	}
	var sawErr bool
	for {
		res, err := p.GetResults()
		if err != nil {
			if pe, ok := err.(*pgconn.PgError); ok && pe.Code == "42501" {
				sawErr = true
				continue
			}
			t.Fatalf("pipeline: %v", err)
		}
		if res == nil {
			break
		}
		if rr, ok := res.(*pgconn.ResultReader); ok {
			if r := rr.Read(); r.Err != nil {
				if pe, ok := r.Err.(*pgconn.PgError); ok && pe.Code == "42501" {
					sawErr = true
				} else {
					t.Fatalf("pipeline result: %v", r.Err)
				}
			}
		}
		if _, ok := res.(*pgconn.PipelineSync); ok {
			break
		}
	}
	if err := p.Close(); err != nil && !sawErr {
		t.Fatalf("pipeline close: %v", err)
	}
	if !sawErr {
		t.Fatal("pipeline: refusal not reported")
	}
	if cnt := h.count("SELECT count(*) FROM t"); cnt != 0 {
		t.Fatalf("pipelined INSERT committed despite refusal in the same batch (%d rows)", cnt)
	}
	if err := c.QueryRow(bg, "SELECT $1::int", 7).Scan(&v); err != nil || v != 7 {
		t.Fatalf("connection unusable after pipeline: %v", err)
	}
}

func TestDecideErrorRefuses(t *testing.T) {
	h := newHarness(t)
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			c := h.connect(m.mode)
			h.dec.setErr(errors.New("decider exploded"))
			var v int
			err := c.QueryRow(bg, "SELECT 1").Scan(&v)
			h.dec.setErr(nil)
			pe := pgErr(t, err)
			if pe.Code != "42501" || !strings.Contains(pe.Message, "no decision") {
				t.Fatalf("got %s %s", pe.Code, pe.Message)
			}
			if err := c.QueryRow(bg, "SELECT 2").Scan(&v); err != nil || v != 2 {
				t.Fatalf("after: %v", err)
			}
		})
	}
}

func TestUnparseableRefused(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	_, err := c.Exec(bg, "SELEC 1")
	if pe := pgErr(t, err); pe.Code != "42601" || !strings.HasPrefix(pe.Message, "fortik: refused") {
		t.Fatalf("got %s %s", pe.Code, pe.Message)
	}
	if len(h.dec.calls()) != 0 {
		t.Fatal("decider called for unparseable SQL")
	}
}

func TestCopy(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE items (id int, name text)")
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	in := strings.NewReader("1\tone\n2\ttwo\n3\tthree\n")
	tag, err := c.PgConn().CopyFrom(bg, in, "COPY items FROM STDIN")
	if err != nil {
		t.Fatal(err)
	}
	if tag.RowsAffected() != 3 {
		t.Fatalf("copy in tag %q", tag)
	}
	if h.dec.last(t).Target["statement_type"] != "COPY_FROM_STDIN" {
		t.Fatal("copy in not decided")
	}
	// pgx CopyFrom (binary) too.
	n, err := c.CopyFrom(bg, pgx.Identifier{"items"}, []string{"id", "name"},
		pgx.CopyFromRows([][]any{{4, "four"}, {5, "five"}}))
	if err != nil || n != 2 {
		t.Fatalf("pgx CopyFrom: %d %v", n, err)
	}
	var out strings.Builder
	tag, err = c.PgConn().CopyTo(bg, &out, "COPY (SELECT * FROM items ORDER BY id) TO STDOUT")
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "1\tone\n2\ttwo\n3\tthree\n4\tfour\n5\tfive\n" || tag.RowsAffected() != 5 {
		t.Fatalf("copy out = %q (%s)", out.String(), tag)
	}
	a := h.dec.last(t)
	if a.Target["statement_type"] != "COPY_TO_STDOUT" || a.Verb != "EXPORT" {
		t.Fatalf("copy out action %+v", a.Target)
	}
	// Refused COPY TO STDOUT.
	h.dec.set("COPY_TO_STDOUT", denyRule("pg.export"))
	_, err = c.PgConn().CopyTo(bg, &out, "COPY items TO STDOUT")
	if pe := pgErr(t, err); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
}

func TestCancelRequest(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	errc := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := c.Exec(bg, "SELECT pg_sleep(30)")
		errc <- err
	}()
	time.Sleep(500 * time.Millisecond)
	if err := c.PgConn().CancelRequest(bg); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if pe := pgErr(t, err); pe.Code != "57014" {
			t.Fatalf("got %s", pe.Code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cancel did not interrupt pg_sleep")
	}
	if time.Since(start) > 10*time.Second {
		t.Fatal("too slow")
	}
	var v int
	if err := c.QueryRow(bg, "SELECT 3").Scan(&v); err != nil || v != 3 {
		t.Fatalf("after cancel: %v", err)
	}
}

func TestTrivialStatementsBypassDecide(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	h.dec.reset()
	for _, q := range []string{"BEGIN", "SET search_path TO public", "SHOW search_path", "SAVEPOINT s", "RELEASE SAVEPOINT s", "COMMIT", "SET TIME ZONE 'UTC'", "DISCARD ALL", ""} {
		if _, err := c.Exec(bg, q); err != nil {
			t.Fatalf("%q: %v", q, err)
		}
	}
	if n := len(h.dec.calls()); n != 0 {
		t.Fatalf("decider called %d times for trivial statements", n)
	}
	if _, err := c.Exec(bg, "SELECT 1"); err != nil {
		t.Fatal(err)
	}
	if n := len(h.dec.calls()); n != 1 {
		t.Fatalf("SELECT not decided (%d calls)", n)
	}
	// Extended protocol: Parse of a SESSION statement is not decided either.
	ce := h.connect(pgx.QueryExecModeCacheStatement)
	h.dec.reset()
	if err := ce.PgConn().ExecParams(bg, "SHOW search_path", nil, nil, nil, nil).Read().Err; err != nil {
		t.Fatal(err)
	}
	if n := len(h.dec.calls()); n != 0 {
		t.Fatalf("extended SHOW decided (%d)", n)
	}
	// SET ROLE is not trivial.
	h.dec.set("SET_ROLE", denyRule("pg.set_role"))
	if _, err := c.Exec(bg, "SET ROLE postgres"); err == nil {
		t.Fatal("SET ROLE not refused")
	}
}

func TestWhereNarrowAndEstimate(t *testing.T) {
	h := newHarness(t)
	setupOrders(h)
	h.exec("CREATE TABLE payments (a int, b int, note text, UNIQUE (a, b))")
	h.exec("ANALYZE orders")
	h.dec.set("DELETE", denyRule("pg.inspect"))
	h.dec.set("UPDATE", denyRule("pg.inspect"))
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	cases := []struct {
		sql      string
		narrow   bool
		prep     bool
		estimate bool
	}{
		{"DELETE FROM orders WHERE id = 3", true, true, false},
		{"DELETE FROM orders WHERE grp = 'a'", false, true, true},
		{"DELETE FROM orders", false, true, true},
		{"UPDATE orders SET note = 'x' WHERE id = 3", true, true, false},
		{"DELETE FROM payments WHERE a = 1 AND b = 2", true, true, false},
		{"DELETE FROM payments WHERE a = 1", false, true, true},
		{"UPDATE payments SET note = 'x' WHERE a = 1 AND b = 2", true, false, false}, // no PK
	}
	for _, tc := range cases {
		_, _ = c.Exec(bg, tc.sql)
		a := h.dec.last(t)
		if a.Target["where_narrow"] != tc.narrow || a.Target["undo_preparable"] != tc.prep ||
			(a.PayloadSummary.RowsEstimate != nil) != tc.estimate {
			t.Errorf("%s: narrow=%v prep=%v est=%v", tc.sql, a.Target["where_narrow"], a.Target["undo_preparable"], a.PayloadSummary.RowsEstimate)
		}
	}
	_, _ = c.Exec(bg, "DELETE FROM orders WHERE grp = 'a'")
	if est := h.dec.last(t).PayloadSummary.RowsEstimate; est == nil || *est < 1 || *est > 20 {
		t.Fatalf("estimate = %v", est)
	}
	// Pre-queries inside a transaction block do not disturb it.
	tx, _ := c.Begin(bg)
	if _, err := tx.Exec(bg, "INSERT INTO payments VALUES (9, 9, 'keep')"); err != nil {
		t.Fatal(err)
	}
	_, _ = tx.Exec(bg, "SELECT 1") // fine
	h.dec.set("DELETE", policy.Result{Decision: policy.Allow, RuleID: "x"})
	if _, err := tx.Exec(bg, "DELETE FROM orders WHERE grp = 'zzz'"); err != nil {
		t.Fatalf("delete in tx after pre-queries: %v", err)
	}
	var to string
	if err := tx.QueryRow(bg, "SHOW statement_timeout").Scan(&to); err != nil || to != "0" {
		t.Fatalf("statement_timeout leaked into client tx: %q %v", to, err)
	}
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	if n := h.count("SELECT count(*) FROM payments WHERE note = 'keep'"); n != 1 {
		t.Fatal("client transaction lost")
	}
	if n := h.count("SELECT count(*) FROM pg_prepared_statements"); n < 0 {
		t.Fatal()
	}
}

func TestDataModifyingCTEDecidedAsDelete(t *testing.T) {
	h := newHarness(t)
	setupOrders(h)
	h.dec.set("DELETE", denyRule("pg.delete"))
	for _, m := range modes {
		c := h.connect(m.mode)
		rows, _ := c.Query(bg, "WITH d AS (DELETE FROM orders RETURNING id) SELECT count(*) FROM d")
		rows.Close()
		if pe := pgErr(t, rows.Err()); pe.Code != "42501" {
			t.Fatalf("%s: got %s", m.name, pe.Code)
		}
		if a := h.dec.last(t); a.Verb != "DELETE" || a.Target["undo_preparable"] != false {
			t.Fatalf("%s: action %+v", m.name, a.Target)
		}
	}
	if n := h.count("SELECT count(*) FROM orders"); n != 20 {
		t.Fatal("rows deleted")
	}
}

func TestFastpathRefused(t *testing.T) {
	h := newHarness(t)
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	// pgx has no public fastpath API; use the large-object API which uses SQL
	// functions (decided as SELECT / dangerous). lo_import is dangerous.
	h.dec.set("DANGEROUS_FUNCTION", denyRule("pg.dangerous"))
	_, err := c.Exec(bg, "SELECT lo_import('/etc/passwd')")
	if pe := pgErr(t, err); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
	if fns := h.dec.last(t).Target["dangerous_functions"].([]string); len(fns) != 1 || fns[0] != "lo_import" {
		t.Fatalf("dangerous_functions = %v", fns)
	}
}

func TestCachedPreparedStatementRedecided(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int PRIMARY KEY)")
	c := h.connect(pgx.QueryExecModeCacheStatement)
	h.dec.reset()
	for i := 0; i < 3; i++ {
		if _, err := c.Exec(bg, "INSERT INTO t VALUES ($1)", i); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(h.dec.calls()); n != 3 {
		t.Fatalf("expected one decision per execution, got %d", n)
	}
	// Policy changes (e.g. agent stepped down): the cached statement is refused.
	h.dec.set("INSERT", denyRule("pg.readonly"))
	_, err := c.Exec(bg, "INSERT INTO t VALUES ($1)", 99)
	if pe := pgErr(t, err); pe.Code != "42501" {
		t.Fatalf("got %s", pe.Code)
	}
	if n := h.count("SELECT count(*) FROM t WHERE id = 99"); n != 0 {
		t.Fatal("cached statement ran without a fresh decision")
	}
	var v int
	if err := c.QueryRow(bg, "SELECT $1::int", 5).Scan(&v); err != nil || v != 5 {
		t.Fatalf("connection unusable: %v", err)
	}
	// DEALLOCATE ALL forgets everything; pgx re-prepares transparently.
	h.dec.set("INSERT", policy.Result{Decision: policy.Allow, RuleID: "x"})
	if _, err := c.Exec(bg, "DEALLOCATE ALL"); err != nil {
		t.Fatal(err)
	}
	c.DeallocateAll(bg) //nolint:errcheck
	if _, err := c.Exec(bg, "INSERT INTO t VALUES ($1)", 100); err != nil {
		t.Fatal(err)
	}
}
