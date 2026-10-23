package pgproxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"

	"fortik/internal/policy"
	"fortik/internal/undo"
)

// Regression tests for the adversarial review findings.

func errOf(t *testing.T, m pgproto3.BackendMessage) *pgproto3.ErrorResponse {
	t.Helper()
	e, ok := m.(*pgproto3.ErrorResponse)
	if !ok {
		t.Fatalf("expected ErrorResponse, got %T", m)
	}
	return e
}

// A Parse that Postgres rejects (name already exists) must not replace the
// proxy's record of the statement: the next Bind runs the ORIGINAL statement
// upstream and has to be decided as that statement.
func TestReparseExistingNameCannotSkipDecision(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int PRIMARY KEY)")
	h.exec("INSERT INTO t VALUES (1), (2), (3)")
	rc := h.raw(pgproto3.ProtocolVersion30)
	rc.send(&pgproto3.Parse{Name: "s1", Query: "DELETE FROM t WHERE id = $1"}, &pgproto3.Sync{})
	rc.expect("ParseComplete", "ReadyForQuery")
	rc.send(&pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{[]byte("1")}}, &pgproto3.Execute{}, &pgproto3.Sync{})
	rc.expect("BindComplete", "CommandComplete", "ReadyForQuery")

	h.dec.set("DELETE", denyRule("pg.no_delete"))
	rc.send(&pgproto3.Parse{Name: "s1", Query: "SELECT 1"}, &pgproto3.Sync{})
	msgs := rc.expect("ErrorResponse", "ReadyForQuery")
	if e := errOf(t, msgs[0]); e.Code != "42P05" {
		t.Fatalf("re-parse: %s %s", e.Code, e.Message)
	}
	rc.send(&pgproto3.Bind{PreparedStatement: "s1", Parameters: [][]byte{[]byte("2")}}, &pgproto3.Execute{}, &pgproto3.Sync{})
	msgs = rc.expect("ErrorResponse", "ReadyForQuery")
	if e := errOf(t, msgs[0]); e.Code != "42501" {
		t.Fatalf("bind: %s %s", e.Code, e.Message)
	}
	if n := h.count("SELECT count(*) FROM t WHERE id = 2"); n != 1 {
		t.Fatal("the original DELETE ran without a new decision")
	}
}

// A Parse that Postgres skips (an earlier message in the batch failed) must
// not be recorded either.
func TestSkippedParseCannotSkipDecision(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int PRIMARY KEY)")
	h.exec("INSERT INTO t VALUES (1), (2), (3)")
	rc := h.raw(pgproto3.ProtocolVersion30)
	rc.send(&pgproto3.Parse{Query: "DELETE FROM t WHERE id = $1"}, &pgproto3.Bind{Parameters: [][]byte{[]byte("3")}},
		&pgproto3.Execute{}, &pgproto3.Sync{})
	rc.expect("ParseComplete", "BindComplete", "CommandComplete", "ReadyForQuery")

	h.dec.set("DELETE", denyRule("pg.no_delete"))
	rc.send(&pgproto3.Parse{Name: "x", Query: "SELECT * FROM missing_table_zz"},
		&pgproto3.Parse{Query: "SELECT 1"}, &pgproto3.Sync{})
	msgs := rc.expect("ErrorResponse", "ReadyForQuery")
	if e := errOf(t, msgs[0]); e.Code != "42P01" {
		t.Fatalf("got %s %s", e.Code, e.Message)
	}
	rc.send(&pgproto3.Bind{Parameters: [][]byte{[]byte("2")}}, &pgproto3.Execute{}, &pgproto3.Sync{})
	msgs = rc.expect("ErrorResponse", "ReadyForQuery")
	if e := errOf(t, msgs[0]); e.Code != "26000" && e.Code != "42501" {
		t.Fatalf("got %s %s", e.Code, e.Message)
	}
	if n := h.count("SELECT count(*) FROM t WHERE id = 2"); n != 1 {
		t.Fatal("the unnamed DELETE ran without a new decision")
	}
}

// Internal pre-queries must not destroy the client's unnamed statement or
// unnamed portal (Postgres drops both on any simple Query).
func TestPreQueriesKeepUnnamedStatementAndPortal(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE u (id int PRIMARY KEY, v int)")
	h.exec("INSERT INTO u SELECT g, g * 10 FROM generate_series(1, 20) g")
	h.exec("ANALYZE u")

	t.Run("re-decided Bind of the unnamed statement", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Parse{Query: "UPDATE u SET v = v + 1 WHERE v > $1"}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "ReadyForQuery")
		for _, p := range []string{"1000", "2000"} {
			rc.send(&pgproto3.Bind{Parameters: [][]byte{[]byte(p)}}, &pgproto3.Execute{}, &pgproto3.Sync{})
			rc.expect("BindComplete", "CommandComplete", "ReadyForQuery")
		}
	})

	t.Run("unnamed statement survives another Parse", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Parse{Query: "SELECT v FROM u WHERE id = $1"}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "ReadyForQuery")
		h.dec.set("DELETE", denyRule("pg.inspect"))
		defer h.dec.set("DELETE", allowAll())
		// Not narrow: needs EXPLAIN (with a parameter: needs GENERIC_PLAN).
		rc.send(&pgproto3.Parse{Name: "s2", Query: "DELETE FROM u WHERE v > $1"}, &pgproto3.Sync{})
		rc.expect("ErrorResponse", "ReadyForQuery")
		// Without parameters EXPLAIN runs over the extended protocol.
		rc.send(&pgproto3.Parse{Name: "s3", Query: "DELETE FROM u WHERE v > 5"}, &pgproto3.Sync{})
		rc.expect("ErrorResponse", "ReadyForQuery")
		if est := h.dec.last(t).PayloadSummary.RowsEstimate; est == nil || *est < 1 {
			t.Fatalf("rows_estimate not computed over the extended protocol: %v", est)
		}
		rc.send(&pgproto3.Bind{Parameters: [][]byte{[]byte("3")}}, &pgproto3.Execute{}, &pgproto3.Sync{})
		msgs := rc.expect("BindComplete", "DataRow", "CommandComplete", "ReadyForQuery")
		if v := string(msgs[1].(*pgproto3.DataRow).Values[0]); v != "30" {
			t.Fatalf("got %s", v)
		}
	})

	t.Run("suspended unnamed portal survives a catalog lookup", func(t *testing.T) {
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Query{String: "BEGIN"})
		rc.expect("CommandComplete", "ReadyForQuery")
		rc.send(&pgproto3.Parse{Query: "SELECT g FROM generate_series(1, 5) g"}, &pgproto3.Bind{},
			&pgproto3.Execute{MaxRows: 2}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "BindComplete", "DataRow", "DataRow", "PortalSuspended", "ReadyForQuery")
		// Narrowness needs a catalog lookup (first time for this session).
		rc.send(&pgproto3.Parse{Name: "s2", Query: "UPDATE u SET v = 0 WHERE id = $1"}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "ReadyForQuery")
		if a := h.dec.last(t); a.Target["where_narrow"] != true || a.Target["undo_preparable"] != true {
			t.Fatalf("catalog facts over the extended protocol: %+v", a.Target)
		}
		rc.send(&pgproto3.Execute{MaxRows: 2}, &pgproto3.Sync{})
		msgs := rc.expect("DataRow", "DataRow", "PortalSuspended", "ReadyForQuery")
		if v := string(msgs[0].(*pgproto3.DataRow).Values[0]); v != "3" {
			t.Fatalf("portal resumed at %s", v)
		}
		if msgs[3].(*pgproto3.ReadyForQuery).TxStatus != 'T' {
			t.Fatal("client transaction disturbed")
		}
		rc.send(&pgproto3.Query{String: "ROLLBACK"})
		rc.expect("CommandComplete", "ReadyForQuery")
	})

	t.Run("refusal injection keeps the unnamed statement", func(t *testing.T) {
		h.dec.set("DROP_TABLE", denyRule("pg.drop"))
		rc := h.raw(pgproto3.ProtocolVersion30)
		rc.send(&pgproto3.Query{String: "BEGIN"})
		rc.expect("CommandComplete", "ReadyForQuery")
		rc.send(&pgproto3.Parse{Query: "SELECT 7"}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "ReadyForQuery")
		rc.send(&pgproto3.Parse{Name: "bad", Query: "DROP TABLE u"}, &pgproto3.Bind{PreparedStatement: "bad"},
			&pgproto3.Execute{}, &pgproto3.Sync{})
		msgs := rc.expect("ErrorResponse", "ReadyForQuery")
		if e := errOf(t, msgs[0]); e.Code != "42501" || e.Where != "" {
			t.Fatalf("refusal %+v", e)
		}
		if msgs[1].(*pgproto3.ReadyForQuery).TxStatus != 'E' {
			t.Fatal("transaction not aborted")
		}
		// ROLLBACK over the extended protocol: a simple Query would drop the
		// unnamed statement in Postgres itself.
		rc.send(&pgproto3.Parse{Name: "rb", Query: "ROLLBACK"}, &pgproto3.Bind{PreparedStatement: "rb"},
			&pgproto3.Execute{}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "BindComplete", "CommandComplete", "ReadyForQuery")
		rc.send(&pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
		msgs = rc.expect("BindComplete", "DataRow", "CommandComplete", "ReadyForQuery")
		if v := string(msgs[1].(*pgproto3.DataRow).Values[0]); v != "7" {
			t.Fatalf("got %s", v)
		}
	})
}

// In-transaction snapshot handles are resolved by how the transaction
// actually ended, not by a per-batch "saw COMMIT" flag.
func TestInTransactionSnapshotResolution(t *testing.T) {
	h := newHarness(t)
	setupOrders(h)
	h.dec.set("DELETE", snapshotRule())
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	exec := func(q string) {
		t.Helper()
		if _, err := c.Exec(bg, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	status := func(id string) (string, undo.PGRowsData) {
		hd, d := handleFor(t, h, id)
		return hd.Status, d
	}

	// ROLLBACK; COMMIT: the snapshot was rolled back.
	exec("BEGIN")
	exec("DELETE FROM orders WHERE id = 4")
	a1 := h.dec.last(t)
	exec("ROLLBACK; COMMIT")
	if st, _ := status(a1.ActionID); st != undo.StatusFailed {
		t.Fatalf("ROLLBACK; COMMIT: handle %s", st)
	}

	// COMMIT AND CHAIN commits (status stays T); a later ROLLBACK only
	// rolls back the chained transaction.
	exec("BEGIN")
	exec("DELETE FROM orders WHERE id = 8")
	a2 := h.dec.last(t)
	exec("COMMIT AND CHAIN")
	exec("ROLLBACK")
	st, d := status(a2.ActionID)
	if st != undo.StatusActive {
		t.Fatalf("COMMIT AND CHAIN: handle %s", st)
	}
	if n := h.count(`SELECT count(*) FROM fortik_undo."` + d.SnapshotTable + `" WHERE id = 8`); n != 1 {
		t.Fatal("snapshot missing")
	}

	// ROLLBACK TO SAVEPOINT discards the snapshot; COMMIT must not activate it.
	exec("BEGIN")
	exec("SAVEPOINT s")
	exec("DELETE FROM orders WHERE id = 12")
	a3 := h.dec.last(t)
	exec("ROLLBACK TO SAVEPOINT s")
	exec("COMMIT")
	if st, _ := status(a3.ActionID); st != undo.StatusFailed {
		t.Fatalf("ROLLBACK TO SAVEPOINT; COMMIT: handle %s", st)
	}
	if n := h.count("SELECT count(*) FROM orders WHERE id = 12"); n != 1 {
		t.Fatal("row 12 gone")
	}

	// END is a COMMIT.
	exec("BEGIN")
	exec("DELETE FROM orders WHERE id = 16")
	a4 := h.dec.last(t)
	exec("END")
	if st, _ := status(a4.ActionID); st != undo.StatusActive {
		t.Fatalf("END: handle %s", st)
	}
}

// A CancelRequest that arrives while the proxy is still deciding cancels the
// statement: it is never forwarded.
func TestCancelDuringDecision(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE t (id int)")
	for _, m := range modes {
		t.Run(m.name, func(t *testing.T) {
			c := h.connect(m.mode)
			h.dec.setDelay(700 * time.Millisecond)
			errc := make(chan error, 1)
			go func() {
				_, err := c.Exec(bg, "INSERT INTO t SELECT $1::int FROM pg_sleep(0.5)", 1)
				errc <- err
			}()
			time.Sleep(200 * time.Millisecond)
			if err := c.PgConn().CancelRequest(bg); err != nil {
				t.Fatal(err)
			}
			var err error
			select {
			case err = <-errc:
			case <-time.After(10 * time.Second):
				t.Fatal("statement did not return")
			}
			h.dec.setDelay(0)
			if pe := pgErr(t, err); pe.Code != "57014" {
				t.Fatalf("got %s %s", pe.Code, pe.Message)
			}
			time.Sleep(800 * time.Millisecond)
			if n := h.count("SELECT count(*) FROM t"); n != 0 {
				t.Fatalf("cancelled statement ran (%d rows)", n)
			}
			var v int
			if err := c.QueryRow(bg, "SELECT $1::int", 9).Scan(&v); err != nil || v != 9 {
				t.Fatalf("after cancel: %v", err)
			}
		})
	}
	// Inside a transaction block the cancel aborts it, like Postgres.
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	if _, err := c.Exec(bg, "BEGIN"); err != nil {
		t.Fatal(err)
	}
	h.dec.setDelay(700 * time.Millisecond)
	errc := make(chan error, 1)
	go func() { _, err := c.Exec(bg, "INSERT INTO t VALUES (1)"); errc <- err }()
	time.Sleep(200 * time.Millisecond)
	_ = c.PgConn().CancelRequest(bg)
	err := <-errc
	h.dec.setDelay(0)
	if pe := pgErr(t, err); pe.Code != "57014" {
		t.Fatalf("got %s", pe.Code)
	}
	if c.PgConn().TxStatus() != 'E' {
		t.Fatalf("tx status %c", c.PgConn().TxStatus())
	}
	_, _ = c.Exec(bg, "ROLLBACK")
}

// flakyListener returns scripted errors from Accept before delegating.
type flakyListener struct {
	net.Listener
	mu   sync.Mutex
	errs []error
	hook chan error // when non-nil, Accept returns the error sent here
}

func (l *flakyListener) Accept() (net.Conn, error) {
	l.mu.Lock()
	if len(l.errs) > 0 {
		e := l.errs[0]
		l.errs = l.errs[1:]
		l.mu.Unlock()
		return nil, e
	}
	hook := l.hook
	l.mu.Unlock()
	if hook != nil {
		type res struct {
			c   net.Conn
			err error
		}
		ch := make(chan res, 1)
		go func() { c, err := l.Listener.Accept(); ch <- res{c, err} }()
		select {
		case r := <-ch:
			return r.c, r.err
		case e := <-hook:
			return nil, e
		}
	}
	return l.Listener.Accept()
}

func emfile() error {
	return &net.OpError{Op: "accept", Net: "tcp", Err: os.NewSyscallError("accept", syscall.EMFILE)}
}

func TestServeAcceptErrors(t *testing.T) {
	h := newHarness(t)
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))

	t.Run("temporary errors are retried", func(t *testing.T) {
		srv, err := New(h.srv.cfg, h.srv.undoCfg, h.sec, h.dec, h.us, quiet)
		if err != nil {
			t.Fatal(err)
		}
		inner, _ := net.Listen("tcp", "127.0.0.1:0")
		ln := &flakyListener{Listener: inner, errs: []error{emfile(), emfile(), emfile()}}
		ctx, cancel := context.WithCancel(bg)
		done := make(chan error, 1)
		go func() { done <- srv.Serve(ctx, ln) }()
		h2 := *h
		h2.addr = inner.Addr().String()
		c, err := h2.connectErr(testAgent, testToken, upName, pgx.QueryExecModeSimpleProtocol)
		if err != nil {
			cancel()
			t.Fatalf("proxy stopped accepting after EMFILE: %v", err)
		}
		c.Close(bg)
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})

	t.Run("fatal error closes sessions and returns", func(t *testing.T) {
		srv, err := New(h.srv.cfg, h.srv.undoCfg, h.sec, h.dec, h.us, quiet)
		if err != nil {
			t.Fatal(err)
		}
		inner, _ := net.Listen("tcp", "127.0.0.1:0")
		ln := &flakyListener{Listener: inner, hook: make(chan error, 1)}
		done := make(chan error, 1)
		go func() { done <- srv.Serve(bg, ln) }()
		h2 := *h
		h2.addr = inner.Addr().String()
		c, err := h2.connectErr(testAgent, testToken, upName, pgx.QueryExecModeSimpleProtocol)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(bg)
		ln.hook <- errors.New("listener exploded")
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "listener exploded") {
				t.Fatalf("Serve returned %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("Serve blocked on live sessions after a fatal accept error")
		}
		if _, err := c.Exec(bg, "SELECT 1"); err == nil {
			t.Fatal("session still open after Serve returned")
		}
	})
}

// libpq-style COPY FROM STDIN over the extended protocol sends a Sync that
// Postgres ignores (copy-in mode) and another one after CopyDone.
func TestExtendedCopyInKeepsBatchAccounting(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE c (a int)")
	setupOrders(h)
	h.dec.set("DELETE", denyRule("pg.inspect"))
	rc := h.raw(pgproto3.ProtocolVersion30)
	for i := 0; i < 2; i++ {
		rc.send(&pgproto3.Parse{Query: "COPY c FROM STDIN"}, &pgproto3.Bind{}, &pgproto3.Describe{ObjectType: 'P'},
			&pgproto3.Execute{}, &pgproto3.Sync{})
		rc.expect("ParseComplete", "BindComplete", "NoData", "CopyInResponse")
		rc.send(&pgproto3.CopyData{Data: []byte("1\n2\n")}, &pgproto3.CopyDone{}, &pgproto3.Sync{})
		rc.expect("CommandComplete", "ReadyForQuery")
	}
	// A failed copy (bad data) ends with the same two Syncs.
	rc.send(&pgproto3.Parse{Query: "COPY c FROM STDIN"}, &pgproto3.Bind{}, &pgproto3.Execute{}, &pgproto3.Sync{})
	rc.expect("ParseComplete", "BindComplete", "CopyInResponse")
	rc.send(&pgproto3.CopyData{Data: []byte("not a number\n")}, &pgproto3.CopyDone{}, &pgproto3.Sync{})
	rc.expect("ErrorResponse", "ReadyForQuery")
	if n := h.count("SELECT count(*) FROM c"); n != 4 {
		t.Fatalf("copied %d rows", n)
	}
	// The session is idle again: pre-queries (catalog lookup) run.
	rc.send(&pgproto3.Query{String: "DELETE FROM orders WHERE id = 1"})
	msgs := rc.expect("ErrorResponse", "ReadyForQuery")
	if e := errOf(t, msgs[0]); e.Code != "42501" || e.Where != "" {
		t.Fatalf("refusal %+v", e)
	}
	if a := h.dec.last(t); a.Target["where_narrow"] != true {
		t.Fatalf("session not idle after extended COPY: where_narrow=%v", a.Target["where_narrow"])
	}
	rc.send(&pgproto3.Query{String: "SELECT 1"})
	rc.expect("RowDescription", "DataRow", "CommandComplete", "ReadyForQuery")
}

// Contract additions the Rego policy reads.
func TestTargetContractAdditions(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE kv (id int PRIMARY KEY, v int)")
	h.exec("INSERT INTO kv SELECT g, g FROM generate_series(1, 10) g")
	for _, st := range []string{"INSERT", "MERGE", "DELETE", "DROP_SCHEMA"} {
		h.dec.set(st, denyRule("pg.inspect"))
	}
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	cases := []struct {
		sql                                 string
		typ                                 string
		onConflict, mergeDelete, volatile   bool
		undoPreparable, narrow, checkNarrow bool
	}{
		{"INSERT INTO kv VALUES (1, 1) ON CONFLICT (id) DO UPDATE SET v = 2", "INSERT", true, false, false, false, false, false},
		{"INSERT INTO kv VALUES (1, 1) ON CONFLICT DO NOTHING", "INSERT", false, false, false, false, false, false},
		{"MERGE INTO kv USING (SELECT 1 AS id) s ON kv.id = s.id WHEN MATCHED THEN DELETE", "MERGE", false, true, false, false, false, false},
		{"MERGE INTO kv USING (SELECT 1 AS id) s ON kv.id = s.id WHEN MATCHED THEN UPDATE SET v = 0", "MERGE", false, false, false, false, false, false},
		{"DELETE FROM kv WHERE random() < 0.5", "DELETE", false, false, true, false, false, true},
		{"DELETE FROM kv WHERE id = 1", "DELETE", false, false, false, true, true, true},
		{"DELETE FROM kv WHERE id::int = 1", "DELETE", false, false, false, true, false, true},
	}
	for _, tc := range cases {
		_, _ = c.Exec(bg, tc.sql)
		a := h.dec.last(t)
		tg := a.Target
		if tg["statement_type"] != tc.typ || tg["on_conflict_update"] != tc.onConflict ||
			tg["merge_has_delete"] != tc.mergeDelete || tg["volatile_where"] != tc.volatile ||
			tg["undo_preparable"] != tc.undoPreparable || (tc.checkNarrow && tg["where_narrow"] != tc.narrow) {
			t.Errorf("%s: %+v", tc.sql, tg)
		}
		if tc.typ == "MERGE" && a.Verb != "WRITE" {
			t.Errorf("%s: verb %s", tc.sql, a.Verb)
		}
	}
	// A volatile WHERE cannot be snapshotted: allow_reduced fails closed.
	h.dec.set("DELETE", snapshotRule())
	_, err := c.Exec(bg, "DELETE FROM kv WHERE random() < 0.5")
	if pe := pgErr(t, err); pe.Code != "42501" || !strings.Contains(pe.Message, "undo_preparable=false") {
		t.Fatalf("got %s %s", pe.Code, pe.Message)
	}
	if n := h.count("SELECT count(*) FROM kv"); n != 10 {
		t.Fatal("rows deleted")
	}
	if len(h.us.all()) != 0 {
		t.Fatal("undo handle prepared for a volatile WHERE")
	}
	// DROP SCHEMA exposes the schema: schema-level and table rules apply.
	_, _ = c.Exec(bg, "DROP SCHEMA public CASCADE")
	a := h.dec.last(t)
	if a.Target["schema"] != "public" || a.Target["table"] != "" ||
		strings.Join(a.Target["tables"].([]string), ",") != "public.*" ||
		strings.Join(a.PayloadSummary.DataLabels, ",") != "customer_pii,financial" {
		t.Fatalf("drop schema: %+v labels=%v", a.Target, a.PayloadSummary.DataLabels)
	}
}

func allowAll() policy.Result {
	return policy.Result{Class: policy.Green, Decision: policy.Allow, RuleID: "test.allow", Reason: "allowed"}
}
