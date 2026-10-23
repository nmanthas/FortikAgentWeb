package pgundo

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/broker/pgroles"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/config"
	"fortik/internal/pgsql"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

var bg = context.Background()

type noSecrets struct{}

func (noSecrets) Get(_ context.Context, name string) ([]byte, error) {
	return nil, secrets.ErrNotFound
}

type env struct {
	t    *testing.T
	db   string
	conn *pgx.Conn
	ex   *Executor
}

func setup(t *testing.T) *env {
	t.Helper()
	base := os.Getenv("FORTIK_TEST_PG_URL")
	if base == "" {
		t.Skip("FORTIK_TEST_PG_URL is not set; skipping Postgres integration test (e.g. postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable)")
	}
	admin, err := pgx.Connect(bg, base)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(bg)
	var b [6]byte
	_, _ = rand.Read(b[:])
	db := "fortik_undo_test_" + hex.EncodeToString(b[:])
	if _, err := admin.Exec(bg, "CREATE DATABASE "+db); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(bg, base)
		if err != nil {
			return
		}
		defer c.Close(bg)
		_, _ = c.Exec(bg, "DROP DATABASE IF EXISTS "+db+" WITH (FORCE)")
	})
	pc, _ := pgconn.ParseConfig(base)
	cc, _ := pgx.ParseConfig(base)
	cc.Database = db
	conn, err := pgx.ConnectConfig(bg, cc)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(bg) })
	var sec secrets.Provider = noSecrets{}
	up := config.UpstreamConfig{Host: pc.Host, Port: int(pc.Port), Database: db, User: pc.User, SSLMode: "disable", Environment: "dev"}
	if pc.Password != "" {
		sec = staticSecret{"pw": []byte(pc.Password)}
		up.PasswordSecret = "pw"
	}
	cfg := config.PGProxyConfig{Upstreams: map[string]config.UpstreamConfig{"app": up}}
	return &env{t: t, db: db, conn: conn, ex: NewExecutor(cfg, sec)}
}

type staticSecret map[string][]byte

func (s staticSecret) Get(_ context.Context, name string) ([]byte, error) {
	if v, ok := s[name]; ok {
		return v, nil
	}
	return nil, secrets.ErrNotFound
}

func (e *env) exec(sql string) {
	e.t.Helper()
	if _, err := e.conn.Exec(bg, sql); err != nil {
		e.t.Fatalf("%s: %v", sql, err)
	}
}

func (e *env) digest(sql string) string {
	e.t.Helper()
	var s string
	if err := e.conn.QueryRow(bg, "SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ("+sql+") x").Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	return s
}

// snapshot runs exactly what the proxy runs before the statement.
func (e *env) snapshot(stmt, actionID string) (string, *pgsql.Statement) {
	e.t.Helper()
	sts, err := pgsql.Classify(stmt)
	if err != nil {
		e.t.Fatal(err)
	}
	st := &sts[0]
	name := pgsql.SnapshotTableName(st.Table, actionID)
	q, err := pgsql.SnapshotSQL(st, pgsql.SnapshotSchema, name)
	if err != nil {
		e.t.Fatal(err)
	}
	e.exec("CREATE SCHEMA IF NOT EXISTS fortik_undo")
	e.exec(q)
	e.exec(stmt)
	return name, st
}

func rowsHandle(t *testing.T, d undo.PGRowsData) undo.Handle {
	b, _ := json.Marshal(d)
	return undo.Handle{ActionID: "act_x", Kind: undo.KindPGRows, Data: b, Status: undo.StatusUndoing, ExpiresAt: time.Now().Add(time.Hour)}
}

func TestDeleteUndoRestoresRowsExactly(t *testing.T) {
	e := setup(t)
	e.exec(`CREATE TABLE "Orders" (
		id int GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
		grp text, amount numeric(10,2), note text, tags text[], data jsonb,
		doubled numeric GENERATED ALWAYS AS (amount * 2) STORED)`)
	e.exec(`INSERT INTO "Orders" (grp, amount, note, tags, data)
		SELECT CASE WHEN g % 3 = 0 THEN 'a' ELSE 'b' END, g * 1.25, CASE WHEN g % 5 = 0 THEN NULL ELSE 'n''' || g END,
		       ARRAY['x', g::text], jsonb_build_object('g', g) FROM generate_series(1, 30) g`)
	before := e.digest(`SELECT * FROM "Orders"`)
	snap, _ := e.snapshot(`DELETE FROM "Orders" o WHERE o.grp = 'a'`, "act_01JAAAAAAAAAAAAAAAAAAAAAAA")
	if e.digest(`SELECT * FROM "Orders"`) == before {
		t.Fatal("delete did nothing")
	}
	res, err := e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "app", Database: e.db, Schema: "public", Table: "Orders",
		SnapshotSchema: "fortik_undo", SnapshotTable: snap, Op: "DELETE", PKColumns: []string{"id"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_restored"] != int64(10) || res["snapshot_rows"] != int64(10) {
		t.Fatalf("result %v", res)
	}
	if after := e.digest(`SELECT * FROM "Orders"`); after != before {
		t.Fatal("restored table differs from the original")
	}
	// Second undo is harmless (ON CONFLICT DO NOTHING) and reports 0 restored.
	res, err = e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "app", Database: e.db, Schema: "public", Table: "Orders",
		SnapshotSchema: "fortik_undo", SnapshotTable: snap, Op: "DELETE"}))
	if err != nil || res["rows_restored"] != int64(0) {
		t.Fatalf("repeat undo: %v %v", res, err)
	}
}

func TestUpdateUndoRestoresOldValues(t *testing.T) {
	e := setup(t)
	e.exec("CREATE SCHEMA app")
	e.exec("CREATE TABLE app.accounts (tenant int, id int, balance numeric, status text, PRIMARY KEY (tenant, id))")
	e.exec("INSERT INTO app.accounts SELECT g % 2, g, g * 10, 'ok' FROM generate_series(1, 12) g")
	before := e.digest("SELECT * FROM app.accounts")
	snap, _ := e.snapshot("UPDATE app.accounts SET balance = 0, status = NULL WHERE tenant = 1", "act_01JBBBBBBBBBBBBBBBBBBBBBBB")
	e.exec("INSERT INTO app.accounts VALUES (5, 99, 1, 'new')") // unrelated later write survives
	res, err := e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "app", Database: e.db, Schema: "app", Table: "accounts",
		SnapshotSchema: "fortik_undo", SnapshotTable: snap, Op: "UPDATE", PKColumns: []string{"tenant", "id"}}))
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_restored"] != int64(6) {
		t.Fatalf("result %v", res)
	}
	if got := e.digest("SELECT * FROM app.accounts WHERE id <> 99"); got != before {
		t.Fatal("values not restored")
	}
	var n int
	_ = e.conn.QueryRow(bg, "SELECT count(*) FROM app.accounts WHERE id = 99").Scan(&n)
	if n != 1 {
		t.Fatal("unrelated row lost")
	}
	// UPDATE undo without PK columns is refused.
	if _, err := e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "app", Database: e.db, Schema: "app", Table: "accounts",
		SnapshotTable: snap, Op: "UPDATE"})); err == nil {
		t.Fatal("expected error without pk_columns")
	}
}

func renameHandle(d undo.PGRenameData) undo.Handle {
	b, _ := json.Marshal(d)
	return undo.Handle{ActionID: "act_r", Kind: undo.KindPGRename, Data: b, Status: undo.StatusUndoing}
}

func TestRenameUndo(t *testing.T) {
	e := setup(t)
	now := time.Now()
	// DROP TABLE safe form.
	e.exec("CREATE TABLE users (id int PRIMARY KEY, name text)")
	e.exec("INSERT INTO users SELECT g, 'u' || g FROM generate_series(1, 7) g")
	sts, _ := pgsql.Classify("DROP TABLE users")
	sql, trash, err := pgsql.SafeRenameSQL(&sts[0], now)
	if err != nil {
		t.Fatal(err)
	}
	e.exec(sql)
	res, err := e.ex.Undo(bg, renameHandle(undo.PGRenameData{Upstream: "app", Database: e.db, Schema: "public", Table: "users", TrashTable: trash, Op: "DROP"}))
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_restored"] != int64(7) {
		t.Fatalf("result %v", res)
	}

	// TRUNCATE safe form: recreated empty table is dropped, trash renamed back.
	sts, _ = pgsql.Classify("TRUNCATE users")
	sql, trash, _ = pgsql.SafeRenameSQL(&sts[0], now.Add(time.Second))
	e.exec(sql)
	var n int
	_ = e.conn.QueryRow(bg, "SELECT count(*) FROM users").Scan(&n)
	if n != 0 {
		t.Fatal("safe truncate did not leave an empty table")
	}
	h := renameHandle(undo.PGRenameData{Upstream: "app", Database: e.db, Schema: "public", Table: "users", TrashTable: trash, Op: "TRUNCATE"})
	// Non-empty recreated table: refuse, change nothing.
	e.exec("INSERT INTO users VALUES (100, 'new')")
	if _, err := e.ex.Undo(bg, h); err == nil {
		t.Fatal("expected refusal for non-empty recreated table")
	}
	_ = e.conn.QueryRow(bg, "SELECT count(*) FROM users").Scan(&n)
	if n != 1 {
		t.Fatal("failed undo changed data")
	}
	e.exec("DELETE FROM users")
	res, err = e.ex.Undo(bg, h)
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_restored"] != int64(7) || res["dropped_empty_recreated_table"] != true {
		t.Fatalf("result %v", res)
	}
	// DROP undo when the name is taken again: refused.
	sts, _ = pgsql.Classify("DROP TABLE users")
	sql, trash, _ = pgsql.SafeRenameSQL(&sts[0], now.Add(2*time.Second))
	e.exec(sql)
	e.exec("CREATE TABLE users (x int)")
	if _, err := e.ex.Undo(bg, renameHandle(undo.PGRenameData{Upstream: "app", Database: e.db, Schema: "public", Table: "users", TrashTable: trash, Op: "DROP"})); err == nil {
		t.Fatal("expected refusal when table name is taken")
	}
}

func TestMissingSnapshot(t *testing.T) {
	e := setup(t)
	e.exec("CREATE TABLE t (id int)")
	_, err := e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "app", Database: e.db, Schema: "public", Table: "t",
		SnapshotSchema: "fortik_undo", SnapshotTable: "t_nope", Op: "DELETE"}))
	if !errors.Is(err, undo.ErrNothingToUndo) {
		t.Fatalf("got %v", err)
	}
	_, err = e.ex.Undo(bg, renameHandle(undo.PGRenameData{Upstream: "app", Database: e.db, Schema: "public", Table: "t", TrashTable: "fortik_trash_t_1", Op: "DROP"}))
	if !errors.Is(err, undo.ErrNothingToUndo) {
		t.Fatalf("rename: got %v", err)
	}
	if _, err := e.ex.Undo(bg, undo.Handle{Kind: "gmail_delayed_send"}); !errors.Is(err, undo.ErrUnsupported) {
		t.Fatalf("unsupported kind: %v", err)
	}
	if _, err := e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "nope", Schema: "public", Table: "t", SnapshotTable: "x", Op: "DELETE"})); err == nil {
		t.Fatal("unknown upstream accepted")
	}
}

// TestIntegrationUpstreamUndoRunsAsAdmin: for an integration-backed upstream
// the snapshot is created and owned by the agent's own role (as pgproxy does,
// with SELECT granted to the integration admin) and undo runs as the admin.
// The YAML upstream of the same name points nowhere, so only the integration
// path can succeed.
func TestIntegrationUpstreamUndoRunsAsAdmin(t *testing.T) {
	const up = "appdb"
	f := pgrolestest.New(t, up)
	f.Exec("CREATE TABLE public.orders (id int PRIMARY KEY, amount numeric, note text)")
	f.Exec("INSERT INTO public.orders SELECT g, g * 1.5, 'n' || g FROM generate_series(1, 20) g")
	before := digestConn(t, f.Super, "SELECT * FROM public.orders")

	mgr := f.Manager(time.Minute)
	agent := f.Agent("undo-agent", pgroles.ModeReadWrite, true)
	pc, sess, err := mgr.Connect(bg, agent, "", up, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close(bg)
	sts, err := pgsql.Classify("DELETE FROM public.orders WHERE amount > 15")
	if err != nil {
		t.Fatal(err)
	}
	snap := pgsql.SnapshotTableName(sts[0].Table, "act_01JCCCCCCCCCCCCCCCCCCCCCCC")
	snapSQL, err := pgsql.SnapshotSQL(&sts[0], pgsql.SnapshotSchema, snap)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pc.Exec(bg, "BEGIN; "+snapSQL+"; GRANT SELECT ON TABLE "+pgsql.QuoteQualified(pgsql.SnapshotSchema, snap)+
		" TO "+pgsql.QuoteIdent(f.AdminUser)+"; DELETE FROM public.orders WHERE amount > 15; COMMIT").ReadAll(); err != nil {
		t.Fatalf("snapshot + delete as %s: %v", sess.User, err)
	}
	var owner string
	if err := f.Super.QueryRow(bg, "SELECT tableowner FROM pg_tables WHERE schemaname = 'fortik_undo' AND tablename = $1", snap).Scan(&owner); err != nil || owner != sess.User {
		t.Fatalf("snapshot owner %q (%v)", owner, err)
	}

	bogus := config.PGProxyConfig{Upstreams: map[string]config.UpstreamConfig{up: {
		Host: "127.0.0.1", Port: 1, Database: f.DB, User: "nobody", SSLMode: "disable", Environment: "dev"}}}
	ex := NewExecutor(bogus, noSecrets{}, WithIntegrations(f.Source))
	h := rowsHandle(t, undo.PGRowsData{Upstream: up, Database: f.DB, Schema: "public", Table: "orders",
		SnapshotSchema: pgsql.SnapshotSchema, SnapshotTable: snap, Op: "DELETE", PKColumns: []string{"id"}})
	res, err := ex.Undo(bg, h)
	if err != nil {
		t.Fatal(err)
	}
	if res["rows_restored"] != int64(10) {
		t.Fatalf("result %v", res)
	}
	if after := digestConn(t, f.Super, "SELECT * FROM public.orders"); after != before {
		t.Fatal("restored table differs from the original")
	}

	// Without the GRANT the admin (not a superuser) cannot read the agent's
	// snapshot: the grant pgproxy adds is what makes undo possible.
	f.Exec("REVOKE SELECT ON TABLE " + pgsql.QuoteQualified(pgsql.SnapshotSchema, snap) + " FROM " + f.AdminUser)
	if _, err := ex.Undo(bg, h); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("undo without grant: %v", err)
	}

	// Integration errors fail closed (no fallback to the YAML upstream).
	f.Source.SetErr(errors.New("integrations unavailable"))
	if _, err := ex.Undo(bg, h); err == nil || !strings.Contains(err.Error(), "integrations unavailable") {
		t.Fatalf("source error: %v", err)
	}
	f.Source.SetErr(nil)
	// A handle for another database is refused.
	h2 := rowsHandle(t, undo.PGRowsData{Upstream: up, Database: "otherdb", Schema: "public", Table: "orders",
		SnapshotTable: snap, Op: "DELETE"})
	if _, err := ex.Undo(bg, h2); err == nil || !strings.Contains(err.Error(), "does not match integration") {
		t.Fatalf("database mismatch: %v", err)
	}
}

// TestIntegrationSourceFallsBackToYAML: an upstream that is not an
// integration still uses its YAML ("legacy") settings.
func TestIntegrationSourceFallsBackToYAML(t *testing.T) {
	e := setup(t)
	e.ex.src = pgrolestest.NewSource() // configured, but without postgres:app
	e.exec("CREATE TABLE t (id int PRIMARY KEY)")
	e.exec("INSERT INTO t SELECT generate_series(1, 3)")
	snap, _ := e.snapshot("DELETE FROM t WHERE id > 1", "act_01JDDDDDDDDDDDDDDDDDDDDDDD")
	res, err := e.ex.Undo(bg, rowsHandle(t, undo.PGRowsData{Upstream: "app", Database: e.db, Schema: "public", Table: "t",
		SnapshotSchema: "fortik_undo", SnapshotTable: snap, Op: "DELETE"}))
	if err != nil || res["rows_restored"] != int64(2) {
		t.Fatalf("%v %v", res, err)
	}
}

func digestConn(t *testing.T, c *pgx.Conn, sql string) string {
	t.Helper()
	var s string
	if err := c.QueryRow(bg, "SELECT coalesce(md5(string_agg(x::text, '|' ORDER BY x::text)), '') FROM ("+sql+") x").Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}
