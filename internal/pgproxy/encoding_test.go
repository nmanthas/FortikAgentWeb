package pgproxy

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// A client must not be able to make Postgres lex statement bytes differently
// from the classifier (SJIS/BIG5/GBK absorb a backslash into a multibyte
// character, hiding a DROP inside what UTF-8 sees as a string literal).
func TestClientEncodingPinnedToUTF8(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE enc_victim (id int)")

	cfg, err := pgx.ParseConfig(h.url(testAgent, testToken, upName))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["client_encoding"] = "SJIS"
	cfg.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer c.Close(context.Background())

	var enc string
	if err := c.QueryRow(bg, "SHOW client_encoding").Scan(&enc); err != nil || enc != "UTF8" {
		t.Fatalf("client_encoding = %q, %v (want UTF8)", enc, err)
	}
	// Under SJIS this would run DROP TABLE; under the pinned UTF8 it is one
	// harmless SELECT of a string literal, exactly as classified.
	if _, err := c.Exec(bg, "SELECT E'\xC3\x95\\'; DROP TABLE enc_victim; --'"); err != nil {
		t.Fatalf("select: %v", err)
	}
	if h.count("SELECT count(*) FROM pg_tables WHERE tablename = 'enc_victim'") != 1 {
		t.Fatal("table was dropped via client_encoding bypass")
	}
	// Changing the encoding at runtime is refused without reaching Postgres.
	for _, q := range []string{"SET client_encoding = 'SJIS'", "SET NAMES 'SJIS'", "SELECT set_config('client_encoding', 'SJIS', false)"} {
		h.dec.set("UNKNOWN", denyRule("pg.unknown"))
		h.dec.set("DANGEROUS_FUNCTION", denyRule("pg.dangerous"))
		if _, err := c.Exec(bg, q); err == nil {
			t.Fatalf("%q not refused", q)
		}
		if err := c.QueryRow(bg, "SHOW client_encoding").Scan(&enc); err != nil || enc != "UTF8" {
			t.Fatalf("after %q: client_encoding = %q, %v", q, enc, err)
		}
	}
}

// CREATE TABLE AS EXECUTE re-runs a prepared statement whose content Fortik
// cannot see; it is decided as UNKNOWN (EXECUTE), like plain EXECUTE.
func TestCreateTableAsExecuteDecidedUnknown(t *testing.T) {
	h := newHarness(t)
	h.exec("CREATE TABLE ctas_src (id int)")
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	if _, err := c.Exec(bg, "PREPARE zp AS SELECT * FROM ctas_src"); err != nil {
		t.Fatalf("prepare: %v", err)
	}
	h.dec.set("UNKNOWN", denyRule("pg.unknown"))
	if _, err := c.Exec(bg, "CREATE TEMP TABLE zx AS EXECUTE zp"); err == nil {
		t.Fatal("CREATE TABLE AS EXECUTE not refused")
	}
	if a := h.dec.last(t); a.Target["statement_type"] != "UNKNOWN" {
		t.Fatalf("statement_type = %v", a.Target["statement_type"])
	}
}
