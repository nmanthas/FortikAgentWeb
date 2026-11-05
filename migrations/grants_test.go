package migrations_test

import (
	"context"
	"regexp"
	"testing"

	"fortik/internal/testutil"
	"fortik/migrations"
)

// Every table the migrations create must be named in the application role's
// grants (a new table without a grant only fails in a deployment, where the
// app does not run as superuser).
func TestEveryTableHasAnAppGrant(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	sql, err := migrations.AppGrants("fortik_app")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := pool.Query(context.Background(), `SELECT table_name FROM information_schema.tables
		WHERE table_schema = 'public' AND table_type = 'BASE TABLE'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var tbl string
		if err := rows.Scan(&tbl); err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`(?m)^GRANT [^;]*\b` + regexp.QuoteMeta(tbl) + `\b[^;]*TO fortik_app;`).MatchString(sql) {
			t.Errorf("table %s has no grant in migrations/app_grants.sql.tmpl", tbl)
		}
	}
	if _, err := migrations.AppGrants("x; DROP TABLE diary"); err == nil {
		t.Fatal("role name not validated")
	}
}
