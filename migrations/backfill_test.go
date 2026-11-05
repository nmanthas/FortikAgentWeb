package migrations_test

import (
	"context"
	"io/fs"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"fortik/internal/integrations"
	"fortik/internal/testutil"
	"fortik/migrations"
)

// Migration 0018 links every existing connection to a logical integration
// with the same id integrations.LogicalID derives, so a deployment's
// connections (including a live QuickStart one) keep working unchanged.
func TestAppIntegrationsBackfill(t *testing.T) {
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, testutil.TempDB(t, "fortik_backfill"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	names, _ := fs.Glob(migrations.FS, "*.sql")
	sort.Strings(names)
	apply := func(name string) {
		b, _ := migrations.FS.ReadFile(name)
		if _, err := conn.Exec(ctx, string(b)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	i := 0
	for ; names[i] < "0018"; i++ {
		apply(names[i])
	}
	rows := map[string]string{ // key -> config
		"netsuite":            `{"account_id": "1234567_SB1"}`,
		"netsuite_quickstart": `{"tenant_label": "Acme QuickStart"}`,
		"github":              `{}`,
		"postgres:orders":     `{}`,
		"memory:notes":        `{}`,
		"notify_slack":        `{}`,
	}
	for key, cfg := range rows {
		system := key
		if k, _, ok := strings.Cut(key, ":"); ok {
			system = k
		}
		if _, err := conn.Exec(ctx, `INSERT INTO integrations (key, system, config_json, updated_by) VALUES ($1, $2, $3, 'test')`, key, system, cfg); err != nil {
			t.Fatalf("seed %s: %v", key, err)
		}
	}
	for ; i < len(names); i++ {
		apply(names[i])
	}
	want := map[string]struct{ transport, env, tenant string }{
		"netsuite":            {integrations.TransportREST, "full", "1234567_SB1"},
		"netsuite_quickstart": {integrations.TransportMCP, "quickstart", "Acme QuickStart"},
		"github":              {integrations.TransportREST, "", ""},
		"postgres:orders":     {integrations.TransportNative, "", ""},
		"memory:notes":        {integrations.TransportNative, "", ""},
		"notify_slack":        {integrations.TransportREST, "", ""},
	}
	for key, w := range want {
		var appID, transport, env, tenant string
		if err := conn.QueryRow(ctx, `SELECT i.app_integration_id, i.transport, a.environment, a.tenant_ref
			FROM integrations i JOIN app_integrations a ON a.integration_id = i.app_integration_id WHERE i.key = $1`, key).Scan(&appID, &transport, &env, &tenant); err != nil {
			t.Fatalf("%s: %v", key, err)
		}
		_, id, _ := integrations.LogicalID(key)
		if appID != id || transport != w.transport || env != w.env || tenant != w.tenant {
			t.Errorf("%s: %s %s %q %q, want %s %+v", key, appID, transport, env, tenant, id, w)
		}
	}
	var n int
	_ = conn.QueryRow(ctx, `SELECT count(*) FROM integrations WHERE app_integration_id IS NULL OR transport IS NULL`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d connections left unlinked", n)
	}
}
