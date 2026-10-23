package discoverers_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/alerts"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/shadow"
	"fortik/internal/shadow/discoverers"
	"fortik/internal/testutil"
)

var bg = context.Background()

func newService(t *testing.T, ds ...shadow.Discoverer) (*shadow.Service, *pgxpool.Pool, *alerts.PGStore) {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	al := alerts.NewPGStore(pool, d)
	svc, err := shadow.NewService(shadow.Config{Pool: pool, Diary: d, Alerts: al, Discoverers: ds})
	if err != nil {
		t.Fatal(err)
	}
	return svc, pool, al
}

func findByRef(t *testing.T, svc *shadow.Service, system, kind, ref string) shadow.Finding {
	t.Helper()
	f, err := svc.Get(bg, shadow.FindingID(system, kind, ref))
	if err != nil {
		t.Fatalf("finding %s/%s/%s: %v", system, kind, ref, err)
	}
	return f
}

func evidence(f shadow.Finding) map[string]any {
	m := map[string]any{}
	_ = json.Unmarshal(f.Evidence, &m)
	return m
}

// connectAs opens a session on the fixture database as role.
func connectAs(t *testing.T, fx *pgrolestest.Fixture, role, pw, app string) *pgx.Conn {
	t.Helper()
	cfg, err := pgx.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable application_name='%s'",
		fx.Host, fx.Port, fx.DB, role, pw, app))
	if err != nil {
		t.Fatal(err)
	}
	c, err := pgx.ConnectConfig(bg, cfg)
	if err != nil {
		t.Fatalf("connect as %s: %v", role, err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

// Scenario 7 (plan): a forgotten nightly sync script logs in to a production
// database with its own standing role. Discovery finds it, registers it as a
// discovered agent (no owner, ISOLATED), flags the credential, and security
// revokes it: NOLOGIN and its session ends.
func TestScenario7ShadowPostgresRole(t *testing.T) {
	fx := pgrolestest.New(t, "acme_"+pgrolestest.RandHex(3))
	tag := pgrolestest.RandHex(3)
	script, alice, legacy := "nightly_sync_script_"+tag, "alice_"+tag, "legacy_loader_"+tag
	pw := "pw-" + pgrolestest.RandHex(8)
	// The admin role creates the script's role (so, on PG16+, it holds ADMIN
	// OPTION on it); the superuser creates two others.
	admin := connectAs(t, fx, fx.AdminUser, fx.AdminPW, "setup")
	if _, err := admin.Exec(bg, fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", script, pw)); err != nil {
		t.Fatal(err)
	}
	fx.Exec(fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", alice, pw))
	fx.Exec(fmt.Sprintf("CREATE ROLE %s LOGIN PASSWORD '%s'", legacy, pw))
	fx.Exec(fmt.Sprintf("GRANT CONNECT ON DATABASE %s TO %s, %s, %s", fx.DB, script, alice, legacy))
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), testutil.AdminURL(t))
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		for _, r := range []string{script, alice, legacy} {
			_, _ = c.Exec(context.Background(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", r)
			_, _ = c.Exec(context.Background(), "DROP OWNED BY "+r)
			_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+r)
		}
	})
	scriptConn := connectAs(t, fx, script, pw, "python-requests/sync")
	_ = connectAs(t, fx, alice, pw, "psql")
	if _, err := scriptConn.Exec(bg, "SELECT 1"); err != nil {
		t.Fatal(err)
	}

	pg := discoverers.NewPostgres(fx.Source, nil, nil)
	svc, pool, al := newService(t, pg)
	rep, err := svc.Scan(bg, "user:sec@example.com", "")
	if err != nil {
		t.Fatal(err)
	}
	var res *shadow.ScanResult
	for i := range rep.Systems {
		if rep.Systems[i].Integration == "postgres:"+fx.Upstream {
			res = &rep.Systems[i]
		}
	}
	if res == nil || (res.Status != shadow.ScanScanned && res.Status != shadow.ScanPartial) {
		t.Fatalf("postgres result: %+v", rep.Systems)
	}

	up := fx.Upstream
	f := findByRef(t, svc, shadow.SystemPostgres, shadow.KindDBRole, up+"/"+script)
	ev := evidence(f)
	if !f.UsedBySoftware || f.Status != shadow.StatusFlagged || f.Holder != script || f.AgentID == "" {
		t.Fatalf("script finding: %+v", f)
	}
	if apps, _ := ev["application_names"].([]any); len(apps) == 0 || apps[0] != "python-requests/sync" {
		t.Fatalf("evidence: %v", ev)
	}
	if !strings.Contains(fmt.Sprint(ev["classified_by"]), "non-interactive application_name") {
		t.Fatalf("classified_by: %v", ev["classified_by"])
	}
	if strings.Contains(string(f.Evidence), pw) {
		t.Fatal("password in evidence")
	}
	st, err := control.Get(bg, pool, f.AgentID)
	if err != nil || !st.Registered || !st.Discovered || st.Sponsor != "" || st.Level != control.Isolated {
		t.Fatalf("discovered agent: %+v %v", st, err)
	}
	if a, _ := al.List(bg, alerts.Filter{Kind: shadow.AlertKindShadow, AgentID: f.AgentID}); len(a) != 1 {
		t.Fatalf("alert: %+v", a)
	}
	// A person using psql is a finding, but not software.
	if fa := findByRef(t, svc, shadow.SystemPostgres, shadow.KindDBRole, up+"/"+alice); fa.UsedBySoftware || fa.Status != shadow.StatusOpen || fa.AgentID != "" {
		t.Fatalf("alice: %+v", fa)
	}
	// No session, name suggests a loader: software by name.
	fl := findByRef(t, svc, shadow.SystemPostgres, shadow.KindDBRole, up+"/"+legacy)
	if !fl.UsedBySoftware {
		t.Fatalf("legacy loader: %+v", fl)
	}
	// Fortik's own roles are never findings.
	for _, r := range []string{fx.AdminUser, fx.ReadRole, fx.WriteRole} {
		if _, err := svc.Get(bg, shadow.FindingID(shadow.SystemPostgres, shadow.KindDBRole, up+"/"+r)); err == nil {
			t.Fatalf("Fortik role %s reported", r)
		}
	}
	// Idempotent.
	if rep2, _ := svc.Scan(bg, "", ""); rep2.Flagged != 0 {
		t.Fatalf("rescan flagged again: %+v", rep2)
	}

	// Revoke: NOLOGIN + the script's session is terminated.
	f, out, err := svc.Revoke(bg, f.FindingID, "user:sec@example.com", "nightly script with a standing password")
	if err != nil || out.Outcome != shadow.OutcomeRevoked || f.Status != shadow.StatusRevoked {
		t.Fatalf("revoke: %v %+v %+v", err, out, f)
	}
	var canLogin bool
	if err := fx.Super.QueryRow(bg, "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", script).Scan(&canLogin); err != nil || canLogin {
		t.Fatalf("role still LOGIN: %v", err)
	}
	ctx, cancel := context.WithTimeout(bg, 5*time.Second)
	defer cancel()
	if _, err := scriptConn.Exec(ctx, "SELECT 1"); err == nil {
		t.Fatal("the script's session survived the revoke")
	}
	if _, err := pgx.Connect(bg, fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=%s sslmode=disable", fx.Host, fx.Port, fx.DB, script, pw)); err == nil {
		t.Fatal("revoked role can still log in")
	}

	// A role the admin does not administer: honest failure, nothing claimed.
	fl, out, err = svc.Revoke(bg, fl.FindingID, "user:sec@example.com", "legacy loader")
	if err != nil || out.Outcome != shadow.OutcomeNotRevoked || fl.Status == shadow.StatusRevoked || !strings.Contains(out.Detail, "NOT revoked") {
		t.Fatalf("revoke of a superuser-created role: %v %+v %+v", err, out, fl)
	}
	if err := fx.Super.QueryRow(bg, "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", legacy).Scan(&canLogin); err != nil || !canLogin {
		t.Fatal("legacy role changed although the revoke reported failure")
	}
}

func TestPostgresNotConfiguredAndBroken(t *testing.T) {
	src := pgrolestest.NewSource()
	pg := discoverers.NewPostgres(src, nil, nil)
	res := pg.Discover(bg)
	if len(res) != 1 || res[0].Status != shadow.ScanNotConfigured {
		t.Fatalf("no integrations: %+v", res)
	}
	src.Put(integrations.Resolved{Integration: integrations.Integration{Key: "postgres:down", System: "postgres", Status: "configured"},
		ConfigMap: map[string]any{"host": "127.0.0.1", "port": float64(1), "database": "x", "sslmode": "disable", "environment": "dev",
			"admin_user": "a", "read_role": "r", "write_role": "w"}, Secrets: map[string]string{"admin_password": "p"}})
	res = pg.Discover(bg)
	if len(res) != 1 || res[0].Status != shadow.ScanError || res[0].Integration != "postgres:down" || strings.Contains(res[0].Detail, "p@") {
		t.Fatalf("unreachable: %+v", res)
	}
	src.SetErr(fmt.Errorf("boom"))
	if res = pg.Discover(bg); res[0].Status != shadow.ScanError {
		t.Fatalf("source error: %+v", res)
	}
}

// Phase 5 review M3: a superuser login role used by software is the most
// dangerous standing credential; discovery reports it (it used to be skipped
// as a "system role"), and revoke is manual (Fortik does not alter superusers).
func TestSuperuserRoleIsAFinding(t *testing.T) {
	fx := pgrolestest.New(t, "acme_"+pgrolestest.RandHex(3))
	etl := "etl_admin_" + pgrolestest.RandHex(3)
	pw := "pw-" + pgrolestest.RandHex(8)
	fx.Exec(fmt.Sprintf("CREATE ROLE %s LOGIN SUPERUSER PASSWORD '%s'", etl, pw))
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), testutil.AdminURL(t))
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", etl)
		_, _ = c.Exec(context.Background(), "DROP ROLE IF EXISTS "+etl)
	})
	_ = connectAs(t, fx, etl, pw, "airflow-worker")

	svc, _, _ := newService(t, discoverers.NewPostgres(fx.Source, nil, nil))
	if _, err := svc.Scan(bg, "user:sec@example.com", ""); err != nil {
		t.Fatal(err)
	}
	f := findByRef(t, svc, shadow.SystemPostgres, shadow.KindDBRole, fx.Upstream+"/"+etl)
	ev := evidence(f)
	attrs, _ := ev["attributes"].(map[string]any)
	if !f.UsedBySoftware || f.Status != shadow.StatusFlagged || attrs["superuser"] != true {
		t.Fatalf("superuser finding: %+v %v", f, ev)
	}
	_, out, err := svc.Revoke(bg, f.FindingID, "user:sec@example.com", "standing superuser used by a script")
	if err != nil || out.Outcome != shadow.OutcomeManualRequired || !strings.Contains(out.Detail, "NOSUPERUSER") {
		t.Fatalf("revoke: %v %+v", err, out)
	}
}
