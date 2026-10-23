package pgroles_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/broker/pgroles"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/control"
	"fortik/internal/integrations"
)

var bg = context.Background()

const upName = "appdb"

func TestRoleName(t *testing.T) {
	a := pgroles.RoleName("agent-1", "acme_prod")
	if a != pgroles.RoleName("agent-1", "acme_prod") {
		t.Fatal("not deterministic")
	}
	if !strings.HasPrefix(a, "fortik_a_agent_1_") || len(a) != len("fortik_a_agent_1_")+6 {
		t.Fatalf("shape: %s", a)
	}
	if a == pgroles.RoleName("agent-1", "acme_staging") {
		t.Fatal("two upstreams share a role (roles are cluster-wide)")
	}
	if pgroles.RoleName("agent.1", "acme_prod") == pgroles.RoleName("agent-1", "acme_prod") {
		t.Fatal("agents that sanitize alike share a role")
	}
	long := pgroles.RoleName(strings.Repeat("Ab.", 42)+"x", "acme_prod")
	if len(long) > 63 {
		t.Fatalf("role name %d bytes", len(long))
	}
	for _, r := range long {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			t.Fatalf("unsafe rune %q in %s", r, long)
		}
	}
}

func TestParseUpstream(t *testing.T) {
	base := func() integrations.Resolved {
		return integrations.Resolved{
			Integration: integrations.Integration{Key: "postgres:acme", System: "postgres"},
			ConfigMap: map[string]any{"host": "db", "database": "acme", "environment": "prod",
				"admin_user": "adm", "read_role": "r", "write_role": "w"},
			Secrets: map[string]string{"admin_password": "s3cret-value"},
		}
	}
	u, err := pgroles.ParseUpstream(base())
	if err != nil {
		t.Fatal(err)
	}
	if u.Port != 5432 || u.SSLMode != "prefer" || u.Name != "acme" {
		t.Fatalf("defaults: %+v", u)
	}
	for _, s := range []string{u.String(), fmt.Sprintf("%v %+v %#v", u, u, u)} {
		if strings.Contains(s, "s3cret") {
			t.Fatalf("password printed: %s", s)
		}
	}
	cases := map[string]func(*integrations.Resolved){
		"bad key":         func(r *integrations.Resolved) { r.Key = "postgres:Bad-Name" },
		"no host":         func(r *integrations.Resolved) { delete(r.ConfigMap, "host") },
		"bad port":        func(r *integrations.Resolved) { r.ConfigMap["port"] = 70000.0 },
		"frac port":       func(r *integrations.Resolved) { r.ConfigMap["port"] = 54.5 },
		"bad env":         func(r *integrations.Resolved) { r.ConfigMap["environment"] = "qa" },
		"bad sslmode":     func(r *integrations.Resolved) { r.ConfigMap["sslmode"] = "maybe" },
		"same roles":      func(r *integrations.Resolved) { r.ConfigMap["write_role"] = "r" },
		"admin is role":   func(r *integrations.Resolved) { r.ConfigMap["admin_user"] = "w" },
		"managed role":    func(r *integrations.Resolved) { r.ConfigMap["read_role"] = "fortik_a_x" },
		"wrong system":    func(r *integrations.Resolved) { r.System = "aws" },
		"non-string host": func(r *integrations.Resolved) { r.ConfigMap["host"] = 5.0 },
	}
	for name, mod := range cases {
		r := base()
		mod(&r)
		if _, err := pgroles.ParseUpstream(r); !errors.Is(err, integrations.ErrInvalid) {
			t.Errorf("%s: got %v", name, err)
		}
	}
	r := base()
	delete(r.Secrets, "admin_password")
	if _, err := pgroles.ParseUpstream(r); !errors.Is(err, integrations.ErrNotConfigured) {
		t.Fatalf("missing secret: %v", err)
	}
	r = base()
	r.ConfigMap["port"] = "6543"
	if u, err := pgroles.ParseUpstream(r); err != nil || u.Port != 6543 {
		t.Fatalf("string port: %v %v", u.Port, err)
	}
}

func TestSessionModesAndPrivilegeWall(t *testing.T) {
	f := pgrolestest.New(t, upName)
	f.Exec("CREATE TABLE public.items (id int PRIMARY KEY, name text)")
	f.Exec("INSERT INTO public.items SELECT g, 'item ' || g FROM generate_series(1, 5) g")
	mgr := f.Manager(time.Minute)
	ro := f.Agent("ro", pgroles.ModeReadOnly, true)
	rw := f.Agent("rw", pgroles.ModeReadWrite, true)

	sro, err := mgr.Session(bg, ro, "inst-1", upName)
	if err != nil {
		t.Fatal(err)
	}
	if sro.User != pgroles.RoleName(ro, upName) || sro.Mode != pgroles.ModeReadOnly || len(sro.Password) < 40 {
		t.Fatalf("session %v", sro)
	}
	if got := f.Memberships(sro.User); fmt.Sprint(got) != fmt.Sprint([]string{f.ReadRole}) {
		t.Fatalf("read_only memberships = %v", got)
	}
	var super, createRole, createDB, canLogin, inherit bool
	var validUntil time.Time
	var comment string
	if err := f.Super.QueryRow(bg, `SELECT rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolinherit, rolvaliduntil,
	       shobj_description(oid, 'pg_authid') FROM pg_roles WHERE rolname = $1`, sro.User).
		Scan(&super, &createRole, &createDB, &canLogin, &inherit, &validUntil, &comment); err != nil {
		t.Fatal(err)
	}
	if super || createRole || createDB || !canLogin || !inherit {
		t.Fatalf("attributes super=%v createrole=%v createdb=%v login=%v inherit=%v", super, createRole, createDB, canLogin, inherit)
	}
	if !validUntil.Equal(sro.ExpiresAt) || time.Until(validUntil) > time.Minute+5*time.Second || time.Until(validUntil) < 50*time.Second {
		t.Fatalf("valid until %v, expires %v", validUntil, sro.ExpiresAt)
	}
	if !strings.Contains(comment, "agent="+ro) {
		t.Fatalf("comment %q", comment)
	}
	if !f.PasswordMatches(sro.User, sro.Password) {
		t.Fatal("stored verifier does not match the issued password")
	}

	// The privilege layer is a second wall: even if policy allowed an INSERT,
	// the read_only role cannot write.
	pc, s2, err := mgr.Connect(bg, ro, "inst-1", upName, map[string]string{"application_name": "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close(bg)
	if s2.Password == sro.Password {
		t.Fatal("password not rotated per session")
	}
	if r := pc.ExecParams(bg, "SELECT count(*), current_user FROM public.items", nil, nil, nil, nil).Read(); r.Err != nil ||
		string(r.Rows[0][0]) != "5" || string(r.Rows[0][1]) != sro.User {
		t.Fatalf("read_only SELECT: %v %q", r.Err, r.Rows)
	}
	if _, err := pc.Exec(bg, "INSERT INTO public.items VALUES (100, 'x')").ReadAll(); pgrolestest.PGCode(err) != "42501" {
		t.Fatalf("read_only INSERT: want 42501 permission denied, got %v", err)
	}
	if _, err := pc.Exec(bg, "CREATE TABLE fortik_undo.snap_ro AS SELECT 1").ReadAll(); pgrolestest.PGCode(err) != "42501" {
		t.Fatalf("read_only snapshot table: want 42501, got %v", err)
	}

	// read_write can write and create undo snapshots.
	pw, srw, err := mgr.Connect(bg, rw, "", upName, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pw.Close(bg)
	if got := f.Memberships(srw.User); fmt.Sprint(got) != fmt.Sprint([]string{f.WriteRole}) {
		t.Fatalf("read_write memberships = %v", got)
	}
	if _, err := pw.Exec(bg, "INSERT INTO public.items VALUES (100, 'x'); CREATE TABLE fortik_undo.snap_rw AS SELECT * FROM public.items WHERE id = 100").ReadAll(); err != nil {
		t.Fatalf("read_write: %v", err)
	}
	// The agent cannot SET ROLE to the group role (PG 16+: SET FALSE).
	if _, err := pw.Exec(bg, "SET ROLE "+f.WriteRole).ReadAll(); pgrolestest.PGCode(err) != "42501" {
		t.Fatalf("SET ROLE write_role: want 42501, got %v", err)
	}

	// Mode changes move the membership, never accumulate it.
	f.Profiles.Set(ro, map[string]string{upName: pgroles.ModeReadWrite})
	if _, err := mgr.Session(bg, ro, "", upName); err != nil {
		t.Fatal(err)
	}
	if got := f.Memberships(sro.User); fmt.Sprint(got) != fmt.Sprint([]string{f.WriteRole}) {
		t.Fatalf("after widening: %v", got)
	}
	f.Profiles.Set(ro, map[string]string{upName: pgroles.ModeReadOnly})
	if _, err := mgr.Session(bg, ro, "", upName); err != nil {
		t.Fatal(err)
	}
	if got := f.Memberships(sro.User); fmt.Sprint(got) != fmt.Sprint([]string{f.ReadRole}) {
		t.Fatalf("after narrowing: %v", got)
	}

	// Every issuance was recorded with a non-secret scope.
	creds := f.Recorder.All()
	if len(creds) != 5 {
		t.Fatalf("recorded %d issuances", len(creds))
	}
	for _, c := range creds {
		if c.System != "postgres" || c.IssuanceID == "" || c.ExpiresAt.IsZero() || len(c.Secret) != 0 || len(c.Scope) != 3 {
			t.Fatalf("credential %+v", c)
		}
		if c.Scope["upstream"] != upName || (c.Scope["mode"] != pgroles.ModeReadOnly && c.Scope["mode"] != pgroles.ModeReadWrite) ||
			!strings.HasPrefix(fmt.Sprint(c.Scope["role"]), "fortik_a_") {
			t.Fatalf("scope %+v", c.Scope)
		}
		for _, s := range []string{sro.Password, s2.Password, srw.Password} {
			if strings.Contains(fmt.Sprintf("%+v", c), s) {
				t.Fatal("password recorded")
			}
		}
	}
	if strings.Contains(fmt.Sprintf("%v %+v %#v", s2, s2, s2), s2.Password) {
		t.Fatal("Session prints its password")
	}
}

func TestSessionRefusals(t *testing.T) {
	f := pgrolestest.New(t, upName)
	mgr := f.Manager(time.Minute)
	noProfile := f.Agent("np", "", true)
	if _, err := mgr.Session(bg, noProfile, "", upName); !errors.Is(err, pgroles.ErrNoAccess) {
		t.Fatalf("no profile: %v", err)
	}
	none := f.Agent("none", pgroles.ModeNone, true)
	if _, err := mgr.Session(bg, none, "", upName); !errors.Is(err, pgroles.ErrNoAccess) {
		t.Fatalf("none: %v", err)
	}
	other := f.Agent("other", "", true)
	f.Profiles.Set(other, map[string]string{"another_db": pgroles.ModeReadWrite})
	if _, err := mgr.Session(bg, other, "", upName); !errors.Is(err, pgroles.ErrNoAccess) {
		t.Fatalf("upstream missing from profile: %v", err)
	}
	weird := f.Agent("weird", "admin", true)
	if _, err := mgr.Session(bg, weird, "", upName); !errors.Is(err, pgroles.ErrNoAccess) {
		t.Fatalf("unknown mode: %v", err)
	}
	for _, a := range []string{noProfile, none, other, weird} {
		var n int
		if err := f.Super.QueryRow(bg, "SELECT count(*) FROM pg_roles WHERE rolname = $1", pgroles.RoleName(a, upName)).Scan(&n); err != nil || n != 0 {
			t.Fatalf("refused agent %s got a role (%v)", a, err)
		}
	}

	q := f.Agent("quarantined", pgroles.ModeReadWrite, true)
	f.Levels.Set(q, control.Quarantined)
	if _, err := mgr.Session(bg, q, "", upName); !errors.Is(err, pgroles.ErrAgentBlocked) {
		t.Fatalf("quarantined: %v", err)
	}
	if _, err := mgr.Session(bg, "ghost-"+pgrolestest.RandHex(2), "", upName); !errors.Is(err, pgroles.ErrAgentBlocked) {
		t.Fatalf("unregistered: %v", err)
	}
	if _, err := mgr.Session(bg, "bad agent id", "", upName); err == nil {
		t.Fatal("invalid agent id accepted")
	}

	rw := f.Agent("rw", pgroles.ModeReadWrite, true)
	if _, err := mgr.Session(bg, rw, "", "unknown_db"); !errors.Is(err, pgroles.ErrUpstreamNotManaged) {
		t.Fatalf("unknown upstream: %v", err)
	}
	// The integration exists but its secret is missing: not a fallback case.
	f.Source.Put(f.Resolved(nil, map[string]string{"admin_password": ""}))
	if _, err := mgr.Session(bg, rw, "", upName); !errors.Is(err, integrations.ErrNotConfigured) || errors.Is(err, pgroles.ErrUpstreamNotManaged) {
		t.Fatalf("missing secret: %v", err)
	}
	// Source errors fail closed.
	f.Source.SetErr(errors.New("db down"))
	if _, err := mgr.Session(bg, rw, "", upName); err == nil || errors.Is(err, pgroles.ErrUpstreamNotManaged) {
		t.Fatalf("source error: %v", err)
	}
	f.Source.SetErr(nil)
	// The admin cannot log in.
	f.Source.Put(f.Resolved(map[string]any{"port": 1.0}, nil))
	if _, err := mgr.Session(bg, rw, "", upName); err == nil {
		t.Fatal("unreachable upstream accepted")
	}
	f.Source.Put(f.Resolved(nil, nil))

	// A failed issuance record rolls the role change back.
	f.Recorder.SetErr(errors.New("diary unavailable"))
	if _, err := mgr.Session(bg, rw, "", upName); err == nil {
		t.Fatal("issuance without a record")
	}
	var n int
	if err := f.Super.QueryRow(bg, "SELECT count(*) FROM pg_roles WHERE rolname = $1", pgroles.RoleName(rw, upName)).Scan(&n); err != nil || n != 0 {
		t.Fatalf("role created without a record (n=%d, %v)", n, err)
	}
	f.Recorder.SetErr(nil)
	if _, err := mgr.Session(bg, rw, "", "postgres:"+upName); err != nil {
		t.Fatalf("prefixed key: %v", err)
	}
}

func TestPasswordRotationAndExpiry(t *testing.T) {
	f := pgrolestest.New(t, upName)
	mgr := f.Manager(2 * time.Second)
	a := f.Agent("rot", pgroles.ModeReadWrite, true)
	s1, err := mgr.Session(bg, a, "", upName)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := mgr.Session(bg, a, "", upName)
	if err != nil {
		t.Fatal(err)
	}
	if s1.Password == s2.Password || !s2.ExpiresAt.After(s1.ExpiresAt) {
		t.Fatal("password or expiry not rotated")
	}
	if f.PasswordMatches(s2.User, s1.Password) || !f.PasswordMatches(s2.User, s2.Password) {
		t.Fatal("stored verifier is not the latest password's")
	}
	if !f.Enforced {
		t.Log("cluster does not enforce passwords (trust auth): login checks skipped; rotation and VALID UNTIL " +
			"verified in the catalog. Run against a scram-sha-256 cluster to exercise Postgres' own enforcement.")
	} else {
		if c, err := f.Login(s2.User, s1.Password); err == nil {
			c.Close(bg)
			t.Fatal("old password still logs in after rotation")
		}
		c, err := f.Login(s2.User, s2.Password)
		if err != nil {
			t.Fatalf("current password rejected: %v", err)
		}
		c.Close(bg)
	}
	time.Sleep(time.Until(s2.ExpiresAt) + 500*time.Millisecond)
	var expired bool
	if err := f.Super.QueryRow(bg, "SELECT rolvaliduntil < now() FROM pg_roles WHERE rolname = $1", s2.User).Scan(&expired); err != nil || !expired {
		t.Fatalf("VALID UNTIL not in the past (%v)", err)
	}
	if f.Enforced {
		if c, err := f.Login(s2.User, s2.Password); err == nil {
			c.Close(bg)
			t.Fatal("password still logs in after VALID UNTIL")
		} else if pgrolestest.PGCode(err) != "28P01" {
			t.Fatalf("expired password: want 28P01, got %v", err)
		}
	}
	// A new session works again.
	pc, _, err := mgr.Connect(bg, a, "", upName, nil)
	if err != nil {
		t.Fatal(err)
	}
	pc.Close(bg)
}

func TestConcurrentSessionsSameAgent(t *testing.T) {
	f := pgrolestest.New(t, upName)
	mgr := f.Manager(time.Minute)
	a := f.Agent("conc", pgroles.ModeReadWrite, true)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	conns := make(chan *pgconn.PgConn, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			pc, _, err := mgr.Connect(bg, a, "", upName, nil)
			if err != nil {
				errs <- err
				return
			}
			conns <- pc
		}()
	}
	wg.Wait()
	close(errs)
	close(conns)
	for err := range errs {
		t.Errorf("concurrent connect: %v", err)
	}
	n := 0
	for pc := range conns {
		n++
		pc.Close(bg)
	}
	if n != 8 {
		t.Fatalf("%d of 8 sessions", n)
	}
	if got := len(f.Recorder.All()); got != 8 {
		t.Fatalf("%d issuances recorded", got)
	}
}

func TestRevokeAgent(t *testing.T) {
	f := pgrolestest.New(t, upName)
	mgr := f.Manager(time.Minute)
	a := f.Agent("rev", pgroles.ModeReadWrite, true)
	pc, s, err := mgr.Connect(bg, a, "", upName, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close(bg)
	desc, err := mgr.RevokeAgent(bg, a)
	if err != nil {
		t.Fatalf("revoke: %v (%s)", err, desc)
	}
	if !strings.Contains(desc, "NOLOGIN set") || !strings.Contains(desc, "1 of 1 live sessions terminated") || !strings.Contains(desc, s.User) {
		t.Fatalf("description %q", desc)
	}
	if _, err := pc.Exec(bg, "SELECT 1").ReadAll(); err == nil {
		t.Fatal("live session survived revocation")
	}
	var canLogin, hasPassword bool
	if err := f.Super.QueryRow(bg, "SELECT rolcanlogin, rolpassword IS NOT NULL FROM pg_authid WHERE rolname = $1", s.User).Scan(&canLogin, &hasPassword); err != nil {
		t.Fatal(err)
	}
	if canLogin || hasPassword {
		t.Fatalf("after revoke: login=%v password=%v", canLogin, hasPassword)
	}
	// NOLOGIN is enforced even on trust clusters.
	if c, err := f.Login(s.User, s.Password); err == nil {
		c.Close(bg)
		t.Fatal("revoked role can still log in")
	} else if code := pgrolestest.PGCode(err); code != "28000" && code != "28P01" {
		t.Fatalf("login after revoke: %v", err)
	}
	// After the step-down that triggers revocation, no new session is issued.
	f.Levels.Set(a, control.Killed)
	if _, err := mgr.Session(bg, a, "", upName); !errors.Is(err, pgroles.ErrAgentBlocked) {
		t.Fatalf("session after kill: %v", err)
	}
	if err := f.Super.QueryRow(bg, "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", s.User).Scan(&canLogin); err != nil || canLogin {
		t.Fatal("login re-enabled for a killed agent")
	}
	// An agent that never had a session.
	b := f.Agent("never", pgroles.ModeReadOnly, true)
	desc, err = mgr.RevokeAgent(bg, b)
	if err != nil || !strings.Contains(desc, "no role") {
		t.Fatalf("never issued: %q %v", desc, err)
	}
	// Stepping back up re-enables issuance.
	f.Levels.Set(a, control.Full)
	pc2, _, err := mgr.Connect(bg, a, "", upName, nil)
	if err != nil {
		t.Fatal(err)
	}
	pc2.Close(bg)
	// No integrations: honest description.
	empty, err := pgroles.New(pgroles.Config{Integrations: pgrolestest.NewSource(), Access: f.Profiles, Control: f.Levels, Recorder: f.Recorder})
	if err != nil {
		t.Fatal(err)
	}
	desc, err = empty.RevokeAgent(bg, a)
	if err != nil || !strings.Contains(desc, "nothing revoked") {
		t.Fatalf("no upstreams: %q %v", desc, err)
	}
	// A source failure is reported, not hidden.
	f.Source.SetErr(errors.New("db down"))
	if desc, err := mgr.RevokeAgent(bg, a); err == nil || !strings.Contains(desc, "not attempted") {
		t.Fatalf("source failure: %q %v", desc, err)
	}
}

func TestRoleConflicts(t *testing.T) {
	f := pgrolestest.New(t, upName)
	mgr := f.Manager(time.Minute)
	// A pre-existing role with the managed name is never taken over.
	a := f.Agent("squat", pgroles.ModeReadWrite, true)
	f.Exec("CREATE ROLE " + pgroles.RoleName(a, upName) + " LOGIN")
	if _, err := mgr.Session(bg, a, "", upName); !errors.Is(err, pgroles.ErrRoleConflict) {
		t.Fatalf("foreign role: %v", err)
	}
	if desc, err := mgr.RevokeAgent(bg, a); !errors.Is(err, pgroles.ErrRoleConflict) || !strings.Contains(desc, "NOT revoked") {
		t.Fatalf("revoke foreign role: %q %v", desc, err)
	}
	// Memberships granted outside Fortik make the session fail closed.
	b := f.Agent("extra", pgroles.ModeReadOnly, true)
	s, err := mgr.Session(bg, b, "", upName)
	if err != nil {
		t.Fatal(err)
	}
	f.Exec("GRANT pg_read_all_data TO " + s.User)
	if _, err := mgr.Session(bg, b, "", upName); !errors.Is(err, pgroles.ErrRoleConflict) {
		t.Fatalf("extra membership: %v", err)
	}
	f.Exec("REVOKE pg_read_all_data FROM " + s.User)
	// A read_role that carries write_role's privileges is refused for read_only.
	f.Exec("GRANT " + f.WriteRole + " TO " + f.ReadRole)
	if _, err := mgr.Session(bg, b, "", upName); !errors.Is(err, integrations.ErrInvalid) {
		t.Fatalf("read_role in write_role: %v", err)
	}
	if err := mgr.Test(bg, f.Resolved(nil, nil)); err == nil || !strings.Contains(err.Error(), "read_only agents could write") {
		t.Fatalf("tester: %v", err)
	}
	f.Exec("REVOKE " + f.WriteRole + " FROM " + f.ReadRole)
	if _, err := mgr.Session(bg, b, "", upName); err != nil {
		t.Fatal(err)
	}
}

func TestTester(t *testing.T) {
	f := pgrolestest.New(t, upName)
	mgr := f.Manager(time.Minute)
	if mgr.System() != "postgres" {
		t.Fatal(mgr.System())
	}
	if err := mgr.Test(bg, f.Resolved(nil, nil)); err != nil {
		t.Fatalf("good integration: %v", err)
	}
	check := func(name string, r integrations.Resolved, want string) {
		t.Helper()
		err := pgroles.Test(bg, r)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("%s: want %q, got %v", name, want, err)
		}
		if strings.Contains(err.Error(), f.AdminPW) {
			t.Fatalf("%s: error leaks the password", name)
		}
	}
	check("missing role", f.Resolved(map[string]any{"read_role": "nope_" + f.Tag}, nil), "does not exist")
	check("bad config", f.Resolved(map[string]any{"host": nil}, nil), "host is required")
	check("unreachable", f.Resolved(map[string]any{"port": 1.0}, nil), "connect as")
	if f.Enforced {
		check("wrong password", f.Resolved(nil, map[string]string{"admin_password": "wrong"}), "28P01")
	}

	f.Exec("REVOKE CREATE ON SCHEMA fortik_undo FROM " + f.WriteRole)
	check("no create on fortik_undo", f.Resolved(nil, nil), "needs USAGE and CREATE on schema fortik_undo")
	f.Exec("GRANT CREATE ON SCHEMA fortik_undo TO " + f.WriteRole)

	f.Exec("REVOKE pg_signal_backend FROM " + f.AdminUser)
	check("no pg_signal_backend", f.Resolved(nil, nil), "pg_signal_backend")
	f.Exec("GRANT pg_signal_backend TO " + f.AdminUser)

	f.Exec("REVOKE " + f.ReadRole + " FROM " + f.AdminUser)
	check("no admin option", f.Resolved(nil, nil), "ADMIN OPTION")
	f.Exec("GRANT " + f.ReadRole + " TO " + f.AdminUser + " WITH ADMIN OPTION")

	f.Exec("ALTER ROLE " + f.AdminUser + " NOCREATEROLE")
	check("no createrole", f.Resolved(nil, nil), "CREATEROLE")
	f.Exec("ALTER ROLE " + f.AdminUser + " CREATEROLE")

	f.Exec("ALTER SCHEMA fortik_undo RENAME TO fortik_undo_old")
	check("no schema", f.Resolved(nil, nil), "schema fortik_undo does not exist")
	f.Exec("ALTER SCHEMA fortik_undo_old RENAME TO fortik_undo")
	if err := pgroles.Test(bg, f.Resolved(nil, nil)); err != nil {
		t.Fatalf("restored: %v", err)
	}
}

// brokenSource is a source that also reports a configured upstream whose
// admin secret is missing (integrations.PGStore.Broken).
type brokenSource struct {
	*pgrolestest.Source
	broken []string
}

func (b brokenSource) Broken(context.Context, string) ([]string, error) { return b.broken, nil }

// An upstream whose admin secret was lost is reported as NOT revoked (with
// an error), never silently skipped as if there were nothing to revoke.
func TestRevokeAgentReportsBrokenIntegrations(t *testing.T) {
	f := pgrolestest.New(t, upName)
	src := brokenSource{Source: pgrolestest.NewSource(), broken: []string{"postgres:lost_secret"}}
	mgr, err := pgroles.New(pgroles.Config{Integrations: src, Access: f.Profiles, Control: f.Levels, Recorder: f.Recorder})
	if err != nil {
		t.Fatal(err)
	}
	desc, err := mgr.RevokeAgent(context.Background(), "agent-1")
	if err == nil || !strings.Contains(desc, "postgres:lost_secret: NOT revoked") || strings.Contains(desc, "nothing revoked") {
		t.Fatalf("broken integration must be reported: %q %v", desc, err)
	}
}
