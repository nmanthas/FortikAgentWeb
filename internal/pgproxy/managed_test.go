package pgproxy

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/broker/pgroles"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/undo"
)

// Integration-backed upstreams: postgres:appdb is an integration (fake
// integrations.Source) pointing at the harness database, and wins over the
// harness' YAML upstream of the same name, whose static user is the test
// superuser. Agents therefore reach the database as their own role.

type managed struct {
	h   *harness
	f   *pgrolestest.Fixture
	mgr *pgroles.Manager
}

func newManaged(t *testing.T, ttl time.Duration, mod func(*config.PGProxyConfig)) *managed {
	t.Helper()
	m := &managed{}
	m.h = newHarnessOpts(t, mod, func(h *harness) []Option {
		m.f = pgrolestest.Attach(t, h.dbName, upName)
		m.mgr = m.f.Manager(ttl)
		return []Option{WithRoles(m.mgr)}
	})
	return m
}

// agent registers a unique agent with a Fortik token and a postgres profile
// mode ("" = none) and returns its id and token.
func (m *managed) agent(base, mode string) (string, string) {
	m.h.t.Helper()
	id := m.f.Agent(base, mode, true)
	token := "tok-" + pgrolestest.RandHex(8)
	raw, err := m.h.sec.Get(bg, "agent_tokens")
	if err != nil {
		m.h.t.Fatal(err)
	}
	toks := map[string]string{}
	if err := json.Unmarshal(raw, &toks); err != nil {
		m.h.t.Fatal(err)
	}
	toks[id] = sha(token)
	b, _ := json.Marshal(toks)
	m.h.sec.set("agent_tokens", b)
	return id, token
}

func (m *managed) connect(id, token string, mode pgx.QueryExecMode) *pgx.Conn {
	m.h.t.Helper()
	c, err := m.h.connectErr(id, token, upName, mode)
	if err != nil {
		m.h.t.Fatalf("connect %s through proxy: %v", id, err)
	}
	m.h.t.Cleanup(func() { c.Close(bg) })
	return c
}

// storedVerifier returns the role's stored password verifier ("" when the
// role or its password does not exist).
func (m *managed) storedVerifier(t *testing.T, role string) string {
	t.Helper()
	var v *string
	err := m.h.admin.QueryRow(bg, "SELECT rolpassword FROM pg_authid WHERE rolname = $1", role).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	if v == nil {
		return ""
	}
	return *v
}

func TestManagedUpstreamPerAgentRole(t *testing.T) {
	m := newManaged(t, time.Minute, nil)
	id, tok := m.agent("rw", pgroles.ModeReadWrite)
	role := pgroles.RoleName(id, upName)
	m.h.exec("CREATE TABLE items (id int PRIMARY KEY, name text)")
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			before := m.storedVerifier(t, role)
			c := m.connect(id, tok, mode.mode)
			var user, app string
			if err := c.QueryRow(bg, "SELECT current_user::text, current_setting('application_name')").Scan(&user, &app); err != nil {
				t.Fatal(err)
			}
			// The integration wins over the YAML upstream (superuser).
			if user != role {
				t.Fatalf("upstream user = %q, want the agent's own role %q", user, role)
			}
			if app != "fortik:"+id+":inst-7" {
				t.Fatalf("application_name = %q", app)
			}
			if _, err := c.Exec(bg, "INSERT INTO items VALUES ($1, 'x')", len(mode.name)); err != nil {
				t.Fatalf("read_write INSERT: %v", err)
			}
			// Every client session rotates the role's password.
			if after := m.storedVerifier(t, role); after == before || after == "" {
				t.Fatal("password not rotated for the new client session")
			}
			if got := m.f.Memberships(role); len(got) != 1 || got[0] != m.f.WriteRole {
				t.Fatalf("memberships %v", got)
			}
			// The decision still sees the integration's upstream facts.
			a := m.h.dec.last(t)
			if a.AgentID != id || a.Target["upstream"] != upName || a.Target["database"] != m.h.dbName || a.Target["environment"] != "dev" {
				t.Fatalf("action %+v", a)
			}
		})
	}
	creds := m.f.Recorder.All()
	if len(creds) != 2 {
		t.Fatalf("%d issuances recorded, want one per client session", len(creds))
	}
	for _, c := range creds {
		if c.Scope["role"] != role || c.Scope["mode"] != pgroles.ModeReadWrite || c.Scope["upstream"] != upName || len(c.Secret) != 0 {
			t.Fatalf("issuance %+v", c)
		}
	}
}

func TestManagedReadOnlyPrivilegeWall(t *testing.T) {
	m := newManaged(t, time.Minute, nil)
	id, tok := m.agent("ro", pgroles.ModeReadOnly)
	m.h.exec("CREATE TABLE items (id int PRIMARY KEY, name text)")
	m.h.exec("INSERT INTO items VALUES (1, 'a')")
	// The fake decider allows everything: the database's privileges are the
	// second wall.
	for _, mode := range modes {
		t.Run(mode.name, func(t *testing.T) {
			c := m.connect(id, tok, mode.mode)
			var n int
			if err := c.QueryRow(bg, "SELECT count(*) FROM items").Scan(&n); err != nil || n != 1 {
				t.Fatalf("SELECT: %d %v", n, err)
			}
			_, err := c.Exec(bg, "INSERT INTO items VALUES (2, 'b')")
			if pe := pgErr(t, err); pe.Code != "42501" || !contains(pe.Message, "permission denied") {
				t.Fatalf("INSERT as read_only role: %s %s", pe.Code, pe.Message)
			}
			if a := m.h.dec.last(t); a.Target["statement_type"] != "INSERT" {
				t.Fatalf("INSERT was not decided first: %+v", a.Target)
			}
		})
	}
	if n := m.h.count("SELECT count(*) FROM items"); n != 1 {
		t.Fatalf("rows = %d", n)
	}
}

func TestManagedRefusals(t *testing.T) {
	m := newManaged(t, time.Minute, nil)
	refused := func(id, tok, wantCode, wantMsg string) {
		t.Helper()
		_, err := m.h.connectErr(id, tok, upName, pgx.QueryExecModeSimpleProtocol)
		pe := pgErr(t, err)
		if pe.Severity != "FATAL" || pe.Code != wantCode || !contains(pe.Message, wantMsg) {
			t.Fatalf("got %s %s %q, want %s %q", pe.Severity, pe.Code, pe.Message, wantCode, wantMsg)
		}
	}
	np, npTok := m.agent("noprofile", "")
	refused(np, npTok, "08004", "no access")
	none, noneTok := m.agent("none", pgroles.ModeNone)
	refused(none, noneTok, "08004", "no access")
	q, qTok := m.agent("quarantined", pgroles.ModeReadWrite)
	m.f.Levels.Set(q, control.Quarantined)
	refused(q, qTok, "08004", "control level")

	rw, rwTok := m.agent("rw", pgroles.ModeReadWrite)
	// Integration errors never fall back to the YAML upstream (superuser).
	m.f.Source.SetErr(errors.New("integrations store down"))
	refused(rw, rwTok, "08004", "not available")
	m.f.Source.SetErr(nil)
	m.f.Source.Put(m.f.Resolved(nil, map[string]string{"admin_password": ""}))
	refused(rw, rwTok, "08004", "not available")
	m.f.Source.Put(m.f.Resolved(map[string]any{"port": 1.0}, nil))
	refused(rw, rwTok, "08004", "not available")
	m.f.Source.Put(m.f.Resolved(nil, nil))
	// Unknown everywhere: unchanged Phase 1 answer.
	_, err := m.h.connectErr(rw, rwTok, "nope", pgx.QueryExecModeSimpleProtocol)
	if pe := pgErr(t, err); pe.Code != "3D000" {
		t.Fatalf("unknown database: %s %s", pe.Code, pe.Message)
	}
	// A bad Fortik token is still refused before anything else.
	_, err = m.h.connectErr(rw, "wrong", upName, pgx.QueryExecModeSimpleProtocol)
	if pe := pgErr(t, err); pe.Code != "28P01" {
		t.Fatalf("bad token: %s", pe.Code)
	}
	c := m.connect(rw, rwTok, pgx.QueryExecModeSimpleProtocol)
	if err := c.Ping(bg); err != nil {
		t.Fatal(err)
	}
	for _, cr := range m.f.Recorder.All() {
		if cr.Scope["role"] != pgroles.RoleName(rw, upName) {
			t.Fatalf("refused agent got a credential: %+v", cr)
		}
	}
}

func TestManagedSnapshotRunsAsAgentRole(t *testing.T) {
	m := newManaged(t, time.Minute, nil)
	id, tok := m.agent("snap", pgroles.ModeReadWrite)
	role := pgroles.RoleName(id, upName)
	setupOrders(m.h)
	m.h.dec.set("DELETE", snapshotRule())
	m.h.dec.set("UPDATE", snapshotRule())
	c := m.connect(id, tok, pgx.QueryExecModeSimpleProtocol)

	checkSnap := func(actionID string, rows int64) {
		t.Helper()
		hd, d := handleFor(t, m.h, actionID)
		if hd.Status != undo.StatusActive {
			t.Fatalf("handle %s history %v (%s)", hd.Status, m.h.us.history[actionID], hd.Error)
		}
		var owner string
		var adminCanRead bool
		if err := m.h.admin.QueryRow(bg, `SELECT tableowner, has_table_privilege($3, format('%I.%I', schemaname, tablename), 'SELECT')
			FROM pg_tables WHERE schemaname = $1 AND tablename = $2`, d.SnapshotSchema, d.SnapshotTable, m.f.AdminUser).Scan(&owner, &adminCanRead); err != nil {
			t.Fatal(err)
		}
		if owner != role || !adminCanRead {
			t.Fatalf("snapshot owner %q (want %q), admin can read: %v", owner, role, adminCanRead)
		}
		if n := m.h.count(`SELECT count(*) FROM fortik_undo."` + d.SnapshotTable + `"`); n != rows {
			t.Fatalf("snapshot rows %d", n)
		}
	}
	// Idle: Fortik's own transaction around snapshot + statement.
	tag, err := c.Exec(bg, "DELETE FROM orders WHERE grp = 'a'")
	if err != nil || tag.String() != "DELETE 5" {
		t.Fatalf("%v %v", tag, err)
	}
	checkSnap(m.h.dec.last(t).ActionID, 5)
	// Inside the client's transaction: verified after COMMIT as the admin.
	tx, err := c.Begin(bg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(bg, "UPDATE orders SET note = 'x' WHERE id = 3"); err != nil {
		t.Fatal(err)
	}
	upd := m.h.dec.last(t).ActionID
	if err := tx.Commit(bg); err != nil {
		t.Fatal(err)
	}
	checkSnap(upd, 1)

	// A read_only agent cannot create snapshots (nor delete): the statement
	// never runs even though policy allowed its reduced form.
	ro, roTok := m.agent("snap-ro", pgroles.ModeReadOnly)
	cro := m.connect(ro, roTok, pgx.QueryExecModeSimpleProtocol)
	_, err = cro.Exec(bg, "DELETE FROM orders WHERE grp = 'b'")
	if pe := pgErr(t, err); pe.Code != "42501" || !contains(pe.Message, "undo snapshot failed") {
		t.Fatalf("read_only snapshot: %s %s", pe.Code, pe.Message)
	}
	if hd, _ := handleFor(t, m.h, m.h.dec.last(t).ActionID); hd.Status != undo.StatusFailed {
		t.Fatalf("read_only handle %s", hd.Status)
	}
	if n := m.h.count("SELECT count(*) FROM orders WHERE grp = 'b'"); n != 15 {
		t.Fatalf("rows deleted: %d left", n)
	}
	if err := cro.Ping(bg); err != nil {
		t.Fatalf("session unusable after refusal: %v", err)
	}
}

func TestManagedRevokeTerminatesProxySession(t *testing.T) {
	m := newManaged(t, time.Minute, nil)
	id, tok := m.agent("rev", pgroles.ModeReadWrite)
	c := m.connect(id, tok, pgx.QueryExecModeSimpleProtocol)
	if err := c.Ping(bg); err != nil {
		t.Fatal(err)
	}
	desc, err := m.mgr.RevokeAgent(bg, id)
	if err != nil || !contains(desc, "1 of 1 live sessions terminated") {
		t.Fatalf("revoke: %q %v", desc, err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		var v int
		if err := c.QueryRow(bg, "SELECT 1").Scan(&v); err != nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("proxied session survived revocation")
		}
		time.Sleep(50 * time.Millisecond)
	}
	m.f.Levels.Set(id, control.Killed)
	_, err = m.h.connectErr(id, tok, upName, pgx.QueryExecModeSimpleProtocol)
	if pe := pgErr(t, err); pe.Code != "08004" {
		t.Fatalf("reconnect after kill: %s %s", pe.Code, pe.Message)
	}
}

func TestManagedCancelRequest(t *testing.T) {
	m := newManaged(t, time.Minute, nil)
	id, tok := m.agent("cancel", pgroles.ModeReadOnly)
	c := m.connect(id, tok, pgx.QueryExecModeSimpleProtocol)
	errc := make(chan error, 1)
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
}

func TestLegacyUpstreamAlongsideIntegrations(t *testing.T) {
	var legacyDB string
	m := newManaged(t, time.Minute, func(cfg *config.PGProxyConfig) {
		up := cfg.Upstreams[upName]
		legacyDB = up.Database
		cfg.Upstreams["legacy_db"] = up
	})
	id, tok := m.agent("legacy", "")
	c, err := m.h.connectErr(id, tok, "legacy_db", pgx.QueryExecModeSimpleProtocol)
	if err != nil {
		t.Fatalf("YAML-only upstream: %v", err)
	}
	defer c.Close(bg)
	var user, db string
	if err := c.QueryRow(bg, "SELECT current_user::text, current_database()::text").Scan(&user, &db); err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(user, "fortik_a_") || db != legacyDB {
		t.Fatalf("legacy upstream connected as %q to %q", user, db)
	}
	if len(m.f.Recorder.All()) != 0 {
		t.Fatal("legacy session recorded a per-agent credential")
	}
}
