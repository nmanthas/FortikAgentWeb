package pgroles_test

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/broker"
	"fortik/internal/broker/pgroles"
	"fortik/internal/broker/pgroles/pgrolestest"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

// TestWiredThroughRealBroker wires the Manager exactly as cmd/fortik does:
// the real integrations.PGStore (secrets in an encfile store) is the Source, a
// LateRecorder breaks the broker <-> adapter construction cycle, the real
// broker.Service records issuances (credential_issuances + Diary) and its
// RevokeAll reaches the Manager. Neither the row nor the Diary may contain the
// password.
func TestWiredThroughRealBroker(t *testing.T) {
	f := pgrolestest.New(t, upName)
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))

	src := realSource(t, f, pool, d)
	if err := pgroles.Test(bg, mustGet(t, src)); err != nil {
		t.Fatalf("tester over the real source: %v", err)
	}

	late := &pgroles.LateRecorder{}
	mgr, err := pgroles.New(pgroles.Config{Integrations: src, Access: f.Profiles, Control: f.Levels,
		Recorder: late, TTL: time.Minute, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	a := f.Agent("wired", pgroles.ModeReadWrite, true)

	// Before the broker is wired, nothing can be issued (fail closed) and no
	// role is created.
	if _, err := mgr.Session(bg, a, "", upName); !errors.Is(err, pgroles.ErrRecorderUnset) {
		t.Fatalf("unwired recorder: %v", err)
	}
	if got := f.Memberships(pgroles.RoleName(a, upName)); len(got) != 0 {
		t.Fatalf("role granted without a record: %v", got)
	}

	svc := broker.New(nil, pool, d, nil, map[string]broker.Adapter{pgroles.System: mgr}, log)
	late.Set(svc)

	s, err := mgr.Session(bg, a, "inst-1", upName)
	if err != nil {
		t.Fatal(err)
	}
	var (
		system, instance, scope string
		expires                 time.Time
	)
	if err := pool.QueryRow(bg, `SELECT system, instance_id, scope_json::text, expires_at
		FROM credential_issuances WHERE issuance_id = $1 AND agent_id = $2`, s.IssuanceID, a).
		Scan(&system, &instance, &scope, &expires); err != nil {
		t.Fatalf("issuance row: %v", err)
	}
	if system != "postgres" || instance != "inst-1" {
		t.Fatalf("row system=%s instance=%s", system, instance)
	}
	for _, want := range []string{`"upstream": "` + upName + `"`, `"mode": "read_write"`, `"role": "` + s.User + `"`} {
		if !strings.Contains(scope, want) {
			t.Fatalf("scope %s lacks %s", scope, want)
		}
	}
	if d := expires.Sub(s.ExpiresAt); d < -time.Second || d > time.Second {
		t.Fatalf("recorded expiry %s != role expiry %s", expires, s.ExpiresAt)
	}
	entries, err := d.Query(bg, diary.Filter{AgentID: a})
	if err != nil {
		t.Fatal(err)
	}
	issued := 0
	for _, e := range entries {
		if strings.Contains(e.BodyJSON, s.Password) || strings.Contains(scope, s.Password) {
			t.Fatal("password leaked into the issuance record")
		}
		if e.EventType == broker.EventIssued {
			issued++
		}
	}
	if issued != 1 {
		t.Fatalf("credential.issued events: %d", issued)
	}

	// The broker's RevokeAll (called on QUARANTINED/KILLED) reaches the role.
	res, err := svc.RevokeAll(bg, a, "user:sec@example.com", "test")
	if err != nil {
		t.Fatalf("RevokeAll: %v (%v)", err, res)
	}
	if !strings.Contains(res[pgroles.System], "NOLOGIN set") {
		t.Fatalf("revocation description: %q", res[pgroles.System])
	}
	var canLogin bool
	if err := f.Super.QueryRow(bg, "SELECT rolcanlogin FROM pg_roles WHERE rolname = $1", s.User).Scan(&canLogin); err != nil || canLogin {
		t.Fatalf("role can still log in (%v)", err)
	}
}

// realSource configures the fixture's upstream through the real integrations
// store, as the console's PUT /v1/integrations/postgres:<name> would.
func realSource(t *testing.T, f *pgrolestest.Fixture, pool *pgxpool.Pool, d *diary.Diary) *integrations.PGStore {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	enc, err := secrets.NewEncFile(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	st := integrations.NewPGStore(pool, d, enc)
	raw := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	pw := f.AdminPW
	_, err = st.Configure(bg, pgroles.Key(f.Upstream), integrations.ConfigureInput{
		Config: map[string]json.RawMessage{
			"host": raw(f.Host), "port": raw(int(f.Port)), "database": raw(f.DB), "sslmode": raw("disable"),
			"environment": raw("dev"), "admin_user": raw(f.AdminUser), "read_role": raw(f.ReadRole), "write_role": raw(f.WriteRole),
		},
		Secrets: map[string]*string{"admin_password": &pw},
	}, "user:sec@example.com")
	if err != nil {
		t.Fatalf("configure integration: %v", err)
	}
	return st
}

func mustGet(t *testing.T, src integrations.Source) integrations.Resolved {
	t.Helper()
	r, err := src.Get(bg, pgroles.Key(upName))
	if err != nil {
		t.Fatalf("get integration: %v", err)
	}
	return r
}
