// Package pgrolestest provides test fixtures for integration-backed Postgres
// upstreams: an upstream database with its own admin, read and write roles on
// the real test cluster (FORTIK_TEST_PG_URL), plus in-memory FAKES of the
// stores pgroles depends on (integrations.Source, access profiles, control
// levels, the issuance recorder). The fakes implement only the subset of the
// real interfaces that pgroles uses. For tests only.
package pgrolestest

import (
	"context"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/access"
	"fortik/internal/broker"
	"fortik/internal/broker/pgroles"
	"fortik/internal/control"
	"fortik/internal/integrations"
	"fortik/internal/testutil"
)

// ---- fakes ----

// Source is a fake integrations.Source over a map.
type Source struct {
	mu  sync.Mutex
	m   map[string]integrations.Resolved
	err error
}

func NewSource() *Source { return &Source{m: map[string]integrations.Resolved{}} }

func (s *Source) Get(_ context.Context, key string) (integrations.Resolved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return integrations.Resolved{}, s.err
	}
	r, ok := s.m[key]
	if !ok {
		return integrations.Resolved{}, integrations.ErrNotConfigured
	}
	return r, nil
}

func (s *Source) List(_ context.Context, system string) ([]integrations.Resolved, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	var out []integrations.Resolved
	for _, r := range s.m {
		if r.System == system {
			out = append(out, r)
		}
	}
	return out, nil
}

// Put adds or replaces an integration.
func (s *Source) Put(r integrations.Resolved) {
	s.mu.Lock()
	s.m[r.Key] = r
	s.mu.Unlock()
}

// SetErr makes every call fail with err (nil restores).
func (s *Source) SetErr(err error) {
	s.mu.Lock()
	s.err = err
	s.mu.Unlock()
}

// Profiles is a fake of the access.Store subset pgroles uses (Current).
type Profiles struct {
	mu sync.Mutex
	m  map[string]json.RawMessage
}

func NewProfiles() *Profiles { return &Profiles{m: map[string]json.RawMessage{}} }

func (p *Profiles) Current(_ context.Context, agentID, system string) (access.Profile, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	raw, ok := p.m[agentID+"/"+system]
	if !ok {
		return access.Profile{}, access.ErrNotFound
	}
	return access.Profile{AgentID: agentID, System: system, Version: 1, Profile: raw}, nil
}

// Set gives agentID the postgres profile {"upstreams": upstreams}.
func (p *Profiles) Set(agentID string, upstreams map[string]string) {
	b, _ := json.Marshal(map[string]any{"upstreams": upstreams})
	p.mu.Lock()
	p.m[agentID+"/postgres"] = b
	p.mu.Unlock()
}

// Clear removes agentID's postgres profile.
func (p *Profiles) Clear(agentID string) {
	p.mu.Lock()
	delete(p.m, agentID+"/postgres")
	p.mu.Unlock()
}

// Levels is a fake of the control.Store subset pgroles uses (Get).
// Unknown agents are unregistered.
type Levels struct {
	mu sync.Mutex
	m  map[string]control.Level
}

func NewLevels() *Levels { return &Levels{m: map[string]control.Level{}} }

func (l *Levels) Get(_ context.Context, agentID string) (control.State, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lvl, ok := l.m[agentID]
	if !ok {
		return control.State{AgentID: agentID, Level: control.Isolated, LevelName: control.Isolated.String()}, nil
	}
	return control.State{AgentID: agentID, Registered: true, Level: lvl, LevelName: lvl.String()}, nil
}

func (l *Levels) Set(agentID string, lvl control.Level) {
	l.mu.Lock()
	l.m[agentID] = lvl
	l.mu.Unlock()
}

// Recorder is a fake of broker.Broker.RecordIssuance.
type Recorder struct {
	mu    sync.Mutex
	creds []broker.Credential
	err   error
}

func (r *Recorder) RecordIssuance(_ context.Context, c broker.Credential, _, _ string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	r.creds = append(r.creds, c)
	return nil
}

// SetErr makes RecordIssuance fail with err (nil restores).
func (r *Recorder) SetErr(err error) {
	r.mu.Lock()
	r.err = err
	r.mu.Unlock()
}

// All returns the recorded credentials.
func (r *Recorder) All() []broker.Credential {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]broker.Credential(nil), r.creds...)
}

// ---- upstream fixture ----

// Fixture is an upstream database with its own admin, read and write roles.
// Roles are cluster-wide, so every role name carries a random tag; all of
// them (and the per-agent roles of agents created with Agent) are dropped at
// cleanup, after the database itself.
type Fixture struct {
	T         testing.TB
	Upstream  string // integration name (key postgres:<Upstream>)
	Tag       string
	DB        string
	Host      string
	Port      uint16
	Super     *pgx.Conn // superuser connection to DB
	AdminUser string
	AdminPW   string
	ReadRole  string
	WriteRole string
	// Enforced reports whether the cluster checks passwords for the
	// fixture's roles (a trust-auth dev cluster does not).
	Enforced bool

	Source   *Source
	Profiles *Profiles
	Levels   *Levels
	Recorder *Recorder

	mu     sync.Mutex
	agents []string
}

// RandHex returns n random bytes in hex.
func RandHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// New creates a temp database and attaches the fixture to it.
func New(t testing.TB, upstream string) *Fixture {
	t.Helper()
	dsn := testutil.TempDB(t, "fortik_pgroles")
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	return Attach(t, strings.TrimPrefix(u.Path, "/"), upstream)
}

// Attach creates the fixture's roles for an existing temp database db and
// prepares it like an operator would for a postgres:<upstream> integration:
// schema fortik_undo (owned by the admin, USAGE+CREATE for write_role),
// default privileges so tables the superuser creates later in public are
// readable by read_role and write_role, writable by write_role and fully
// accessible to the admin. Its cleanup DROPs db (WITH FORCE) before the roles.
func Attach(t testing.TB, db, upstream string) *Fixture {
	t.Helper()
	adminURL := testutil.AdminURL(t)
	pc, err := pgconn.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fixture{T: t, Upstream: upstream, Tag: "fxt_" + RandHex(4), DB: db, Host: pc.Host, Port: pc.Port,
		Source: NewSource(), Profiles: NewProfiles(), Levels: NewLevels(), Recorder: &Recorder{}}
	f.AdminUser, f.ReadRole, f.WriteRole = f.Tag+"_admin", f.Tag+"_read", f.Tag+"_write"
	f.AdminPW = "pw-" + RandHex(12)
	ctx := context.Background()
	root, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close(ctx)
	for _, q := range []string{
		fmt.Sprintf("CREATE ROLE %s LOGIN CREATEROLE PASSWORD '%s'", f.AdminUser, f.AdminPW),
		"CREATE ROLE " + f.ReadRole + " NOLOGIN",
		"CREATE ROLE " + f.WriteRole + " NOLOGIN",
		fmt.Sprintf("GRANT %s, %s TO %s WITH ADMIN OPTION", f.ReadRole, f.WriteRole, f.AdminUser),
		"GRANT pg_signal_backend TO " + f.AdminUser,
	} {
		if _, err := root.Exec(ctx, q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	t.Cleanup(func() { f.cleanup(adminURL) })

	cc, err := pgx.ParseConfig(adminURL)
	if err != nil {
		t.Fatal(err)
	}
	cc.Database = db
	if f.Super, err = pgx.ConnectConfig(ctx, cc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Super.Close(context.Background()) })
	for _, q := range []string{
		"CREATE SCHEMA fortik_undo AUTHORIZATION " + f.AdminUser,
		"GRANT USAGE, CREATE ON SCHEMA fortik_undo TO " + f.WriteRole,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO " + f.ReadRole + ", " + f.WriteRole,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT INSERT, UPDATE, DELETE ON TABLES TO " + f.WriteRole,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO " + f.AdminUser,
		"ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO " + f.WriteRole + ", " + f.AdminUser,
	} {
		f.Exec(q)
	}

	// Does the cluster check passwords for these roles (it may use trust)?
	bad, err := pgconn.ParseConfig(fmt.Sprintf("host=%s port=%d dbname=%s user=%s password=wrong-%s sslmode=disable",
		f.Host, f.Port, f.DB, f.AdminUser, RandHex(4)))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := pgconn.ConnectConfig(ctx, bad); err == nil {
		c.Close(ctx)
	} else {
		f.Enforced = true
	}
	f.Source.Put(f.Resolved(nil, nil))
	return f
}

func (f *Fixture) cleanup(adminURL string) {
	ctx := context.Background()
	c, err := pgx.Connect(ctx, adminURL)
	if err != nil {
		f.T.Logf("cleanup connect: %v", err)
		return
	}
	defer c.Close(ctx)
	if _, err := c.Exec(ctx, "DROP DATABASE IF EXISTS "+pgx.Identifier{f.DB}.Sanitize()+" WITH (FORCE)"); err != nil {
		f.T.Logf("cleanup drop database: %v", err)
	}
	f.mu.Lock()
	var roles []string
	for _, a := range f.agents {
		roles = append(roles, pgroles.RoleName(a, f.Upstream))
	}
	f.mu.Unlock()
	roles = append(roles, f.AdminUser, f.ReadRole, f.WriteRole)
	for _, r := range roles {
		_, _ = c.Exec(ctx, "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $1", r)
		if _, err := c.Exec(ctx, "DROP ROLE IF EXISTS "+pgx.Identifier{r}.Sanitize()); err != nil {
			f.T.Logf("cleanup drop role %s: %v", r, err)
		}
	}
}

// Resolved returns the postgres:<Upstream> integration. cfg entries override
// the config (nil deletes a key); sec entries override secrets ("" deletes).
func (f *Fixture) Resolved(cfg map[string]any, sec map[string]string) integrations.Resolved {
	cm := map[string]any{
		"host": f.Host, "port": float64(f.Port), "database": f.DB, "sslmode": "disable", "environment": "dev",
		"admin_user": f.AdminUser, "read_role": f.ReadRole, "write_role": f.WriteRole,
	}
	for k, v := range cfg {
		if v == nil {
			delete(cm, k)
		} else {
			cm[k] = v
		}
	}
	secrets := map[string]string{"admin_password": f.AdminPW}
	for k, v := range sec {
		if v == "" {
			delete(secrets, k)
		} else {
			secrets[k] = v
		}
	}
	raw, _ := json.Marshal(cm)
	return integrations.Resolved{
		Integration: integrations.Integration{Key: pgroles.Key(f.Upstream), System: pgroles.System, Config: raw,
			SecretFields: []string{"admin_password"}, Status: "configured"},
		ConfigMap: cm,
		Secrets:   secrets,
	}
}

// Manager builds a pgroles.Manager over the fixture's fakes.
func (f *Fixture) Manager(ttl time.Duration) *pgroles.Manager {
	f.T.Helper()
	m, err := pgroles.New(pgroles.Config{Integrations: f.Source, Access: f.Profiles, Control: f.Levels,
		Recorder: f.Recorder, TTL: ttl, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if err != nil {
		f.T.Fatal(err)
	}
	return m
}

// Agent registers an agent at FULL with mode on the fixture's upstream ("" =
// no profile). With unique=true a random suffix is appended to base.
func (f *Fixture) Agent(base, mode string, unique bool) string {
	id := base
	if unique {
		id += "-" + RandHex(3)
	}
	f.TrackAgent(id)
	f.Levels.Set(id, control.Full)
	if mode != "" {
		f.Profiles.Set(id, map[string]string{f.Upstream: mode})
	}
	return id
}

// TrackAgent makes cleanup drop the agent's per-agent role.
func (f *Fixture) TrackAgent(id string) {
	f.mu.Lock()
	f.agents = append(f.agents, id)
	f.mu.Unlock()
}

// Exec runs q as the superuser in the fixture database.
func (f *Fixture) Exec(q string, args ...any) {
	f.T.Helper()
	if _, err := f.Super.Exec(context.Background(), q, args...); err != nil {
		f.T.Fatalf("%s: %v", q, err)
	}
}

// Memberships lists the roles role belongs to directly.
func (f *Fixture) Memberships(role string) []string {
	f.T.Helper()
	rows, err := f.Super.Query(context.Background(), `SELECT r.rolname FROM pg_auth_members m
JOIN pg_roles r ON r.oid = m.roleid JOIN pg_roles a ON a.oid = m.member WHERE a.rolname = $1 ORDER BY 1`, role)
	if err != nil {
		f.T.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		f.T.Fatal(err)
	}
	return out
}

// Login connects to the fixture database as user/password directly.
func (f *Fixture) Login(user, password string) (*pgconn.PgConn, error) {
	cfg, err := pgroles.BuildConnConfig(f.Host, int(f.Port), f.DB, user, password, "disable", nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgconn.ConnectConfig(ctx, cfg)
}

// PasswordMatches checks password against role's stored SCRAM-SHA-256
// verifier (pg_authid, readable by the superuser), with an implementation
// independent of pgroles'. It proves rotation on trust-auth clusters too.
func (f *Fixture) PasswordMatches(role, password string) bool {
	f.T.Helper()
	var stored *string
	if err := f.Super.QueryRow(context.Background(), "SELECT rolpassword FROM pg_authid WHERE rolname = $1", role).Scan(&stored); err != nil {
		f.T.Fatal(err)
	}
	if stored == nil {
		return false
	}
	ok, err := VerifyScram(*stored, password)
	if err != nil {
		f.T.Fatalf("stored verifier: %v", err)
	}
	return ok
}

// VerifyScram reports whether password matches a Postgres
// "SCRAM-SHA-256$<iter>:<salt>$<StoredKey>:<ServerKey>" verifier.
func VerifyScram(stored, password string) (bool, error) {
	rest, ok := strings.CutPrefix(stored, "SCRAM-SHA-256$")
	if !ok {
		return false, errors.New("not a SCRAM-SHA-256 verifier")
	}
	iterSalt, keys, ok1 := strings.Cut(rest, "$")
	iterS, saltB64, ok2 := strings.Cut(iterSalt, ":")
	storedB64, serverB64, ok3 := strings.Cut(keys, ":")
	if !ok1 || !ok2 || !ok3 {
		return false, errors.New("malformed verifier")
	}
	iter, err := strconv.Atoi(iterS)
	if err != nil {
		return false, err
	}
	salt, err1 := base64.StdEncoding.DecodeString(saltB64)
	storedKey, err2 := base64.StdEncoding.DecodeString(storedB64)
	serverKey, err3 := base64.StdEncoding.DecodeString(serverB64)
	if err := errors.Join(err1, err2, err3); err != nil {
		return false, err
	}
	salted, err := pbkdf2.Key(sha256.New, password, salt, iter, sha256.Size)
	if err != nil {
		return false, err
	}
	mac := func(msg string) []byte {
		m := hmac.New(sha256.New, salted)
		m.Write([]byte(msg))
		return m.Sum(nil)
	}
	ck := sha256.Sum256(mac("Client Key"))
	return hmac.Equal(ck[:], storedKey) && hmac.Equal(mac("Server Key"), serverKey), nil
}

// PGCode returns the SQLSTATE of a Postgres error ("" otherwise).
func PGCode(err error) string {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		return pe.Code
	}
	return ""
}
