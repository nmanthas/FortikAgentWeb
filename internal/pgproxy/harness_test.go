package pgproxy

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/action"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

// ---- fakes ----

type memSecrets struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memSecrets) Get(_ context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return nil, fmt.Errorf("%w: %s", secrets.ErrNotFound, name)
	}
	return append([]byte(nil), v...), nil
}

func (s *memSecrets) set(name string, v []byte) {
	s.mu.Lock()
	s.m[name] = v
	s.mu.Unlock()
}

// fakeDecider decides by statement type; default allow.
type fakeDecider struct {
	mu      sync.Mutex
	rules   map[string]policy.Result
	err     error
	delay   time.Duration // simulated decision latency (honours ctx)
	actions []action.Action
}

func newDecider() *fakeDecider { return &fakeDecider{rules: map[string]policy.Result{}} }

func (d *fakeDecider) set(stmtType string, r policy.Result) {
	d.mu.Lock()
	d.rules[stmtType] = r
	d.mu.Unlock()
}

func (d *fakeDecider) setErr(err error) {
	d.mu.Lock()
	d.err = err
	d.mu.Unlock()
}

func (d *fakeDecider) setDelay(v time.Duration) {
	d.mu.Lock()
	d.delay = v
	d.mu.Unlock()
}

func (d *fakeDecider) Decide(ctx context.Context, a action.Action) (decide.Outcome, error) {
	d.mu.Lock()
	delay := d.delay
	d.mu.Unlock()
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return decide.Outcome{}, ctx.Err()
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.actions = append(d.actions, a)
	if d.err != nil {
		return decide.Outcome{}, d.err
	}
	st, _ := a.Target["statement_type"].(string)
	r, ok := d.rules[st]
	if !ok {
		r = policy.Result{Class: policy.Green, Decision: policy.Allow, RuleID: "test.allow", Reason: "allowed"}
	}
	return decide.Outcome{Action: a, Result: r}, nil
}

func (d *fakeDecider) calls() []action.Action {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]action.Action(nil), d.actions...)
}

func (d *fakeDecider) reset() {
	d.mu.Lock()
	d.actions = nil
	d.mu.Unlock()
}

func (d *fakeDecider) last(t *testing.T) action.Action {
	t.Helper()
	c := d.calls()
	if len(c) == 0 {
		t.Fatal("decider was not called")
	}
	return c[len(c)-1]
}

type memUndo struct {
	mu      sync.Mutex
	handles map[string]undo.Handle
	history map[string][]string
}

func newMemUndo() *memUndo {
	return &memUndo{handles: map[string]undo.Handle{}, history: map[string][]string{}}
}

func (m *memUndo) transition(id string, from []string, to, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[id]
	if !ok {
		return undo.ErrNotFound
	}
	okFrom := false
	for _, f := range from {
		if h.Status == f {
			okFrom = true
		}
	}
	if !okFrom {
		return fmt.Errorf("%w: %s -> %s", undo.ErrNotUndoable, h.Status, to)
	}
	h.Status = to
	if reason != "" {
		h.Error = reason
	}
	m.handles[id] = h
	m.history[id] = append(m.history[id], to)
	return nil
}

func (m *memUndo) Prepare(_ context.Context, h undo.Handle, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.handles[h.ActionID]; ok {
		return errors.New("duplicate handle")
	}
	if h.Status != undo.StatusPrepared {
		return errors.New("handle must be prepared")
	}
	m.handles[h.ActionID] = h
	m.history[h.ActionID] = []string{h.Status}
	return nil
}
func (m *memUndo) Activate(_ context.Context, id string) error {
	return m.transition(id, []string{undo.StatusPrepared}, undo.StatusActive, "")
}
func (m *memUndo) Fail(_ context.Context, id, reason string) error {
	return m.transition(id, []string{undo.StatusPrepared}, undo.StatusFailed, reason)
}
func (m *memUndo) Get(_ context.Context, id string) (undo.Handle, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.handles[id]
	if !ok {
		return undo.Handle{}, undo.ErrNotFound
	}
	return h, nil
}
func (m *memUndo) Claim(_ context.Context, id, _ string) (undo.Handle, error) {
	if err := m.transition(id, []string{undo.StatusActive}, undo.StatusUndoing, ""); err != nil {
		return undo.Handle{}, err
	}
	return m.Get(context.Background(), id)
}
func (m *memUndo) Complete(_ context.Context, id, _ string, _ map[string]any) error {
	return m.transition(id, []string{undo.StatusUndoing}, undo.StatusUsed, "")
}
func (m *memUndo) Release(_ context.Context, id, _, reason string) error {
	return m.transition(id, []string{undo.StatusUndoing}, undo.StatusActive, reason)
}

func (m *memUndo) all() []undo.Handle {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []undo.Handle
	for _, h := range m.handles {
		out = append(out, h)
	}
	return out
}

// ---- harness ----

const (
	testAgent = "agent-1"
	testToken = "tok-secret-1"
	upName    = "appdb"
)

func sha(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

type harness struct {
	t      *testing.T
	dbName string
	admin  *pgx.Conn // direct connection to the temp database (bypasses Fortik)
	dec    *fakeDecider
	us     *memUndo
	sec    *memSecrets
	srv    *Server
	addr   string
	stop   func() error
}

func adminURL(t *testing.T) string {
	u := os.Getenv("FORTIK_TEST_PG_URL")
	if u == "" {
		t.Skip("FORTIK_TEST_PG_URL is not set; skipping Postgres integration test (e.g. postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable)")
	}
	return u
}

// createTempDB creates a uniquely named database and drops it at cleanup.
func createTempDB(t *testing.T) (string, *pgconn.Config) {
	t.Helper()
	base := adminURL(t)
	ctx := context.Background()
	c, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}
	defer c.Close(ctx)
	var b [6]byte
	_, _ = rand.Read(b[:])
	name := "fortik_test_" + hex.EncodeToString(b[:])
	if _, err := c.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create db: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			t.Logf("cleanup connect: %v", err)
			return
		}
		defer c.Close(context.Background())
		if _, err := c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)"); err != nil {
			t.Logf("drop db %s: %v", name, err)
		}
	})
	pc, err := pgconn.ParseConfig(base)
	if err != nil {
		t.Fatal(err)
	}
	return name, pc
}

func upstreamFor(pc *pgconn.Config, db string) config.UpstreamConfig {
	return config.UpstreamConfig{Host: pc.Host, Port: int(pc.Port), Database: db, User: pc.User,
		SSLMode: "disable", Environment: "dev"}
}

func newHarness(t *testing.T) *harness { return newHarnessWith(t, nil) }

func newHarnessWith(t *testing.T, mod func(*config.PGProxyConfig)) *harness {
	t.Helper()
	return newHarnessOpts(t, mod, nil)
}

// newHarnessOpts is newHarnessWith plus server options built once the temp
// database exists (e.g. a role broker for integration-backed upstreams).
func newHarnessOpts(t *testing.T, mod func(*config.PGProxyConfig), opts func(h *harness) []Option) *harness {
	t.Helper()
	db, pc := createTempDB(t)
	h := &harness{t: t, dbName: db, dec: newDecider(), us: newMemUndo()}
	toks, _ := json.Marshal(map[string]string{testAgent: sha(testToken), "agent-2": sha("other")})
	h.sec = &memSecrets{m: map[string][]byte{"agent_tokens": toks}}
	up := upstreamFor(pc, db)
	if pc.Password != "" {
		h.sec.m["up_pw"] = []byte(pc.Password)
		up.PasswordSecret = "up_pw"
	}
	cfg := config.PGProxyConfig{
		AgentTokensSecret: "agent_tokens",
		Upstreams:         map[string]config.UpstreamConfig{upName: up},
		DataLabels: []config.DataLabelRule{
			{Match: "public.customers", Labels: []string{"customer_pii"}},
			{Match: "*.payments", Labels: []string{"financial"}},
		},
		PreQueryTimeout: 2 * time.Second,
	}
	if mod != nil {
		mod(&cfg)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if os.Getenv("FORTIK_TEST_VERBOSE") != "" {
		log = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	var o []Option
	if opts != nil {
		o = opts(h)
	}
	srv, err := New(cfg, config.UndoConfig{SnapshotRetention: time.Hour}, h.sec, h.dec, h.us, log, o...)
	if err != nil {
		t.Fatal(err)
	}
	h.srv = srv
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.addr = ln.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	var once sync.Once
	var stopErr error
	h.stop = func() error {
		once.Do(func() {
			cancel()
			select {
			case stopErr = <-done:
			case <-time.After(10 * time.Second):
				stopErr = errors.New("proxy did not shut down within 10s")
			}
		})
		return stopErr
	}
	t.Cleanup(func() {
		if err := h.stop(); err != nil {
			t.Errorf("Serve: %v", err)
		}
	})
	acfg, err := pgx.ParseConfig(adminURL(t))
	if err != nil {
		t.Fatal(err)
	}
	acfg.Database = db
	ac, err := pgx.ConnectConfig(context.Background(), acfg)
	if err != nil {
		t.Fatal(err)
	}
	h.admin = ac
	t.Cleanup(func() { ac.Close(context.Background()) })
	return h
}

func (h *harness) url(agent, token, db string) string {
	return fmt.Sprintf("postgres://%s:%s@%s/%s?sslmode=disable&application_name=fortik:inst-7", agent, token, h.addr, db)
}

func (h *harness) connect(mode pgx.QueryExecMode) *pgx.Conn {
	h.t.Helper()
	c, err := h.connectErr(testAgent, testToken, upName, mode)
	if err != nil {
		h.t.Fatalf("connect through proxy: %v", err)
	}
	h.t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func (h *harness) connectErr(agent, token, db string, mode pgx.QueryExecMode) (*pgx.Conn, error) {
	cfg, err := pgx.ParseConfig(h.url(agent, token, db))
	if err != nil {
		return nil, err
	}
	cfg.DefaultQueryExecMode = mode
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return pgx.ConnectConfig(ctx, cfg)
}

func (h *harness) exec(sql string) {
	h.t.Helper()
	if _, err := h.admin.Exec(context.Background(), sql); err != nil {
		h.t.Fatalf("admin exec %q: %v", sql, err)
	}
}

func (h *harness) count(sql string) int64 {
	h.t.Helper()
	var n int64
	if err := h.admin.QueryRow(context.Background(), sql).Scan(&n); err != nil {
		h.t.Fatalf("admin count %q: %v", sql, err)
	}
	return n
}

func pgErr(t *testing.T, err error) *pgconn.PgError {
	t.Helper()
	var pe *pgconn.PgError
	if !errors.As(err, &pe) {
		t.Fatalf("expected *pgconn.PgError, got %T: %v", err, err)
	}
	return pe
}

var modes = []struct {
	name string
	mode pgx.QueryExecMode
}{
	{"simple", pgx.QueryExecModeSimpleProtocol},
	{"extended", pgx.QueryExecModeCacheStatement},
}

func denyRule(rule string) policy.Result {
	return policy.Result{Class: policy.Red, Decision: policy.Deny, RuleID: rule, Reason: "not allowed in test"}
}

func holdRule(rule string) policy.Result {
	return policy.Result{Class: policy.Red, Decision: policy.Hold, RuleID: rule, Reason: "needs approval"}
}

func snapshotRule() policy.Result {
	return policy.Result{Class: policy.Yellow, Decision: policy.AllowReduced, RuleID: "pg.snapshot",
		Reason: "snapshot first", ReducedForm: map[string]any{"snapshot_rows": true}}
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
