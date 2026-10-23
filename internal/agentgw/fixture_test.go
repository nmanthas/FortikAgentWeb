package agentgw

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"fortik/internal/access"
	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

func repoRoot() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..")
}

// policyDir is the policy bundle under test: the repository's, or
// AGENTGW_TEST_POLICY_DIR (to check these tests against a bundle another
// workstream is changing).
func policyDir() string {
	if d := os.Getenv("AGENTGW_TEST_POLICY_DIR"); d != "" {
		return d
	}
	return filepath.Join(repoRoot(), "policies")
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// memSecrets is an in-memory secrets.Provider for the agent token hashes.
type memSecrets struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memSecrets) Get(_ context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[name]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}

func sha(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

// Agent tokens used by every test (Fortik bearer tokens).
var agentTokens = map[string]string{
	"agent_a": "tok-agent-a-0123456789",
	"agent_b": "tok-agent-b-0123456789",
	"agent_c": "tok-agent-c-0123456789",
}

func bearer(agent string) string { return "Bearer " + agentTokens[agent] }

// fixture is a real Decide stack: Postgres (migrated), the policy bundle,
// access profiles, and D1's delegation store, enricher and observer.
type fixture struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	ctl    *control.Store
	access *access.PGStore
	deleg  *delegation.PGStore
	svc    *decide.Service
	srv    *Server
	cfg    config.AgentGWConfig
	addr   string // callout gRPC address
	conn   *grpc.ClientConn
	stop   func() // stops the callout server (idempotent)
}

// fixtureOpts tune newFixture.
type fixtureOpts struct {
	// stockBundle uses policies/ exactly as checked in. By default the
	// fixture uses a2aBundle (see there).
	stockBundle bool
}

// a2aBundle copies the policy bundle and adds "a2a" to
// fortik.rules.rule_systems when it is not there yet. Until the hook
// workstream (owner of common.rego) lists a2a, every non-READ a2a action,
// DELEGATE included, is held by POL-005 (TestStockBundleHoldsDelegation
// covers that). a2a's own rules are fortik.delegation (POL-601..604) and
// the access gate (POL-020); see the contract change request in the
// workstream report.
func a2aBundle(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "policies")
	src := policyDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if rel == filepath.Join("fortik", "rules", "common.rego") {
			b = ruleSystemsPattern.ReplaceAllFunc(b, func(m []byte) []byte {
				if bytes.Contains(m, []byte(`"a2a"`)) {
					return m
				}
				return bytes.Replace(m, []byte("{"), []byte(`{"a2a", `), 1)
			})
			if !bytes.Contains(b, []byte(`"a2a"`)) {
				return errors.New("could not find rule_systems in common.rego")
			}
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// stockRuleSystem reports whether the checked-in bundle already lists sys in
// fortik.rules.rule_systems (other workstreams extend it).
func stockRuleSystem(t *testing.T, sys string) bool {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(policyDir(), "fortik", "rules", "common.rego"))
	if err != nil {
		t.Fatal(err)
	}
	m := ruleSystemsPattern.Find(b)
	if m == nil {
		t.Fatal("rule_systems not found in common.rego")
	}
	return bytes.Contains(m, []byte(`"`+sys+`"`))
}

var ruleSystemsPattern = regexp.MustCompile(`rule_systems := \{[^}]*\}`)

func newFixture(t *testing.T, cfg config.AgentGWConfig, opts ...fixtureOpts) *fixture {
	t.Helper()
	ctx := context.Background()
	var o fixtureOpts
	if len(opts) > 0 {
		o = opts[0]
	}
	bundle := policyDir()
	if !o.stockBundle {
		bundle = a2aBundle(t)
	}
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, id := range []string{"agent_a", "agent_b", "agent_c"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: id, Type: "worker", Sponsor: "sec@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	log := quietLog()
	eng, err := policy.NewEngine(ctx, bundle, log)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, secrets.MasterKeySize)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	sec, err := secrets.NewEncFile(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	dcfg := config.DelegationConfig{SigningKeySecret: "delegation/signing_key", TokenTTL: 15 * time.Minute, MaxDepth: 5, BypassOriginLevel: "SUPERVISED"}
	dstore, err := delegation.NewPGStore(ctx, pool, d, sec, dcfg)
	if err != nil {
		t.Fatal(err)
	}
	obs, err := delegation.NewObserver(dstore, ctl, d, alerts.NewPGStore(pool, d), dcfg.BypassOriginLevel)
	if err != nil {
		t.Fatal(err)
	}
	acc := access.NewPGStore(pool, d)
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc,
		Enrichers: []decide.Enricher{delegation.NewEnricher(dstore)},
		Observers: []decide.Observer{obs}}

	hashes := map[string]string{}
	for agent, tok := range agentTokens {
		hashes[agent] = sha(tok)
	}
	raw, _ := json.Marshal(hashes)
	auth := gateway.NewAgentAuth(&memSecrets{m: map[string][]byte{"agent_tokens": raw}}, "", log)
	verbs, err := LoadToolVerbs(policyDir())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.A2ATargets == nil {
		cfg.A2ATargets = map[string]string{"agent-b": "agent_b", "agent-c": "agent_c"}
	}
	if cfg.MCPServers == nil {
		cfg.MCPServers = map[string]string{"memory": "memory"}
	}
	srv, err := New(cfg, svc, auth, dstore, verbs, log, WithDiary(d), WithDecideTimeout(5*time.Second), WithPool(pool))
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{pool: pool, diary: d, ctl: ctl, access: acc, deleg: dstore, svc: svc, srv: srv, cfg: cfg}
	f.start(t)
	return f
}

// start serves the callout on a free loopback port until the test ends
// (or until f.stop is called).
func (f *fixture) start(t *testing.T) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = lis.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.srv.Serve(ctx, lis) }()
	conn, err := grpc.NewClient(f.addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	f.conn = conn
	var once sync.Once
	f.stop = func() {
		once.Do(func() {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("callout server: %v", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("callout server did not stop")
			}
		})
	}
	t.Cleanup(func() {
		_ = conn.Close()
		f.stop()
	})
}

func (f *fixture) putProfile(t *testing.T, agent, system, profile string) {
	t.Helper()
	if _, err := f.access.Put(context.Background(), agent, system, json.RawMessage(profile), "user:sec@acme.com", "test"); err != nil {
		t.Fatalf("put %s profile for %s: %v", system, agent, err)
	}
}

func (f *fixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// diaryBodies returns the bodies of all Diary events (to check no token leaked).
func (f *fixture) diaryBodies(t *testing.T) string {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json::text FROM diary ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var all []byte
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			t.Fatal(err)
		}
		all = append(all, b...)
		all = append(all, '\n')
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	var actions string
	if err := f.pool.QueryRow(context.Background(), `SELECT COALESCE(string_agg(target::text || decision_json::text, E'\n'), '') FROM actions`).Scan(&actions); err != nil && !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	return string(all) + actions
}
