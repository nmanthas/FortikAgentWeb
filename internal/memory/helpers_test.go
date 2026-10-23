package memory_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/memory"
	"fortik/internal/policy"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

// The memory service is containment's memory access implementation.
var _ containment.MemoryAccess = (*memory.Service)(nil)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

// fakeSource is an integrations.Source holding memory:<name> integrations.
type fakeSource struct {
	mu sync.Mutex
	m  map[string]integrations.Resolved
}

func (f *fakeSource) Get(_ context.Context, key string) (integrations.Resolved, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.m[key]
	if !ok {
		return integrations.Resolved{}, integrations.ErrNotConfigured
	}
	return r, nil
}

func (f *fakeSource) List(_ context.Context, system string) ([]integrations.Resolved, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []integrations.Resolved{}
	for _, r := range f.m {
		if r.System == system {
			out = append(out, r)
		}
	}
	return out, nil
}

// resolvedFor turns a Postgres DSN into a memory:<name> integration.
func resolvedFor(t testing.TB, name, dsn string, dimension int) integrations.Resolved {
	t.Helper()
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(u.Port())
	pw, _ := u.User.Password()
	cfg := map[string]any{"host": u.Hostname(), "port": float64(port), "database": u.Path[1:], "sslmode": "disable",
		"admin_user": u.User.Username()}
	if dimension > 0 {
		cfg["dimension"] = float64(dimension)
	}
	raw, _ := json.Marshal(cfg)
	return integrations.Resolved{
		Integration: integrations.Integration{Key: memory.IntegrationKey(name), System: memory.System, Config: raw, Status: "ok"},
		ConfigMap:   cfg,
		Secrets:     map[string]string{"admin_password": pw},
	}
}

// fakeAuth authenticates agents by the X-Test-Agent header.
type fakeAuth struct{}

func (fakeAuth) Authenticate(r *http.Request) (authz.Principal, error) {
	id := r.Header.Get("X-Test-Agent")
	if id == "" {
		return authz.Principal{}, gateway.ErrUnauthenticated
	}
	return authz.Principal{Kind: authz.KindAgent, Name: id, AuthMethod: "agent_token"}, nil
}

type env struct {
	pool    *pgxpool.Pool
	d       *diary.Diary
	ctl     *control.Store
	src     *fakeSource
	stores  *memory.Stores
	svc     *memory.Service
	dec     *decide.Service
	undo    *undo.PGStore
	exec    *memory.UndoExecutor
	gw      http.Handler
	api     *http.ServeMux
	custDSN string
}

type envOpts struct {
	delay     time.Duration
	dimension int
}

const (
	supportAgent = "support_agent_1"
	otherAgent   = "billing_agent_1"
	ownerEmail   = "owner@acme.test"
)

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	cust := testutil.TempDB(t, "fortik_memstore")
	ctx := context.Background()
	if o.delay == 0 {
		o.delay = 10 * time.Minute
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	src := &fakeSource{m: map[string]integrations.Resolved{"memory:support": resolvedFor(t, "support", cust, o.dimension)}}
	stores := memory.NewStores(src, o.delay, discard())
	t.Cleanup(stores.Close)
	svc, err := memory.NewService(pool, d, stores, config.MemoryConfig{PromotionDelay: o.delay, PromotionPoll: 50 * time.Millisecond,
		SnapshotRetention: 30 * 24 * time.Hour}, discard())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(ctx, policyDir(), discard())
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: discard(),
		Enrichers: []decide.Enricher{memory.NewEnricher(svc)}}
	us := undo.NewPGStore(pool, d)
	ad, err := memory.NewGatewayAdapter(svc, us, 0, discard())
	if err != nil {
		t.Fatal(err)
	}
	gw, err := gateway.NewServer(config.GatewayConfig{}, dec, fakeAuth{}, []gateway.Adapter{ad}, discard(), gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{pool: pool, d: d, ctl: ctl, src: src, stores: stores, svc: svc, dec: dec, undo: us,
		exec: memory.NewUndoExecutor(stores), gw: gw, api: http.NewServeMux(), custDSN: cust}
	memory.NewHandler(svc, discard()).Register(e.api)
	for _, a := range []string{supportAgent, otherAgent} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: a, Type: "worker", Sponsor: ownerEmail, BusinessUnit: "support"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	return e
}

func (e *env) store(t *testing.T) *memory.PGStore {
	t.Helper()
	st, err := e.stores.Store(context.Background(), "support")
	if err != nil {
		t.Fatal(err)
	}
	return st
}

type resp struct {
	code int
	body map[string]any
	raw  string
}

func do(t *testing.T, h http.Handler, method, path string, body any, setup func(*http.Request)) resp {
	t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = bytes.NewBufferString(b)
	default:
		raw, err := json.Marshal(b)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req := httptest.NewRequest(method, path, rd)
	if setup != nil {
		setup(req)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

// agentCall calls the gateway as an agent.
func (e *env) agentCall(t *testing.T, agent, method, path string, body any) resp {
	t.Helper()
	return do(t, e.gw, method, path, body, func(r *http.Request) { r.Header.Set("X-Test-Agent", agent) })
}

// apiCall calls the API as p (nil = unauthenticated).
func (e *env) apiCall(t *testing.T, p *authz.Principal, method, path string, body any) resp {
	t.Helper()
	return do(t, e.api, method, path, body, func(r *http.Request) {
		if p != nil {
			*r = *r.WithContext(authz.With(r.Context(), *p))
		}
	})
}

func user(email string, roles ...string) *authz.Principal {
	p := &authz.Principal{Kind: authz.KindUser, Name: email, Email: email, AuthMethod: "dev", Roles: map[string]bool{}}
	for _, r := range roles {
		p.Roles[r] = true
	}
	return p
}

var security = user("sec@acme.test", authz.RoleSecurity)

func (e *env) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) str(t *testing.T, q string, args ...any) string {
	t.Helper()
	var s string
	if err := e.pool.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

// custCount counts in the customer database.
func (e *env) custCount(t *testing.T, q string, args ...any) int {
	t.Helper()
	ctx := context.Background()
	p, err := pgxpool.New(ctx, e.custDSN)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	var n int
	if err := p.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) verifyDiary(t *testing.T) {
	t.Helper()
	rep, err := e.d.VerifyChain(context.Background())
	if err != nil || !rep.OK {
		t.Fatalf("diary chain broken: %v %+v", err, rep)
	}
}

// refusal returns the gateway refusal object of r.
func refusal(t *testing.T, r resp) map[string]any {
	t.Helper()
	m, ok := r.body["error"].(map[string]any)
	if !ok {
		t.Fatalf("not a refusal (%d): %s", r.code, r.raw)
	}
	return m
}

func itemsOf(t *testing.T, r resp) []map[string]any {
	t.Helper()
	if r.code != http.StatusOK {
		t.Fatalf("query: %d %s", r.code, r.raw)
	}
	raw, _ := r.body["items"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(map[string]any))
	}
	return out
}

func ids(items []map[string]any) map[string]bool {
	out := map[string]bool{}
	for _, it := range items {
		out[it["id"].(string)] = true
	}
	return out
}

func writePath(ns string) string { return "/gw/memory/support/" + ns + "/items" }
func queryPath(ns string) string { return "/gw/memory/support/" + ns + "/query" }

// mustWrite writes through the gateway and returns (item id, action id).
func (e *env) mustWrite(t *testing.T, agent, ns, content string, emb []float32) (string, string) {
	t.Helper()
	body := map[string]any{"content": content}
	if emb != nil {
		body["embedding"] = emb
	}
	r := e.agentCall(t, agent, http.MethodPost, writePath(ns), body)
	if r.code != http.StatusCreated {
		t.Fatalf("write: %d %s", r.code, r.raw)
	}
	it := r.body["item"].(map[string]any)
	return it["id"].(string), r.body["action_id"].(string)
}

// runUndo runs an undo the way POST /v1/undo/{action_id} does.
func (e *env) runUndo(t *testing.T, actionID string) (map[string]any, error) {
	t.Helper()
	ctx := context.Background()
	h, err := e.undo.Claim(ctx, actionID, security.Actor())
	if err != nil {
		return nil, err
	}
	res, err := e.exec.Undo(ctx, h)
	if err != nil {
		if rerr := e.undo.Release(ctx, actionID, security.Actor(), err.Error()); rerr != nil {
			t.Fatal(rerr)
		}
		return nil, err
	}
	if err := e.undo.Complete(ctx, actionID, security.Actor(), res); err != nil {
		t.Fatal(err)
	}
	return res, nil
}
