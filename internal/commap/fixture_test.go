package commap_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/commap"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
	"fortik/internal/testutil"
)

var _ decide.Enricher = (*commap.Enricher)(nil)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

// clock is a settable test clock shared by Decide and the map.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

var mapCfg = config.MapConfig{Window: 5 * time.Minute, RollupInterval: 20 * time.Millisecond, Retention: 30 * 24 * time.Hour,
	EncodedParamMin: 256}

type env struct {
	pool   *pgxpool.Pool
	d      *diary.Diary
	ctl    *control.Store
	alerts *alerts.PGStore
	dec    *decide.Service
	clk    *clock
	worker *commap.Worker
	svc    *commap.Service
	api    http.Handler
	base   time.Time // the start of a window, an hour ago
}

func newEnv(t *testing.T) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	eng, err := policy.NewEngine(ctx, policyDir(), discard())
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	base := time.Now().UTC().Add(-time.Hour).Truncate(time.Hour)
	clk := &clock{t: base}
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: discard(), Now: clk.Now,
		Enrichers: []decide.Enricher{commap.NewEnricher(mapCfg.EncodedParamMin)}}
	al := alerts.NewPGStore(pool, d)
	e := &env{pool: pool, d: d, ctl: ctl, alerts: al, dec: dec, clk: clk, base: base}
	e.worker = e.newWorker(t, -1)
	svc, err := commap.NewService(pool, mapCfg, commap.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = svc
	mux := http.NewServeMux()
	commap.NewHandler(svc, nil, discard()).Register(mux)
	e.api = mux
	return e
}

// newWorker: settle -1 = no settle delay (sequential tests whose test clock
// is behind the wall clock); the map clock is the wall clock so retention
// never prunes test windows.
func (e *env) newWorker(t *testing.T, settle time.Duration) *commap.Worker {
	t.Helper()
	w, err := commap.NewWorker(e.pool, e.d, e.alerts, mapCfg, discard(), commap.Options{Settle: settle, BatchSize: 50})
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (e *env) register(t *testing.T, id, team, sponsor string) {
	t.Helper()
	if _, err := e.ctl.Register(context.Background(), control.Agent{AgentID: id, Type: "worker", Sponsor: sponsor, BusinessUnit: team}, "test"); err != nil {
		t.Fatal(err)
	}
}

// decideAt records one action through the real Decide service at time at.
func (e *env) decideAt(t *testing.T, at time.Time, a action.Action) decide.Outcome {
	t.Helper()
	e.clk.Set(at)
	out, err := e.dec.Decide(context.Background(), a)
	if err != nil {
		t.Fatalf("decide %s %s: %v", a.System, a.Verb, err)
	}
	return out
}

func (e *env) rollup(t *testing.T) commap.Result {
	t.Helper()
	res, err := e.worker.RollupOnce(context.Background())
	if err != nil {
		t.Fatalf("rollup: %v", err)
	}
	return res
}

type edgeRow struct {
	Window  time.Time
	From    string
	To      string
	Verb    string
	Count   int64
	Bytes   int64
	Labels  []string
	Class   string
	Samples []string
}

func (e *env) edges(t *testing.T) []edgeRow {
	t.Helper()
	rows, err := e.pool.Query(context.Background(), `SELECT window_start, from_node, to_node, verb, count, bytes, data_labels, worst_class, sample_action_ids
		FROM edges ORDER BY window_start, from_node, to_node, verb`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []edgeRow
	for rows.Next() {
		var r edgeRow
		if err := rows.Scan(&r.Window, &r.From, &r.To, &r.Verb, &r.Count, &r.Bytes, &r.Labels, &r.Class, &r.Samples); err != nil {
			t.Fatal(err)
		}
		r.Window = r.Window.UTC()
		out = append(out, r)
	}
	return out
}

func (e *env) edge(t *testing.T, from, to, verb string) []edgeRow {
	t.Helper()
	var out []edgeRow
	for _, r := range e.edges(t) {
		if r.From == from && r.To == to && r.Verb == verb {
			out = append(out, r)
		}
	}
	return out
}

func principal(roles ...string) *authz.Principal {
	m := map[string]bool{}
	for _, r := range roles {
		m[r] = true
	}
	return &authz.Principal{Kind: authz.KindToken, Name: "test", Roles: m}
}

func withPrincipal(p *authz.Principal, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			r = r.WithContext(authz.With(r.Context(), *p))
		}
		h.ServeHTTP(w, r)
	})
}

// get calls the map API as an auditor and decodes the JSON body into out.
func (e *env) get(t *testing.T, path string, out any) int {
	t.Helper()
	return e.getAs(t, principal(authz.RoleAuditor), path, out)
}

func (e *env) getAs(t *testing.T, p *authz.Principal, path string, out any) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	withPrincipal(p, e.api).ServeHTTP(rec, req)
	if out != nil && rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatalf("%s: decode: %v (%s)", path, err, rec.Body.String())
		}
	}
	if rec.Code != http.StatusOK && testing.Verbose() {
		t.Logf("%s -> %d %s", path, rec.Code, rec.Body.String())
	}
	return rec.Code
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func pgRead(agent, upstream string, labels ...string) action.Action {
	return action.Action{AgentID: agent, System: "postgres", Verb: action.VerbRead, Source: action.SourcePGProxy,
		Target: map[string]any{"upstream": upstream, "database": upstream, "statement_type": "SELECT", "environment": "prod",
			"tables": []string{"public.ledger"}},
		// A small read with its row estimate (as pgproxy reports it): a
		// sensitive read without one is held by POL-114.
		PayloadSummary: action.PayloadSummary{Bytes: 2048, DataLabels: labels, RowsEstimate: &smallRead}}
}

var smallRead int64 = 40
