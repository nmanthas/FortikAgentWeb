package swarm_test

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/broker"
	"fortik/internal/config"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/memory"
	"fortik/internal/policy"
	"fortik/internal/population"
	"fortik/internal/queues"
	"fortik/internal/swarm"
	"fortik/internal/testutil"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

// fakeAdapter is a broker adapter: it never mints (no integration in
// tests) and revokes honestly by name.
type fakeAdapter struct {
	mu      sync.Mutex
	revoked map[string]int
	fail    map[string]bool
}

func (f *fakeAdapter) System() string { return "github" }

func (f *fakeAdapter) Mint(context.Context, string, map[string]any, time.Duration) (broker.Credential, error) {
	return broker.Credential{}, broker.ErrNotConfigured
}

func (f *fakeAdapter) RevokeAgent(_ context.Context, agentID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.revoked == nil {
		f.revoked = map[string]int{}
	}
	f.revoked[agentID]++
	if f.fail[agentID] {
		return "", fmt.Errorf("github unreachable")
	}
	return "installation tokens revoked", nil
}

func (f *fakeAdapter) count(agent string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.revoked[agent]
}

func (f *fakeAdapter) setFail(agent string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == nil {
		f.fail = map[string]bool{}
	}
	f.fail[agent] = true
}

// fakeQueue records cancels.
type fakeQueue struct {
	mu      sync.Mutex
	cancels map[string]int
}

func (q *fakeQueue) System() string { return "temporal" }
func (q *fakeQueue) Pause(_ context.Context, a, _ string) (queues.Result, error) {
	return queues.Result{System: "temporal", Detail: "paused " + a}, nil
}
func (q *fakeQueue) Resume(_ context.Context, a, _ string) (queues.Result, error) {
	return queues.Result{System: "temporal", Detail: "resumed " + a}, nil
}
func (q *fakeQueue) Cancel(_ context.Context, a, _ string) (queues.Result, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.cancels == nil {
		q.cancels = map[string]int{}
	}
	q.cancels[a]++
	return queues.Result{System: "temporal", Affected: 1, Detail: "cancelled workflows tagged FortikAgentId=" + a}, nil
}

// noStores: memory access changes need no customer store.
type noStores struct{}

func (noStores) Store(context.Context, string) (*memory.PGStore, error) {
	return nil, memory.ErrStoreNotConfigured
}
func (noStores) Names(context.Context) ([]string, error) { return nil, nil }

type fixture struct {
	t       *testing.T
	pool    *pgxpool.Pool
	d       *diary.Diary
	ctl     *control.Store
	al      *alerts.PGStore
	pop     *population.Service
	cm      *containment.Manager
	sw      *swarm.Service
	dec     *decide.Service
	eng     *policy.Engine
	brk     *broker.Service
	adapter *fakeAdapter
	queue   *fakeQueue
	api     *http.ServeMux
	gw      *http.ServeMux
	signer  *diary.Signer
}

type fixtureOpt struct {
	cfg        config.SwarmConfig
	noEnricher bool // decide without the swarm enricher (observer only)
}

func newFixture(t *testing.T, o fixtureOpt) *fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	al := alerts.NewPGStore(pool, d)
	pop, err := population.New(pool, d, al, population.NewMemoryCounters(), config.PopulationConfig{StaleAfter: 45 * time.Second,
		SpikeCooldown: time.Minute}, discard())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(ctx, policyDir(), discard())
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	f := &fixture{t: t, pool: pool, d: d, ctl: ctl, al: al, pop: pop, eng: eng, adapter: &fakeAdapter{}, queue: &fakeQueue{}}
	f.dec = &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: discard()}
	f.brk = broker.New(f.dec, pool, d, access.NewPGStore(pool, d), map[string]broker.Adapter{"github": f.adapter}, discard())
	mem, err := memory.NewService(pool, d, noStores{}, config.MemoryConfig{}, discard())
	if err != nil {
		t.Fatal(err)
	}
	f.cm, err = containment.New(pool, d, ctl, f.brk, []queues.Adapter{f.queue}, mem, pop.InstanceControl(), discard())
	if err != nil {
		t.Fatal(err)
	}
	_, priv, _ := ed25519.GenerateKey(nil)
	f.signer, err = diary.NewSigner([]byte(base64.StdEncoding.EncodeToString(priv.Seed())))
	if err != nil {
		t.Fatal(err)
	}
	cfg := o.cfg
	if cfg.BreakerN == 0 {
		cfg.BreakerN = 5
	}
	f.sw, err = swarm.New(pool, d, al, f.cm, cfg, swarm.Options{Signer: f.signer, Log: discard()})
	if err != nil {
		t.Fatal(err)
	}
	if !o.noEnricher {
		f.dec.Enrichers = append(f.dec.Enrichers, f.sw)
	}
	f.dec.Enrichers = append(f.dec.Enrichers, pop)
	// The swarm observer runs first so the others see the final decision.
	f.dec.Observers = []decide.Observer{f.sw, pop}
	f.api = http.NewServeMux()
	swarm.NewHandler(f.sw, discard()).Register(f.api)
	f.gw = http.NewServeMux()
	population.NewGatewayHandler(pop, f.dec, discard()).Register(f.gw)
	return f
}

func (f *fixture) agent(id string) {
	f.t.Helper()
	if _, err := f.ctl.Register(context.Background(), control.Agent{AgentID: id, Type: "worker", Sponsor: "owner@acme.com", CopyCap: 3}, "test"); err != nil {
		f.t.Fatal(err)
	}
}

// sendAction is the identical external Gmail send every worker makes.
func sendAction(agent, inst string) action.Action {
	return action.Action{AgentID: agent, InstanceID: inst, System: "gmail", Verb: action.VerbSend, Source: action.SourceAppGateway,
		Target:         map[string]any{"endpoint": "gmail.users.messages.send", "user_id": "me", "to": []any{"victim@evil.example"}, "cc": []any{}, "bcc": []any{}, "external_domains": 1, "attachment_bytes": 0},
		PayloadSummary: action.PayloadSummary{Recipients: 1, Bytes: 1200}}
}

// send decides the identical send and, when it is allowed delayed, queues
// it as the Gmail gateway does (a pending delayed_sends row plus its active
// undo handle).
func (f *fixture) send(agent, inst string) decide.Outcome {
	f.t.Helper()
	ctx := context.Background()
	out, err := f.dec.Decide(ctx, sendAction(agent, inst))
	if err != nil {
		f.t.Fatal(err)
	}
	if out.FailClosed {
		f.t.Fatalf("send by %s failed closed: %s", agent, out.Result.Reason)
	}
	if out.Result.Decision == policy.AllowReduced {
		if _, ok := out.Result.ReducedForm["delay_send_seconds"]; !ok {
			f.t.Fatalf("send allowed without a delay: %+v", out.Result)
		}
		f.exec(`INSERT INTO delayed_sends (action_id, agent_id, send_at, status, payload_enc, nonce, key_id, meta_json)
			VALUES ($1, $2, now() + interval '120 seconds', 'pending', '\x00', '\x00', 'k', '{"recipients":1}')`, out.Action.ActionID, agent)
		f.exec(`INSERT INTO undo_handles (action_id, agent_id, kind, handle_json, status, expires_at)
			VALUES ($1, $2, 'gmail_delayed_send', '{}', 'active', now() + interval '1 hour')`, out.Action.ActionID, agent)
	}
	return out
}

func (f *fixture) delegate(from, to, parent string) string {
	f.t.Helper()
	id := action.NewID("dlg")
	var root string
	var chain []string
	var depth int
	if parent == "" {
		root, chain, depth = from, []string{from, to}, 1
	} else {
		if err := f.pool.QueryRow(context.Background(), `SELECT root_agent, chain, depth FROM delegations WHERE delegation_id = $1`, parent).
			Scan(&root, &chain, &depth); err != nil {
			f.t.Fatal(err)
		}
		chain, depth = append(chain, to), depth+1
	}
	f.exec(`INSERT INTO delegations (delegation_id, parent_id, root_agent, from_agent, to_agent, chain, depth, task_id, channel, status, expires_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, 'brief-1', 'a2a', 'open', now() + interval '15 minutes')`,
		id, parent, root, from, to, chain, depth)
	return id
}

func (f *fixture) exec(q string, args ...any) {
	f.t.Helper()
	if _, err := f.pool.Exec(context.Background(), q, args...); err != nil {
		f.t.Fatalf("%s: %v", strings.Fields(q)[0], err)
	}
}

func (f *fixture) count(q string, args ...any) int {
	f.t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		f.t.Fatal(err)
	}
	return n
}

func (f *fixture) str(q string, args ...any) string {
	f.t.Helper()
	var s string
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		f.t.Fatal(err)
	}
	return s
}

func (f *fixture) level(agent string) control.Level {
	f.t.Helper()
	st, err := f.ctl.Get(context.Background(), agent)
	if err != nil {
		f.t.Fatal(err)
	}
	return st.Level
}

func user(email string, roles ...string) authz.Principal {
	p := authz.Principal{Kind: authz.KindUser, Name: email, Email: email, AuthMethod: "dev", Roles: map[string]bool{}}
	for _, r := range roles {
		p.Roles[r] = true
	}
	return p
}

func agentP(id string) authz.Principal {
	return authz.Principal{Kind: authz.KindAgent, Name: id, AuthMethod: "agent_token"}
}

type resp struct {
	code int
	body map[string]any
	raw  string
}

func call(t *testing.T, h http.Handler, p *authz.Principal, method, path, body string) resp {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if p != nil {
		req = req.WithContext(authz.With(req.Context(), *p))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	r := resp{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &r.body)
	return r
}

// stepsOf decodes an op's steps from a JSON response.
type stepView struct {
	Name    string `json:"name"`
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
	Detail  string `json:"detail"`
	Phase   int    `json:"phase"`
}

type opView struct {
	OpID   string     `json:"op_id"`
	Op     string     `json:"op"`
	Status string     `json:"status"`
	Steps  []stepView `json:"steps"`
}

func decodeOp(t *testing.T, raw string) opView {
	t.Helper()
	var o opView
	if err := json.Unmarshal([]byte(raw), &o); err != nil {
		t.Fatalf("op: %v: %s", err, raw)
	}
	return o
}

// diaryData returns the data of every Diary event of type ev, oldest first.
func (f *fixture) diaryData(ev string) []map[string]any {
	f.t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, ev)
	if err != nil {
		f.t.Fatal(err)
	}
	bodies, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		f.t.Fatal(err)
	}
	var out []map[string]any
	for _, b := range bodies {
		var e struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(b), &e); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, e.Data)
	}
	return out
}

func (f *fixture) swarmOf(agent string) string {
	f.t.Helper()
	return f.str(`SELECT swarm_id FROM swarm_members m JOIN swarms s USING (swarm_id) WHERE m.agent_id = $1 AND s.state <> 'released'
		ORDER BY s.created_at DESC LIMIT 1`, agent)
}

func (f *fixture) verifyChain() {
	f.t.Helper()
	rep, err := f.d.VerifyChain(context.Background())
	if err != nil || !rep.OK {
		f.t.Fatalf("diary chain: %v %+v", err, rep.Problems)
	}
}
