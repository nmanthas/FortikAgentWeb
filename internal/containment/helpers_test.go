package containment_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/memory"
	"fortik/internal/policy"
	"fortik/internal/population"
	"fortik/internal/queues"
	"fortik/internal/testutil"
)

func discard() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

// calls is a concurrency-safe call log.
type calls struct {
	mu  sync.Mutex
	log []string
}

func (c *calls) add(s string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.log = append(c.log, s)
}

func (c *calls) all() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.log)
}

func (c *calls) count(s string) int {
	n := 0
	for _, x := range c.all() {
		if x == s {
			n++
		}
	}
	return n
}

// fakeRevoker stands in for broker.Service.RevokeAll with per-system
// descriptions; fail makes it report a failed system for these agents.
type fakeRevoker struct {
	calls
	mu   sync.Mutex
	fail map[string]bool
}

func (f *fakeRevoker) RevokeAll(_ context.Context, agentID, actor, reason string) (map[string]string, error) {
	f.add(agentID)
	f.mu.Lock()
	fail := f.fail[agentID]
	f.mu.Unlock()
	res := map[string]string{
		"github":   "installation tokens revoked",
		"postgres": "role fortik_agent_x: NOLOGIN PASSWORD NULL; 1 session terminated",
	}
	if fail {
		res["github"] = "revocation FAILED: github unreachable"
		return res, errors.New("github: unreachable")
	}
	return res, nil
}

func (f *fakeRevoker) setFail(agentID string, v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail == nil {
		f.fail = map[string]bool{}
	}
	f.fail[agentID] = v
}

// fakeQueue is a queue adapter that records pause/resume/cancel calls.
type fakeQueue struct {
	calls
	mu    sync.Mutex
	fail  map[string]error // action -> error
	gates map[string]*gate // action -> calls block until released (or ctx done)
	// failDetail is the Result.Detail returned with a failing action's error.
	failDetail map[string]string
}

// gate blocks queue calls of one action: entered is closed when the first
// call arrives, and calls return once release is closed or their context
// ends (with the context's error).
type gate struct {
	entered, release chan struct{}
	once             sync.Once
}

func (q *fakeQueue) setGate(act string) *gate {
	g := &gate{entered: make(chan struct{}), release: make(chan struct{})}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.gates == nil {
		q.gates = map[string]*gate{}
	}
	q.gates[act] = g
	return g
}

func (q *fakeQueue) System() string { return "temporal" }

func (q *fakeQueue) do(ctx context.Context, act, agentID string) (queues.Result, error) {
	q.mu.Lock()
	err := q.fail[act]
	g := q.gates[act]
	q.mu.Unlock()
	if g != nil {
		g.once.Do(func() { close(g.entered) })
		select {
		case <-g.release:
		case <-ctx.Done():
			q.add(act + ":" + agentID + ":timeout")
			return queues.Result{}, ctx.Err()
		}
	}
	q.add(act + ":" + agentID)
	if err != nil {
		q.mu.Lock()
		d := q.failDetail[act]
		q.mu.Unlock()
		return queues.Result{System: "temporal", Detail: d}, err
	}
	return queues.Result{System: "temporal", Affected: 2, Detail: act + " signalled to 2 workflows tagged FortikAgentId=" + agentID}, nil
}

func (q *fakeQueue) Pause(ctx context.Context, agentID, _ string) (queues.Result, error) {
	return q.do(ctx, "pause", agentID)
}

func (q *fakeQueue) Resume(ctx context.Context, agentID, _ string) (queues.Result, error) {
	return q.do(ctx, "resume", agentID)
}

func (q *fakeQueue) Cancel(ctx context.Context, agentID, _ string) (queues.Result, error) {
	return q.do(ctx, "cancel", agentID)
}

func (q *fakeQueue) setFail(act string, err error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.fail == nil {
		q.fail = map[string]error{}
	}
	q.fail[act] = err
}

// fakeMemory implements containment.MemoryAccess the way memory.Service
// does: the memory_access row is written inside the caller's tx.
type fakeMemory struct {
	calls
	pool *pgxpool.Pool
	mu   sync.Mutex
	fail bool
	// held: agent -> writes held for review (PendingReview).
	held map[string][]memory.StagedItem
}

func (f *fakeMemory) PendingReview(_ context.Context, agentID string) ([]memory.StagedItem, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.held[agentID]), nil
}

func (f *fakeMemory) SetAccess(ctx context.Context, tx pgx.Tx, agentID, mode, actor, reason string) error {
	f.add("set:" + agentID + ":" + mode)
	f.mu.Lock()
	fail := f.fail
	f.mu.Unlock()
	if fail {
		return errors.New("memory store unreachable")
	}
	const q = `INSERT INTO memory_access (agent_id, mode, reason, changed_by) VALUES ($1, $2, $3, $4)
		ON CONFLICT (agent_id) DO UPDATE SET mode = EXCLUDED.mode, reason = EXCLUDED.reason, changed_by = EXCLUDED.changed_by, changed_at = now()`
	var err error
	if tx != nil {
		_, err = tx.Exec(ctx, q, agentID, mode, reason, actor)
	} else {
		_, err = f.pool.Exec(ctx, q, agentID, mode, reason, actor)
	}
	return err
}

func (f *fakeMemory) setFail(v bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fail = v
}

func (f *fakeMemory) RollbackToSnapshot(_ context.Context, snapshotID, _, _ string) error {
	f.add("rollback:" + snapshotID)
	if strings.HasPrefix(snapshotID, "msnap_dirty") {
		return fmt.Errorf("%w: the snapshot holds 0 flagged and 1 staged (unreviewed) items", memory.ErrSnapshotNotClean)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("snapshot table missing")
	}
	return nil
}

type env struct {
	pool *pgxpool.Pool
	d    *diary.Diary
	ctl  *control.Store
	pop  *population.Service
	eng  *policy.Engine
	dec  *decide.Service
	rev  *fakeRevoker
	q    *fakeQueue
	mem  *fakeMemory
	mgr  *containment.Manager
	api  *http.ServeMux
	gw   *http.ServeMux
}

type envOpts struct {
	noQueues bool
	noMemory bool
}

func newEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	pop, err := population.New(pool, d, alerts.NewPGStore(pool, d), population.NewMemoryCounters(), config.PopulationConfig{}, discard())
	if err != nil {
		t.Fatal(err)
	}
	eng, err := policy.NewEngine(ctx, policyDir(), discard())
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: discard(),
		Enrichers: []decide.Enricher{pop}, Observers: []decide.Observer{pop}}
	e := &env{pool: pool, d: d, ctl: ctl, pop: pop, eng: eng, dec: dec, rev: &fakeRevoker{}, q: &fakeQueue{}, mem: &fakeMemory{pool: pool},
		api: http.NewServeMux(), gw: http.NewServeMux()}
	var qs []queues.Adapter
	if !o.noQueues {
		qs = []queues.Adapter{e.q}
	}
	var mem containment.MemoryAccess = e.mem
	if o.noMemory {
		mem = nil
	}
	e.mgr, err = containment.New(pool, d, ctl, e.rev, qs, mem, pop.InstanceControl(), discard())
	if err != nil {
		t.Fatal(err)
	}
	containment.NewHandler(e.mgr, discard()).Register(e.api)
	population.NewGatewayHandler(pop, dec, discard()).Register(e.gw)
	return e
}

func (e *env) agent(t *testing.T, id, team, sponsor string, copyCap int) {
	t.Helper()
	if _, err := e.ctl.Register(context.Background(), control.Agent{AgentID: id, Type: "worker", Sponsor: sponsor, BusinessUnit: team, CopyCap: copyCap}, "test"); err != nil {
		t.Fatal(err)
	}
}

func (e *env) state(t *testing.T, id string) control.State {
	t.Helper()
	st, err := e.ctl.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

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

// pgRead is a green action (allowed for a FULL, unsuspended agent).
func pgRead(agent, instance string) action.Action {
	return action.Action{AgentID: agent, InstanceID: instance, System: "postgres", Verb: action.VerbRead, Source: action.SourcePGProxy,
		Target: map[string]any{"statement_type": "SELECT", "environment": "dev", "tables": []string{"public.orders"}, "table": "orders", "schema": "public"}}
}

// externalSend is an email to an outside domain.
func externalSend(agent string) action.Action {
	return action.Action{AgentID: agent, System: "gmail", Verb: action.VerbSend, Source: action.SourceAppGateway,
		Target: map[string]any{"to": []string{"someone@other.example"}, "external_domains": 1, "external": true}}
}

func (e *env) decide(t *testing.T, a action.Action) decide.Outcome {
	t.Helper()
	out, err := e.dec.Decide(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func (e *env) mustAllow(t *testing.T, a action.Action) {
	t.Helper()
	if out := e.decide(t, a); !out.Result.Decision.Executes() {
		t.Fatalf("%s %s by %s refused: %s %s", a.System, a.Verb, a.AgentID, out.Result.RuleID, out.Result.Reason)
	}
}

func (e *env) mustDeny(t *testing.T, a action.Action, rule string) {
	t.Helper()
	out := e.decide(t, a)
	if out.Result.Decision.Executes() || out.Result.RuleID != rule {
		t.Fatalf("%s %s by %s: want refused by %s, got %s %s %s", a.System, a.Verb, a.AgentID, rule, out.Result.Decision, out.Result.RuleID, out.Result.Reason)
	}
}

func userP(email string, roles ...string) *authz.Principal {
	p := authz.Principal{Kind: authz.KindUser, Name: email, Email: email, AuthMethod: "dev", Roles: map[string]bool{}}
	for _, r := range roles {
		p.Roles[r] = true
	}
	return &p
}

var (
	security = userP("sec@acme.com", authz.RoleSecurity)
	auditor  = userP("audit@acme.com", authz.RoleAuditor)
	jane     = userP("jane@acme.com") // owner of jane's agents
	bob      = userP("bob@acme.com")
)

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
	out := resp{code: rec.Code, raw: rec.Body.String()}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out.body); err != nil {
			t.Fatalf("%s %s: non-JSON body %q", method, path, rec.Body.String())
		}
	}
	return out
}

func (e *env) post(t *testing.T, p *authz.Principal, path, body string) resp {
	t.Helper()
	return call(t, e.api, p, "POST", path, body)
}

// op decodes a successful operation response.
func opOf(t *testing.T, r resp) containment.Op {
	t.Helper()
	if r.code != 200 {
		t.Fatalf("operation: %d %s", r.code, r.raw)
	}
	var op containment.Op
	if err := json.Unmarshal([]byte(r.raw), &op); err != nil {
		t.Fatal(err)
	}
	return op
}

// stepsOf returns name -> status for one agent's steps (a repeated name,
// e.g. one queue step per adapter, keeps the last).
func stepsOf(op containment.Op, agent string) map[string]containment.Step {
	out := map[string]containment.Step{}
	for _, s := range op.Steps {
		if s.AgentID == agent || agent == "" && s.AgentID == "" {
			out[s.Name] = s
		}
	}
	return out
}

func wantSteps(t *testing.T, op containment.Op, agent string, want map[string]string) {
	t.Helper()
	got := stepsOf(op, agent)
	for name, status := range want {
		s, ok := got[name]
		if !ok {
			t.Fatalf("op %s: no step %s for %s; steps %+v", op.Op, name, agent, op.Steps)
		}
		if s.Status != status {
			t.Fatalf("op %s: step %s for %s = %s (%s), want %s", op.Op, name, agent, s.Status, s.Detail, status)
		}
	}
}

func (e *env) register(t *testing.T, agent, instance string) {
	t.Helper()
	p := authz.Principal{Kind: authz.KindAgent, Name: agent, AuthMethod: "agent_token"}
	r := call(t, e.gw, &p, "POST", "/v1/instances/register", fmt.Sprintf(`{"instance_id":%q,"host":"h1","parent_instance_id":""}`, instance))
	if r.code != 201 {
		t.Fatalf("register %s/%s: %d %s", agent, instance, r.code, r.raw)
	}
}

// registerResp registers a copy and returns the response whatever it is.
func (e *env) registerResp(t *testing.T, agent, instance string) resp {
	t.Helper()
	p := authz.Principal{Kind: authz.KindAgent, Name: agent, AuthMethod: "agent_token"}
	return call(t, e.gw, &p, "POST", "/v1/instances/register", fmt.Sprintf(`{"instance_id":%q,"host":"h1","parent_instance_id":""}`, instance))
}

// postNoFatal is post for use off the test goroutine (no t.Fatal).
func (e *env) postNoFatal(p *authz.Principal, path, body string) resp {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req = req.WithContext(authz.With(req.Context(), *p))
	rec := httptest.NewRecorder()
	e.api.ServeHTTP(rec, req)
	out := resp{code: rec.Code, raw: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.body)
	return out
}

func (e *env) heartbeat(t *testing.T, agent, instance string) resp {
	t.Helper()
	p := authz.Principal{Kind: authz.KindAgent, Name: agent, AuthMethod: "agent_token"}
	return call(t, e.gw, &p, "POST", "/v1/instances/heartbeat", fmt.Sprintf(`{"instance_id":%q}`, instance))
}

// diaryData returns the data of every Diary event of type ev, oldest first.
func (e *env) diaryData(t *testing.T, ev string) []map[string]any {
	t.Helper()
	rows, err := e.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, ev)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			t.Fatal(err)
		}
		var b struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(body), &b); err != nil {
			t.Fatal(err)
		}
		out = append(out, b.Data)
	}
	return out
}
