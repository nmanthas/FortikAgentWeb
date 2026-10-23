package overrides

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

const (
	secActor  = "user:sec@acme.com"
	janeEmail = "jane@acme.com"
)

type fixture struct {
	pool     *pgxpool.Pool
	d        *diary.Diary
	ctl      *control.Store
	profiles *access.PGStore
	store    *PGStore
	revokers map[string]*fakeRevoker
	alerts   *fakeAlerts
}

// fakeRevoker records RevokeAgent calls (the broker adapters in production).
type fakeRevoker struct {
	system string
	mu     sync.Mutex
	calls  []string
	err    error
}

func (r *fakeRevoker) RevokeAgent(_ context.Context, agentID string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, agentID)
	if r.err != nil {
		return "", r.err
	}
	return r.system + " tokens revoked for " + agentID, nil
}

func (r *fakeRevoker) Calls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...)
}

// fakeAlerts stands in for D4's alerts store: it writes the alert row and
// alert.raised in the caller's transaction, as RaiseTx must.
type fakeAlerts struct {
	d   *diary.Diary
	err error
}

func (f *fakeAlerts) RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error) {
	if f.err != nil {
		return alerts.Alert{}, f.err
	}
	a.ID = action.NewID("alr")
	if len(a.Details) == 0 {
		a.Details = json.RawMessage(`{}`)
	}
	if _, err := tx.Exec(ctx, `INSERT INTO alerts (alert_id, kind, severity, agent_id, summary, details, dedup_key)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $6, NULLIF($7, ''))`,
		a.ID, a.Kind, a.Severity, a.AgentID, a.Summary, []byte(a.Details), a.DedupKey); err != nil {
		return alerts.Alert{}, err
	}
	_, err := f.d.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: "alert.raised", Actor: "system:alerts",
		Data: map[string]any{"alert_id": a.ID, "kind": a.Kind, "severity": a.Severity, "summary": a.Summary}})
	return a, err
}

func setup(t *testing.T) *fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	for _, a := range []control.Agent{
		{AgentID: "code_agent_12", Type: "coding", Sponsor: "Jane@Acme.com", BusinessUnit: "platform"},
		{AgentID: "code_agent_13", Type: "coding", Sponsor: "jane@acme.com", BusinessUnit: "platform"},
		{AgentID: "code_agent_14", Type: "coding", Sponsor: "jane@acme.com", BusinessUnit: "platform"},
		{AgentID: "finance_agent_07", Type: "finance", Sponsor: "bob@acme.com", BusinessUnit: "finance"},
	} {
		if _, err := ctl.Register(ctx, a, "test"); err != nil {
			t.Fatal(err)
		}
	}
	revs := map[string]*fakeRevoker{}
	rv := map[string]Revoker{}
	for _, sys := range []string{"github", "gmail", "drive", "aws", "postgres"} {
		revs[sys] = &fakeRevoker{system: sys}
		rv[sys] = revs[sys]
	}
	store := NewPGStore(pool, d, rv, nil)
	return &fixture{pool: pool, d: d, ctl: ctl, profiles: access.NewPGStore(pool, d), store: store, revokers: revs, alerts: &fakeAlerts{d: d}}
}

func (f *fixture) worker(t *testing.T) *Worker {
	t.Helper()
	w, err := NewWorker(f.store, f.profiles, f.alerts, 50*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func (f *fixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// events returns the data of every Diary event of a type, oldest first.
func (f *fixture) events(t *testing.T, eventType string) []map[string]any {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, eventType)
	if err != nil {
		t.Fatal(err)
	}
	bodies, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	out := make([]map[string]any, 0, len(bodies))
	for _, b := range bodies {
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal([]byte(b), &body); err != nil {
			t.Fatal(err)
		}
		out = append(out, body.Data)
	}
	return out
}

// expire moves an override's restore time into the past (simulates time).
func (f *fixture) expire(t *testing.T, id string) {
	t.Helper()
	if _, err := f.pool.Exec(context.Background(), `UPDATE access_overrides SET expires_at = now() - interval '1 second' WHERE override_id = $1`, id); err != nil {
		t.Fatal(err)
	}
}

func (f *fixture) verifyDiary(t *testing.T) {
	t.Helper()
	rep, err := f.d.VerifyChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Fatalf("diary chain broken: %v", rep.Problems)
	}
}

func agentReq(agent, system, mode string, d time.Duration) CreateRequest {
	return CreateRequest{Scope: ScopeAgent, ScopeID: agent, System: system, Mode: mode, Duration: d, Reason: "incident 42"}
}

func mustCreate(t *testing.T, f *fixture, req CreateRequest) Override {
	t.Helper()
	o, err := f.store.Create(context.Background(), req, secActor, nil)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	return o
}

func status(t *testing.T, f *fixture, id string) string {
	t.Helper()
	o, err := f.store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return o.Status
}

var errBoom = errors.New("boom")
