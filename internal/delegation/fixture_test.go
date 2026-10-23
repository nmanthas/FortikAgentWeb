package delegation_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"

	"fortik/internal/access"
	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/delegation"
	"fortik/internal/diary"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

const keySecret = "delegation/signing_key"

// clock is a settable time source shared by the store and the enricher.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type fixture struct {
	pool  *pgxpool.Pool
	d     *diary.Diary
	ctl   *control.Store
	acc   *access.PGStore
	sec   secrets.Store
	store *delegation.PGStore
	clock *clock
	cfg   config.DelegationConfig
}

func newSecrets(t *testing.T) secrets.Store {
	t.Helper()
	s, err := secrets.NewEncFile(t.TempDir(), bytes.Repeat([]byte{7}, secrets.MasterKeySize))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setup creates a migrated database with agents agent_a..agent_g (FULL),
// a secret store and a delegation store on a controllable clock.
func setup(t *testing.T) *fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	ctx := context.Background()
	for _, id := range []string{"agent_a", "agent_b", "agent_c", "agent_d", "agent_e", "agent_f", "agent_g"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: id, Type: "worker", Sponsor: "owner@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	f := &fixture{pool: pool, d: d, ctl: ctl, acc: access.NewPGStore(pool, d), sec: newSecrets(t),
		clock: &clock{t: time.Now().UTC().Truncate(time.Second)},
		cfg:   config.DelegationConfig{SigningKeySecret: keySecret, TokenTTL: 15 * time.Minute, MaxDepth: 5, BypassOriginLevel: "SUPERVISED"}}
	st, err := delegation.NewPGStore(ctx, pool, d, f.sec, f.cfg, delegation.WithClock(f.clock.Now))
	if err != nil {
		t.Fatal(err)
	}
	f.store = st
	return f
}

func (f *fixture) count(t *testing.T, q string, args ...any) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *fixture) level(t *testing.T, agent string) control.Level {
	t.Helper()
	st, err := f.ctl.Get(context.Background(), agent)
	if err != nil {
		t.Fatal(err)
	}
	return st.Level
}

func (f *fixture) putProfile(t *testing.T, agent, system, profile string) {
	t.Helper()
	if _, err := f.acc.Put(context.Background(), agent, system, json.RawMessage(profile), "user:sec@acme.com", "test"); err != nil {
		t.Fatalf("put %s/%s: %v", agent, system, err)
	}
}

// events returns the data of every Diary event of a type, oldest first.
func (f *fixture) events(t *testing.T, eventType string) []map[string]any {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, eventType)
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

// assertNoToken fails if a token appears anywhere it must never be stored.
func (f *fixture) assertNoToken(t *testing.T, tokens ...string) {
	t.Helper()
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		payload, sig, _ := bytesCut(tok)
		for _, needle := range []string{tok, sig, payload} {
			for _, q := range []string{
				`SELECT count(*) FROM diary WHERE strpos(body_json, $1) > 0`,
				`SELECT count(*) FROM actions WHERE strpos(decision_json::text || target::text || reason, $1) > 0`,
				`SELECT count(*) FROM delegations WHERE strpos(row_to_json(delegations)::text, $1) > 0`,
				`SELECT count(*) FROM alerts WHERE strpos(row_to_json(alerts)::text, $1) > 0`,
			} {
				if n := f.count(t, q, needle); n != 0 {
					t.Fatalf("delegation token material stored (%s)", q)
				}
			}
		}
	}
}

func bytesCut(tok string) (string, string, bool) {
	for i := 0; i < len(tok); i++ {
		if tok[i] == '.' {
			return tok[:i], tok[i+1:], true
		}
	}
	return tok, "", false
}

// txRaiser is a minimal alerts raiser writing to the alerts table inside the
// decision transaction (workstream D4 provides the real one).
type txRaiser struct {
	mu   sync.Mutex
	fail bool
	got  []alerts.Alert
}

func (r *txRaiser) RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fail {
		return alerts.Alert{}, errors.New("alerts store unavailable")
	}
	a.ID = "alr_" + ulid.Make().String()
	_, err := tx.Exec(ctx, `
		INSERT INTO alerts (alert_id, kind, severity, agent_id, action_id, summary, details, dedup_key)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), $6, $7, NULLIF($8, ''))
		ON CONFLICT (dedup_key) WHERE status = 'open' AND dedup_key IS NOT NULL
		DO UPDATE SET count = alerts.count + 1, updated_at = now()`,
		a.ID, a.Kind, a.Severity, a.AgentID, a.ActionID, a.Summary, []byte(a.Details), a.DedupKey)
	if err != nil {
		return alerts.Alert{}, err
	}
	r.got = append(r.got, a)
	return a, nil
}

func (r *txRaiser) setFail(v bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.fail = v
}
