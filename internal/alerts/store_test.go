package alerts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

type fixture struct {
	pool  *pgxpool.Pool
	d     *diary.Diary
	store *alerts.PGStore
}

func setup(t *testing.T) fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	return fixture{pool: pool, d: d, store: alerts.NewPGStore(pool, d)}
}

func (f fixture) events(t *testing.T, ev string) []map[string]any {
	t.Helper()
	rows, err := f.pool.Query(context.Background(), `SELECT body_json FROM diary WHERE event_type = $1 ORDER BY seq`, ev)
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

func spike(detail int) alerts.Alert {
	return alerts.Alert{
		Kind: alerts.KindSpawnSpike, Severity: alerts.SevWarning, AgentID: "coder_1", AgentType: "coding",
		Summary: fmt.Sprintf("spawn spike %d", detail), Details: json.RawMessage(fmt.Sprintf(`{"spawns":%d}`, detail)),
		DedupKey: "spawn_spike:type:coding",
	}
}

func TestRaiseDedupAndDiary(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	a1, err := f.store.Raise(ctx, spike(1))
	if err != nil {
		t.Fatal(err)
	}
	if a1.ID == "" || a1.Count != 1 || a1.Status != alerts.StatusOpen || a1.Severity != alerts.SevWarning {
		t.Fatalf("first: %+v", a1)
	}
	// Same open key: bumped, not inserted; severity only escalates.
	high := spike(2)
	high.Severity = alerts.SevHigh
	a2, err := f.store.Raise(ctx, high)
	if err != nil {
		t.Fatal(err)
	}
	a3, err := f.store.Raise(ctx, spike(3))
	if err != nil {
		t.Fatal(err)
	}
	if a3.ID != a1.ID || a2.ID != a1.ID || a3.Count != 3 || a3.Severity != alerts.SevHigh || a3.Summary != "spawn spike 3" ||
		!a3.UpdatedAt.After(a1.CreatedAt) && !a3.UpdatedAt.Equal(a1.CreatedAt) {
		t.Fatalf("bumped: %+v", a3)
	}
	var n int
	if err := f.pool.QueryRow(ctx, `SELECT count(*) FROM alerts`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows %d %v", n, err)
	}
	if ev := f.events(t, alerts.EventRaised); len(ev) != 1 || ev[0]["alert_id"] != a1.ID || ev[0]["kind"] != "spawn_spike" {
		t.Fatalf("alert.raised: %v", ev)
	}
	if ev := f.events(t, alerts.EventRepeated); len(ev) != 2 || ev[1]["count"] != float64(3) {
		t.Fatalf("alert.repeated: %v", ev)
	}
	// Without a dedup key every raise is a new alert.
	plain := spike(4)
	plain.DedupKey = ""
	b1, _ := f.store.Raise(ctx, plain)
	b2, _ := f.store.Raise(ctx, plain)
	if b1.ID == b2.ID || b1.ID == "" {
		t.Fatalf("no dedup key: %s %s", b1.ID, b2.ID)
	}
	// Once acknowledged, the same key opens a new alert.
	if _, err := f.store.Ack(ctx, a1.ID, "user:sec@acme.com", "looking"); err != nil {
		t.Fatal(err)
	}
	c, err := f.store.Raise(ctx, spike(5))
	if err != nil || c.ID == a1.ID || c.Count != 1 {
		t.Fatalf("after ack: %+v %v", c, err)
	}
	if res, err := f.d.VerifyChain(ctx); err != nil || !res.OK {
		t.Fatalf("diary: %+v %v", res, err)
	}
}

func TestDedupWindow(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var now atomic.Int64
	now.Store(time.Now().UnixNano())
	f.store.Now = func() time.Time { return time.Unix(0, now.Load()) }
	f.store.DedupWindow = 10 * time.Minute
	a1, _ := f.store.Raise(ctx, spike(1))
	now.Add(int64(9 * time.Minute))
	a2, _ := f.store.Raise(ctx, spike(2)) // bumps (and refreshes the window)
	now.Add(int64(9 * time.Minute))
	a3, _ := f.store.Raise(ctx, spike(3))
	if a2.ID != a1.ID || a3.ID != a1.ID || a3.Count != 3 {
		t.Fatalf("within window: %+v", a3)
	}
	// 11 minutes of silence: the old alert is resolved by the system and a
	// new incident opens.
	now.Add(int64(11 * time.Minute))
	a4, err := f.store.Raise(ctx, spike(4))
	if err != nil || a4.ID == a1.ID || a4.Count != 1 {
		t.Fatalf("after window: %+v %v", a4, err)
	}
	old, err := f.store.Get(ctx, a1.ID)
	if err != nil || old.Status != alerts.StatusResolved || old.AckedBy != "system:alerts" {
		t.Fatalf("superseded: %+v %v", old, err)
	}
	if ev := f.events(t, alerts.EventResolved); len(ev) != 1 || ev[0]["alert_id"] != a1.ID {
		t.Fatalf("alert.resolved: %v", ev)
	}
}

// Concurrent raises of one key end as one alert whose count is exact.
func TestConcurrentRaiseOneAlert(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := f.store.Raise(ctx, spike(i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	list, err := f.store.List(ctx, alerts.Filter{Kind: alerts.KindSpawnSpike})
	if err != nil || len(list) != 1 || list[0].Count != 25 {
		t.Fatalf("list: %+v %v", list, err)
	}
}

// RaiseTx commits or rolls back with the caller's transaction.
func TestRaiseTxRollsBackWithCaller(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	boom := errors.New("decision failed")
	err := pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		if _, err := f.store.RaiseTx(ctx, tx, spike(1)); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	var n int
	_ = f.pool.QueryRow(ctx, `SELECT count(*) FROM alerts`).Scan(&n)
	if n != 0 || len(f.events(t, alerts.EventRaised)) != 0 {
		t.Fatalf("rolled-back alert persisted: %d", n)
	}
	err = pgx.BeginFunc(ctx, f.pool, func(tx pgx.Tx) error {
		_, err := f.store.RaiseTx(ctx, tx, spike(2))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.events(t, alerts.EventRaised)) != 1 {
		t.Fatal("committed alert has no alert.raised")
	}
}

func TestRaiseValidation(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	bad := []func(*alerts.Alert){
		func(a *alerts.Alert) { a.Kind = "Spawn Spike" },
		func(a *alerts.Alert) { a.Kind = "" },
		func(a *alerts.Alert) { a.Severity = "urgent" },
		func(a *alerts.Alert) { a.Summary = " \x00\x01 " },
		func(a *alerts.Alert) { a.Details = json.RawMessage(`[1,2]`) },
		func(a *alerts.Alert) { a.Details = json.RawMessage(`{bad`) },
		func(a *alerts.Alert) { a.Details = json.RawMessage(`{"x":"` + strings.Repeat("a", 17<<10) + `"}`) },
		func(a *alerts.Alert) { a.AgentID = strings.Repeat("a", 200) },
		func(a *alerts.Alert) { a.DedupKey = "k\x00" },
	}
	for i, mut := range bad {
		a := spike(1)
		mut(&a)
		if _, err := f.store.Raise(ctx, a); !errors.Is(err, alerts.ErrInvalid) {
			t.Fatalf("case %d: %v", i, err)
		}
	}
	// Summaries are cleaned and bounded; null details become {}.
	a := spike(1)
	a.Summary = "line1\nline2\x07 " + strings.Repeat("x", 600)
	a.Details = nil
	a.DedupKey = ""
	got, err := f.store.Raise(ctx, a)
	if err != nil || strings.ContainsAny(got.Summary, "\n\x07") || len([]rune(got.Summary)) > 500 || string(got.Details) != "{}" {
		t.Fatalf("cleaned: %q %s %v", got.Summary, got.Details, err)
	}
}

func TestListAckResolve(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	s1, _ := f.store.Raise(ctx, spike(1))
	rl, _ := f.store.Raise(ctx, alerts.Alert{Kind: alerts.KindRateLimited, Severity: alerts.SevWarning, AgentID: "chatty", Summary: "rate", DedupKey: "rate_limited:agent:chatty"})
	if list, _ := f.store.List(ctx, alerts.Filter{}); len(list) != 2 || list[0].ID != rl.ID {
		t.Fatalf("newest first: %+v", list)
	}
	if list, _ := f.store.List(ctx, alerts.Filter{AgentID: "chatty"}); len(list) != 1 || list[0].ID != rl.ID {
		t.Fatalf("by agent: %+v", list)
	}
	if list, _ := f.store.List(ctx, alerts.Filter{Kind: alerts.KindSpawnSpike, Limit: 1}); len(list) != 1 || list[0].ID != s1.ID {
		t.Fatalf("by kind: %+v", list)
	}
	acked, err := f.store.Ack(ctx, s1.ID, "user:sec@acme.com", "on it")
	if err != nil || acked.Status != alerts.StatusAcknowledged || acked.AckedBy != "user:sec@acme.com" {
		t.Fatalf("ack: %+v %v", acked, err)
	}
	if _, err := f.store.Ack(ctx, s1.ID, "user:sec@acme.com", ""); !errors.Is(err, alerts.ErrState) {
		t.Fatalf("double ack: %v", err)
	}
	res, err := f.store.Resolve(ctx, s1.ID, "user:other@acme.com", "fixed")
	if err != nil || res.Status != alerts.StatusResolved || res.AckedBy != "user:sec@acme.com" {
		t.Fatalf("resolve: %+v %v", res, err)
	}
	if _, err := f.store.Resolve(ctx, s1.ID, "user:sec@acme.com", ""); !errors.Is(err, alerts.ErrState) {
		t.Fatalf("resolve resolved: %v", err)
	}
	if _, err := f.store.Resolve(ctx, rl.ID, "user:sec@acme.com", ""); err != nil {
		t.Fatalf("resolve open: %v", err)
	}
	if _, err := f.store.Ack(ctx, "alr_nope", "user:sec@acme.com", ""); !errors.Is(err, alerts.ErrNotFound) {
		t.Fatalf("missing: %v", err)
	}
	if list, _ := f.store.List(ctx, alerts.Filter{Status: alerts.StatusOpen}); len(list) != 0 {
		t.Fatalf("open: %+v", list)
	}
	ack := f.events(t, alerts.EventAcknowledged)
	resolved := f.events(t, alerts.EventResolved)
	if len(ack) != 1 || ack[0]["note"] != "on it" || len(resolved) != 2 || resolved[0]["previous_status"] != "acknowledged" {
		t.Fatalf("diary: %v %v", ack, resolved)
	}
}

func userP(email string, roles ...string) authz.Principal {
	p := authz.Principal{Kind: authz.KindUser, Name: email, Email: email, Roles: map[string]bool{}}
	for _, r := range roles {
		p.Roles[r] = true
	}
	return p
}

func call(t *testing.T, h http.Handler, p *authz.Principal, method, path, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if p != nil {
		req = req.WithContext(authz.With(req.Context(), *p))
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("%s %s: %q", method, path, rec.Body.String())
	}
	return rec.Code, out
}

func TestHandler(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	mux := http.NewServeMux()
	alerts.NewHandler(f.store, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	a, _ := f.store.Raise(ctx, spike(1))
	sec, aud, nobody := userP("sec@acme.com", authz.RoleSecurity), userP("aud@acme.com", authz.RoleAuditor), userP("dev@acme.com")

	if code, _ := call(t, mux, nil, "GET", "/v1/alerts", ""); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	if code, _ := call(t, mux, &nobody, "GET", "/v1/alerts", ""); code != http.StatusForbidden {
		t.Fatalf("no role: %d", code)
	}
	code, body := call(t, mux, &aud, "GET", "/v1/alerts?status=open&kind=spawn_spike&agent_id=coder_1&limit=10", "")
	if code != http.StatusOK || len(body["alerts"].([]any)) != 1 {
		t.Fatalf("list: %d %v", code, body)
	}
	for _, q := range []string{"status=closed", "kind=Bad%20Kind", "agent_id=a%20b", "limit=0", "limit=x", "limit=1001"} {
		if code, _ := call(t, mux, &aud, "GET", "/v1/alerts?"+q, ""); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", q, code)
		}
	}
	if code, body := call(t, mux, &aud, "GET", "/v1/alerts/"+a.ID, ""); code != http.StatusOK || body["alert_id"] != a.ID {
		t.Fatalf("get: %d %v", code, body)
	}
	if code, _ := call(t, mux, &aud, "GET", "/v1/alerts/alr_missing", ""); code != http.StatusNotFound {
		t.Fatalf("get missing: %d", code)
	}
	// Ack/resolve need security; strict JSON; optional body.
	if code, _ := call(t, mux, &aud, "POST", "/v1/alerts/"+a.ID+"/ack", ""); code != http.StatusForbidden {
		t.Fatalf("auditor ack: %d", code)
	}
	if code, _ := call(t, mux, &sec, "POST", "/v1/alerts/"+a.ID+"/ack", `{"note":"x","extra":1}`); code != http.StatusBadRequest {
		t.Fatalf("unknown field: %d", code)
	}
	if code, body := call(t, mux, &sec, "POST", "/v1/alerts/"+a.ID+"/ack", `{"note":"investigating"}`); code != http.StatusOK || body["status"] != "acknowledged" || body["acked_by"] != "user:sec@acme.com" {
		t.Fatalf("ack: %d %v", code, body)
	}
	if code, _ := call(t, mux, &sec, "POST", "/v1/alerts/"+a.ID+"/ack", ""); code != http.StatusConflict {
		t.Fatalf("re-ack: %d", code)
	}
	if code, body := call(t, mux, &sec, "POST", "/v1/alerts/"+a.ID+"/resolve", ""); code != http.StatusOK || body["status"] != "resolved" {
		t.Fatalf("resolve: %d %v", code, body)
	}
	if code, _ := call(t, mux, &sec, "POST", "/v1/alerts/alr_missing/resolve", ""); code != http.StatusNotFound {
		t.Fatalf("resolve missing: %d", code)
	}
	if ev := f.events(t, alerts.EventAcknowledged); len(ev) != 1 {
		t.Fatalf("alert.acknowledged: %v", ev)
	}
}
