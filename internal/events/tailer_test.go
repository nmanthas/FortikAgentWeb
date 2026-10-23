package events

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"fortik/internal/authz"
	"fortik/internal/diary"
	"fortik/internal/testutil"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func appendN(t *testing.T, d *diary.Diary, n int, typ string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := d.Append(context.Background(), diary.Event{AgentID: "agent_1", EventType: typ, Actor: "test",
			Data: map[string]any{"i": i}}); err != nil {
			t.Fatal(err)
		}
	}
}

func startTailer(t *testing.T, d *diary.Diary, bus Bus) *Tailer {
	t.Helper()
	tl := NewTailer(d, bus, quietLog())
	tl.Interval = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = tl.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	select {
	case <-tl.Started():
	case <-time.After(5 * time.Second):
		t.Fatal("tailer did not start")
	}
	return tl
}

func TestTailerPublishesCommittedEntriesInOrderFromHead(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	appendN(t, d, 3, "history.before_boot") // must not be re-published at boot
	bus := NewMemoryBus(0)
	tl := startTailer(t, d, bus)
	if tl.Last() != 3 {
		t.Fatalf("tailer should start at head 3, got %d", tl.Last())
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sub, _ := bus.Subscribe(ctx, 0)
	// Consume concurrently: a subscriber that falls behind is dropped by design.
	ch := make(chan Event, 1000)
	go func() {
		for e := range sub {
			ch <- e
		}
	}()
	appendN(t, d, 700, "agent.level_changed") // > one poll batch
	for want := int64(4); want <= 703; want++ {
		e := recv(t, ch)
		if e.Seq != want {
			t.Fatalf("got seq %d want %d", e.Seq, want)
		}
		if e.EventType != "agent.level_changed" || e.AgentID != "agent_1" {
			t.Fatalf("bad event %+v", e)
		}
		var data map[string]any
		if err := json.Unmarshal(e.Data, &data); err != nil || data["i"] == nil {
			t.Fatalf("data not carried: %s", e.Data)
		}
	}
	// Backfill serves history straight from the Diary.
	hist, err := tl.Backfill(context.Background(), 0, 3, 100)
	if err != nil || len(hist) != 3 || hist[0].Seq != 1 || hist[2].EventType != "history.before_boot" {
		t.Fatalf("backfill: %v %+v", err, hist)
	}
}

// A rolled-back transaction's entry is never published (outbox semantics).
func TestTailerNeverPublishesUncommitted(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	bus := NewMemoryBus(0)
	startTailer(t, d, bus)
	ctx := context.Background()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.AppendTx(ctx, tx, diary.Event{EventType: "rolled.back", Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	_ = tx.Rollback(ctx)
	appendN(t, d, 1, "committed")
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, _ := bus.Subscribe(sctx, 0)
	e := recv(t, ch)
	if e.EventType != "committed" || e.Seq != 1 {
		t.Fatalf("only the committed entry may be published, got %+v", e)
	}
}

// --- SSE end to end ----------------------------------------------------------

func withPrincipal(p *authz.Principal, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if p != nil {
			r = r.WithContext(authz.With(r.Context(), *p))
		}
		h.ServeHTTP(w, r)
	})
}

type sseEvent struct {
	name, id, data string
	comment        bool
}

func readSSE(t *testing.T, br *bufio.Reader) sseEvent {
	t.Helper()
	var e sseEvent
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			t.Fatalf("read sse: %v", err)
		}
		line = strings.TrimRight(line, "\n")
		switch {
		case line == "":
			if e.name != "" || e.comment {
				return e
			}
		case strings.HasPrefix(line, ":"):
			e.comment = true
		case strings.HasPrefix(line, "event: "):
			e.name = line[7:]
		case strings.HasPrefix(line, "id: "):
			e.id = line[4:]
		case strings.HasPrefix(line, "data: "):
			e.data = line[6:]
		}
	}
}

func nextDiary(t *testing.T, br *bufio.Reader) Event {
	t.Helper()
	for {
		e := readSSE(t, br)
		if e.name != "diary" {
			continue
		}
		var out Event
		if err := json.Unmarshal([]byte(e.data), &out); err != nil {
			t.Fatal(err)
		}
		if e.id != strconv.FormatInt(out.Seq, 10) {
			t.Fatalf("id %q != seq %d", e.id, out.Seq)
		}
		return out
	}
}

func openStream(t *testing.T, url, lastID string) (*http.Response, *bufio.Reader) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if lastID != "" {
		req.Header.Set("Last-Event-ID", lastID)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp, bufio.NewReader(resp.Body)
}

func TestSSEEndToEnd(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	appendN(t, d, 5, "old.event")
	bus := NewMemoryBus(3) // tiny ring: forces Diary backfill on resume
	tl := startTailer(t, d, bus)
	h := NewSSE(bus, SSEOptions{Heartbeat: 50 * time.Millisecond, Head: tl.Head, Backfill: tl.Backfill, Log: quietLog()})

	auditor := &authz.Principal{Kind: authz.KindToken, Name: "aud", Roles: map[string]bool{authz.RoleAuditor: true}}
	interceptor := &authz.Principal{Kind: authz.KindToken, Name: "px", Roles: map[string]bool{authz.RoleInterceptor: true}}
	for _, c := range []struct {
		p    *authz.Principal
		code int
	}{{nil, 401}, {interceptor, 403}} {
		srv := httptest.NewServer(withPrincipal(c.p, h))
		resp, err := http.Get(srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		srv.Close()
		if resp.StatusCode != c.code {
			t.Fatalf("want %d got %d", c.code, resp.StatusCode)
		}
	}

	srv := httptest.NewServer(withPrincipal(auditor, h))
	t.Cleanup(srv.Close) // runs after the stream bodies (registered later) are closed

	// New client: live only (starts at head 5), heartbeats flow.
	resp, br := openStream(t, srv.URL, "")
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream: %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if e := readSSE(t, br); !e.comment && e.name == "" {
		t.Fatal("expected retry/heartbeat preamble")
	}
	appendN(t, d, 2, "agent.level_changed")
	if e := nextDiary(t, br); e.Seq != 6 || e.EventType != "agent.level_changed" {
		t.Fatalf("live: %+v", e)
	}
	if e := nextDiary(t, br); e.Seq != 7 {
		t.Fatalf("live: %+v", e)
	}
	gotHB := false
	for i := 0; i < 5 && !gotHB; i++ {
		gotHB = readSSE(t, br).comment
	}
	if !gotHB {
		t.Fatal("no heartbeat")
	}
	resp.Body.Close()

	// Resume from seq 2: 3..7 must arrive in order although the ring only
	// holds 5..7 (3 and 4 come from the Diary), then live 8.
	_, br = openStream(t, srv.URL, "2")
	for want := int64(3); want <= 7; want++ {
		if e := nextDiary(t, br); e.Seq != want {
			t.Fatalf("resume: got %d want %d", e.Seq, want)
		}
	}
	appendN(t, d, 1, "after.resume")
	if e := nextDiary(t, br); e.Seq != 8 || e.EventType != "after.resume" {
		t.Fatalf("live after resume: %+v", e)
	}

	// Bad Last-Event-ID is rejected.
	resp, _ = openStream(t, srv.URL, "abc")
	if resp.StatusCode != 400 {
		t.Fatalf("bad Last-Event-ID: %d", resp.StatusCode)
	}
}

// A client that stops reading is dropped by the bus; the handler ends the
// response instead of blocking the publisher.
func TestSSESlowClientIsDropped(t *testing.T) {
	bus := NewMemoryBus(0)
	h := NewSSE(bus, SSEOptions{Heartbeat: time.Hour, WriteTimeout: 200 * time.Millisecond, Log: quietLog()})
	auditor := &authz.Principal{Kind: authz.KindToken, Name: "aud", Roles: map[string]bool{authz.RoleAuditor: true}}
	served := make(chan struct{})
	srv := httptest.NewServer(withPrincipal(auditor, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.ServeHTTP(w, r)
		close(served)
	})))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close() // never read: the client is "slow"
	big := json.RawMessage(`{"pad":"` + strings.Repeat("x", 64<<10) + `"}`)
	start := time.Now()
	for i := int64(1); i <= 2000; i++ {
		_ = bus.Publish(context.Background(), Event{Seq: i, EventType: "x", Data: big})
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("publisher was blocked by a slow SSE client")
	}
	select {
	case <-served:
	case <-time.After(10 * time.Second):
		t.Fatal("slow client was not dropped")
	}
}
