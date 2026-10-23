package api_test

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/api"
	"fortik/internal/auth"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/events"
)

// Review finding: a failed revocation could not be retried by repeating the
// KILLED request (no-op level change skipped RevokeAll).
func TestRepeatedKillRetriesRevocation(t *testing.T) {
	e := setupP2(t, p2Options{})
	e.registerBot(t)
	sec := e.login(t, userSec)
	e.rev.mu.Lock()
	e.rev.fail = errors.New("aws unreachable")
	e.rev.mu.Unlock()
	c, out := e.do(t, sec, "PUT", "/v1/agents/bot/level", map[string]any{"level": "KILLED", "reason": "stop"}, nil)
	if c != 200 || !strings.Contains(out["revocation_error"].(string), "aws unreachable") {
		t.Fatalf("kill: %d %v", c, out)
	}
	e.rev.mu.Lock()
	e.rev.fail = nil
	e.rev.mu.Unlock()
	c, out = e.do(t, sec, "PUT", "/v1/agents/bot/level", map[string]any{"level": "KILLED", "reason": "retry revoke"}, nil)
	if c != 200 || out["changed"] != false || out["revocation_error"] != "" || out["revocation"] == nil {
		t.Fatalf("repeat kill: %d %v", c, out)
	}
	if n := len(e.rev.Calls()); n != 2 {
		t.Fatalf("repeat kill must retry revocation: %d calls", n)
	}
	if n := len(e.diaryEvents(t, diary.EventLevelChanged)); n != 1 {
		t.Fatalf("repeat kill must not record a level change: %d", n)
	}
}

// Review finding: an open event stream survived logout.
func TestEventStreamEndsAfterLogout(t *testing.T) {
	var d *diary.Diary
	var sessions *auth.Service
	e := setupWith(t, fakeExec{}, setupOpts{
		configure: func(s *api.Server, pool *pgxpool.Pool, dd *diary.Diary) {
			d = dd
			svc, err := auth.New(auth.Options{
				Config: config.AuthConfig{DevLogin: config.DevLoginConfig{Enabled: true, Users: []config.DevLoginUser{
					{Email: userSec, Roles: []string{"security", "auditor"}}}}},
				APIListen: "127.0.0.1:8080", Pool: pool, Diary: dd, Log: slog.New(slog.NewTextHandler(io.Discard, nil))})
			if err != nil {
				t.Fatal(err)
			}
			sessions, s.Sessions = svc, svc
		},
		mount: func(s *api.Server) {
			s.Mount(sessions.Routes)
			bus := events.NewMemoryBus(100)
			tailer := events.NewTailer(d, bus, slog.New(slog.NewTextHandler(io.Discard, nil)))
			s.Mount(events.NewSSE(bus, events.SSEOptions{Head: tailer.Head, Heartbeat: 50 * time.Millisecond,
				Revalidate: func(r *http.Request) error { return s.Reauthorize(r, authz.RoleAuditor) }}).Mount)
		},
	})
	p := p2env{env: e}
	b := p.login(t, userSec)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", e.srv.URL+"/v1/events/stream", nil)
	resp, err := b.c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	if resp.StatusCode != 200 {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	// Heartbeats flow while the session is valid.
	for i := 0; i < 3; i++ {
		if _, err := br.ReadString('\n'); err != nil {
			t.Fatal(err)
		}
	}
	if c, _ := p.do(t, b, "POST", "/auth/logout", nil, nil); c != 200 {
		t.Fatalf("logout: %d", c)
	}
	rest, err := io.ReadAll(br)
	if ctx.Err() != nil {
		t.Fatal("stream still open after logout")
	}
	if err != nil || !strings.Contains(string(rest), "event: unauthorized") {
		t.Fatalf("stream end: %v %q", err, rest)
	}
}
