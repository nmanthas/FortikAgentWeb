package notify_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/integrations"
	"fortik/internal/notify"
	"fortik/internal/testutil"
)

var bg = context.Background()

// src is a fixed notify_slack integration (or none).
type src struct{ r *integrations.Resolved }

func (s src) Get(_ context.Context, key string) (integrations.Resolved, error) {
	if s.r == nil || key != notify.System {
		return integrations.Resolved{}, integrations.ErrNotConfigured
	}
	return *s.r, nil
}
func (s src) List(context.Context, string) ([]integrations.Resolved, error) { return nil, nil }

type hook struct {
	mu    sync.Mutex
	texts []string
	fail  bool
}

func (h *hook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var m map[string]string
	b, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(b, &m)
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.fail {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	h.texts = append(h.texts, m["text"])
}

func (h *hook) all() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.texts...)
}

func resolved(url string, since time.Time, cfg map[string]any) *integrations.Resolved {
	return &integrations.Resolved{Integration: integrations.Integration{Key: notify.System, System: notify.System, UpdatedAt: since},
		ConfigMap: cfg, Secrets: map[string]string{"webhook_url": url}}
}

func TestNotifyOwnerOnceFiltersAndRetries(t *testing.T) {
	pool, _ := testutil.FortikDB(t)
	h := &hook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	exec := func(q string, a ...any) {
		t.Helper()
		if _, err := pool.Exec(bg, q, a...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO agents (agent_id, name, sponsor) VALUES ('code_agent_12', 'Coder', 'jane.smith@acme.test') ON CONFLICT (agent_id) DO UPDATE SET sponsor = EXCLUDED.sponsor`)
	since := time.Now().Add(-time.Minute)
	alert := func(id, kind, sev, at string) {
		exec(`INSERT INTO alerts (alert_id, kind, severity, agent_id, summary, created_at) VALUES ($1, $2, $3, 'code_agent_12', $4, now() + $5::interval)`,
			id, kind, sev, "summary of "+id, at)
	}
	alert("alt_old", "override_restored", "info", "-1 hour") // before the integration was configured: never sent
	alert("alt_restored", "override_restored", "info", "0 seconds")
	alert("alt_bypass", "delegation_bypass", "high", "1 second")

	// Not configured: nothing happens.
	if n, err := notify.NewWorker(pool, src{}, 0, nil).Pass(bg); err != nil || n != 0 {
		t.Fatalf("unconfigured: %d %v", n, err)
	}
	w := notify.NewWorker(pool, src{resolved(srv.URL+"/hook", since, map[string]any{"min_severity": "info", "console_url": "https://fortik.example"})}, 0, nil)
	if n, err := w.Pass(bg); err != nil || n != 2 {
		t.Fatalf("first pass: %d %v", n, err)
	}
	got := h.all()
	if len(got) != 2 || !strings.Contains(got[0], "override_restored") || !strings.Contains(got[0], "Owner: jane.smith@acme.test") ||
		!strings.Contains(got[0], "https://fortik.example/agents/code_agent_12") || !strings.Contains(got[1], "HIGH") {
		t.Fatalf("messages: %q", got)
	}
	// Sent once only.
	if n, _ := w.Pass(bg); n != 0 || len(h.all()) != 2 {
		t.Fatal("an alert was sent twice")
	}
	var oldStatus *string
	_ = pool.QueryRow(bg, `SELECT notify_status FROM alerts WHERE alert_id = 'alt_old'`).Scan(&oldStatus)
	if oldStatus != nil {
		t.Fatalf("history was sent: %v", *oldStatus)
	}

	// Severity and kind filters.
	alert("alt_info2", "override_restored", "info", "2 seconds")
	alert("alt_swarm", "swarm_detected", "critical", "3 seconds")
	alert("alt_spawn", "spawn_spike", "critical", "4 seconds")
	w = notify.NewWorker(pool, src{resolved(srv.URL+"/hook", since, map[string]any{"min_severity": "high", "kinds": []any{"swarm_detected"}})}, 0, nil)
	if n, _ := w.Pass(bg); n != 1 || !strings.Contains(h.all()[2], "swarm_detected") {
		t.Fatalf("filters: %d %q", n, h.all())
	}

	// A failing endpoint is retried, then given up and recorded.
	h.mu.Lock()
	h.fail = true
	h.mu.Unlock()
	alert("alt_fail", "shadow_agent", "high", "5 seconds")
	w = notify.NewWorker(pool, src{resolved(srv.URL+"/hook", since, nil)}, 0, nil)
	for i := 0; i < 3; i++ {
		_, _ = w.Pass(bg)
	}
	var status string
	var notified *time.Time
	if err := pool.QueryRow(bg, `SELECT notify_status, notified_at FROM alerts WHERE alert_id = 'alt_fail'`).Scan(&status, &notified); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(status, "failed: ") || notified == nil || strings.Contains(status, "/hook") {
		t.Fatalf("after 3 failures: %q %v (the webhook URL must not appear)", status, notified)
	}
}

func TestNotifyTestConnection(t *testing.T) {
	h := &hook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	w := notify.NewWorker(nil, src{}, 0, nil)
	if err := w.Test(bg, *resolved(srv.URL, time.Now(), nil)); err != nil || len(h.all()) != 1 || !strings.Contains(h.all()[0], "connection test") {
		t.Fatalf("test: %v %q", err, h.all())
	}
	if err := w.Test(bg, *resolved("", time.Now(), nil)); err == nil {
		t.Fatal("no webhook URL must fail")
	}
}
