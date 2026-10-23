package gateway

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"fortik/internal/config"
	"fortik/internal/policy"
	"fortik/internal/shadow"
)

type fakeTraffic struct {
	mu     sync.Mutex
	events []shadow.TrafficEvent
}

func (f *fakeTraffic) RecordTraffic(ev shadow.TrafficEvent) {
	f.mu.Lock()
	f.events = append(f.events, ev)
	f.mu.Unlock()
}

func (f *fakeTraffic) all() []shadow.TrafficEvent {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]shadow.TrafficEvent(nil), f.events...)
}

func TestServerRecordsUnknownTokensForShadowDiscovery(t *testing.T) {
	h := newHarness(t, policy.Allow)
	rec := &fakeTraffic{}
	srv, err := NewServer(config.GatewayConfig{MaxBodyBytes: 1024}, h.dec, NewAgentAuth(h.sec, "", quietLog()), []Adapter{h.ad}, quietLog(), WithShadow(rec))
	if err != nil {
		t.Fatal(err)
	}
	do := func(path, auth, ua string) int {
		r := httptest.NewRequest("GET", path, nil)
		r.RemoteAddr = "10.1.2.3:5555"
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		if ua != "" {
			r.Header.Set("User-Agent", ua)
		}
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		return w.Code
	}
	const stale = "agt_stale_script_token_123"
	if c := do("/gw/fake/thing/x?q=1", "Bearer "+stale, "python-requests/2.31"); c != http.StatusUnauthorized {
		t.Fatalf("unknown token: %d", c)
	}
	// Not findings: no credentials, malformed scheme, a valid token.
	for _, a := range []string{"", "Basic abc", "Bearer ", "Bearer a b"} {
		if c := do("/gw/fake/thing", a, ""); c != http.StatusUnauthorized {
			t.Fatalf("auth %q: %d", a, c)
		}
	}
	if c := do("/gw/fake/thing", "Bearer "+goodToken, ""); c == http.StatusUnauthorized {
		t.Fatal("valid token refused")
	}
	if c := do("/v1/hook/claude-code", "Bearer "+stale, "fortik-hook"); c != http.StatusUnauthorized {
		t.Fatalf("hook path: %d", c)
	}
	evs := rec.all()
	if len(evs) != 2 {
		t.Fatalf("want 2 recorded events, got %+v", evs)
	}
	ev := evs[0]
	if ev.Source != shadow.SourceGateway || ev.Kind != shadow.KindUnknownToken || ev.TokenRef != shadow.TokenRef(stale) ||
		ev.Host != "10.1.2.3" || ev.UserAgent != "python-requests/2.31" || ev.Detail != "path=/gw/fake" {
		t.Fatalf("event: %+v", ev)
	}
	if evs[1].Source != shadow.SourceHook {
		t.Fatalf("hook path source: %+v", evs[1])
	}
	for _, e := range evs {
		if strings.Contains(e.TokenRef+e.Detail+e.UserAgent+e.Host+e.AgentID, stale) {
			t.Fatalf("token leaked into the event: %+v", e)
		}
	}
	// Without a recorder nothing breaks.
	if w := h.do(t, "GET", "/gw/fake/thing", "agt_nope", nil); w.Code != http.StatusUnauthorized {
		t.Fatalf("no recorder: %d", w.Code)
	}
}
