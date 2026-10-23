package hook

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"fortik/internal/config"
	"fortik/internal/decide"
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

func TestHandlerRecordsUnauthenticatedTokens(t *testing.T) {
	rec := &fakeTraffic{}
	h, err := NewHandler(config.HookConfig{}, &decide.Service{}, nil, nil, WithShadow(rec))
	if err != nil {
		t.Fatal(err)
	}
	for _, auth := range []string{"Bearer stale-hook-token-1", "", "Basic x"} {
		r := httptest.NewRequest("POST", "/v1/hook/claude-code", strings.NewReader(`{}`))
		r.RemoteAddr = "192.0.2.9:4000"
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("%q: %d", auth, w.Code)
		}
	}
	if len(rec.events) != 1 {
		t.Fatalf("events: %+v", rec.events)
	}
	ev := rec.events[0]
	if ev.Source != shadow.SourceHook || ev.Kind != shadow.KindUnknownToken || ev.TokenRef != shadow.TokenRef("stale-hook-token-1") || ev.Host != "192.0.2.9" {
		t.Fatalf("event: %+v", ev)
	}
}
