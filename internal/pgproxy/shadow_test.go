package pgproxy

import (
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

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

func TestAuthFailuresRecordedForShadowDiscovery(t *testing.T) {
	rec := &fakeTraffic{}
	h := newHarnessOpts(t, nil, func(*harness) []Option { return []Option{WithShadow(rec)} })

	// A successful login records nothing.
	c := h.connect(pgx.QueryExecModeSimpleProtocol)
	_ = c
	if _, err := h.connectErr(testAgent, "stale-token-of-known-agent", upName, pgx.QueryExecModeSimpleProtocol); err == nil {
		t.Fatal("bad token accepted")
	}
	if _, err := h.connectErr("nightly_sync_script", "some-password", upName, pgx.QueryExecModeSimpleProtocol); err == nil {
		t.Fatal("unknown agent accepted")
	}
	evs := rec.all()
	if len(evs) != 2 {
		t.Fatalf("events: %+v", evs)
	}
	bad, unknown := evs[0], evs[1]
	if bad.Source != shadow.SourcePGProxy || bad.Kind != shadow.KindUnknownToken || bad.AgentID != testAgent ||
		bad.TokenRef != shadow.TokenRef("stale-token-of-known-agent") || bad.Host != "127.0.0.1" || bad.UserAgent != "fortik:inst-7" {
		t.Fatalf("bad-token event: %+v", bad)
	}
	if unknown.Kind != shadow.KindUnknownAgent || unknown.AgentID != "nightly_sync_script" || unknown.TokenRef != "" {
		t.Fatalf("unknown-agent event: %+v", unknown)
	}
	for _, e := range evs {
		all := e.TokenRef + e.Detail + e.UserAgent + e.Host + e.AgentID
		if strings.Contains(all, "stale-token-of-known-agent") || strings.Contains(all, "some-password") {
			t.Fatalf("password leaked into the event: %+v", e)
		}
	}
}
