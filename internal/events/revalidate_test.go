package events

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fortik/internal/authz"
)

// An open stream must end once the caller is no longer authorized
// (logout, session expiry, role removal).
func TestSSEClosesWhenRevalidationFails(t *testing.T) {
	var calls atomic.Int32
	h := NewSSE(NewMemoryBus(8), SSEOptions{Heartbeat: 20 * time.Millisecond, Log: quietLog(),
		Revalidate: func(*http.Request) error {
			if calls.Add(1) >= 3 {
				return errors.New("session revoked")
			}
			return nil
		}})
	auditor := &authz.Principal{Kind: authz.KindToken, Name: "aud", Roles: map[string]bool{authz.RoleAuditor: true}}
	srv := httptest.NewServer(withPrincipal(auditor, h))
	defer srv.Close()
	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	done := make(chan string, 1)
	go func() { b, _ := io.ReadAll(resp.Body); done <- string(b) }()
	select {
	case body := <-done:
		if !strings.Contains(body, "event: unauthorized") || calls.Load() != 3 {
			t.Fatalf("calls=%d body=%q", calls.Load(), body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stream kept running after the caller lost authorization")
	}
}
