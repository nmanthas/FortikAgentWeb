package queues

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"fortik/internal/integrations"
)

const hookSecret = "queue-webhook-secret-0123456789abcdef"

type hookCall struct {
	body    []byte
	sig     string
	ctype   string
	payload WebhookPayload
}

type hookServer struct {
	*httptest.Server
	mu    sync.Mutex
	calls []hookCall
	reply func(w http.ResponseWriter, p WebhookPayload)
}

func newHookServer(t *testing.T) *hookServer {
	h := &hookServer{reply: func(w http.ResponseWriter, _ WebhookPayload) { w.WriteHeader(http.StatusNoContent) }}
	h.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		c := hookCall{body: body, sig: r.Header.Get(SignatureHeader), ctype: r.Header.Get("Content-Type")}
		dec := json.NewDecoder(strings.NewReader(string(body)))
		dec.DisallowUnknownFields()
		if r.Method != http.MethodPost || dec.Decode(&c.payload) != nil || r.Header.Get(DeliveryHeader) == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		h.mu.Lock()
		h.calls = append(h.calls, c)
		reply := h.reply
		h.mu.Unlock()
		if !VerifyWebhook(hookSecret, body, c.sig) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		reply(w, c.payload)
	}))
	t.Cleanup(h.Close)
	return h
}

func (h *hookServer) last(t *testing.T) hookCall {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.calls) == 0 {
		t.Fatal("webhook not called")
	}
	return h.calls[len(h.calls)-1]
}

func (h *hookServer) setReply(f func(w http.ResponseWriter, p WebhookPayload)) {
	h.mu.Lock()
	h.reply = f
	h.mu.Unlock()
}

func TestWebhookActions(t *testing.T) {
	srv := newHookServer(t)
	src := newSource()
	src.set(t, SystemWebhook, map[string]any{"url": srv.URL + "/fortik/queue"}, map[string]string{"secret": hookSecret})
	w := NewWebhook(src)
	fixed := time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)
	w.now = func() time.Time { return fixed }
	ctx := context.Background()

	ops := map[string]func(context.Context, string, string) (Result, error){"pause": w.Pause, "resume": w.Resume, "cancel": w.Cancel}
	for action, op := range ops {
		res, err := op(ctx, "agent-7", "suspicious\nbehaviour\x00 ")
		if err != nil {
			t.Fatalf("%s: %v", action, err)
		}
		c := srv.last(t)
		if c.payload != (WebhookPayload{Action: action, AgentID: "agent-7", Reason: "suspicious behaviour", TS: "2026-10-18T12:00:00Z"}) {
			t.Errorf("%s payload: %+v", action, c.payload)
		}
		if c.ctype != "application/json" || !strings.HasPrefix(c.sig, "sha256=") || c.sig != SignWebhook(hookSecret, c.body) {
			t.Errorf("%s headers: %q %q", action, c.ctype, c.sig)
		}
		if VerifyWebhook("another-secret-0123456789", c.body, c.sig) || VerifyWebhook(hookSecret, append(c.body, ' '), c.sig) {
			t.Error("signature verification is not binding")
		}
		if res.System != SystemWebhook || res.Affected != 0 || !strings.Contains(res.Detail, "acknowledged "+action+" (HTTP 204)") || !strings.Contains(res.Detail, "up to the receiver") {
			t.Errorf("%s result: %+v", action, res)
		}
	}

	// A JSON reply with a count is reported.
	srv.setReply(func(w http.ResponseWriter, p WebhookPayload) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"affected": 4}`))
	})
	res, err := w.Cancel(ctx, "agent-7", "kill")
	if err != nil || res.Affected != 4 || !strings.Contains(res.Detail, "4 jobs affected") || !strings.Contains(res.Detail, "not reversible") {
		t.Fatalf("count reply: %+v %v", res, err)
	}

	// Non-2xx is a failed step.
	srv.setReply(func(w http.ResponseWriter, _ WebhookPayload) { w.WriteHeader(http.StatusServiceUnavailable) })
	res, err = w.Pause(ctx, "agent-7", "r")
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") || !strings.Contains(res.Detail, "did not confirm pause") {
		t.Fatalf("503: %+v %v", res, err)
	}
	// Redirects are not followed (the signed body must not go elsewhere).
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("redirect was followed")
	}))
	defer other.Close()
	srv.setReply(func(w http.ResponseWriter, _ WebhookPayload) {
		w.Header().Set("Location", other.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	})
	if _, err := w.Pause(ctx, "agent-7", "r"); err == nil || !strings.Contains(err.Error(), "HTTP 307") {
		t.Fatalf("redirect: %v", err)
	}
	// Timeout.
	release := make(chan struct{})
	srv.setReply(func(w http.ResponseWriter, _ WebhookPayload) { <-release })
	w.client.Timeout = 300 * time.Millisecond
	_, err = w.Pause(ctx, "agent-7", "r")
	close(release)
	if err == nil || !strings.Contains(err.Error(), "no reply within") {
		t.Fatalf("timeout: %v", err)
	}
	w.client.Timeout = WebhookTimeout
	// Wrong secret on Fortik's side: the receiver rejects it.
	srv.setReply(func(w http.ResponseWriter, _ WebhookPayload) { w.WriteHeader(http.StatusOK) })
	src.set(t, SystemWebhook, map[string]any{"url": srv.URL}, map[string]string{"secret": "a-different-secret-value-xyz"})
	_, err = w.Resume(ctx, "agent-7", "r")
	if err == nil || !strings.Contains(err.Error(), "HTTP 401") || strings.Contains(err.Error(), "a-different-secret-value-xyz") {
		t.Fatalf("bad signature: %v", err)
	}
	// Unreachable endpoint: failed, and the error names no secret.
	src.set(t, SystemWebhook, map[string]any{"url": "http://127.0.0.1:1/hook?x=1"}, map[string]string{"secret": hookSecret})
	_, err = w.Pause(ctx, "agent-7", "r")
	if err == nil || strings.Contains(err.Error(), hookSecret) || strings.Contains(err.Error(), "x=1") {
		t.Fatalf("unreachable: %v", err)
	}
}

func TestWebhookTesterAndRefusals(t *testing.T) {
	srv := newHookServer(t)
	src := newSource()
	w := NewWebhook(src)
	ctx := context.Background()

	if _, err := w.Pause(ctx, "agent-1", "r"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
	src.set(t, SystemWebhook, map[string]any{"url": srv.URL}, map[string]string{"secret": hookSecret})
	for _, bad := range []string{"", "-x", "a b", "a'b", strings.Repeat("a", 129)} {
		if _, err := w.Pause(ctx, bad, "r"); err == nil || errors.Is(err, ErrNotConfigured) {
			t.Errorf("agent id %q accepted", bad)
		}
	}
	r, _ := src.Get(ctx, SystemWebhook)
	if err := w.Test(ctx, r); err != nil {
		t.Fatal(err)
	}
	if c := srv.last(t); c.payload.Action != "test" || c.payload.AgentID != "" {
		t.Errorf("test payload: %+v", c.payload)
	}
	srv.setReply(func(w http.ResponseWriter, _ WebhookPayload) { w.WriteHeader(http.StatusNotFound) })
	if err := w.Test(ctx, r); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("tester 404: %v", err)
	}
	// Settings that bypassed validation are refused before sending.
	src.set(t, SystemWebhook, map[string]any{"url": "ftp://example.com/x"}, map[string]string{"secret": hookSecret})
	if _, err := w.Pause(ctx, "agent-1", "r"); err == nil || !strings.Contains(err.Error(), "not a valid http(s) URL") {
		t.Fatalf("bad scheme: %v", err)
	}
	if NewWebhook(nil).System() != SystemWebhook {
		t.Fatal("system")
	}
	if _, err := NewWebhook(nil).Cancel(ctx, "agent-1", "r"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("nil source: %v", err)
	}
}

func TestSetRegistersTesters(t *testing.T) {
	s := New(newSource(), nil)
	if len(s.Adapters()) != 3 {
		t.Fatal("adapters")
	}
	got := map[string]bool{}
	for _, a := range s.Adapters() {
		got[a.System()] = true
	}
	if !got[SystemTemporal] || !got[SystemCelery] || !got[SystemWebhook] {
		t.Fatalf("systems: %v", got)
	}
	reg := integrations.NewRegistry()
	if err := s.RegisterTesters(reg); err != nil {
		t.Fatal(err)
	}
	for sys := range got {
		if _, ok := reg.Tester(sys); !ok {
			t.Errorf("no tester for %s", sys)
		}
	}
	if err := s.RegisterTesters(reg); err == nil {
		t.Error("double registration accepted")
	}
}
