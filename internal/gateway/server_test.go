package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
	"fortik/internal/policy"
)

// fakeDecider records actions and answers with a fixed result.
type fakeDecider struct {
	mu     sync.Mutex
	seen   []action.Action
	result policy.Result
	err    error
}

func (d *fakeDecider) Decide(_ context.Context, a action.Action) (decide.Outcome, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, a)
	if d.err != nil {
		return decide.Outcome{}, d.err
	}
	return decide.Outcome{Action: a, Result: d.result, Held: d.result.Decision == policy.Hold}, nil
}

func (d *fakeDecider) last(t *testing.T) action.Action {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.seen) == 0 {
		t.Fatal("Decide was not called")
	}
	return d.seen[len(d.seen)-1]
}

// fakeAdapter is a gateway.Adapter whose behaviour each test sets.
type fakeAdapter struct {
	mapErr     error
	enrichErr  error
	forwardErr error
	forwarded  int
	mapped     action.Action
}

func (f *fakeAdapter) Prefix() string { return "fake" }

func (f *fakeAdapter) Map(_ context.Context, _ authz.Principal, _ *http.Request, body []byte) (Op, error) {
	if f.mapErr != nil {
		return Op{}, f.mapErr
	}
	a := f.mapped
	if a.System == "" {
		a = action.Action{System: "gmail", Verb: action.VerbRead, Target: map[string]any{"endpoint": "x"},
			AgentID: "spoofed_agent", ActionID: "act_spoofed", Source: "api"}
	}
	return Op{Action: a, Body: body}, nil
}

func (f *fakeAdapter) Enrich(context.Context, authz.Principal, *Op) error { return f.enrichErr }

func (f *fakeAdapter) Forward(_ context.Context, _ authz.Principal, _ *Op, _ decide.Outcome, w http.ResponseWriter, _ *http.Request) error {
	f.forwarded++
	if f.forwardErr != nil {
		return f.forwardErr
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]string{"ok": "forwarded"})
	return nil
}

type harness struct {
	srv *Server
	dec *fakeDecider
	ad  *fakeAdapter
	sec *memSecrets
}

const goodToken = "agt_test_token"

func newHarness(t *testing.T, decision policy.Decision) harness {
	t.Helper()
	sec := &memSecrets{}
	sec.set("agent_tokens", `{"agent_a":"`+hashOf(goodToken)+`"}`)
	dec := &fakeDecider{result: policy.Result{Class: policy.Green, Decision: decision, RuleID: "POL-TEST", Reason: "test reason"}}
	if decision == policy.Deny || decision == policy.Hold {
		dec.result.Class = policy.Red
	}
	ad := &fakeAdapter{}
	srv, err := NewServer(config.GatewayConfig{MaxBodyBytes: 1024}, dec, NewAgentAuth(sec, "", quietLog()), []Adapter{ad}, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	return harness{srv: srv, dec: dec, ad: ad, sec: sec}
}

func (h harness) do(t *testing.T, method, path, token string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	return w
}

type errBody struct {
	Error struct {
		Code     string `json:"code"`
		Decision string `json:"decision"`
		Class    string `json:"class"`
		RuleID   string `json:"rule_id"`
		Reason   string `json:"reason"`
		ActionID string `json:"action_id"`
		Held     bool   `json:"held"`
		System   string `json:"system"`
	} `json:"error"`
}

func decodeErr(t *testing.T, w *httptest.ResponseRecorder) errBody {
	t.Helper()
	var b errBody
	if err := json.Unmarshal(w.Body.Bytes(), &b); err != nil {
		t.Fatalf("body %q: %v", w.Body.String(), err)
	}
	return b
}

func TestServerRequiresAgentToken(t *testing.T) {
	h := newHarness(t, policy.Allow)
	for _, tok := range []string{"", "agt_wrong"} {
		w := h.do(t, "GET", "/gw/fake/thing", tok, nil)
		if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") == "" {
			t.Fatalf("token %q: code %d", tok, w.Code)
		}
	}
	if len(h.dec.seen) != 0 || h.ad.forwarded != 0 {
		t.Fatal("unauthenticated request reached Decide or the adapter")
	}
	if w := h.do(t, "GET", "/healthz", "", nil); w.Code != 200 {
		t.Fatalf("healthz: %d", w.Code)
	}
}

func TestServerAuthUnavailable503(t *testing.T) {
	h := newHarness(t, policy.Allow)
	h.sec.setFail(errors.New("down"))
	srv, _ := NewServer(config.GatewayConfig{}, h.dec, NewAgentAuth(h.sec, "", quietLog()), []Adapter{h.ad}, quietLog())
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/gw/fake/x", nil)
	r.Header.Set("Authorization", "Bearer "+goodToken)
	srv.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", w.Code)
	}
}

func TestServerAllowForwardsWithServerOwnedFields(t *testing.T) {
	h := newHarness(t, policy.Allow)
	r := httptest.NewRequest("POST", "/gw/fake/thing", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer "+goodToken)
	r.Header.Set(InstanceHeader, "inst-7")
	w := httptest.NewRecorder()
	h.srv.ServeHTTP(w, r)
	if w.Code != 200 || h.ad.forwarded != 1 {
		t.Fatalf("code %d forwarded %d: %s", w.Code, h.ad.forwarded, w.Body)
	}
	a := h.dec.last(t)
	if a.AgentID != "agent_a" || a.InstanceID != "inst-7" || a.Source != action.SourceAppGateway || a.ActionID == "act_spoofed" || a.ActionID == "" {
		t.Fatalf("server-owned fields not enforced: %+v", a)
	}
	if got := w.Header().Get(ActionIDHeader); got != a.ActionID {
		t.Fatalf("X-Fortik-Action-Id %q, want %q", got, a.ActionID)
	}
}

func TestServerRefusalShape(t *testing.T) {
	for _, d := range []policy.Decision{policy.Deny, policy.Hold} {
		h := newHarness(t, d)
		w := h.do(t, "GET", "/gw/fake/thing", goodToken, nil)
		if w.Code != http.StatusForbidden || h.ad.forwarded != 0 {
			t.Fatalf("%s: code %d forwarded %d", d, w.Code, h.ad.forwarded)
		}
		b := decodeErr(t, w)
		e := b.Error
		if e.Code != "fortik_refused" || e.Decision != string(d) || e.RuleID != "POL-TEST" || e.Class != "red" ||
			e.Reason != "test reason" || e.ActionID == "" || e.ActionID != w.Header().Get(ActionIDHeader) || e.Held != (d == policy.Hold) {
			t.Fatalf("%s: refusal %+v", d, e)
		}
	}
}

func TestServerNeverForwardsWhenDecideErrors(t *testing.T) {
	h := newHarness(t, policy.Allow)
	h.dec.err = errors.New("db down")
	if w := h.do(t, "GET", "/gw/fake/thing", goodToken, nil); w.Code != http.StatusInternalServerError {
		t.Fatalf("code %d", w.Code)
	}
	h.dec.err = fmt.Errorf("%w: bad", action.ErrInvalid)
	if w := h.do(t, "GET", "/gw/fake/thing", goodToken, nil); w.Code != http.StatusBadRequest {
		t.Fatalf("code %d", w.Code)
	}
	if h.ad.forwarded != 0 {
		t.Fatal("forwarded without a decision")
	}
}

func TestServerMapAndEnrichFailuresAreDecidedAsUnknown(t *testing.T) {
	h := newHarness(t, policy.Deny)
	h.ad.mapErr = errors.New("cannot map")
	h.do(t, "GET", "/gw/fake/thing?x=1", goodToken, nil)
	if a := h.dec.last(t); a.Verb != "UNKNOWN" || a.System != "fake" || a.Target["reason"] != "map_failed" {
		t.Fatalf("map failure: %+v", a)
	}
	h.ad.mapErr = nil
	h.ad.enrichErr = errors.New("lookup failed")
	h.do(t, "GET", "/gw/fake/thing", goodToken, nil)
	if a := h.dec.last(t); a.Verb != "UNKNOWN" || a.Target["reason"] != "enrich_failed" || a.Target["mapped_verb"] != "READ" {
		t.Fatalf("enrich failure: %+v", a)
	}
	if h.ad.forwarded != 0 {
		t.Fatal("forwarded")
	}
}

func TestServerForwardErrors(t *testing.T) {
	cases := []struct {
		err  error
		code int
		want string
	}{
		{&NotConfiguredError{System: "google_workspace"}, 503, "integration_not_configured"},
		{fmt.Errorf("wrapped: %w", integrations.ErrNotConfigured), 503, "integration_not_configured"},
		{ErrReducedFormUnsupported{Key: "mystery"}, 403, "fortik_refused"},
		{&RefusedError{RuleID: "GW-IDENTITY", Reason: "no identity"}, 403, "fortik_refused"},
		{errors.New("boom"), 502, "upstream_failed"},
	}
	for _, c := range cases {
		h := newHarness(t, policy.Allow)
		h.ad.forwardErr = c.err
		w := h.do(t, "GET", "/gw/fake/thing", goodToken, nil)
		b := decodeErr(t, w)
		if w.Code != c.code || b.Error.Code != c.want {
			t.Fatalf("%v: code %d body %s", c.err, w.Code, w.Body)
		}
		if c.code == 503 && (b.Error.System == "" || b.Error.ActionID == "") {
			t.Fatalf("503 body lacks system/action_id: %s", w.Body)
		}
		if ref, ok := c.err.(*RefusedError); ok && b.Error.RuleID != ref.RuleID {
			t.Fatalf("rule id %q", b.Error.RuleID)
		}
		if c.code == 403 && b.Error.Decision != "deny" {
			t.Fatalf("decision %q", b.Error.Decision)
		}
	}
}

func TestServerBodyLimitAndRouting(t *testing.T) {
	h := newHarness(t, policy.Allow)
	if w := h.do(t, "POST", "/gw/fake/thing", goodToken, bytes.Repeat([]byte("x"), 2048)); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("too large: %d", w.Code)
	}
	if w := h.do(t, "GET", "/gw/nope/thing", goodToken, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unknown prefix: %d", w.Code)
	}
	if w := h.do(t, "GET", "/v1/nothing", goodToken, nil); w.Code != http.StatusNotFound {
		t.Fatalf("unmounted: %d", w.Code)
	}
	if len(h.dec.seen) != 0 {
		t.Fatal("decided a rejected request")
	}
	var got authz.Principal
	h.srv.Mount("POST /v1/credentials/issue", func(w http.ResponseWriter, r *http.Request) {
		got, _ = authz.From(r.Context())
		httpx.WriteJSON(w, 200, map[string]string{"ok": "1"})
	})
	if w := h.do(t, "POST", "/v1/credentials/issue", goodToken, []byte("{}")); w.Code != 200 || got.Name != "agent_a" || got.Kind != authz.KindAgent {
		t.Fatalf("mounted: %d %+v", w.Code, got)
	}
	if w := h.do(t, "POST", "/v1/credentials/issue", "", []byte("{}")); w.Code != 401 {
		t.Fatalf("mounted handler without auth: %d", w.Code)
	}
}

func TestNewServerRejectsDuplicatePrefix(t *testing.T) {
	_, err := NewServer(config.GatewayConfig{}, &fakeDecider{}, NewAgentAuth(&memSecrets{}, "", quietLog()), []Adapter{&fakeAdapter{}, &fakeAdapter{}}, quietLog())
	if err == nil {
		t.Fatal("duplicate prefix accepted")
	}
}
