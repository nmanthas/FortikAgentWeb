package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"fortik/internal/authz"
	"fortik/internal/secrets"
)

// memSecrets is an in-memory secrets.Provider with failure injection.
type memSecrets struct {
	mu   sync.Mutex
	m    map[string][]byte
	fail error
}

func (s *memSecrets) Get(_ context.Context, name string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return nil, s.fail
	}
	v, ok := s.m[name]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	return v, nil
}

func (s *memSecrets) set(name, v string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m == nil {
		s.m = map[string][]byte{}
	}
	s.m[name] = []byte(v)
}

func (s *memSecrets) setFail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fail = err
}

func hashOf(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:])
}

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func newAuth(t *testing.T, sec *memSecrets) (*AgentAuth, *clock) {
	t.Helper()
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	a := NewAgentAuth(sec, "", quietLog())
	a.Now = c.now
	return a, c
}

func req(token, instance string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/gw/x/y", nil)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if instance != "" {
		r.Header.Set(InstanceHeader, instance)
	}
	return r
}

func TestAgentAuthAcceptsKnownTokenAndInstance(t *testing.T) {
	sec := &memSecrets{}
	sec.set("agent_tokens", `{"agent_a":"`+hashOf("agt_secret_a")+`","agent_b":["`+hashOf("agt_old_b")+`","`+hashOf("agt_new_b")+`"]}`)
	a, _ := newAuth(t, sec)

	p, err := a.Authenticate(req("agt_secret_a", "copy-1"))
	if err != nil {
		t.Fatal(err)
	}
	if p.Kind != authz.KindAgent || p.Name != "agent_a" || p.InstanceID != "copy-1" || p.AuthMethod != "agent_token" || p.Actor() != "agent:agent_a" {
		t.Fatalf("principal = %+v", p)
	}
	for _, tok := range []string{"agt_old_b", "agt_new_b"} {
		if p, err := a.Authenticate(req(tok, "")); err != nil || p.Name != "agent_b" {
			t.Fatalf("list-valued hash %s: %+v %v", tok, p, err)
		}
	}
}

func TestAgentAuthRejects(t *testing.T) {
	sec := &memSecrets{}
	sec.set("agent_tokens", `{"agent_a":"`+hashOf("agt_secret_a")+`"}`)
	a, _ := newAuth(t, sec)
	cases := map[string]*http.Request{
		"no header":    req("", ""),
		"wrong token":  req("agt_wrong", ""),
		"basic scheme": func() *http.Request { r := req("", ""); r.Header.Set("Authorization", "Basic YTpi"); return r }(),
		"empty bearer": func() *http.Request { r := req("", ""); r.Header.Set("Authorization", "Bearer "); return r }(),
	}
	for name, r := range cases {
		if _, err := a.Authenticate(r); !errors.Is(err, ErrUnauthenticated) {
			t.Errorf("%s: err = %v, want ErrUnauthenticated", name, err)
		}
	}
	if _, err := a.Authenticate(req("agt_secret_a", "bad instance!")); !errors.Is(err, ErrBadInstanceID) {
		t.Fatalf("bad instance: %v", err)
	}
}

func TestAgentAuthDuplicateHashRefused(t *testing.T) {
	sec := &memSecrets{}
	h := hashOf("shared")
	sec.set("agent_tokens", `{"agent_a":"`+h+`","agent_b":"`+h+`"}`)
	a, _ := newAuth(t, sec)
	if _, err := a.Authenticate(req("shared", "")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("ambiguous token accepted: %v", err)
	}
}

func TestAgentAuthMissingSecretRejectsAll(t *testing.T) {
	a, _ := newAuth(t, &memSecrets{})
	if _, err := a.Authenticate(req("anything", "")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v", err)
	}
}

func TestAgentAuthCacheAndRevocation(t *testing.T) {
	sec := &memSecrets{}
	sec.set("agent_tokens", `{"agent_a":"`+hashOf("tok")+`"}`)
	a, c := newAuth(t, sec)
	if _, err := a.Authenticate(req("tok", "")); err != nil {
		t.Fatal(err)
	}
	sec.set("agent_tokens", `{}`) // revoked
	c.add(2 * time.Second)
	if _, err := a.Authenticate(req("tok", "")); err != nil {
		t.Fatalf("within the cache TTL the old copy is used: %v", err)
	}
	c.add(4 * time.Second)
	if _, err := a.Authenticate(req("tok", "")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("revocation not applied after the cache TTL: %v", err)
	}
}

func TestAgentAuthFailsClosedWhenSecretStale(t *testing.T) {
	sec := &memSecrets{}
	sec.set("agent_tokens", `{"agent_a":"`+hashOf("tok")+`"}`)
	a, c := newAuth(t, sec)
	if _, err := a.Authenticate(req("tok", "")); err != nil {
		t.Fatal(err)
	}
	sec.setFail(errors.New("vault sealed"))
	c.add(90 * time.Second)
	if _, err := a.Authenticate(req("tok", "")); err != nil {
		t.Fatalf("last good copy must be used for up to 2 minutes: %v", err)
	}
	c.add(31 * time.Second) // 121s since the last good read
	if _, err := a.Authenticate(req("tok", "")); !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("stale secret must reject everything: %v", err)
	}
	sec.setFail(nil)
	c.add(6 * time.Second)
	if _, err := a.Authenticate(req("tok", "")); err != nil {
		t.Fatalf("recovery after the secret is readable again: %v", err)
	}
}

func TestAgentAuthNeverLoadedIsUnavailable(t *testing.T) {
	sec := &memSecrets{}
	sec.setFail(errors.New("down"))
	a, _ := newAuth(t, sec)
	if _, err := a.Authenticate(req("tok", "")); !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("err = %v", err)
	}
	sec.setFail(nil)
	sec.set("agent_tokens", `not json`)
	a2, _ := newAuth(t, sec)
	if _, err := a2.Authenticate(req("tok", "")); !errors.Is(err, ErrAuthUnavailable) {
		t.Fatalf("malformed secret: err = %v", err)
	}
}
