package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/secrets"
)

type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (s *memStore) Get(_ context.Context, n string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[n]
	if !ok {
		return nil, secrets.ErrNotFound
	}
	return append([]byte(nil), v...), nil
}
func (s *memStore) Put(_ context.Context, n string, v []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[n] = append([]byte(nil), v...)
	return nil
}
func (s *memStore) Delete(_ context.Context, n string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, n)
	return nil
}

// Review finding: when the Diary write fails (possibly an ambiguous COMMIT
// that did record the revocation), the rollback restored the previous
// secret and re-enabled the revoked token.
func TestTokenDiaryFailureNeverReenablesRevokedToken(t *testing.T) {
	pool, err := pgxpool.New(context.Background(), "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	st := &memStore{m: map[string][]byte{"agent_tokens": []byte(`{"bot":"aaaa","other":"bbbb"}`)}}
	s := NewServer(Server{Pool: pool, Secrets: st, Log: slog.New(slog.DiscardHandler)}, nil)
	read := func() map[string]string {
		raw, _ := st.Get(context.Background(), "agent_tokens")
		m := map[string]string{}
		_ = json.Unmarshal(raw, &m)
		return m
	}

	// Revocation whose Diary write fails: the token must stay revoked.
	_, err = s.updateAgentTokens(context.Background(), "bot", EventAgentTokenRevoked, "test", func(m map[string]string) map[string]any {
		delete(m, "bot")
		return map[string]any{}
	})
	if err == nil {
		t.Fatal("expected the Diary failure to be reported")
	}
	if m := read(); m["bot"] != "" || m["other"] != "bbbb" {
		t.Fatalf("revoked token was restored: %v", m)
	}

	// Pure addition whose Diary write fails: rolled back (no unrecorded token).
	_, err = s.updateAgentTokens(context.Background(), "new", EventAgentTokenIssued, "test", func(m map[string]string) map[string]any {
		m["new"] = "cccc"
		return map[string]any{}
	})
	if err == nil {
		t.Fatal("expected the Diary failure to be reported")
	}
	if m := read(); m["new"] != "" || m["other"] != "bbbb" {
		t.Fatalf("unrecorded new token must be rolled back: %v", m)
	}
}
