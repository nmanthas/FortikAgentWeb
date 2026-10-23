package api

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/diary"
	"fortik/internal/secrets"
)

// AgentTokenPrefix marks Fortik agent tokens (helps secret scanners).
const AgentTokenPrefix = "agt_"

// errTokenConflict: the secret changed between our read and our write.
var errTokenConflict = errors.New("agent token secret changed concurrently")

// readAgentTokens returns the {"agent_id": "<sha256 hex>"} map and the raw
// bytes it was parsed from (nil when the secret does not exist yet). A
// secret that exists but does not parse is an error: it is never overwritten.
func (s *Server) readAgentTokens(ctx context.Context) (map[string]string, []byte, error) {
	raw, err := s.Secrets.Get(ctx, s.AgentTokensSecret)
	if errors.Is(err, secrets.ErrNotFound) {
		return map[string]string{}, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", s.AgentTokensSecret, err)
	}
	m := map[string]string{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, nil, fmt.Errorf("%s is not a JSON object of agent_id -> sha256; refusing to overwrite it", s.AgentTokensSecret)
	}
	return m, raw, nil
}

// tokenIssued reports whether the agent currently has a token (nil when it
// cannot be determined). Only presence is reported, never the hash.
func (s *Server) tokenIssued(ctx context.Context, agentID string) *bool {
	if s.Secrets == nil {
		return nil
	}
	m, _, err := s.readAgentTokens(ctx)
	if err != nil {
		return nil
	}
	_, ok := m[agentID]
	return &ok
}

// updateAgentTokens performs one read-modify-write of the token secret
// under the process lock, with a version check (the secret must still hold
// the bytes we read), then records the Diary event. If the Diary write fails
// the previous secret is restored only when that cannot re-enable a token
// (see restoreAgentTokens): an unrecorded revocation stands and is logged.
// mutate returns the Diary event data, or nil for "nothing to change".
func (s *Server) updateAgentTokens(ctx context.Context, agentID, eventType, actor string,
	mutate func(m map[string]string) map[string]any) (map[string]any, error) {
	s.st.tokenMu.Lock()
	defer s.st.tokenMu.Unlock()
	// The write must finish (or roll back) even if the client goes away.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()

	m, prev, err := s.readAgentTokens(ctx)
	if err != nil {
		return nil, err
	}
	data := mutate(m)
	if data == nil {
		return nil, nil
	}
	next, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	// Version check: another writer (a second Fortik process, an operator)
	// must not be silently overwritten.
	cur, err := s.Secrets.Get(ctx, s.AgentTokensSecret)
	switch {
	case errors.Is(err, secrets.ErrNotFound):
		cur = nil
	case err != nil:
		return nil, fmt.Errorf("re-read %s: %w", s.AgentTokensSecret, err)
	}
	if !bytes.Equal(cur, prev) {
		return nil, errTokenConflict
	}
	if err := s.Secrets.Put(ctx, s.AgentTokensSecret, next); err != nil {
		return nil, err
	}
	// The Diary append takes the chain's head lock, so it runs after the
	// (possibly remote) secret write rather than holding the lock across it.
	data["secret"] = s.AgentTokensSecret
	if err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		_, err := s.Diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: eventType, Actor: actor, Data: data})
		return err
	}); err != nil {
		rerr := s.restoreAgentTokens(ctx, prev, next)
		if rerr != nil {
			s.Log.Error("agent token secret written but its Diary record failed and the secret could not be restored; review manually",
				"agent_id", agentID, "event", eventType, "diary_err", err, "restore_err", rerr)
		}
		return nil, fmt.Errorf("record %s: %w", eventType, err)
	}
	return data, nil
}

// restoreAgentTokens undoes a token-secret write whose Diary record failed.
// It fails toward the safe state: the outcome of a failed COMMIT is
// unknown (the Diary may hold the event), so a restore that would make any
// token valid again (undoing a revocation or rotation) is never done; and
// a secret changed by someone else since our write is left alone.
func (s *Server) restoreAgentTokens(ctx context.Context, prev, next []byte) error {
	if reenables(prev, next) {
		return errors.New("restore skipped: it would re-enable a revoked or replaced agent token")
	}
	cur, err := s.Secrets.Get(ctx, s.AgentTokensSecret)
	if err != nil {
		return fmt.Errorf("restore re-read: %w", err)
	}
	if !bytes.Equal(cur, next) {
		return errors.New("restore skipped: the secret changed after our write")
	}
	if prev == nil {
		return s.Secrets.Delete(ctx, s.AgentTokensSecret)
	}
	return s.Secrets.Put(ctx, s.AgentTokensSecret, prev)
}

// reenables reports whether prev holds any (agent, hash) pair next lacks.
func reenables(prev, next []byte) bool {
	if prev == nil {
		return false
	}
	pm, nm := map[string]string{}, map[string]string{}
	if json.Unmarshal(prev, &pm) != nil || json.Unmarshal(next, &nm) != nil {
		return true
	}
	for id, h := range pm {
		if nm[id] != h {
			return true
		}
	}
	return false
}

func (s *Server) tokenPrecheck(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if s.Secrets == nil {
		writeError(w, http.StatusServiceUnavailable, "agent tokens need a writable secret store (secrets.provider encfile or vault)")
		return "", false
	}
	var exists bool
	if err := s.Pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1)`, id).Scan(&exists); err != nil {
		s.internal(w, err)
		return "", false
	}
	if !exists {
		writeError(w, http.StatusNotFound, "agent not found")
		return "", false
	}
	return id, true
}

func (s *Server) tokenError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTokenConflict):
		writeError(w, http.StatusConflict, "the agent token secret changed while updating it; retry")
	case errors.Is(err, secrets.ErrReadOnly):
		writeError(w, http.StatusServiceUnavailable, "the secret provider is read-only; configure encfile or vault to manage agent tokens")
	default:
		s.internal(w, err)
	}
}

// issueAgentToken: POST /v1/agents/{id}/tokens. The token is returned once;
// only its SHA-256 is stored, in the agent_tokens secret (the map pgproxy
// and the gateway authenticate against). An agent has one token: issuing a
// new one replaces (revokes) the previous one.
func (s *Server) issueAgentToken(w http.ResponseWriter, r *http.Request) {
	id, ok := s.tokenPrecheck(w, r)
	if !ok {
		return
	}
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		s.internal(w, err)
		return
	}
	token := AgentTokenPrefix + base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	fp := hash[:12]
	data, err := s.updateAgentTokens(r.Context(), id, EventAgentTokenIssued, principalFrom(r.Context()).Actor(),
		func(m map[string]string) map[string]any {
			_, replaced := m[id]
			m[id] = hash
			return map[string]any{"fingerprint": fp, "replaced": replaced}
		})
	if err != nil {
		s.tokenError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "agent_id": id, "fingerprint": fp,
		"replaced": data["replaced"], "note": "shown once: Fortik stores only its SHA-256"})
}

// revokeAgentTokens: DELETE /v1/agents/{id}/tokens.
func (s *Server) revokeAgentTokens(w http.ResponseWriter, r *http.Request) {
	id, ok := s.tokenPrecheck(w, r)
	if !ok {
		return
	}
	data, err := s.updateAgentTokens(r.Context(), id, EventAgentTokenRevoked, principalFrom(r.Context()).Actor(),
		func(m map[string]string) map[string]any {
			h, ok := m[id]
			if !ok {
				return nil
			}
			delete(m, id)
			fp := h
			if len(fp) > 12 {
				fp = fp[:12]
			}
			return map[string]any{"fingerprint": fp}
		})
	if err != nil {
		s.tokenError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_id": id, "revoked": data != nil})
}
