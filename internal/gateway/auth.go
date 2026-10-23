package gateway

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"fortik/internal/authz"
	"fortik/internal/secrets"
)

// Authenticator identifies the agent behind a gateway request.
type Authenticator interface {
	Authenticate(r *http.Request) (authz.Principal, error)
}

var (
	// ErrUnauthenticated: no, malformed, unknown or revoked agent token (401).
	ErrUnauthenticated = errors.New("agent authentication required")
	// ErrAuthUnavailable: the agent token secret has been unreadable for longer
	// than the stale limit, so every request is refused (fail closed, 503).
	ErrAuthUnavailable = errors.New("agent authentication unavailable")
	// ErrBadInstanceID: X-Fortik-Instance-Id is present but malformed (400).
	ErrBadInstanceID = errors.New("invalid X-Fortik-Instance-Id")
)

// InstanceHeader optionally names the agent instance (copy) making the call.
const InstanceHeader = "X-Fortik-Instance-Id"

// idPattern mirrors action.Action's id validation (agent and instance ids).
var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

const (
	defaultTokenCacheTTL = 5 * time.Second
	defaultMaxStale      = 2 * time.Minute
	maxTokenLen          = 512
)

// AgentAuth authenticates agents by bearer token. The secret (default
// "agent_tokens", shared with pgproxy) holds JSON {"<agent_id>": "<lowercase
// hex sha256 of the token>"}; a value may also be a list of hashes so an agent
// can hold more than one live token during rotation. The secret is re-read at
// most every CacheTTL; if it cannot be read, the last good copy is used for at
// most MaxStale, after which every request is refused (fail closed).
type AgentAuth struct {
	sec      secrets.Provider
	name     string
	log      *slog.Logger
	CacheTTL time.Duration
	MaxStale time.Duration
	Now      func() time.Time

	mu      sync.Mutex
	entries []tokenEntry
	loaded  bool      // entries hold a successfully parsed secret
	lastOK  time.Time // last successful read
	lastTry time.Time // last read attempt
}

type tokenEntry struct {
	agentID string
	sum     []byte // lowercase hex sha256, as bytes
}

// NewAgentAuth reads agent token hashes from secretName ("agent_tokens" if empty).
func NewAgentAuth(sec secrets.Provider, secretName string, log *slog.Logger) *AgentAuth {
	if secretName == "" {
		secretName = "agent_tokens"
	}
	if log == nil {
		log = slog.Default()
	}
	return &AgentAuth{sec: sec, name: secretName, log: log}
}

var _ Authenticator = (*AgentAuth)(nil)

func (a *AgentAuth) now() time.Time {
	if a.Now != nil {
		return a.Now()
	}
	return time.Now()
}

// Authenticate returns the agent principal for r. Errors are ErrUnauthenticated,
// ErrAuthUnavailable or ErrBadInstanceID; none carries token material.
func (a *AgentAuth) Authenticate(r *http.Request) (authz.Principal, error) {
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		return authz.Principal{}, ErrUnauthenticated
	}
	instance := r.Header.Get(InstanceHeader)
	if instance != "" && !idPattern.MatchString(instance) {
		return authz.Principal{}, ErrBadInstanceID
	}
	entries, err := a.current(r.Context())
	if err != nil {
		return authz.Principal{}, err
	}
	sum := sha256.Sum256([]byte(token))
	got := []byte(hex.EncodeToString(sum[:]))
	// Compare against every entry without early exit so timing does not
	// reveal which (or whether an) agent matched.
	match := ""
	matches := 0
	for _, e := range entries {
		if subtle.ConstantTimeCompare(got, e.sum) == 1 {
			if match != e.agentID {
				matches++
			}
			match = e.agentID
		}
	}
	if matches != 1 {
		if matches > 1 {
			a.log.Error("agent token hash is registered for more than one agent; refusing")
		}
		return authz.Principal{}, ErrUnauthenticated
	}
	return authz.Principal{Kind: authz.KindAgent, Name: match, AuthMethod: "agent_token", InstanceID: instance}, nil
}

func bearer(h string) (string, bool) {
	scheme, tok, ok := strings.Cut(strings.TrimSpace(h), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	tok = strings.TrimSpace(tok)
	if tok == "" || len(tok) > maxTokenLen || strings.ContainsAny(tok, " \t\r\n") {
		return "", false
	}
	return tok, true
}

// current returns the cached entries, refreshing them when the cache is older
// than CacheTTL. A refresh failure keeps the last good copy until MaxStale.
func (a *AgentAuth) current(ctx context.Context) ([]tokenEntry, error) {
	ttl, maxStale := a.CacheTTL, a.MaxStale
	if ttl <= 0 {
		ttl = defaultTokenCacheTTL
	}
	if maxStale <= 0 {
		maxStale = defaultMaxStale
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	if !a.loaded || now.Sub(a.lastTry) >= ttl {
		a.lastTry = now
		entries, err := a.load(ctx)
		if err == nil {
			a.entries, a.loaded, a.lastOK = entries, true, now
		} else {
			a.log.Error("agent token secret unreadable; using last good copy until it is stale",
				"secret", a.name, "err", err, "max_stale", maxStale)
		}
	}
	if !a.loaded || now.Sub(a.lastOK) > maxStale {
		a.entries, a.loaded = nil, false
		return nil, ErrAuthUnavailable
	}
	return a.entries, nil
}

// load reads and parses the secret. A missing secret is a valid empty set
// (no agent has a token yet); an unreadable or malformed one is an error.
func (a *AgentAuth) load(ctx context.Context) ([]tokenEntry, error) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	raw, err := a.sec.Get(rctx, a.name)
	if errors.Is(err, secrets.ErrNotFound) {
		return []tokenEntry{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read agent token secret: %w", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, errors.New("agent token secret is not a JSON object")
	}
	out := make([]tokenEntry, 0, len(m))
	for agentID, v := range m {
		if !idPattern.MatchString(agentID) {
			a.log.Warn("agent token secret: skipping malformed agent id")
			continue
		}
		var hashes []string
		var one string
		if err := json.Unmarshal(v, &one); err == nil {
			hashes = []string{one}
		} else if err := json.Unmarshal(v, &hashes); err != nil {
			return nil, fmt.Errorf("agent token secret: value for %s is neither a hash nor a list of hashes", agentID)
		}
		for _, h := range hashes {
			h = strings.ToLower(strings.TrimSpace(h))
			if len(h) != 64 {
				a.log.Warn("agent token secret: skipping malformed hash", "agent_id", agentID)
				continue
			}
			if _, err := hex.DecodeString(h); err != nil {
				a.log.Warn("agent token secret: skipping malformed hash", "agent_id", agentID)
				continue
			}
			out = append(out, tokenEntry{agentID: agentID, sum: []byte(h)})
		}
	}
	return out, nil
}
