package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"fortik/internal/auth"
	"fortik/internal/authz"
	"fortik/internal/httpx"
	"fortik/internal/secrets"
)

// Roles (aliases of the shared authz roles, kept for existing callers).
// Services and operators authenticate with bearer tokens whose SHA-256
// hashes live in the secret provider; humans use console sessions
// (internal/auth). Every role check is explicit per route.
const (
	RoleInterceptor = authz.RoleInterceptor // interception points: may call decide
	RoleAuditor     = authz.RoleAuditor     // read actions, held actions, diary, export, metrics
	RoleSecurity    = authz.RoleSecurity    // security-state changes (undo, levels, agents, tokens)
	RoleAdmin       = authz.RoleAdmin       // all of the above
)

// Principal is the shared caller identity.
type Principal = authz.Principal

type tokenEntry struct {
	Name   string   `json:"name"`
	SHA256 string   `json:"sha256"`
	Roles  []string `json:"roles"`
}

// TokenAuth verifies bearer tokens against hashed entries, reloading the
// secret periodically so rotation needs no restart.
type TokenAuth struct {
	sec    secrets.Provider
	name   string
	mu     sync.RWMutex
	tokens []tokenEntry
	loaded time.Time
	ttl    time.Duration
	// maxStale: if the token secret cannot be re-read for this long, every
	// token is refused (a revocation must not be masked by a read failure).
	maxStale time.Duration
}

func NewTokenAuth(ctx context.Context, sec secrets.Provider, secretName string) (*TokenAuth, error) {
	t := &TokenAuth{sec: sec, name: secretName, ttl: 30 * time.Second, maxStale: 2 * time.Minute}
	if err := t.reload(ctx); err != nil {
		return nil, err
	}
	return t, nil
}

func (t *TokenAuth) reload(ctx context.Context) error {
	raw, err := t.sec.Get(ctx, t.name)
	if err != nil {
		return fmt.Errorf("api tokens: %w", err)
	}
	var entries []tokenEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return fmt.Errorf("api tokens: invalid JSON: %w", err)
	}
	for _, e := range entries {
		if e.Name == "" || len(e.SHA256) != 64 || len(e.Roles) == 0 {
			return fmt.Errorf("api tokens: entry %q needs name, 64-hex sha256 and roles", e.Name)
		}
		for _, r := range e.Roles {
			switch r {
			case RoleInterceptor, RoleAuditor, RoleSecurity, RoleAdmin:
			default:
				return fmt.Errorf("api tokens: entry %q has unknown role %q", e.Name, r)
			}
		}
	}
	t.mu.Lock()
	t.tokens, t.loaded = entries, time.Now()
	t.mu.Unlock()
	return nil
}

// Authenticate returns the principal (Kind token) for a bearer token, or false.
func (t *TokenAuth) Authenticate(ctx context.Context, token string) (Principal, bool) {
	t.mu.RLock()
	stale := time.Since(t.loaded) > t.ttl
	t.mu.RUnlock()
	if stale {
		// Keep the previous set through a brief secret-store blip, but never
		// past maxStale: then fail closed.
		_ = t.reload(ctx)
	}
	t.mu.RLock()
	expired := time.Since(t.loaded) > t.maxStale
	t.mu.RUnlock()
	if token == "" || expired {
		return Principal{}, false
	}
	sum := sha256.Sum256([]byte(token))
	got := hex.EncodeToString(sum[:])
	t.mu.RLock()
	defer t.mu.RUnlock()
	var match *tokenEntry
	for i := range t.tokens {
		// Compare every entry (no early exit) in constant time per entry.
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(t.tokens[i].SHA256)), []byte(got)) == 1 {
			match = &t.tokens[i]
		}
	}
	if match == nil {
		return Principal{}, false
	}
	p := Principal{Kind: authz.KindToken, Name: match.Name, Roles: map[string]bool{}, AuthMethod: "token"}
	for _, r := range match.Roles {
		p.Roles[r] = true
	}
	return p, true
}

// principalFrom returns the authenticated principal (zero value if none;
// every /v1 route is behind authenticate, so handlers always have one).
func principalFrom(ctx context.Context) Principal {
	p, _ := authz.From(ctx)
	return p
}

// needsAuth lists the path prefixes the middleware authenticates. Everything
// under /v1/ (including routes other packages Mount) requires a principal.
func needsAuth(path string) bool {
	return strings.HasPrefix(path, "/v1/") || path == "/metrics"
}

// authenticate resolves the caller for protected paths: a bearer service
// token (Authorization header) or, failing that, a console session cookie.
// Cookie-authenticated requests that are not GET/HEAD must carry
// X-Fortik-CSRF equal to the session's csrf. Fails closed on any error.
func (s *Server) authenticate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !needsAuth(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
		}
		if h := r.Header.Get("Authorization"); h != "" {
			// A presented bearer token is authoritative: an invalid one is
			// refused, never silently replaced by a cookie.
			token, ok := strings.CutPrefix(h, "Bearer ")
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "unsupported Authorization scheme (use Bearer)")
				return
			}
			if s.auth == nil {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			p, ok := s.auth.Authenticate(r.Context(), strings.TrimSpace(token))
			if !ok {
				httpx.WriteError(w, http.StatusUnauthorized, "invalid token")
				return
			}
			next.ServeHTTP(w, r.WithContext(authz.With(r.Context(), p)))
			return
		}
		if s.Sessions == nil {
			httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
			return
		}
		sess, err := s.Sessions.Authenticate(r.Context(), r)
		switch {
		case errors.Is(err, auth.ErrNoSession):
			httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
			return
		case errors.Is(err, auth.ErrInvalidSession):
			httpx.WriteError(w, http.StatusUnauthorized, "session expired or invalid; log in again")
			return
		case err != nil:
			s.Log.Error("session lookup failed", "err", err)
			httpx.WriteError(w, http.StatusServiceUnavailable, "session store unavailable")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !auth.CheckCSRF(r, sess) {
			httpx.WriteError(w, http.StatusForbidden, "missing or invalid "+auth.CSRFHeader+" header")
			return
		}
		ctx := auth.WithSession(authz.With(r.Context(), sess.Principal()), sess)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Reauthorize re-resolves the caller of r from its credentials (bearer
// token or session cookie) as the middleware would, and checks it still
// holds role (or, when several are given, any one of them). Long-lived
// responses (the event stream) call it periodically so logout, session
// expiry, token revocation or role removal ends them.
func (s *Server) Reauthorize(r *http.Request, role string, more ...string) error {
	var p Principal
	if h := r.Header.Get("Authorization"); h != "" {
		token, ok := strings.CutPrefix(h, "Bearer ")
		if !ok || s.auth == nil {
			return errors.New("invalid token")
		}
		if p, ok = s.auth.Authenticate(r.Context(), strings.TrimSpace(token)); !ok {
			return errors.New("invalid token")
		}
	} else {
		if s.Sessions == nil {
			return errors.New("authentication required")
		}
		sess, err := s.Sessions.Authenticate(r.Context(), r)
		if err != nil {
			return err
		}
		p = sess.Principal()
	}
	for _, want := range append([]string{role}, more...) {
		if p.Has(want) {
			return nil
		}
	}
	return fmt.Errorf("role %s no longer held", strings.Join(append([]string{role}, more...), " or "))
}

// require wraps a handler with a role check (authentication already ran in
// the middleware; authz.Require writes 401/403).
func (s *Server) require(role string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authz.Require(w, r, role); !ok {
			return
		}
		h(w, r)
	}
}
