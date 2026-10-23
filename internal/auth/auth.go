// Package auth is human login for the console: OIDC (authorization code +
// PKCE), a loopback-only dev login, and server-side sessions (design §8).
//
// Sessions are random 32-byte ids held only in an HttpOnly, SameSite=Strict
// cookie; Postgres stores their SHA-256. Every login, logout and refused
// login is a Diary event (never a token, code or cookie value). Bearer
// service tokens stay in internal/api; the API middleware asks this package
// to resolve a session cookie and enforces CSRF on cookie-authenticated
// writes with the session's csrf value.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/time/rate"

	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/httpx"
	"fortik/internal/secrets"
)

const (
	// SessionCookie holds the console session id.
	SessionCookie = "fortik_session"
	// CSRFHeader must equal the session's csrf on every non-GET request
	// authenticated by the session cookie.
	CSRFHeader = "X-Fortik-CSRF"

	MethodOIDC = "oidc"
	MethodDev  = "dev"

	EventLogin       = "auth.login"
	EventLogout      = "auth.logout"
	EventLoginFailed = "auth.login_failed"
)

var (
	// ErrNoSession: the request carries no session cookie.
	ErrNoSession = errors.New("no session cookie")
	// ErrInvalidSession: a cookie was sent but is unknown, malformed or expired.
	ErrInvalidSession = errors.New("session invalid or expired")
)

// knownRoles are the roles a human may be mapped to.
var knownRoles = map[string]bool{
	authz.RoleAdmin: true, authz.RoleSecurity: true, authz.RoleAuditor: true, authz.RoleInterceptor: true,
}

// Options wires the service.
type Options struct {
	Config    config.AuthConfig
	APIListen string // api.listen: decides Secure cookies and gates dev login
	Pool      *pgxpool.Pool
	Diary     *diary.Diary
	Secrets   secrets.Provider // holds the OIDC client secret (by name)
	Log       *slog.Logger
	// HTTPClient is used for OIDC discovery, JWKS and token calls
	// (default: 15s timeout).
	HTTPClient *http.Client
	// Now is the clock (tests); default time.Now.
	Now func() time.Time
	// FlowKey signs the short-lived login-flow cookie (state, nonce, PKCE
	// verifier). Default: 32 random bytes per process, so a restart in the
	// middle of a login simply asks the user to start again.
	FlowKey []byte
	// PostLoginRedirect is where a successful OIDC login lands (default "/").
	PostLoginRedirect string
}

// Service implements login, logout, sessions and /v1/me.
type Service struct {
	cfg        config.AuthConfig
	pool       *pgxpool.Pool
	diary      *diary.Diary
	sec        secrets.Provider
	log        *slog.Logger
	http       *http.Client
	now        func() time.Time
	flowKey    []byte
	secure     bool
	devEnabled bool
	oidcOn     bool
	redirect   string
	emailRoles map[string][]string // lower-cased emails
	devUsers   map[string]config.DevLoginUser
	// failLimiter bounds auth.login_failed Diary writes: refused logins are
	// unauthenticated input and must not be able to flood the Diary.
	failLimiter *rate.Limiter

	oidcMu sync.Mutex
	oidc   *oidcClient // discovered lazily; nil until the first success
}

// New validates the configuration (fail closed on anything ambiguous).
func New(o Options) (*Service, error) {
	if o.Pool == nil || o.Diary == nil {
		return nil, errors.New("auth: pool and diary are required")
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.HTTPClient == nil {
		o.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if len(o.FlowKey) == 0 {
		o.FlowKey = make([]byte, 32)
		if _, err := rand.Read(o.FlowKey); err != nil {
			return nil, fmt.Errorf("auth: flow key: %w", err)
		}
	} else if len(o.FlowKey) < 32 {
		return nil, errors.New("auth: flow key must be at least 32 bytes")
	}
	if o.PostLoginRedirect == "" {
		o.PostLoginRedirect = "/"
	}
	if !strings.HasPrefix(o.PostLoginRedirect, "/") || strings.HasPrefix(o.PostLoginRedirect, "//") {
		return nil, errors.New("auth: post-login redirect must be a local path")
	}
	c := o.Config
	if c.SessionTTL <= 0 {
		c.SessionTTL = 12 * time.Hour
	}
	if c.SessionIdleTTL <= 0 {
		c.SessionIdleTTL = time.Hour
	}
	s := &Service{
		cfg: c, pool: o.Pool, diary: o.Diary, sec: o.Secrets, log: o.Log, http: o.HTTPClient, now: o.Now,
		flowKey: o.FlowKey, secure: !isLoopback(o.APIListen), redirect: o.PostLoginRedirect,
		emailRoles: map[string][]string{}, devUsers: map[string]config.DevLoginUser{},
		failLimiter: rate.NewLimiter(rate.Every(2*time.Second), 30),
	}

	oc := c.OIDC
	if oc.Issuer != "" || oc.ClientID != "" || oc.RedirectURL != "" {
		if oc.Issuer == "" || oc.ClientID == "" || oc.RedirectURL == "" {
			return nil, errors.New("auth: oidc needs issuer, client_id and redirect_url together")
		}
		if oc.ClientSecretSecret != "" && o.Secrets == nil {
			return nil, errors.New("auth: oidc client_secret_secret is set but no secret provider was given")
		}
		for claim, roles := range oc.RoleMap {
			if err := checkRoles(roles); err != nil {
				return nil, fmt.Errorf("auth: oidc.role_map[%q]: %w", claim, err)
			}
		}
		for email, roles := range oc.EmailRoles {
			if err := checkRoles(roles); err != nil {
				return nil, fmt.Errorf("auth: oidc.email_roles[%q]: %w", email, err)
			}
			k := strings.ToLower(strings.TrimSpace(email))
			s.emailRoles[k] = append(s.emailRoles[k], roles...)
		}
		if len(oc.RoleMap) == 0 && len(oc.EmailRoles) == 0 {
			return nil, errors.New("auth: oidc needs role_map or email_roles (no roles = nobody can log in)")
		}
		if len(oc.RoleMap) > 0 && oc.RoleClaim == "" {
			return nil, errors.New("auth: oidc.role_map needs role_claim")
		}
		s.oidcOn = true
	}

	if c.DevLogin.Enabled {
		// The config layer already refuses this; re-checked here so a
		// hand-built config cannot enable dev login on a public listener.
		if !isLoopback(o.APIListen) {
			return nil, fmt.Errorf("auth: dev login is only allowed when the API listens on loopback (got %q)", o.APIListen)
		}
		for _, u := range c.DevLogin.Users {
			e := strings.ToLower(strings.TrimSpace(u.Email))
			if e == "" || !strings.Contains(e, "@") {
				return nil, fmt.Errorf("auth: dev_login user %q needs an email", u.Email)
			}
			if len(u.Roles) == 0 {
				return nil, fmt.Errorf("auth: dev_login user %s needs roles", e)
			}
			if err := checkRoles(u.Roles); err != nil {
				return nil, fmt.Errorf("auth: dev_login user %s: %w", e, err)
			}
			u.Email = e
			s.devUsers[e] = u
		}
		s.devEnabled = true
	}
	return s, nil
}

func checkRoles(roles []string) error {
	for _, r := range roles {
		if !knownRoles[r] {
			return fmt.Errorf("unknown role %q", r)
		}
	}
	return nil
}

// OIDCEnabled and DevLoginEnabled report which login methods are on.
func (s *Service) OIDCEnabled() bool     { return s.oidcOn }
func (s *Service) DevLoginEnabled() bool { return s.devEnabled }

// Routes registers /auth/* (public; each handler authenticates itself) and
// GET /v1/me (behind the API middleware, which sets the principal).
func (s *Service) Routes(mux *http.ServeMux) {
	mux.HandleFunc("GET /auth/config", s.handleConfig)
	mux.HandleFunc("GET /auth/login", s.handleLogin)
	mux.HandleFunc("GET /auth/callback", s.handleCallback)
	mux.HandleFunc("POST /auth/logout", s.handleLogout)
	mux.HandleFunc("POST /auth/dev-login", s.handleDevLogin)
	mux.HandleFunc("GET /v1/me", s.handleMe)
}

// --- request-scoped session ----------------------------------------------------

type sessionKey struct{}

// WithSession stores the authenticated session in ctx (set by the API
// middleware alongside authz.With).
func WithSession(ctx context.Context, sess *Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, sess)
}

// SessionFrom returns the session that authenticated the request, if any.
func SessionFrom(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok && s != nil
}

// CheckCSRF reports whether the request's X-Fortik-CSRF header matches the
// session's csrf value (constant time).
func CheckCSRF(r *http.Request, sess *Session) bool {
	got := r.Header.Get(CSRFHeader)
	return got != "" && sess != nil && sess.CSRF != "" && subtle.ConstantTimeCompare([]byte(got), []byte(sess.CSRF)) == 1
}

// --- handlers --------------------------------------------------------------------

type devUserView struct {
	Email string   `json:"email"`
	Name  string   `json:"name,omitempty"`
	Roles []string `json:"roles"`
}

func (s *Service) handleConfig(w http.ResponseWriter, _ *http.Request) {
	out := map[string]any{"oidc_enabled": s.oidcOn, "dev_login_enabled": s.devEnabled}
	if s.devEnabled {
		users := make([]devUserView, 0, len(s.devUsers))
		for _, u := range s.devUsers {
			users = append(users, devUserView{Email: u.Email, Name: u.Name, Roles: sortedRoles(u.Roles)})
		}
		sort.Slice(users, func(i, j int) bool { return users[i].Email < users[j].Email })
		out["dev_users"] = users
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

type meResponse struct {
	Kind            string   `json:"kind"`
	Email           string   `json:"email,omitempty"`
	Name            string   `json:"name"`
	Roles           []string `json:"roles"`
	AuthMethod      string   `json:"auth_method"`
	CSRF            string   `json:"csrf,omitempty"`
	ExpiresAt       string   `json:"expires_at,omitempty"`
	DevLoginEnabled bool     `json:"dev_login_enabled"`
	OIDCEnabled     bool     `json:"oidc_enabled"`
}

func (s *Service) handleMe(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	roles := make([]string, 0, len(p.Roles))
	for role, on := range p.Roles {
		if on {
			roles = append(roles, role)
		}
	}
	sort.Strings(roles)
	out := meResponse{Kind: p.Kind, Email: p.Email, Name: p.Name, Roles: roles, AuthMethod: p.AuthMethod,
		DevLoginEnabled: s.devEnabled, OIDCEnabled: s.oidcOn}
	if sess, ok := SessionFrom(r.Context()); ok {
		out.CSRF = sess.CSRF
		out.ExpiresAt = sess.ExpiresAt.UTC().Format(time.RFC3339)
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	sess, err := s.Authenticate(r.Context(), r)
	switch {
	case err == nil:
		if !CheckCSRF(r, sess) {
			httpx.WriteError(w, http.StatusForbidden, "missing or invalid "+CSRFHeader+" header")
			return
		}
		if err := s.deleteSession(r.Context(), sess, "logout"); err != nil {
			s.log.Error("auth: logout failed", "err", err)
			httpx.WriteError(w, http.StatusInternalServerError, "internal error")
			return
		}
	case errors.Is(err, ErrNoSession), errors.Is(err, ErrInvalidSession):
		// Idempotent: nothing to revoke, just clear the cookie.
	default:
		s.log.Error("auth: session lookup failed during logout", "err", err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "session store unavailable")
		return
	}
	s.clearSessionCookie(w)
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// --- helpers -----------------------------------------------------------------------

func (s *Service) setSessionCookie(w http.ResponseWriter, value string) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: value, Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: int(s.cfg.SessionTTL / time.Second)})
}

func (s *Service) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: SessionCookie, Value: "", Path: "/", HttpOnly: true, Secure: s.secure,
		SameSite: http.SameSiteStrictMode, MaxAge: -1})
}

// recordFailure writes auth.login_failed (rate limited; never secrets).
func (s *Service) recordFailure(ctx context.Context, method, reason, email string) {
	s.log.Info("console login refused", "method", method, "reason", reason, "email", email)
	if !s.failLimiter.Allow() {
		return
	}
	data := map[string]any{"method": method, "reason": reason}
	if email != "" {
		data["email"] = email
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	if _, err := s.diary.Append(ctx, diary.Event{EventType: EventLoginFailed, Actor: "system:auth", Data: data}); err != nil {
		s.log.Error("auth: could not record refused login", "err", err)
	}
}

func randomToken(n int) (string, []byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	return base64.RawURLEncoding.EncodeToString(b), b, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func sortedRoles(roles []string) []string {
	out := slices.Clone(roles)
	sort.Strings(out)
	return slices.Compact(out)
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func remoteIsLoopback(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
