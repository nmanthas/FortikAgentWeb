package auth

import (
	"html"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"fortik/internal/httpx"
)

type devLoginRequest struct {
	Email string `json:"email"`
}

// handleDevLogin: POST /auth/dev-login {email}. Only for configured dev
// users, only while dev login is enabled, only on a loopback listener and
// only from a loopback client.
func (s *Service) handleDevLogin(w http.ResponseWriter, r *http.Request) {
	if !s.devEnabled {
		httpx.WriteError(w, http.StatusNotFound, "dev login is not enabled")
		return
	}
	// DNS rebinding: a hostile page whose name resolves to 127.0.0.1 is
	// "same-origin" with itself, so Host and Origin must literally name
	// loopback, not merely agree with each other.
	if !httpx.IsLoopbackName(r.Host) {
		httpx.WriteError(w, http.StatusForbidden, "dev login is only accepted on a loopback host name (127.0.0.1, localhost, [::1])")
		return
	}
	if !remoteIsLoopback(r) {
		httpx.WriteError(w, http.StatusForbidden, "dev login is only accepted from loopback clients")
		return
	}
	// Login CSRF: a cross-site form cannot send application/json without a
	// CORS preflight, and a browser-supplied Origin must be this host.
	if mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mt != "application/json" {
		httpx.WriteError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return
	}
	if o := r.Header.Get("Origin"); o != "" {
		u, err := url.Parse(o)
		if err != nil || !strings.EqualFold(u.Host, r.Host) || !httpx.IsLoopbackName(u.Host) {
			httpx.WriteError(w, http.StatusForbidden, "cross-origin dev login refused")
			return
		}
	}
	var req devLoginRequest
	if err := httpx.DecodeStrict(r, &req, 4096); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	email := strings.ToLower(strings.TrimSpace(req.Email))
	u, ok := s.devUsers[email]
	if !ok {
		// The submitted string is unauthenticated input: not recorded.
		s.recordFailure(r.Context(), MethodDev, "unknown_dev_user", "")
		httpx.WriteError(w, http.StatusForbidden, "not a configured dev login user")
		return
	}
	name := u.Name
	if name == "" {
		name = u.Email
	}
	cookie, sess, err := s.createSession(r.Context(), u.Email, name, u.Roles, MethodDev)
	if err != nil {
		s.log.Error("auth: create dev session failed", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.setSessionCookie(w, cookie)
	httpx.WriteJSON(w, http.StatusOK, meResponse{Kind: "user", Email: sess.Email, Name: sess.Name, Roles: sess.Roles,
		AuthMethod: MethodDev, CSRF: sess.CSRF, ExpiresAt: sess.ExpiresAt.Format(time.RFC3339),
		DevLoginEnabled: true, OIDCEnabled: s.oidcOn})
}

// page renders a minimal, self-contained HTML message (login flows are
// browser navigations, not API calls). All text is escaped.
func page(w http.ResponseWriter, code int, title, msg string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.WriteHeader(code)
	_, _ = w.Write([]byte(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Fortik: ` +
		html.EscapeString(title) + `</title><style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:4rem auto;padding:0 1rem;color:#1f2937}h1{font-size:1.25rem}a{color:#2563eb}</style></head><body><h1>` +
		html.EscapeString(title) + `</h1><p>` + html.EscapeString(msg) + `</p><p><a href="/">Back to Fortik</a></p></body></html>`))
}
