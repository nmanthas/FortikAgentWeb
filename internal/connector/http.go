package connector

import (
	"encoding/json"
	"errors"
	"html"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the OAuth endpoints (gateway) and the admin API (API).
type Handler struct {
	s   *Service
	log *slog.Logger
}

// NewHandler returns the connector HTTP handler.
func NewHandler(s *Service, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{s: s, log: log}
}

// Mounter is satisfied by the gateway server and *http.ServeMux.
type Mounter interface {
	Mount(pattern string, h http.HandlerFunc)
}

// MountOAuth registers the public OAuth endpoints (no Fortik token: the
// client authenticates with its client secret; the browser with the upstream):
//
//	GET  /oauth/authorize   start (client -> browser -> upstream consent)
//	GET  /oauth/callback    upstream consent done -> client redirect with a code
//	POST /oauth/token       authorization_code | refresh_token (each a Fortik decision)
//	POST /oauth/revoke      RFC 7009
func (h *Handler) MountOAuth(m Mounter) {
	m.Mount("GET /oauth/authorize", h.authorize)
	m.Mount("GET /oauth/callback", h.callback)
	m.Mount("POST /oauth/token", h.token)
	m.Mount("POST /oauth/revoke", h.revoke)
}

// RegisterAdmin registers the admin API (security; GET also auditor):
//
//	GET  /v1/connectors              list
//	POST /v1/connectors              register (client secret returned once)
//	GET  /v1/connectors/{id}         one
//	POST /v1/connectors/{id}/disable {reason}  (revokes every grant upstream)
func (h *Handler) RegisterAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/connectors", h.list)
	mux.HandleFunc("POST /v1/connectors", h.register)
	mux.HandleFunc("GET /v1/connectors/{id}", h.get)
	mux.HandleFunc("POST /v1/connectors/{id}/disable", h.disable)
}

func (h *Handler) authorize(w http.ResponseWriter, r *http.Request) {
	to, oe := h.s.Authorize(r.Context(), r.URL.Query())
	if oe != nil {
		h.oauthRedirectOrPage(w, r, oe)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

func (h *Handler) callback(w http.ResponseWriter, r *http.Request) {
	to, oe := h.s.Callback(r.Context(), r.URL.Query(), "browser:"+clip(r.RemoteAddr, 64))
	if oe != nil {
		h.oauthRedirectOrPage(w, r, oe)
		return
	}
	http.Redirect(w, r, to, http.StatusFound)
}

// oauthRedirectOrPage returns an error to the client's (validated) redirect
// URI, or shows it when the redirect URI itself could not be trusted.
func (h *Handler) oauthRedirectOrPage(w http.ResponseWriter, r *http.Request, oe *OAuthError) {
	if oe.Redirect != "" {
		u, err := url.Parse(oe.Redirect)
		if err == nil {
			q := u.Query()
			q.Set("error", oe.Code)
			q.Set("error_description", oe.Desc)
			if oe.State != "" {
				q.Set("state", oe.State)
			}
			u.RawQuery = q.Encode()
			http.Redirect(w, r, u.String(), http.StatusFound)
			return
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusBadRequest)
	_, _ = w.Write([]byte("<!doctype html><title>Fortik</title><h1>Authorization refused</h1><p>" +
		html.EscapeString(oe.Code+": "+oe.Desc) + "</p>"))
}

func clientCreds(r *http.Request) (string, string) {
	if id, sec, ok := r.BasicAuth(); ok {
		id, _ = url.QueryUnescape(id)
		sec, _ = url.QueryUnescape(sec)
		return id, sec
	}
	return r.PostFormValue("client_id"), r.PostFormValue("client_secret")
}

func (h *Handler) token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuth(w, http.StatusBadRequest, map[string]string{"error": "invalid_request", "error_description": "malformed form"})
		return
	}
	id, sec := clientCreds(r)
	res, oe := h.s.Token(r.Context(), id, sec, r.PostForm)
	if oe != nil {
		status := oe.Status
		if status == 0 || status == http.StatusFound {
			status = http.StatusBadRequest
		}
		if status == http.StatusUnauthorized {
			w.Header().Set("WWW-Authenticate", `Basic realm="fortik"`)
		}
		writeOAuth(w, status, map[string]string{"error": oe.Code, "error_description": oe.Desc})
		return
	}
	writeOAuth(w, http.StatusOK, res)
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuth(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}
	id, sec := clientCreds(r)
	if oe := h.s.RevokeToken(r.Context(), id, sec, r.PostFormValue("token")); oe != nil {
		writeOAuth(w, oe.Status, map[string]string{"error": oe.Code, "error_description": oe.Desc})
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func writeOAuth(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// --- admin ---------------------------------------------------------------------

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	cs, err := h.s.List(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"connectors": cs, "callback_url": h.s.CallbackURL()})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	c, err := h.s.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, c)
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var req RegisterRequest
	if err := httpx.DecodeStrict(r, &req, 64<<10); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.s.Register(r.Context(), req, p.Actor())
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	httpx.WriteJSON(w, http.StatusCreated, out)
}

func (h *Handler) disable(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	if err := httpx.DecodeStrict(r, &req, 16<<10); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.s.Disable(r.Context(), r.PathValue("id"), req.Reason, p.Actor())
	if err != nil && res == nil {
		h.fail(w, err)
		return
	}
	body := map[string]any{"connector_id": r.PathValue("id"), "status": "disabled", "grants": res}
	if err != nil {
		body["revoke_errors"] = err.Error()
	}
	httpx.WriteJSON(w, http.StatusOK, body)
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotConfigured):
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
	default:
		if strings.Contains(err.Error(), "duplicate key") {
			httpx.WriteError(w, http.StatusConflict, "already exists")
			return
		}
		h.log.Error("connector", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
	}
}
