package access

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the access-profile API (docs/PHASE2_DESIGN.md §5, §8):
//
//	GET  /v1/agents/{id}/access                    auditor, security or the agent's owner
//	GET  /v1/agents/{id}/access/{system}/history   auditor, security or the agent's owner
//	PUT  /v1/agents/{id}/access/{system}           security; the owner only to narrow
//	POST /v1/agents/{id}/access/{system}/revert    security; the owner only to narrow
//
// The caller's identity comes from authz.From (set by the API's auth
// middleware). Owner = a user principal whose email equals agents.sponsor.
type Handler struct {
	store  *PGStore
	pool   *pgxpool.Pool
	widens WideningChecker
	log    *slog.Logger
}

func NewHandler(store *PGStore, pool *pgxpool.Pool, log *slog.Logger) *Handler {
	return &Handler{store: store, pool: pool, widens: Widens, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agents/{id}/access", h.getAll)
	mux.HandleFunc("GET /v1/agents/{id}/access/{system}/history", h.history)
	mux.HandleFunc("PUT /v1/agents/{id}/access/{system}", h.put)
	mux.HandleFunc("POST /v1/agents/{id}/access/{system}/revert", h.revert)
}

// errWidens is the guard failure for an owner trying to widen.
var errWidens = errors.New("owners may only narrow an access profile; widening requires the security role")

// access levels a caller can hold over an agent's profiles.
type grant int

const (
	grantNone  grant = iota
	grantRead        // auditor
	grantOwner       // sponsor: read, and narrow only
	grantFull        // security: read and any change
)

// authorize resolves the caller's grant for agentID. It writes 401/403/404/500
// and returns ok=false when the caller may not proceed with `need`.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, agentID string, need grant) (authz.Principal, grant, bool) {
	p, ok := authz.From(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return authz.Principal{}, grantNone, false
	}
	sponsor, exists, err := h.sponsor(r.Context(), agentID)
	if err != nil {
		h.internal(w, err)
		return p, grantNone, false
	}
	g := grantNone
	switch {
	case p.Has(authz.RoleSecurity):
		g = grantFull
	case exists && p.IsOwner(sponsor):
		g = grantOwner
	case p.Has(authz.RoleAuditor):
		g = grantRead
	}
	if g < need {
		// Same answer for "no such agent" and "not yours", so non-privileged
		// callers cannot enumerate agents.
		httpx.WriteError(w, http.StatusForbidden, "security role or ownership of this agent required")
		return p, grantNone, false
	}
	if !exists {
		httpx.WriteError(w, http.StatusNotFound, "agent not found")
		return p, grantNone, false
	}
	return p, g, true
}

func (h *Handler) sponsor(ctx context.Context, agentID string) (string, bool, error) {
	var s string
	err := h.pool.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, agentID).Scan(&s)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	return s, true, nil
}

// profileView is one system's current profile; Version 0 and a null profile
// when the agent has none.
type profileView struct {
	System    string          `json:"system"`
	Version   int             `json:"version"`
	Profile   json.RawMessage `json:"profile"`
	ChangedBy string          `json:"changed_by,omitempty"`
	ChangedAt *time.Time      `json:"changed_at,omitempty"`
	Reason    string          `json:"reason,omitempty"`
}

func view(p Profile) profileView {
	t := p.ChangedAt
	return profileView{System: p.System, Version: p.Version, Profile: p.Profile, ChangedBy: p.ChangedBy, ChangedAt: &t, Reason: p.Reason}
}

func (h *Handler) getAll(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if _, _, ok := h.authorize(w, r, id, grantRead); !ok {
		return
	}
	all, err := h.store.All(r.Context(), id)
	if err != nil {
		h.internal(w, err)
		return
	}
	cur := map[string]Profile{}
	for _, p := range all {
		cur[p.System] = p
	}
	out := make([]profileView, 0, len(Systems))
	for _, sys := range Systems {
		if p, ok := cur[sys]; ok {
			out = append(out, view(p))
		} else {
			out = append(out, profileView{System: sys, Profile: json.RawMessage("null")})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_id": id, "profiles": out})
}

func (h *Handler) history(w http.ResponseWriter, r *http.Request) {
	id, sys := r.PathValue("id"), r.PathValue("system")
	if !KnownSystem(sys) {
		httpx.WriteError(w, http.StatusNotFound, "unknown system")
		return
	}
	if _, _, ok := h.authorize(w, r, id, grantRead); !ok {
		return
	}
	limit := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		limit = n
	}
	hist, err := h.store.History(r.Context(), id, sys, limit)
	if err != nil {
		h.internal(w, err)
		return
	}
	out := make([]profileView, 0, len(hist))
	for _, p := range hist {
		out = append(out, view(p))
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_id": id, "system": sys, "versions": out})
}

type putBody struct {
	Profile json.RawMessage `json:"profile"`
	Reason  string          `json:"reason"`
}

type revertBody struct {
	Version int    `json:"version"`
	Reason  string `json:"reason"`
}

func (h *Handler) put(w http.ResponseWriter, r *http.Request) {
	id, sys := r.PathValue("id"), r.PathValue("system")
	if !KnownSystem(sys) {
		httpx.WriteError(w, http.StatusNotFound, "unknown system")
		return
	}
	p, g, ok := h.authorize(w, r, id, grantOwner)
	if !ok {
		return
	}
	var body putBody
	if err := httpx.DecodeStrict(r, &body, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if isNull(body.Profile) {
		httpx.WriteError(w, http.StatusBadRequest, "profile is required")
		return
	}
	saved, err := h.store.PutGuarded(r.Context(), id, sys, body.Profile, p.Actor(), body.Reason, h.guard(sys, g))
	h.respond(w, saved, err)
}

func (h *Handler) revert(w http.ResponseWriter, r *http.Request) {
	id, sys := r.PathValue("id"), r.PathValue("system")
	if !KnownSystem(sys) {
		httpx.WriteError(w, http.StatusNotFound, "unknown system")
		return
	}
	p, g, ok := h.authorize(w, r, id, grantOwner)
	if !ok {
		return
	}
	var body revertBody
	if err := httpx.DecodeStrict(r, &body, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	saved, err := h.store.RevertGuarded(r.Context(), id, sys, body.Version, p.Actor(), body.Reason, h.guard(sys, g))
	h.respond(w, saved, err)
}

// guard returns nil for security (any change) and, for owners, a guard that
// refuses any change that widens the current profile.
func (h *Handler) guard(system string, g grant) Guard {
	if g == grantFull {
		return nil
	}
	return func(prev, next json.RawMessage) error {
		wider, err := h.widens(system, prev, next)
		if err != nil || wider {
			return errWidens
		}
		return nil
	}
}

func (h *Handler) respond(w http.ResponseWriter, saved Profile, err error) {
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, view(saved))
	case errors.Is(err, errWidens):
		httpx.WriteError(w, http.StatusForbidden, errWidens.Error())
	case errors.Is(err, ErrInvalidProfile):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound), errors.Is(err, ErrAgentNotFound):
		httpx.WriteError(w, http.StatusNotFound, err.Error())
	default:
		h.internal(w, err)
	}
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	if h.log != nil {
		h.log.Error("access api", "err", err)
	}
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}
