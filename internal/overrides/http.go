package overrides

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the overrides API (docs/PHASE3_DESIGN.md §5):
//
//	POST /v1/overrides                    security; the agent's owner for agent scope on their own agent
//	POST /v1/overrides/{id}/release       security; the owner only for an override they created themselves
//	POST /v1/overrides/{id}/extend        security; the owner for agent scope on their own agent
//	POST /v1/overrides/{id}/permanent     security; the owner for agent scope on their own agent
//	GET  /v1/overrides?agent_id=&status=  auditor or security; the owner with agent_id = their own agent
//	GET  /v1/overrides/{id}               auditor or security; the owner for agent scope on their own agent
//
// Team scope always needs the security role. Owner = a user principal whose
// email equals agents.sponsor; ownership is checked inside the change
// transaction with the override row locked. An owner may tighten an
// override set by anyone on their agent (extend, make permanent) but may only
// release one they created: lifting a security team's suspension needs the
// security role.
type Handler struct {
	store *PGStore
	log   *slog.Logger
}

// NewHandler returns the overrides API handler.
func NewHandler(store *PGStore, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{store: store, log: log}
}

// Register mounts the routes (pass to api.Server.Mount).
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/overrides", h.create)
	mux.HandleFunc("GET /v1/overrides", h.list)
	mux.HandleFunc("GET /v1/overrides/{id}", h.get)
	mux.HandleFunc("POST /v1/overrides/{id}/release", h.release)
	mux.HandleFunc("POST /v1/overrides/{id}/extend", h.extend)
	mux.HandleFunc("POST /v1/overrides/{id}/permanent", h.permanent)
}

// forbidden is an authorization refusal (403) with its message.
type forbidden string

func (f forbidden) Error() string { return string(f) }

const (
	msgNeedOwner    = "security role or ownership of this agent required"
	msgTeamSecurity = "team overrides require the security role"
	msgReleaseOwn   = "owners may only release overrides they created; lifting someone else's override requires the security role"
)

type createBody struct {
	Scope           string `json:"scope"`
	ScopeID         string `json:"scope_id"`
	System          string `json:"system"`
	Mode            string `json:"mode"`
	DurationSeconds *int64 `json:"duration_seconds"`
	UntilReleased   bool   `json:"until_released"`
	Reason          string `json:"reason"`
}

type extendBody struct {
	DurationSeconds *int64 `json:"duration_seconds"`
	Reason          string `json:"reason"`
}

type reasonBody struct {
	Reason string `json:"reason"`
}

// principal returns the caller; only security or a user (who may be an
// owner) can change overrides at all.
func principal(w http.ResponseWriter, r *http.Request) (authz.Principal, bool) {
	p, ok := authz.Require(w, r)
	if !ok {
		return p, false
	}
	if !p.Has(authz.RoleSecurity) && p.Kind != authz.KindUser {
		httpx.WriteError(w, http.StatusForbidden, msgNeedOwner)
		return p, false
	}
	return p, true
}

func ownsAgent(ctx context.Context, q pgx.Tx, p authz.Principal, agentID string) (bool, error) {
	var sponsor string
	err := q.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, agentID).Scan(&sponsor)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.IsOwner(sponsor), nil
}

// ownerAuthorizer allows security, or the owner of an agent-scope override's agent.
func ownerAuthorizer(p authz.Principal) Authorizer {
	return func(ctx context.Context, tx pgx.Tx, o Override) error {
		if p.Has(authz.RoleSecurity) {
			return nil
		}
		if o.Scope != ScopeAgent {
			return forbidden(msgTeamSecurity)
		}
		owns, err := ownsAgent(ctx, tx, p, o.ScopeID)
		if err != nil {
			return err
		}
		if !owns {
			return forbidden(msgNeedOwner)
		}
		return nil
	}
}

func (h *Handler) create(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	var body createBody
	if err := httpx.DecodeStrict(r, &body, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Scope == "" {
		body.Scope = ScopeAgent
	}
	if body.Scope == ScopeTeam && !p.Has(authz.RoleSecurity) {
		httpx.WriteError(w, http.StatusForbidden, msgTeamSecurity)
		return
	}
	req := CreateRequest{Scope: body.Scope, ScopeID: body.ScopeID, System: body.System, Mode: body.Mode,
		UntilReleased: body.UntilReleased, Reason: body.Reason}
	switch {
	case body.DurationSeconds != nil && body.UntilReleased:
		httpx.WriteError(w, http.StatusBadRequest, "give either duration_seconds or until_released, not both")
		return
	case body.DurationSeconds != nil:
		d, err := h.duration(*body.DurationSeconds)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, err.Error())
			return
		}
		req.Duration = d
	case !body.UntilReleased:
		httpx.WriteError(w, http.StatusBadRequest, "duration_seconds or until_released is required")
		return
	}
	o, err := h.store.Create(r.Context(), req, p.Actor(), ownerAuthorizer(p))
	if err != nil {
		h.fail(w, p, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, o)
}

// duration converts and bounds duration_seconds without overflow.
func (h *Handler) duration(secs int64) (time.Duration, error) {
	if secs <= 0 || secs > int64(h.store.maxDuration/time.Second) {
		return 0, invalid("duration_seconds must be between %d and %d", int64(h.store.minDuration/time.Second), int64(h.store.maxDuration/time.Second))
	}
	d := time.Duration(secs) * time.Second
	if err := h.store.checkDuration(d); err != nil {
		return 0, err
	}
	return d, nil
}

func (h *Handler) release(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	var body reasonBody
	if err := decodeOptional(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	owner := ownerAuthorizer(p)
	o, err := h.store.Release(r.Context(), r.PathValue("id"), p.Actor(), body.Reason, func(ctx context.Context, tx pgx.Tx, o Override) error {
		if err := owner(ctx, tx, o); err != nil {
			return err
		}
		if !p.Has(authz.RoleSecurity) && o.CreatedBy != p.Actor() {
			return forbidden(msgReleaseOwn)
		}
		return nil
	})
	h.respond(w, p, o, err)
}

func (h *Handler) extend(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	var body extendBody
	if err := httpx.DecodeStrict(r, &body, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.DurationSeconds == nil {
		httpx.WriteError(w, http.StatusBadRequest, "duration_seconds is required")
		return
	}
	d, err := h.duration(*body.DurationSeconds)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	o, err := h.store.Extend(r.Context(), r.PathValue("id"), d, p.Actor(), body.Reason, ownerAuthorizer(p))
	h.respond(w, p, o, err)
}

func (h *Handler) permanent(w http.ResponseWriter, r *http.Request) {
	p, ok := principal(w, r)
	if !ok {
		return
	}
	var body reasonBody
	if err := decodeOptional(r, &body); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	o, err := h.store.MakePermanent(r.Context(), r.PathValue("id"), p.Actor(), body.Reason, ownerAuthorizer(p))
	h.respond(w, p, o, err)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	f := ListFilter{AgentID: q.Get("agent_id"), Status: q.Get("status")}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}
	if !p.Has(authz.RoleSecurity) && !p.Has(authz.RoleAuditor) {
		allowed := false
		if f.AgentID != "" && p.Kind == authz.KindUser {
			var err error
			allowed, err = h.ownsAgentPool(r.Context(), p, f.AgentID)
			if err != nil {
				h.internal(w, err)
				return
			}
		}
		if !allowed {
			httpx.WriteError(w, http.StatusForbidden, "auditor or security role, or agent_id of an agent you own, required")
			return
		}
	}
	out, err := h.store.List(r.Context(), f)
	if err != nil {
		h.fail(w, p, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"overrides": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	o, err := h.store.Get(r.Context(), r.PathValue("id"))
	privileged := p.Has(authz.RoleSecurity) || p.Has(authz.RoleAuditor)
	if err != nil {
		if !privileged && errors.Is(err, ErrNotFound) {
			httpx.WriteError(w, http.StatusForbidden, msgNeedOwner)
			return
		}
		h.fail(w, p, err)
		return
	}
	if !privileged {
		owns := false
		if o.Scope == ScopeAgent && p.Kind == authz.KindUser {
			owns, err = h.ownsAgentPool(r.Context(), p, o.ScopeID)
			if err != nil {
				h.internal(w, err)
				return
			}
		}
		if !owns {
			httpx.WriteError(w, http.StatusForbidden, msgNeedOwner)
			return
		}
	}
	httpx.WriteJSON(w, http.StatusOK, o)
}

func (h *Handler) ownsAgentPool(ctx context.Context, p authz.Principal, agentID string) (bool, error) {
	var sponsor string
	err := h.store.pool.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, agentID).Scan(&sponsor)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.IsOwner(sponsor), nil
}

// decodeOptional decodes a strict JSON body that may be empty.
func decodeOptional(r *http.Request, v any) error {
	if r.Body == nil {
		return nil
	}
	br := bufio.NewReader(r.Body)
	if _, err := br.Peek(1); errors.Is(err, io.EOF) {
		return nil
	}
	r.Body = io.NopCloser(br)
	return httpx.DecodeStrict(r, v, 0)
}

func (h *Handler) respond(w http.ResponseWriter, p authz.Principal, o Override, err error) {
	if err != nil {
		h.fail(w, p, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, o)
}

func (h *Handler) fail(w http.ResponseWriter, p authz.Principal, err error) {
	var f forbidden
	switch {
	case errors.As(err, &f):
		httpx.WriteError(w, http.StatusForbidden, f.Error())
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrScopeNotFound), errors.Is(err, ErrNotFound):
		// Non-privileged callers get the same answer for "no such agent or
		// override" and "not yours", so they cannot enumerate.
		if !p.Has(authz.RoleSecurity) && !p.Has(authz.RoleAuditor) {
			httpx.WriteError(w, http.StatusForbidden, msgNeedOwner)
			return
		}
		httpx.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	default:
		h.internal(w, err)
	}
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("overrides api", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}
