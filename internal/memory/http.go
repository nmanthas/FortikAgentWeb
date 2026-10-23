package memory

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
)

// Handler serves the memory management API (pass Register to api.Server.Mount):
//
//	GET  /v1/memory/stores                                   auditor | security
//	GET  /v1/memory/snapshots?store=&namespace=&clean=&limit= auditor | security
//	POST /v1/memory/snapshots                                security  {"store","namespace","reason"}
//	POST /v1/memory/snapshots/{id}/restore                   security  {"reason"}
//	POST /v1/memory/items/{store}/{namespace}/{id}/flag      security | owner of the writer  {"reason"}
//	POST /v1/memory/items/{store}/{namespace}/{id}/drop      security | owner of the writer  {"reason"}
//	GET  /v1/agents/{id}/memory                              auditor | security | owner
type Handler struct {
	svc *Service
	log *slog.Logger
}

// NewHandler builds the API handler.
func NewHandler(svc *Service, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{svc: svc, log: log}
}

// Register mounts the routes.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/memory/stores", h.stores)
	mux.HandleFunc("GET /v1/memory/snapshots", h.listSnapshots)
	mux.HandleFunc("POST /v1/memory/snapshots", h.createSnapshot)
	mux.HandleFunc("POST /v1/memory/snapshots/{id}/restore", h.restore)
	mux.HandleFunc("POST /v1/memory/items/{store}/{namespace}/{id}/flag", h.flag)
	mux.HandleFunc("POST /v1/memory/items/{store}/{namespace}/{id}/drop", h.drop)
	mux.HandleFunc("GET /v1/agents/{id}/memory", h.agent)
}

const msgNeedOwner = "security role, or ownership of the agent that wrote the item, required"

func (h *Handler) stores(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	names, err := h.svc.stores.Names(r.Context())
	if err != nil {
		h.internal(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"stores": names})
}

func (h *Handler) listSnapshots(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	q := r.URL.Query()
	f := SnapshotFilter{Store: q.Get("store"), Namespace: q.Get("namespace")}
	if v := q.Get("clean"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "clean must be true or false")
			return
		}
		f.CleanOnly = b
	}
	if v := q.Get("include_purged"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			httpx.WriteError(w, http.StatusBadRequest, "include_purged must be true or false")
			return
		}
		f.IncludePurged = b
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be a positive integer")
			return
		}
		f.Limit = n
	}
	if f.Namespace != "" && !ValidNamespace(f.Namespace) {
		httpx.WriteError(w, http.StatusBadRequest, "namespace must match "+namespacePattern.String())
		return
	}
	list, err := h.svc.ListSnapshots(r.Context(), f)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"snapshots": list})
}

type snapshotBody struct {
	Store     string `json:"store"`
	Namespace string `json:"namespace"`
	Reason    string `json:"reason"`
}

func (h *Handler) createSnapshot(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var b snapshotBody
	if err := httpx.DecodeStrict(r, &b, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if b.Reason == "" {
		httpx.WriteError(w, http.StatusBadRequest, "reason is required")
		return
	}
	sn, err := h.svc.CreateSnapshot(r.Context(), b.Store, b.Namespace, p.Actor(), b.Reason)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusCreated, sn)
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func decodeReason(w http.ResponseWriter, r *http.Request) (string, bool) {
	var b reasonBody
	if err := httpx.DecodeStrict(r, &b, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	if b.Reason == "" {
		httpx.WriteError(w, http.StatusBadRequest, "reason is required")
		return "", false
	}
	return b.Reason, true
}

func (h *Handler) restore(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	reason, ok := decodeReason(w, r)
	if !ok {
		return
	}
	// A restore that started must finish (and be recorded) even if the
	// client goes away.
	res, err := h.svc.RestoreSnapshot(context.WithoutCancel(r.Context()), r.PathValue("id"), p.Actor(), reason)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ownerAuthorize lets security through and otherwise requires the caller to
// own (be the sponsor of) the agent that wrote the item.
func (h *Handler) ownerAuthorize(p authz.Principal) Authorize {
	return func(ctx context.Context, writer string) error {
		if p.Has(authz.RoleSecurity) {
			return nil
		}
		own, err := h.owns(ctx, p, writer)
		if err != nil {
			return err
		}
		if !own {
			return Forbidden(msgNeedOwner)
		}
		return nil
	}
}

func (h *Handler) owns(ctx context.Context, p authz.Principal, agentID string) (bool, error) {
	if p.Kind != authz.KindUser {
		return false, nil
	}
	var sponsor string
	err := h.svc.pool.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, agentID).Scan(&sponsor)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return p.IsOwner(sponsor), nil
}

func (h *Handler) flag(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	reason, ok := decodeReason(w, r)
	if !ok {
		return
	}
	res, err := h.svc.FlagItem(context.WithoutCancel(r.Context()), r.PathValue("store"), r.PathValue("namespace"), r.PathValue("id"),
		p.Actor(), reason, h.ownerAuthorize(p))
	if err != nil {
		h.failItem(w, p, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) drop(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	reason, ok := decodeReason(w, r)
	if !ok {
		return
	}
	it, err := h.svc.DropItem(context.WithoutCancel(r.Context()), r.PathValue("store"), r.PathValue("namespace"), r.PathValue("id"),
		p.Actor(), reason, h.ownerAuthorize(p))
	if err != nil {
		h.failItem(w, p, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"dropped": it.ID, "namespace": it.Namespace, "writer": it.AgentID})
}

func (h *Handler) agent(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !p.Has(authz.RoleSecurity) && !p.Has(authz.RoleAuditor) {
		own, err := h.owns(r.Context(), p, id)
		if err != nil {
			h.internal(w, err)
			return
		}
		if !own {
			httpx.WriteError(w, http.StatusForbidden, "auditor or security role, or ownership of the agent, required")
			return
		}
	}
	limit := 50
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be between 1 and 500")
			return
		}
		limit = n
	}
	var exists bool
	if err := h.svc.pool.QueryRow(r.Context(), `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1)`, id).Scan(&exists); err != nil {
		h.internal(w, err)
		return
	}
	if !exists {
		httpx.WriteError(w, http.StatusNotFound, ErrAgentNotFound.Error())
		return
	}
	view, err := h.svc.AgentView(r.Context(), id, limit)
	if err != nil {
		h.internal(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}

// failItem hides "no such item" from callers who could not see it anyway.
func (h *Handler) failItem(w http.ResponseWriter, p authz.Principal, err error) {
	if errors.Is(err, ErrItemNotFound) && !p.Has(authz.RoleSecurity) {
		httpx.WriteError(w, http.StatusForbidden, msgNeedOwner)
		return
	}
	h.fail(w, err)
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	var f Forbidden
	switch {
	case errors.As(err, &f):
		httpx.WriteError(w, http.StatusForbidden, f.Error())
	case errors.Is(err, ErrInvalid), errors.Is(err, integrations.ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrSnapshotNotFound), errors.Is(err, ErrItemNotFound), errors.Is(err, ErrAgentNotFound):
		httpx.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrStoreNotConfigured):
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
	case errors.Is(err, ErrSnapshotPurged), errors.Is(err, ErrSnapshotMissing):
		httpx.WriteError(w, http.StatusGone, err.Error())
	case errors.Is(err, ErrAlreadyPromoted), errors.Is(err, ErrSnapshotNotClean):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrNotRecorded):
		// The change took effect: say so instead of a bare "internal error".
		h.log.Error("memory api: change applied but not recorded", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "the change was APPLIED but could not be recorded in the Diary (see the server log)")
	default:
		h.internal(w, err)
	}
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("memory api", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}
