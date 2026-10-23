package alerts

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the alerts API (docs/PHASE3_DESIGN.md §2.9):
//
//	GET  /v1/alerts?status=&kind=&agent_id=&limit=   auditor (or security)
//	GET  /v1/alerts/{id}                             auditor (or security)
//	POST /v1/alerts/{id}/ack       {"note": "..."}   security
//	POST /v1/alerts/{id}/resolve   {"note": "..."}   security
//
// The body of ack/resolve is optional. Mount it on the API mux (api.Server.Mount).
type Handler struct {
	store *PGStore
	log   *slog.Logger
}

func NewHandler(store *PGStore, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{store: store, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/alerts", h.list)
	mux.HandleFunc("GET /v1/alerts/{id}", h.get)
	mux.HandleFunc("POST /v1/alerts/{id}/ack", h.ack)
	mux.HandleFunc("POST /v1/alerts/{id}/resolve", h.resolve)
}

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	validStatus = map[string]bool{"": true, StatusOpen: true, StatusAcknowledged: true, StatusResolved: true}
)

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	q := r.URL.Query()
	f := Filter{Status: q.Get("status"), Kind: q.Get("kind"), AgentID: q.Get("agent_id")}
	if !validStatus[f.Status] {
		httpx.WriteError(w, http.StatusBadRequest, "status must be open, acknowledged or resolved")
		return
	}
	if f.Kind != "" && !kindPattern.MatchString(f.Kind) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid kind")
		return
	}
	if f.AgentID != "" && !idPattern.MatchString(f.AgentID) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid agent_id")
		return
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be an integer between 1 and 1000")
			return
		}
		f.Limit = n
	}
	out, err := h.store.List(r.Context(), f)
	if err != nil {
		h.internal(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"alerts": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	id := r.PathValue("id")
	if !idPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
		return
	}
	a, err := h.store.Get(r.Context(), id)
	h.respond(w, a, err)
}

type noteBody struct {
	Note string `json:"note"`
}

func (h *Handler) ack(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, h.store.Ack)
}

func (h *Handler) resolve(w http.ResponseWriter, r *http.Request) {
	h.change(w, r, h.store.Resolve)
}

func (h *Handler) change(w http.ResponseWriter, r *http.Request, fn func(ctx context.Context, id, actor, note string) (Alert, error)) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !idPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
		return
	}
	var body noteBody
	if err := httpx.DecodeStrict(r, &body, 8<<10); err != nil && !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	a, err := fn(r.Context(), id, p.Actor(), body.Note)
	h.respond(w, a, err)
}

func (h *Handler) respond(w http.ResponseWriter, a Alert, err error) {
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, a)
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
	case errors.Is(err, ErrState):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	default:
		h.internal(w, err)
	}
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("alerts api", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}
