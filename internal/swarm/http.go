package swarm

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

const maxBody = 8 << 10

// Handler serves the swarm API on the API listener (api.Server.Mount):
//
//	GET  /v1/swarms?state=&limit=         auditor (or security)
//	GET  /v1/swarms/{id}                  auditor: members, signal, breakers, held calls, release votes, spawn tree
//	POST /v1/swarms/{id}/trip             security {reason, action_hash?}
//	POST /v1/swarms/{id}/suspend|isolate  security {reason}
//	POST /v1/swarms/{id}/kill             security {reason, keep_root_read_only?}
//	POST /v1/swarms/{id}/release          security {reason}: 1st vote {released:false, votes:1, required:2}; a 2nd, different approver releases
//	GET  /v1/swarms/{id}/bundle           auditor: the sealed bundle, signed like Diary exports
//
// Bodies are strict JSON (unknown fields refused); the actor is the
// authenticated principal.
type Handler struct {
	s   *Service
	log *slog.Logger
}

// NewHandler returns the swarm API handler.
func NewHandler(s *Service, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{s: s, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/swarms", h.list)
	mux.HandleFunc("GET /v1/swarms/{id}", h.get)
	mux.HandleFunc("GET /v1/swarms/{id}/bundle", h.bundle)
	mux.HandleFunc("POST /v1/swarms/{id}/trip", h.trip)
	mux.HandleFunc("POST /v1/swarms/{id}/suspend", h.simple(h.s.Suspend))
	mux.HandleFunc("POST /v1/swarms/{id}/isolate", h.simple(h.s.Isolate))
	mux.HandleFunc("POST /v1/swarms/{id}/kill", h.kill)
	mux.HandleFunc("POST /v1/swarms/{id}/release", h.release)
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	q := r.URL.Query()
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be an integer between 1 and 500")
			return
		}
		limit = n
	}
	out, err := h.s.List(r.Context(), strings.TrimSpace(q.Get("state")), limit)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"swarms": out})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	d, err := h.s.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, d)
}

func (h *Handler) bundle(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity)
	if !ok {
		return
	}
	b, err := h.s.Bundle(r.Context(), r.PathValue("id"), p.Actor())
	if err != nil {
		h.fail(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="fortik-swarm-bundle-`+b.SwarmID+`.json"`)
	httpx.WriteJSON(w, http.StatusOK, b)
}

// security checks the role and decodes the strict JSON body.
func security(w http.ResponseWriter, r *http.Request, v any) (authz.Principal, bool) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return p, false
	}
	if err := httpx.DecodeStrict(r, v, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return p, false
	}
	return p, true
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func (h *Handler) simple(fn func(ctx context.Context, id, reason, actor string) (Op, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b reasonBody
		p, ok := security(w, r, &b)
		if !ok {
			return
		}
		op, err := fn(r.Context(), r.PathValue("id"), b.Reason, p.Actor())
		if err != nil {
			h.fail(w, err)
			return
		}
		httpx.WriteJSON(w, http.StatusOK, op)
	}
}

func (h *Handler) trip(w http.ResponseWriter, r *http.Request) {
	var b TripRequest
	p, ok := security(w, r, &b)
	if !ok {
		return
	}
	op, err := h.s.Trip(r.Context(), r.PathValue("id"), b, p.Actor())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, op)
}

func (h *Handler) kill(w http.ResponseWriter, r *http.Request) {
	var b KillRequest
	p, ok := security(w, r, &b)
	if !ok {
		return
	}
	op, err := h.s.Kill(r.Context(), r.PathValue("id"), b, p.Actor())
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, op)
}

func (h *Handler) release(w http.ResponseWriter, r *http.Request) {
	var b reasonBody
	p, ok := security(w, r, &b)
	if !ok {
		return
	}
	res, err := h.s.Release(r.Context(), r.PathValue("id"), b.Reason, ApproverKey(p), p.Actor())
	if err != nil && !res.Released {
		h.fail(w, err)
		return
	}
	if err != nil {
		// Released (two approvers, state committed) but resuming the
		// members could not be recorded: say both.
		h.log.Error("swarm released; resume steps not recorded", "swarm_id", r.PathValue("id"), "err", err)
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"released": true, "votes": res.Votes, "required": res.Required,
			"warning": "the swarm is released, but resuming its members could not be recorded: check its members and resume them individually"})
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

// ApproverKey identifies a distinct release approver: the principal's Diary
// actor, with user emails case-folded so one person cannot vote twice
// (the same rule as held-action approvals).
func ApproverKey(p authz.Principal) string {
	if p.Kind == authz.KindUser {
		return strings.ToLower(p.Actor())
	}
	return p.Actor()
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrAlreadyVoted), errors.Is(err, ErrTwoPerson), errors.Is(err, ErrConflict), errors.Is(err, ErrNotSealed), errors.Is(err, ErrBusy):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrNoSigner):
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
	default:
		h.log.Error("swarm api", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
	}
}
