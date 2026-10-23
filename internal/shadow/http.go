package shadow

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the shadow-discovery API (docs/PHASE5_DESIGN.md §3):
//
//	GET  /v1/shadow?status=&system=&kind=&agent_id=&limit=   auditor (or security)
//	GET  /v1/shadow/{id}                                      auditor (or security)
//	POST /v1/shadow/scan           {} or {"reason"}          security
//	POST /v1/shadow/{id}/revoke    {} or {"reason"}          security
//	POST /v1/shadow/{id}/dismiss   {} or {"reason"}          security
//	POST /v1/shadow/{id}/register  {"sponsor","name","team","reason"?}  security
//
// Mount it on the API mux: api.Server.Mount(h.Register).
type Handler struct {
	svc *Service
	log *slog.Logger
}

// NewHandler returns the API handler.
func NewHandler(svc *Service, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{svc: svc, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/shadow", h.list)
	mux.HandleFunc("POST /v1/shadow/scan", h.scan)
	mux.HandleFunc("GET /v1/shadow/{id}", h.get)
	mux.HandleFunc("POST /v1/shadow/{id}/revoke", h.revoke)
	mux.HandleFunc("POST /v1/shadow/{id}/dismiss", h.dismiss)
	mux.HandleFunc("POST /v1/shadow/{id}/register", h.register)
}

const maxBody = 16 << 10

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	q := r.URL.Query()
	for k := range q {
		switch k {
		case "status", "system", "kind", "agent_id", "limit":
		default:
			httpx.WriteError(w, http.StatusBadRequest, "unknown query parameter "+strconv.Quote(Clean(k, 40)))
			return
		}
	}
	f := Filter{Status: q.Get("status"), System: q.Get("system"), Kind: q.Get("kind"), AgentID: q.Get("agent_id")}
	if f.Status != "" && !validStatus[f.Status] {
		httpx.WriteError(w, http.StatusBadRequest, "status must be open, flagged_for_revocation, revoked, dismissed or registered")
		return
	}
	if f.System != "" && !validSystem[f.System] {
		httpx.WriteError(w, http.StatusBadRequest, "system must be postgres, github, aws, google_workspace or traffic")
		return
	}
	if f.Kind != "" && !kindPattern.MatchString(f.Kind) {
		httpx.WriteError(w, http.StatusBadRequest, "invalid kind")
		return
	}
	if f.AgentID != "" && !agentIDPattern.MatchString(f.AgentID) {
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
	out, err := h.svc.List(r.Context(), f)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"findings": out, "last_scan": h.svc.LastScan()})
}

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	f, err := h.svc.Get(r.Context(), r.PathValue("id"))
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, f)
}

func (h *Handler) scan(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var body reasonBody
	if !decodeOptional(w, r, &body) {
		return
	}
	if err := validText("reason", body.Reason, 1000, false); err != nil {
		h.fail(w, err)
		return
	}
	// The scan completes even if the caller disconnects (its findings and
	// discovered agents must not be left half-applied).
	rep, err := h.svc.Scan(context.WithoutCancel(r.Context()), p.Actor(), body.Reason)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, rep)
}

type reasonBody struct {
	Reason string `json:"reason"`
}

// decodeOptional accepts an empty body, {} or {"reason": "..."} (strict:
// unknown fields and trailing data are refused).
func decodeOptional(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := httpx.DecodeStrict(r, v, maxBody); err != nil && !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, err.Error()+" (want an empty body, {} or {\"reason\": \"...\"})")
		return false
	}
	return true
}

func (h *Handler) revoke(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var body reasonBody
	if !decodeOptional(w, r, &body) {
		return
	}
	f, res, err := h.svc.Revoke(context.WithoutCancel(r.Context()), r.PathValue("id"), p.Actor(), body.Reason)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"finding": f, "outcome": res.Outcome, "revoked": res.Outcome == OutcomeRevoked, "detail": res.Detail})
}

func (h *Handler) dismiss(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var body reasonBody
	if !decodeOptional(w, r, &body) {
		return
	}
	f, err := h.svc.Dismiss(r.Context(), r.PathValue("id"), p.Actor(), body.Reason)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, f)
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var body RegisterInput
	if err := httpx.DecodeStrict(r, &body, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error()+" (want {\"sponsor\", \"name\", \"team\", \"reason\"})")
		return
	}
	f, err := h.svc.Register(r.Context(), r.PathValue("id"), p.Actor(), body)
	if err != nil {
		h.fail(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"finding": f, "agent_id": f.AgentID,
		"note": "the agent keeps its current level (a discovered agent starts ISOLATED); step it up through the level API"})
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrState), errors.Is(err, ErrScanRunning), errors.Is(err, ErrAgentConflict):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	case errors.Is(err, ErrNotRecorded):
		h.log.Error("shadow api", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, err.Error())
	default:
		h.log.Error("shadow api", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
	}
}
