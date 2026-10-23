package baseline

import (
	"errors"
	"net/http"
	"regexp"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the baseline API (docs/PHASE5_DESIGN.md §4):
//
//	GET /v1/agents/{id}/baseline?verb=   auditor or security
//
// The response is a View: one verb's hourly series and statistics, and the
// list of verbs with counts.
type Handler struct{ svc *Service }

// NewHandler returns the HTTP handler; mount it with api.Server.Mount(h.Register).
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc} }

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agents/{id}/baseline", h.get)
}

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

func (h *Handler) get(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	id := r.PathValue("id")
	if !agentIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrNoAgent.Error())
		return
	}
	q := r.URL.Query()
	for k := range q {
		if k != "verb" {
			httpx.WriteError(w, http.StatusBadRequest, "unknown query parameter "+k)
			return
		}
	}
	if len(q["verb"]) > 1 {
		httpx.WriteError(w, http.StatusBadRequest, "verb given more than once")
		return
	}
	verb := q.Get("verb")
	if verb != "" && !action.KnownVerb(action.Verb(verb)) {
		httpx.WriteError(w, http.StatusBadRequest, "unknown verb")
		return
	}
	view, err := h.svc.AgentBaseline(r.Context(), id, verb)
	switch {
	case errors.Is(err, ErrNoAgent):
		httpx.WriteError(w, http.StatusNotFound, ErrNoAgent.Error())
		return
	case errors.Is(err, ErrStoreUnavailable):
		h.svc.log.Error("baseline API: store unavailable", "err", err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "baseline store unavailable")
		return
	case err != nil:
		h.svc.log.Error("baseline API", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, view)
}
