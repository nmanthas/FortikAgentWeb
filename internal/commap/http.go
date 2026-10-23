package commap

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the map API (docs/PHASE5_DESIGN.md §2):
//
//	GET /v1/map?view=team|agent|swarm|external|blast&id=&from=&to=   auditor (or security)
//	GET /v1/map/path?label=&dest=&from=&to=&depth=                   auditor (or security)
//	GET /v1/map/live                                                 auditor (or security), SSE
//
// Mount it on the API mux (api.Server.Mount(h.Register)).
type Handler struct {
	svc  *Service
	live *Live
	log  *slog.Logger
}

// NewHandler returns the map API handler; live may be nil (no /v1/map/live).
func NewHandler(svc *Service, live *Live, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{svc: svc, live: live, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/map", h.getMap)
	mux.HandleFunc("GET /v1/map/path", h.getPath)
	if h.live != nil {
		mux.Handle("GET /v1/map/live", h.live)
	}
}

var (
	swarmIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$`)
	views          = map[string]bool{ViewTeam: true, ViewAgent: true, ViewSwarm: true, ViewExternal: true, ViewBlast: true}
)

// strictQuery rejects unknown and repeated parameters.
func strictQuery(r *http.Request, allowed ...string) (url.Values, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, errors.New("malformed query string")
	}
	for k, v := range q {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
			}
		}
		if !ok {
			return nil, fmt.Errorf("unknown parameter %q (allowed: %s)", clipName(k), strings.Join(allowed, ", "))
		}
		if len(v) != 1 {
			return nil, fmt.Errorf("parameter %q given more than once", k)
		}
	}
	return q, nil
}

// window parses from/to (RFC 3339). Default: the last hour. The span is at
// most map.retention (older windows are pruned anyway).
func (h *Handler) window(q url.Values) (Window, error) {
	now := h.svc.now()
	w := Window{To: now}
	if v := q.Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Window{}, errors.New("to must be an RFC 3339 time")
		}
		w.To = t.UTC()
	}
	w.From = w.To.Add(-time.Hour)
	if v := q.Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return Window{}, errors.New("from must be an RFC 3339 time")
		}
		w.From = t.UTC()
	}
	switch {
	case !w.From.Before(w.To):
		return Window{}, errors.New("from must be before to")
	case w.To.Sub(w.From) > h.svc.cfg.Retention:
		return Window{}, fmt.Errorf("the range from..to may span at most map.retention (%s)", h.svc.cfg.Retention)
	case w.To.After(now.Add(h.svc.cfg.Window)):
		return Window{}, errors.New("to is in the future")
	}
	return w, nil
}

func (h *Handler) getMap(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	q, err := strictQuery(r, "view", "id", "from", "to")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	view := q.Get("view")
	if view == "" {
		view = ViewAgent
	}
	if !views[view] {
		httpx.WriteError(w, http.StatusBadRequest, "view must be team, agent, swarm, external or blast")
		return
	}
	id := q.Get("id")
	if msg := validID(view, id); msg != "" {
		httpx.WriteError(w, http.StatusBadRequest, msg)
		return
	}
	win, err := h.window(q)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if view == ViewExternal && id != "" {
		id = nodeLabel(DomainNode(id))
	}
	res, err := h.svc.Map(r.Context(), Query{View: view, ID: id, Window: win})
	if errors.Is(err, ErrNotFound) {
		httpx.WriteError(w, http.StatusNotFound, view+" not found")
		return
	}
	if err != nil {
		h.internal(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func validID(view, id string) string {
	switch view {
	case ViewBlast:
		if id == "" {
			return "view=blast needs id=<agent id>"
		}
		fallthrough
	case ViewAgent:
		if id != "" && !agentIDPattern.MatchString(id) {
			return "id must be an agent id"
		}
	case ViewTeam:
		if id != "" && !teamPattern.MatchString(id) {
			return "id must be a team (business unit) name of at most 128 printable characters"
		}
	case ViewSwarm:
		if id != "" && !swarmIDPattern.MatchString(id) {
			return "id must be a swarm id"
		}
	case ViewExternal:
		if id != "" && (DomainNode(id) == "" || strings.HasPrefix(id, "domain:")) {
			return "id must be a host name"
		}
	}
	return ""
}

func (h *Handler) getPath(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	q, err := strictQuery(r, "label", "dest", "from", "to", "depth")
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	label, dest := q.Get("label"), q.Get("dest")
	if !ValidLabel(label) {
		httpx.WriteError(w, http.StatusBadRequest, "label must be a data label (lowercase letters, digits, _ . : -; at most 64)")
		return
	}
	if !ValidNode(dest) {
		httpx.WriteError(w, http.StatusBadRequest, "dest must be a typed node id such as domain:example.com or agent:<id>")
		return
	}
	win, err := h.window(q)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	depth := 0
	if v := q.Get("depth"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > h.svc.limits.MaxDepth {
			httpx.WriteError(w, http.StatusBadRequest, fmt.Sprintf("depth must be an integer between 1 and %d", h.svc.limits.MaxDepth))
			return
		}
		depth = n
	}
	res, err := h.svc.Path(r.Context(), PathQuery{Label: label, Dest: dest, Window: win, Depth: depth})
	if err != nil {
		h.internal(w, r, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, res)
}

func (h *Handler) internal(w http.ResponseWriter, r *http.Request, err error) {
	var pgErr *pgconn.PgError
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &pgErr) && pgErr.Code == "57014") {
		httpx.WriteError(w, http.StatusServiceUnavailable, "map query took too long; narrow the time range or the view")
		return
	}
	h.log.Error("map api error", "path", r.URL.Path, "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}
