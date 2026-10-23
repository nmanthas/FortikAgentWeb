package approvals

import (
	"log/slog"
	"net/http"
	"regexp"
	"strconv"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

// Handler serves the approvals API (docs/PHASE3_DESIGN.md §6 and
// docs/PHASE5_DESIGN.md §5):
//
//	POST /v1/held/{id}/approve   {reason, use_safe_form}   security
//	POST /v1/held/{id}/deny      {reason}                  security
//	POST /v1/held/{id}/assign    {assignee, reason?}       security
//	POST /v1/held/bulk-deny      {action_ids, reason}      security
//	GET  /v1/approvals/queue?status=&agent_id=&swarm_id=&rule_id=&class=
//	     &assigned_to=&sort=&order=&limit=&offset=         auditor or security
//
// The agent's sponsor is refused unless Config.AllowOwnerApproval. The
// caller's identity comes from authz.From (the API's auth middleware).
type Handler struct {
	svc *Service
	log *slog.Logger
}

// NewHandler returns the HTTP handler; mount it with api.Server.Mount(h.Register).
func NewHandler(svc *Service) *Handler { return &Handler{svc: svc, log: svc.log} }

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/held/{id}/approve", h.approve)
	mux.HandleFunc("POST /v1/held/{id}/deny", h.deny)
	mux.HandleFunc("POST /v1/held/{id}/assign", h.assign)
	mux.HandleFunc("POST /v1/held/bulk-deny", h.bulkDeny)
	mux.HandleFunc("GET /v1/approvals/queue", h.queue)
}

var actionIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

func (h *Handler) approve(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !actionIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
		return
	}
	var req ApproveRequest
	if err := httpx.DecodeStrict(r, &req, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.Approve(r.Context(), p, id, req)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	code := http.StatusOK
	if out.Outcome == OutcomePending {
		code = http.StatusAccepted
	}
	httpx.WriteJSON(w, code, out)
}

func (h *Handler) deny(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !actionIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
		return
	}
	var req DenyRequest
	if err := httpx.DecodeStrict(r, &req, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.Deny(r.Context(), p, id, req)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) writeErr(w http.ResponseWriter, err error) {
	code, msg := errStatus(err)
	if code == http.StatusInternalServerError {
		h.log.Error("approvals internal error", "err", err)
	}
	httpx.WriteError(w, code, msg)
}

func (h *Handler) assign(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	id := r.PathValue("id")
	if !actionIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrNotFound.Error())
		return
	}
	var req AssignRequest
	if err := httpx.DecodeStrict(r, &req, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.Assign(r.Context(), p, id, req)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

func (h *Handler) bulkDeny(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	var req BulkDenyRequest
	if err := httpx.DecodeStrict(r, &req, 0); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := h.svc.BulkDeny(r.Context(), p, req)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}

var queueParams = map[string]bool{"status": true, "agent_id": true, "swarm_id": true, "rule_id": true, "class": true,
	"assigned_to": true, "sort": true, "order": true, "limit": true, "offset": true}

func (h *Handler) queue(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity)
	if !ok {
		return
	}
	q := r.URL.Query()
	for k, v := range q {
		if !queueParams[k] {
			httpx.WriteError(w, http.StatusBadRequest, "unknown query parameter "+k)
			return
		}
		if len(v) > 1 {
			httpx.WriteError(w, http.StatusBadRequest, "query parameter "+k+" given more than once")
			return
		}
	}
	f := QueueFilter{Status: q.Get("status"), AgentID: q.Get("agent_id"), SwarmID: q.Get("swarm_id"), RuleID: q.Get("rule_id"),
		Class: q.Get("class"), AssignedTo: q.Get("assigned_to"), Sort: q.Get("sort"), Order: q.Get("order")}
	for name, dst := range map[string]*int{"limit": &f.Limit, "offset": &f.Offset} {
		if v := q.Get(name); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				httpx.WriteError(w, http.StatusBadRequest, name+" must be an integer")
				return
			}
			if name == "limit" && n == 0 {
				n = -1 // explicit 0 is out of range, not the default
			}
			*dst = n
		}
	}
	out, err := h.svc.Queue(r.Context(), p, f)
	if err != nil {
		h.writeErr(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, out)
}
