package containment

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
	"fortik/internal/httpx"
)

const maxBody = 8 << 10

// Handler serves the containment API on the API listener (api.Server.Mount).
// Every write needs a reason and strict JSON; the actor is the
// authenticated principal.
//
//	POST /v1/containment                     a Request (+ "confirm" for estop)
//	POST /v1/agents/{id}/suspend|resume|isolate|kill        {"reason"}
//	POST /v1/agents/{id}/memory/remove       {"reason", "memory_mode"}
//	POST /v1/agents/{id}/memory/restore      {"reason", "rollback_snapshot_id"}
//	POST /v1/agents/{id}/queue/cancel        {"reason"}
//	POST /v1/instances/{id}/suspend|resume   {"reason"}
//	POST /v1/teams/{team}/suspend|resume|kill {"reason"}
//	POST /v1/fleet/estop                     {"reason", "confirm": "STOP ALL AGENTS"}
//	POST /v1/fleet/release                   {"reason", "op_id"}  (op_id "" = every e-stop)
//	GET  /v1/containment?target_type=&target_id=&limit=
//
// Roles: kill, team and fleet operations, cancel_queue and a memory_restore
// with rollback_snapshot_id need security; suspend, resume, isolate and
// memory remove/restore of one agent (or one of its copies) need security
// or the agent's owner (agents.sponsor). An owner lifts (resume,
// memory_restore) only containment they imposed themselves: anything
// imposed by someone else (security, an e-stop, the level API) needs
// security; the manager enforces this under the agent's lock. History:
// auditor or security, or the owner for their agent's history (with only
// that agent's steps).
type Handler struct {
	m   *Manager
	log *slog.Logger
}

func NewHandler(m *Manager, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{m: m, log: log}
}

// Register mounts the routes on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/containment", h.generic)
	mux.HandleFunc("GET /v1/containment", h.list)
	for _, op := range []string{OpSuspend, OpResume, OpIsolate, OpKill} {
		mux.HandleFunc("POST /v1/agents/{id}/"+op, h.simple(op, TargetAgent, "id"))
	}
	mux.HandleFunc("POST /v1/agents/{id}/memory/remove", h.memoryRemove)
	mux.HandleFunc("POST /v1/agents/{id}/memory/restore", h.memoryRestore)
	mux.HandleFunc("POST /v1/agents/{id}/queue/cancel", h.simple(OpCancelQueue, TargetAgent, "id"))
	for _, op := range []string{OpSuspend, OpResume} {
		mux.HandleFunc("POST /v1/instances/{id}/"+op, h.simple(op, TargetInstance, "id"))
	}
	for _, op := range []string{OpSuspend, OpResume, OpKill} {
		mux.HandleFunc("POST /v1/teams/{team}/"+op, h.simple(op, TargetTeam, "team"))
	}
	mux.HandleFunc("POST /v1/fleet/estop", h.estop)
	mux.HandleFunc("POST /v1/fleet/release", h.release)
}

type genericBody struct {
	Op                 string `json:"op"`
	TargetType         string `json:"target_type"`
	TargetID           string `json:"target_id"`
	Reason             string `json:"reason"`
	MemoryMode         string `json:"memory_mode"`
	RollbackSnapshotID string `json:"rollback_snapshot_id"`
	Confirm            string `json:"confirm"`
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func (h *Handler) generic(w http.ResponseWriter, r *http.Request) {
	var b genericBody
	if !decode(w, r, &b) {
		return
	}
	h.run(w, r, Request{Op: b.Op, TargetType: b.TargetType, TargetID: b.TargetID, Reason: b.Reason,
		MemoryMode: b.MemoryMode, RollbackSnapshotID: b.RollbackSnapshotID}, b.Confirm)
}

func (h *Handler) simple(op, targetType, pathKey string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b reasonBody
		if !decode(w, r, &b) {
			return
		}
		h.run(w, r, Request{Op: op, TargetType: targetType, TargetID: r.PathValue(pathKey), Reason: b.Reason}, "")
	}
}

func (h *Handler) memoryRemove(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reason     string `json:"reason"`
		MemoryMode string `json:"memory_mode"`
	}
	if !decode(w, r, &b) {
		return
	}
	h.run(w, r, Request{Op: OpMemoryRemove, TargetType: TargetAgent, TargetID: r.PathValue("id"), Reason: b.Reason, MemoryMode: b.MemoryMode}, "")
}

func (h *Handler) memoryRestore(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reason             string `json:"reason"`
		RollbackSnapshotID string `json:"rollback_snapshot_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	h.run(w, r, Request{Op: OpMemoryRestore, TargetType: TargetAgent, TargetID: r.PathValue("id"), Reason: b.Reason,
		RollbackSnapshotID: b.RollbackSnapshotID}, "")
}

func (h *Handler) estop(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reason  string `json:"reason"`
		Confirm string `json:"confirm"`
	}
	if !decode(w, r, &b) {
		return
	}
	h.run(w, r, Request{Op: OpEStop, TargetType: TargetFleet, TargetID: FleetTargetID, Reason: b.Reason}, b.Confirm)
}

func (h *Handler) release(w http.ResponseWriter, r *http.Request) {
	var b struct {
		Reason string `json:"reason"`
		OpID   string `json:"op_id"`
	}
	if !decode(w, r, &b) {
		return
	}
	target := strings.TrimSpace(b.OpID)
	if target == "" {
		target = FleetTargetID
	}
	h.run(w, r, Request{Op: OpEStopRelease, TargetType: TargetFleet, TargetID: target, Reason: b.Reason}, "")
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if _, ok := authz.Require(w, r); !ok {
		return false
	}
	if err := httpx.DecodeStrict(r, v, maxBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func (h *Handler) run(w http.ResponseWriter, r *http.Request, req Request, confirm string) {
	p, _ := authz.From(r.Context())
	if !h.authorize(w, r, p, req) {
		return
	}
	op, err := h.m.RunAs(r.Context(), req, confirm, Caller{Actor: p.Actor(), Security: p.Has(authz.RoleSecurity)})
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, op)
	case errors.Is(err, ErrForbidden):
		httpx.WriteError(w, http.StatusForbidden, err.Error())
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrNotFound):
		httpx.WriteError(w, http.StatusNotFound, err.Error())
	case errors.Is(err, ErrConflict), errors.Is(err, ErrBusy):
		httpx.WriteError(w, http.StatusConflict, err.Error())
	default:
		h.internal(w, err)
	}
}

// authorize applies the role rules. For a caller without the security
// role, a missing target and a target they do not own get the same 403, so
// agents cannot be enumerated.
func (h *Handler) authorize(w http.ResponseWriter, r *http.Request, p authz.Principal, req Request) bool {
	if p.Has(authz.RoleSecurity) {
		return true
	}
	if SecurityOnly(req) {
		httpx.WriteError(w, http.StatusForbidden, "the security role is required for "+opLabel(req))
		return false
	}
	sponsor, err := h.ownerOf(r.Context(), req)
	if err != nil {
		h.internal(w, err)
		return false
	}
	if !p.IsOwner(sponsor) {
		httpx.WriteError(w, http.StatusForbidden, "security role or ownership of this agent required")
		return false
	}
	// Whether the owner may lift the target's current containment (D2) is
	// decided by the manager under the agent's lock (RunAs, ErrForbidden).
	return true
}

// ownerOf returns the sponsor of the agent (or of the instance's agent); ""
// when there is no such target.
func (h *Handler) ownerOf(ctx context.Context, req Request) (string, error) {
	var sponsor string
	var err error
	switch req.TargetType {
	case TargetAgent:
		err = h.m.pool.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, strings.TrimSpace(req.TargetID)).Scan(&sponsor)
	case TargetInstance:
		err = h.m.pool.QueryRow(ctx, `SELECT a.sponsor FROM instances i JOIN agents a ON a.agent_id = i.agent_id
			WHERE i.instance_id = $1`, strings.TrimSpace(req.TargetID)).Scan(&sponsor)
	default:
		return "", nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return sponsor, err
}

func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	targetType, targetID := q.Get("target_type"), q.Get("target_id")
	ownerOnly := !p.Has(authz.RoleAuditor) && !p.Has(authz.RoleSecurity)
	if ownerOnly {
		allowed := false
		if targetType == TargetAgent && targetID != "" {
			sponsor, err := h.ownerOf(r.Context(), Request{TargetType: TargetAgent, TargetID: targetID})
			if err != nil {
				h.internal(w, err)
				return
			}
			allowed = p.IsOwner(sponsor)
		}
		if !allowed {
			httpx.WriteError(w, http.StatusForbidden, "auditor or security role, or ownership of the agent (target_type=agent&target_id=...), required")
			return
		}
	}
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > MaxListLimit {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be an integer between 1 and "+strconv.Itoa(MaxListLimit))
			return
		}
		limit = n
	}
	ops, err := h.m.List(r.Context(), targetType, targetID, limit)
	if err == nil && ownerOnly {
		// An owner sees only their agent's part of team and fleet
		// operations: other agents' ids and steps are not theirs to read.
		for i := range ops {
			ops[i] = ownView(ops[i], targetID)
		}
	}
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"operations": ops})
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		h.internal(w, err)
	}
}

func (h *Handler) internal(w http.ResponseWriter, err error) {
	h.log.Error("containment api", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}

// ownView keeps only agentID's steps of op (and the operation-wide steps of
// an operation that targeted agentID itself).
func ownView(op Op, agentID string) Op {
	own := op.TargetType == TargetAgent && op.TargetID == agentID || op.TargetType == TargetInstance
	steps := make([]Step, 0, len(op.Steps))
	for _, s := range op.Steps {
		if s.AgentID == agentID || s.AgentID == "" && own {
			steps = append(steps, s)
		}
	}
	op.Steps = steps
	return op
}
