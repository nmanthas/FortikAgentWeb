package population

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/broker"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/httpx"
)

// HeaderActionID carries the decided action's id (same header as the broker
// and the gateway).
const HeaderActionID = broker.HeaderActionID

const maxInstanceBody = 8 << 10

// registerAttempts bounds re-decisions after a lost registration race
// (ErrSpawnRaceLost makes the decision fail closed; the next attempt sees
// the fresh counts and policy refuses by rule).
const registerAttempts = 3

// Mounter is satisfied by *gateway.Server (agent-authenticated routes).
type Mounter interface {
	Mount(pattern string, h http.HandlerFunc)
}

// GatewayHandler serves the agent-facing instance API (docs/PHASE3_DESIGN.md
// §2.1) on the gateway listener. The agent comes from the authenticated
// principal (authz kind agent), never from the body.
//
//	POST /v1/instances/register   {instance_id, host, parent_instance_id}  201 | 403 | 429
//	POST /v1/instances/heartbeat  {instance_id}                            200 | 410 | 423 {"action":"pause"}
//	POST /v1/instances/stop       {instance_id}                            200
type GatewayHandler struct {
	svc *Service
	dec decide.Decider
	log *slog.Logger
}

func NewGatewayHandler(svc *Service, dec decide.Decider, log *slog.Logger) *GatewayHandler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &GatewayHandler{svc: svc, dec: dec, log: log}
}

// Mount adds the routes to the gateway (gateway.Server.Mount).
func (h *GatewayHandler) Mount(m Mounter) {
	m.Mount("POST /v1/instances/register", h.register)
	m.Mount("POST /v1/instances/heartbeat", h.heartbeat)
	m.Mount("POST /v1/instances/stop", h.stop)
}

// Register adds the routes to a mux whose requests already carry an agent
// principal (tests, or a custom listener).
func (h *GatewayHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/instances/register", h.register)
	mux.HandleFunc("POST /v1/instances/heartbeat", h.heartbeat)
	mux.HandleFunc("POST /v1/instances/stop", h.stop)
}

func agentPrincipal(w http.ResponseWriter, r *http.Request) (authz.Principal, bool) {
	p, ok := authz.From(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return p, false
	}
	if p.Kind != authz.KindAgent || p.Name == "" {
		httpx.WriteError(w, http.StatusForbidden, "an agent token is required")
		return p, false
	}
	return p, true
}

type registerRequest struct {
	InstanceID       string `json:"instance_id"`
	Host             string `json:"host"`
	ParentInstanceID string `json:"parent_instance_id"`
}

type instanceRequest struct {
	InstanceID string `json:"instance_id"`
}

func validHost(hst string) bool {
	if len(hst) > maxHostLen {
		return false
	}
	for _, r := range hst {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return false
		}
	}
	return true
}

func (h *GatewayHandler) register(w http.ResponseWriter, r *http.Request) {
	p, ok := agentPrincipal(w, r)
	if !ok {
		return
	}
	var req registerRequest
	if err := httpx.DecodeStrict(r, &req, maxInstanceBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !instanceIDPattern.MatchString(req.InstanceID) {
		httpx.WriteError(w, http.StatusBadRequest, "instance_id must match "+instanceIDPattern.String())
		return
	}
	if !validHost(req.Host) {
		httpx.WriteError(w, http.StatusBadRequest, fmt.Sprintf("host must be at most %d bytes without spaces or control characters", maxHostLen))
		return
	}
	if req.ParentInstanceID != "" && !instanceIDPattern.MatchString(req.ParentInstanceID) {
		httpx.WriteError(w, http.StatusBadRequest, "parent_instance_id must match "+instanceIDPattern.String())
		return
	}
	ctx := r.Context()
	pre, err := h.svc.preRegister(ctx, p.Name, req)
	switch {
	case errors.Is(err, ErrInstanceExists):
		httpx.WriteError(w, http.StatusConflict, ErrInstanceExists.Error())
		return
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	case err != nil:
		h.log.Error("instance registration lookup failed; refusing", "agent_id", p.Name, "err", err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "Fortik could not decide: refused")
		return
	}
	target := map[string]any{
		"operation": OperationSpawn, "instance_id": req.InstanceID, "host": req.Host,
		"parent_instance_id": req.ParentInstanceID, "new_host": pre.newHost,
	}
	if pre.parentAgent != "" {
		target["parent_agent_id"] = pre.parentAgent
	}
	var out decide.Outcome
	for attempt := 0; attempt < registerAttempts; attempt++ {
		lost := new(atomic.Bool)
		dctx := withRaceFlag(decide.WithActor(ctx, p.Actor()), lost)
		a := action.Action{
			ActionID: action.NewID("act"), AgentID: p.Name, InstanceID: req.InstanceID,
			System: SystemAgents, Verb: action.VerbDelegate, Source: action.SourceAppGateway, Target: target,
		}
		out, err = h.dec.Decide(dctx, a)
		if err != nil {
			if errors.Is(err, action.ErrInvalid) {
				httpx.WriteError(w, http.StatusBadRequest, "registration could not be expressed as a valid action: refused")
				return
			}
			h.log.Error("decide failed; refusing registration", "agent_id", p.Name, "err", err)
			httpx.WriteError(w, http.StatusInternalServerError, "Fortik could not decide: refused")
			return
		}
		// Only a lost registration race is retried; any other fail-closed
		// outcome is final.
		if !out.FailClosed || !lost.Load() {
			break
		}
	}
	w.Header().Set(HeaderActionID, out.Action.ActionID)
	if out.Result.Decision.Executes() {
		httpx.WriteJSON(w, http.StatusCreated, map[string]any{
			"instance_id": req.InstanceID, "status": StatusLive, "new_host": pre.newHost,
			"heartbeat_interval_s": int(h.svc.cfg.HeartbeatInterval.Seconds()),
			"stale_after_s":        int(h.svc.cfg.StaleAfter.Seconds()),
			"action_id":            out.Action.ActionID,
		})
		return
	}
	if out.FailClosed {
		// The observer did not run on the fail-closed path: store the
		// refused instance here (best effort; the refusal stands either way).
		h.svc.recordRefusedBestEffort(ctx, out, req)
	}
	code := http.StatusForbidden
	switch out.Result.RuleID {
	case RuleSpawnRate:
		code = http.StatusTooManyRequests
		w.Header().Set("Retry-After", strconv.Itoa(int(h.svc.cfg.SpikeCooldown.Seconds())))
	case RuleActionRate:
		code = http.StatusTooManyRequests
		w.Header().Set("Retry-After", "60")
	}
	writeRefusal(w, code, out)
}

// writeRefusal writes the refusal JSON of broker.WriteRefusal with the
// given status (403 for caps and policy, 429 for rate limits).
func writeRefusal(w http.ResponseWriter, code int, out decide.Outcome) {
	if code == http.StatusForbidden {
		broker.WriteRefusal(w, out)
		return
	}
	w.Header().Set(HeaderActionID, out.Action.ActionID)
	httpx.WriteJSON(w, code, map[string]any{"error": broker.RefusalBody{
		Code: "fortik_refused", Decision: string(out.Result.Decision), Class: string(out.Result.Class),
		RuleID: out.Result.RuleID, Reason: out.Result.Reason, ActionID: out.Action.ActionID, Held: out.Held,
	}})
}

func (h *GatewayHandler) heartbeat(w http.ResponseWriter, r *http.Request) {
	p, ok := agentPrincipal(w, r)
	if !ok {
		return
	}
	var req instanceRequest
	if err := httpx.DecodeStrict(r, &req, maxInstanceBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !instanceIDPattern.MatchString(req.InstanceID) {
		httpx.WriteError(w, http.StatusBadRequest, "instance_id must match "+instanceIDPattern.String())
		return
	}
	in, err := h.svc.Heartbeat(r.Context(), p.Name, req.InstanceID)
	var gone *GoneError
	var suspended *SuspendedError
	switch {
	case errors.As(err, &suspended):
		// 423 Locked: the copy stays registered but must pause until resumed.
		httpx.WriteJSON(w, http.StatusLocked, map[string]any{
			"action": "pause", "instance_id": suspended.Instance.InstanceID, "status": suspended.Instance.Status,
			"reason":               suspended.Instance.Reason,
			"heartbeat_interval_s": int(h.svc.cfg.HeartbeatInterval.Seconds()),
		})
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, map[string]any{
			"instance_id": in.InstanceID, "status": in.Status,
			"heartbeat_interval_s": int(h.svc.cfg.HeartbeatInterval.Seconds()),
		})
	case errors.As(err, &gone):
		httpx.WriteJSON(w, http.StatusGone, map[string]any{"error": map[string]any{
			"code": "instance_not_live", "instance_id": gone.Instance.InstanceID, "status": gone.Instance.Status,
			"reason": gone.Instance.Reason, "message": "this instance must stop",
		}})
	case errors.Is(err, ErrInstanceNotFound):
		httpx.WriteError(w, http.StatusNotFound, ErrInstanceNotFound.Error())
	default:
		h.log.Error("heartbeat failed", "agent_id", p.Name, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
	}
}

func (h *GatewayHandler) stop(w http.ResponseWriter, r *http.Request) {
	p, ok := agentPrincipal(w, r)
	if !ok {
		return
	}
	var req instanceRequest
	if err := httpx.DecodeStrict(r, &req, maxInstanceBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	if !instanceIDPattern.MatchString(req.InstanceID) {
		httpx.WriteError(w, http.StatusBadRequest, "instance_id must match "+instanceIDPattern.String())
		return
	}
	in, err := h.svc.Stop(r.Context(), p.Name, req.InstanceID, p.Actor())
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, map[string]any{"instance_id": in.InstanceID, "status": in.Status})
	case errors.Is(err, ErrInstanceNotFound):
		httpx.WriteError(w, http.StatusNotFound, ErrInstanceNotFound.Error())
	default:
		h.log.Error("instance stop failed", "agent_id", p.Name, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
	}
}

// preRegistration holds the lookups made before deciding a registration.
type preRegistration struct {
	newHost     bool
	parentAgent string
}

// preRegister checks the id is new, resolves the parent instance and
// computes new_host (first time this agent is seen on the host; refused
// attempts do not count as seen).
func (s *Service) preRegister(ctx context.Context, agentID string, req registerRequest) (preRegistration, error) {
	var pre preRegistration
	var exists bool
	var parentAgent *string
	err := s.pool.QueryRow(ctx, `SELECT
			EXISTS (SELECT 1 FROM instances WHERE instance_id = $1),
			(SELECT agent_id FROM instances WHERE instance_id = NULLIF($2, '')),
			$3 <> '' AND NOT EXISTS (SELECT 1 FROM instances WHERE agent_id = $4 AND host = $3 AND status <> 'refused')`,
		req.InstanceID, req.ParentInstanceID, req.Host, agentID).Scan(&exists, &parentAgent, &pre.newHost)
	if err != nil {
		return pre, err
	}
	if exists {
		return pre, ErrInstanceExists
	}
	if req.ParentInstanceID != "" {
		if parentAgent == nil {
			return pre, fmt.Errorf("%w: unknown parent_instance_id", ErrInvalid)
		}
		pre.parentAgent = *parentAgent
	}
	return pre, nil
}

// recordRefusedBestEffort stores a registration refused on the decision's
// fail-closed path (no observer ran) as a refused instance.
func (s *Service) recordRefusedBestEffort(ctx context.Context, out decide.Outcome, req registerRequest) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	reason := clip(fmt.Sprintf("%s: %s", out.Result.RuleID, out.Result.Reason), maxReasonLen)
	err := pgx.BeginFunc(rctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(rctx, `
			INSERT INTO instances (instance_id, agent_id, host, parent_instance_id, started_at, last_heartbeat, status, reason)
			SELECT $1, $2, $3, NULLIF($4, ''), $5, $5, 'refused', $6 WHERE EXISTS (SELECT 1 FROM agents WHERE agent_id = $2)
			ON CONFLICT (instance_id) DO NOTHING`,
			req.InstanceID, out.Action.AgentID, req.Host, req.ParentInstanceID, s.now(), reason)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		_, err = s.diary.AppendTx(rctx, tx, diary.Event{AgentID: out.Action.AgentID, EventType: EventInstanceRefused, Actor: "agent:" + out.Action.AgentID,
			Data: map[string]any{"instance_id": req.InstanceID, "host": req.Host, "action_id": out.Action.ActionID,
				"decision": string(out.Result.Decision), "rule_id": out.Result.RuleID, "reason": clip(out.Result.Reason, maxReasonLen), "fail_closed": true}})
		return err
	})
	if err != nil {
		s.log.Error("could not record refused instance", "instance_id", req.InstanceID, "err", err)
	}
}

// --- API (console / operators) ----------------------------------------------------

// APIHandler serves the operator API on the API listener (api.Server.Mount):
//
//	GET  /v1/agents/{id}/instances?status=&limit=   auditor, security or the agent's owner
//	POST /v1/agents/{id}/instances/pause-extra      security or the agent's owner  {"reason": "..."}
//	GET  /v1/agent-types                            auditor or security
//	PUT  /v1/agent-types/{type}                     security
type APIHandler struct {
	svc *Service
	log *slog.Logger
}

func NewAPIHandler(svc *Service, log *slog.Logger) *APIHandler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &APIHandler{svc: svc, log: log}
}

// Register mounts the routes on mux.
func (h *APIHandler) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/agents/{id}/instances", h.listInstances)
	mux.HandleFunc("POST /v1/agents/{id}/instances/pause-extra", h.pauseExtra)
	mux.HandleFunc("GET /v1/agent-types", h.listTypes)
	mux.HandleFunc("PUT /v1/agent-types/{type}", h.putType)
}

// authorizeAgent lets through security, the agent's owner, and (when
// allowAuditor) auditors. "No such agent" and "not yours" get the same 403
// for callers without a role, so agents cannot be enumerated.
func (h *APIHandler) authorizeAgent(w http.ResponseWriter, r *http.Request, agentID string, allowAuditor bool) (authz.Principal, bool) {
	p, ok := authz.From(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return p, false
	}
	var sponsor string
	err := h.svc.pool.QueryRow(r.Context(), `SELECT sponsor FROM agents WHERE agent_id = $1`, agentID).Scan(&sponsor)
	exists := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		h.internal(w, err)
		return p, false
	}
	allowed := p.Has(authz.RoleSecurity) || (exists && p.IsOwner(sponsor)) || (allowAuditor && p.Has(authz.RoleAuditor))
	if !allowed {
		msg := "security role or ownership of this agent required"
		if allowAuditor {
			msg = "auditor or security role, or ownership of this agent, required"
		}
		httpx.WriteError(w, http.StatusForbidden, msg)
		return p, false
	}
	if !exists {
		httpx.WriteError(w, http.StatusNotFound, ErrAgentNotFound.Error())
		return p, false
	}
	return p, true
}

var validInstanceStatus = map[string]bool{"": true, StatusLive: true, StatusPaused: true, StatusStopped: true, StatusRefused: true, StatusStale: true,
	StatusSuspended: true}

func (h *APIHandler) listInstances(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !instanceIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrAgentNotFound.Error())
		return
	}
	if _, ok := h.authorizeAgent(w, r, id, true); !ok {
		return
	}
	q := r.URL.Query()
	status := q.Get("status")
	if !validInstanceStatus[status] {
		httpx.WriteError(w, http.StatusBadRequest, "status must be live, stale, paused, suspended, stopped or refused")
		return
	}
	limit := 0
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 1000 {
			httpx.WriteError(w, http.StatusBadRequest, "limit must be an integer between 1 and 1000")
			return
		}
		limit = n
	}
	out, err := h.svc.ListInstances(r.Context(), id, status, limit)
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, out)
	case errors.Is(err, ErrAgentNotFound):
		httpx.WriteError(w, http.StatusNotFound, ErrAgentNotFound.Error())
	default:
		h.internal(w, err)
	}
}

type reasonBody struct {
	Reason string `json:"reason"`
}

func (h *APIHandler) pauseExtra(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !instanceIDPattern.MatchString(id) {
		httpx.WriteError(w, http.StatusNotFound, ErrAgentNotFound.Error())
		return
	}
	p, ok := h.authorizeAgent(w, r, id, false)
	if !ok {
		return
	}
	var body reasonBody
	if err := httpx.DecodeStrict(r, &body, maxInstanceBody); err != nil && !errors.Is(err, io.EOF) {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	res, err := h.svc.PauseExtra(r.Context(), id, p.Actor(), body.Reason)
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, res)
	case errors.Is(err, ErrAgentNotFound):
		httpx.WriteError(w, http.StatusNotFound, ErrAgentNotFound.Error())
	default:
		h.internal(w, err)
	}
}

func (h *APIHandler) listTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	out, err := h.svc.AgentTypes(r.Context())
	if err != nil {
		h.internal(w, err)
		return
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"agent_types": out})
}

// putTypeBody: PUT replaces the whole type, so every limit is required.
type putTypeBody struct {
	ExpectedMaxInstances *int   `json:"expected_max_instances"`
	MaxAgents            *int   `json:"max_agents"`
	SpawnRatePerMin      *int   `json:"spawn_rate_per_min"`
	ActionRatePerMin     *int   `json:"action_rate_per_min"`
	Reason               string `json:"reason"`
}

func (h *APIHandler) putType(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.Require(w, r, authz.RoleSecurity)
	if !ok {
		return
	}
	typ := r.PathValue("type")
	if !typePattern.MatchString(typ) {
		httpx.WriteError(w, http.StatusBadRequest, "type must match "+typePattern.String())
		return
	}
	var body putTypeBody
	if err := httpx.DecodeStrict(r, &body, maxInstanceBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	var missing []string
	for name, v := range map[string]*int{"expected_max_instances": body.ExpectedMaxInstances, "max_agents": body.MaxAgents,
		"spawn_rate_per_min": body.SpawnRatePerMin, "action_rate_per_min": body.ActionRatePerMin} {
		if v == nil {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		httpx.WriteError(w, http.StatusBadRequest, "missing fields (PUT replaces the type): "+strings.Join(sorted(missing), ", "))
		return
	}
	t := AgentType{Type: typ, ExpectedMaxInstances: *body.ExpectedMaxInstances, MaxAgents: *body.MaxAgents,
		SpawnRatePerMin: *body.SpawnRatePerMin, ActionRatePerMin: *body.ActionRatePerMin}
	saved, err := h.svc.PutAgentType(r.Context(), t, p.Actor(), body.Reason)
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, saved)
	case errors.Is(err, ErrInvalid):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	default:
		h.internal(w, err)
	}
}

func (h *APIHandler) internal(w http.ResponseWriter, err error) {
	h.log.Error("population api", "err", err)
	httpx.WriteError(w, http.StatusInternalServerError, "internal error")
}

func sorted(s []string) []string {
	sort.Strings(s)
	return s
}
