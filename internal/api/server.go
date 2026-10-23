// Package api is Fortik's internal HTTP API (the plan's /v1 surface). Every
// /v1 route authenticates (bearer service token or console session cookie,
// with CSRF on cookie writes) and checks a role; every security-state change
// is written to the Diary in the same transaction as the change.
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"fortik/internal/action"
	"fortik/internal/auth"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/httpx"
	"fortik/internal/metrics"
	"fortik/internal/secrets"
	"fortik/internal/undo"
)

type Server struct {
	Pool      *pgxpool.Pool
	Decider   decide.Decider
	Diary     *diary.Diary
	Signer    *diary.Signer
	Undo      *undo.PGStore
	Executors map[string]undo.Executor
	Policy    interface{ Version() string }
	Log       *slog.Logger

	// Phase 2 (all optional; a nil dependency disables only its feature).

	// Sessions resolves console session cookies; nil = bearer tokens only.
	Sessions *auth.Service
	// Revoker is called (best effort) when an agent is set to QUARANTINED or
	// KILLED; normally the broker (broker.Broker satisfies it).
	Revoker Revoker
	// AgentGuard refuses agent registrations beyond the type's max_agents
	// (UC2 registration surge); nil = no limit. Called first inside the
	// create (or type-change) transaction.
	AgentGuard AgentGuard
	// Secrets is the writable store for agent tokens; nil = token issuance
	// returns 503.
	Secrets secrets.Store
	// AgentTokensSecret names the agent token map (default "agent_tokens",
	// the same secret pgproxy and the gateway read).
	AgentTokensSecret string
	// LoopbackHosts / AllowedHosts restrict the Host header (DNS rebinding
	// defence for cookie-authenticated routes): see httpx.HostAllowlist.
	LoopbackHosts bool
	AllowedHosts  []string

	auth *TokenAuth
	st   *serverState
}

// serverState is the server's mutable internals (behind a pointer so Server
// stays copyable for NewServer's by-value argument).
type serverState struct {
	tokenMu sync.Mutex // serialises read-modify-write of the agent token secret
	mountMu sync.Mutex
	mounts  []func(*http.ServeMux)
}

// Revoker revokes every live credential of an agent across systems and
// returns a per-system description of what was actually achieved.
type Revoker interface {
	RevokeAll(ctx context.Context, agentID, actor, reason string) (map[string]string, error)
}

func NewServer(s Server, auth *TokenAuth) *Server {
	s.auth, s.st = auth, &serverState{}
	if s.AgentTokensSecret == "" {
		s.AgentTokensSecret = "agent_tokens"
	}
	if s.Log == nil {
		s.Log = slog.New(slog.DiscardHandler)
	}
	return &s
}

// Mount registers another package's routes (integrations, access, events,
// auth, console) on the API mux, behind the same authentication middleware:
// every /v1/* route gets an authenticated principal (authz.From) and CSRF
// protection for cookie-authenticated writes; handlers still check roles
// with authz.Require. Call Mount before Handler.
func (s *Server) Mount(register func(mux *http.ServeMux)) {
	s.st.mountMu.Lock()
	defer s.st.mountMu.Unlock()
	s.st.mounts = append(s.st.mounts, register)
}

const maxBody = httpx.MaxBody

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", s.ready)
	mux.Handle("GET /metrics", s.require(RoleAuditor, promhttp.HandlerFor(metrics.Registry, promhttp.HandlerOpts{}).ServeHTTP))

	mux.HandleFunc("POST /v1/actions/decide", s.require(RoleInterceptor, s.decide))
	mux.HandleFunc("GET /v1/actions", s.require(RoleAuditor, s.listActions))
	mux.HandleFunc("GET /v1/actions/{id}", s.require(RoleAuditor, s.getAction))
	mux.HandleFunc("GET /v1/held", s.require(RoleAuditor, s.listHeld))
	mux.HandleFunc("GET /v1/agents", s.require(RoleAuditor, s.listAgents))
	mux.HandleFunc("GET /v1/policy", s.require(RoleAuditor, func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]string{"version": s.Policy.Version()})
	}))

	mux.HandleFunc("GET /v1/diary", s.require(RoleAuditor, s.diaryQuery))
	mux.HandleFunc("GET /v1/diary/verify", s.require(RoleAuditor, s.diaryVerify))
	mux.HandleFunc("GET /v1/diary/export", s.require(RoleAuditor, s.diaryExport))

	mux.HandleFunc("GET /v1/undo", s.require(RoleAuditor, s.listUndo))
	mux.HandleFunc("POST /v1/undo/{action_id}", s.require(RoleSecurity, s.runUndo))

	// Phase 2: agent management, control ladder, tokens, console summaries.
	mux.HandleFunc("POST /v1/agents", s.require(RoleSecurity, s.createAgent))
	mux.HandleFunc("GET /v1/agents/{id}", s.require(RoleAuditor, s.getAgent))
	mux.HandleFunc("PATCH /v1/agents/{id}", s.require(RoleSecurity, s.patchAgent))
	mux.HandleFunc("PUT /v1/agents/{id}/level", s.setLevel) // security or owner: checked in the handler
	mux.HandleFunc("POST /v1/agents/{id}/tokens", s.require(RoleSecurity, s.issueAgentToken))
	mux.HandleFunc("DELETE /v1/agents/{id}/tokens", s.require(RoleSecurity, s.revokeAgentTokens))
	mux.HandleFunc("GET /v1/agents/{id}/stats", s.require(RoleAuditor, s.agentStats))
	mux.HandleFunc("GET /v1/stats/summary", s.require(RoleAuditor, s.statsSummary))

	s.st.mountMu.Lock()
	for _, register := range s.st.mounts {
		register(mux)
	}
	s.st.mountMu.Unlock()
	return s.logRequests(httpx.HostAllowlist(s.LoopbackHosts, s.AllowedHosts, s.authenticate(mux)))
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(rw, r)
		s.Log.Debug("http", "method", r.Method, "path", r.URL.Path, "status", rw.status, "dur_ms", time.Since(start).Milliseconds())
	})
}

// AgentGuard is satisfied by *population.Service. An error wrapping
// ErrAgentSurge (population.ErrAgentSurge) becomes 409; any other error refuses.
type AgentGuard interface {
	CheckAgentRegistrationTx(ctx context.Context, tx pgx.Tx, agentType string) error
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) { w.status = code; w.ResponseWriter.WriteHeader(code) }

// Unwrap lets http.ResponseController reach the real writer (Flush, write
// deadlines): without it streaming responses such as the SSE event stream
// cannot flush through the logging wrapper.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (s *Server) ready(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	if err := s.Pool.Ping(ctx); err != nil {
		writeError(w, http.StatusServiceUnavailable, "database unavailable")
		return
	}
	writeJSON(w, 200, map[string]string{"status": "ready", "policy_version": s.Policy.Version()})
}

// --- decide ---------------------------------------------------------------

type decideResponse struct {
	ActionID      string         `json:"action_id"`
	Class         string         `json:"class"`
	Decision      string         `json:"decision"`
	ReducedForm   map[string]any `json:"reduced_form,omitempty"`
	LadderChange  any            `json:"ladder_change,omitempty"`
	Reason        string         `json:"reason"`
	RuleID        string         `json:"rule_id"`
	Matched       any            `json:"matched,omitempty"`
	LevelBefore   string         `json:"level_before"`
	LevelAfter    string         `json:"level_after"`
	Held          bool           `json:"held"`
	FailClosed    bool           `json:"fail_closed"`
	LatencyUS     int64          `json:"latency_us"`
	PolicyVersion string         `json:"policy_version,omitempty"`
	// ApprovalsRequired: distinct approvers a hold needs, when more than one.
	ApprovalsRequired int `json:"approvals_required,omitempty"`
}

func (s *Server) decide(w http.ResponseWriter, r *http.Request) {
	var a action.Action
	if err := decodeStrict(r, &a); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Out-of-process callers: the Diary actor is the authenticated token, never
	// a body field. safe_form is generated by Fortik's own interception points
	// only; a caller-supplied one is dropped so approvers never see injected SQL.
	if a.Source == "" {
		a.Source = action.SourceAPI
	}
	delete(a.Target, "safe_form")
	ctx := decide.WithActor(r.Context(), principalFrom(r.Context()).Actor())
	out, err := s.Decider.Decide(ctx, a)
	if err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, action.ErrInvalid) {
			code = http.StatusBadRequest
		}
		writeError(w, code, err.Error())
		return
	}
	res := out.Result
	resp := decideResponse{
		ActionID: out.Action.ActionID, Class: string(res.Class), Decision: string(res.Decision), ReducedForm: res.ReducedForm,
		Reason: res.Reason, RuleID: res.RuleID, Matched: res.Matched, LevelBefore: out.LevelBefore.String(), LevelAfter: out.LevelAfter.String(),
		Held: out.Held, FailClosed: out.FailClosed, LatencyUS: out.LatencyUS, PolicyVersion: res.PolicyVersion,
	}
	if out.Held && res.ApprovalsRequired > 1 {
		resp.ApprovalsRequired = res.ApprovalsRequired
	}
	if res.LadderChange != nil {
		resp.LadderChange = res.LadderChange
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- explainability ---------------------------------------------------------

type actionRow struct {
	ActionID       string          `json:"action_id"`
	AgentID        string          `json:"agent_id"`
	InstanceID     *string         `json:"instance_id,omitempty"`
	System         string          `json:"system"`
	Verb           string          `json:"verb"`
	ActionHash     string          `json:"action_hash"`
	Class          string          `json:"class"`
	Decision       string          `json:"decision"`
	RuleID         string          `json:"rule_id"`
	Reason         string          `json:"reason"`
	Reversible     bool            `json:"reversible"`
	Source         string          `json:"source"`
	Target         json.RawMessage `json:"target"`
	PayloadSummary json.RawMessage `json:"payload_summary"`
	DecisionJSON   json.RawMessage `json:"explanation"`
	FailClosed     bool            `json:"fail_closed"`
	LatencyUS      int64           `json:"latency_us"`
	TS             time.Time       `json:"ts"`
	Held           json.RawMessage `json:"held,omitempty"`
	Undo           json.RawMessage `json:"undo,omitempty"`
}

const actionCols = `a.action_id, a.agent_id, a.instance_id, a.system, a.verb, a.action_hash, a.class, a.decision, a.rule_id, a.reason,
	a.reversible, a.source, a.target, a.payload_summary, a.decision_json, a.fail_closed, a.latency_us, a.ts,
	(SELECT to_jsonb(h) - 'action_id' FROM held_actions h WHERE h.action_id = a.action_id),
	(SELECT jsonb_build_object('kind', u.kind, 'status', u.status, 'expires_at', u.expires_at, 'used_at', u.used_at, 'error', u.error)
	   FROM undo_handles u WHERE u.action_id = a.action_id)`

func scanAction(row pgx.Row) (actionRow, error) {
	var a actionRow
	err := row.Scan(&a.ActionID, &a.AgentID, &a.InstanceID, &a.System, &a.Verb, &a.ActionHash, &a.Class, &a.Decision, &a.RuleID,
		&a.Reason, &a.Reversible, &a.Source, &a.Target, &a.PayloadSummary, &a.DecisionJSON, &a.FailClosed, &a.LatencyUS, &a.TS, &a.Held, &a.Undo)
	return a, err
}

func (s *Server) getAction(w http.ResponseWriter, r *http.Request) {
	a, err := scanAction(s.Pool.QueryRow(r.Context(), `SELECT `+actionCols+` FROM actions a WHERE a.action_id = $1`, r.PathValue("id")))
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "action not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, a)
}

func (s *Server) listActions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	rows, err := s.Pool.Query(r.Context(), `SELECT `+actionCols+` FROM actions a
		WHERE ($1 = '' OR a.agent_id = $1) AND ($2 = '' OR a.class = $2) AND ($3 = '' OR a.decision = $3)
		ORDER BY a.ts DESC LIMIT $4`, q.Get("agent_id"), q.Get("class"), q.Get("decision"), limit(q.Get("limit"), 100, 1000))
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	out := []actionRow{}
	for rows.Next() {
		a, err := scanAction(rows)
		if err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, a)
	}
	writeJSON(w, 200, map[string]any{"actions": out})
}

func (s *Server) listHeld(w http.ResponseWriter, r *http.Request) {
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}
	rows, err := s.Pool.Query(r.Context(), `
		SELECT jsonb_build_object('action_id', h.action_id, 'agent_id', h.agent_id, 'rule_id', h.rule_id, 'reason', h.reason,
			'approvals_required', h.approvals_required, 'approver_role', h.approver_role, 'safe_form', h.safe_form,
			'expires_at', h.expires_at, 'outcome', h.outcome, 'created_at', h.created_at,
			'class', a.class, 'decision', a.decision, 'system', a.system, 'verb', a.verb, 'target', a.target,
			'level_at_decision', a.decision_json->'level_before', 'level_after', a.decision_json->'level_after',
			'undo_available', false)
		FROM held_actions h JOIN actions a USING (action_id)
		WHERE ($1 = 'all' OR h.outcome = $1) ORDER BY h.created_at DESC LIMIT $2`, status, limit(r.URL.Query().Get("limit"), 100, 1000))
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	out := []json.RawMessage{}
	for rows.Next() {
		var j json.RawMessage
		if err := rows.Scan(&j); err != nil {
			s.internal(w, err)
			return
		}
		out = append(out, j)
	}
	writeJSON(w, 200, map[string]any{"held": out})
}

// --- diary ------------------------------------------------------------------

func diaryFilter(r *http.Request) (diary.Filter, error) {
	q := r.URL.Query()
	f := diary.Filter{AgentID: q.Get("agent_id"), ActionID: q.Get("action_id"), Limit: limit(q.Get("limit"), 1000, 10000)}
	if len(f.ActionID) > 128 {
		return f, errors.New("action_id: too long")
	}
	var err error
	if v := q.Get("from"); v != "" {
		if f.From, err = time.Parse(time.RFC3339, v); err != nil {
			return f, fmt.Errorf("from: %w", err)
		}
	}
	if v := q.Get("to"); v != "" {
		if f.To, err = time.Parse(time.RFC3339, v); err != nil {
			return f, fmt.Errorf("to: %w", err)
		}
	}
	if v := q.Get("after_seq"); v != "" {
		if f.AfterSeq, err = strconv.ParseInt(v, 10, 64); err != nil {
			return f, fmt.Errorf("after_seq: %w", err)
		}
	}
	return f, nil
}

func (s *Server) diaryQuery(w http.ResponseWriter, r *http.Request) {
	f, err := diaryFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	entries, err := s.Diary.Query(r.Context(), f)
	if err != nil {
		s.internal(w, err)
		return
	}
	if entries == nil {
		entries = []diary.Entry{}
	}
	writeJSON(w, 200, map[string]any{"entries": entries})
}

func (s *Server) diaryVerify(w http.ResponseWriter, r *http.Request) {
	rep, err := s.Diary.VerifyChain(r.Context())
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, rep)
}

func (s *Server) diaryExport(w http.ResponseWriter, r *http.Request) {
	f, err := diaryFilter(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	exp, err := s.Diary.Export(r.Context(), f, s.Signer, principalFrom(r.Context()).Actor())
	if err != nil {
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="fortik-diary-export.json"`)
	writeJSON(w, 200, exp)
}

// --- undo -------------------------------------------------------------------

func (s *Server) listUndo(w http.ResponseWriter, r *http.Request) {
	hs, err := s.Undo.List(r.Context(), r.URL.Query().Get("agent_id"), limit(r.URL.Query().Get("limit"), 100, 500))
	if err != nil {
		s.internal(w, err)
		return
	}
	// Each handle carries whether Undo is possible now and, if not, why
	// (the console shows the Undo button only when undoable is true).
	type undoView struct {
		undo.Handle
		undo.Assessment
	}
	// Delayed emails are assessed against their live delayed_sends row
	// (status and current send_at): the handle's send_at is only the time
	// recorded when the email was queued. If the rows cannot be read, the
	// handle-only assessment keeps Undo offered ("send time reached: may
	// already be sent") and the executor decides.
	now := time.Now()
	var delayedIDs []string
	for _, h := range hs {
		if h.Kind == undo.KindGmailDelayedSend && h.Status == undo.StatusActive {
			delayedIDs = append(delayedIDs, h.ActionID)
		}
	}
	var delayed map[string]undo.DelayedSendState
	if len(delayedIDs) > 0 && s.Pool != nil {
		if delayed, err = undo.LoadDelayedSends(r.Context(), s.Pool, delayedIDs); err != nil {
			s.Log.Warn("undo list: delayed send rows unavailable; using the handles only", "err", err)
		}
	}
	out := make([]undoView, 0, len(hs))
	for _, h := range hs {
		a := undo.UndoabilityAt(h, now)
		if h.Kind == undo.KindGmailDelayedSend {
			if row, ok := delayed[h.ActionID]; ok {
				a = undo.AssessDelayedSendAt(h, &row, now)
			}
		}
		if _, ok := s.Executors[h.Kind]; a.Undoable && !ok {
			a.Undoable, a.WhyNot = false, undo.WhyNotUnsupported
		}
		out = append(out, undoView{Handle: h, Assessment: a})
	}
	writeJSON(w, 200, map[string]any{"undo": out})
}

type undoRequest struct {
	Reason string `json:"reason"`
}

func (s *Server) runUndo(w http.ResponseWriter, r *http.Request) {
	var req undoRequest
	if err := decodeStrict(r, &req); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Reason == "" {
		writeError(w, http.StatusBadRequest, "reason is required")
		return
	}
	actionID := r.PathValue("action_id")
	actor := principalFrom(r.Context()).Actor()

	h, err := s.Undo.Get(r.Context(), actionID)
	if errors.Is(err, undo.ErrNotFound) {
		writeError(w, http.StatusNotFound, "no undo handle was prepared for this action: it is NOT undoable")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	ex, ok := s.Executors[h.Kind]
	if !ok {
		writeError(w, http.StatusNotImplemented, fmt.Sprintf("undo kind %q is not supported in this build", h.Kind))
		return
	}
	h, err = s.Undo.Claim(r.Context(), actionID, actor)
	switch {
	case errors.Is(err, undo.ErrExpired):
		writeError(w, http.StatusGone, "undo handle expired (retention elapsed): NOT undoable")
		return
	case errors.Is(err, undo.ErrNotUndoable):
		writeError(w, http.StatusConflict, err.Error())
		return
	case err != nil:
		s.internal(w, err)
		return
	}
	// Run the undo even if the HTTP client disconnects; state transitions get
	// their own context so a slow or timed-out executor cannot leave the
	// handle stuck in "undoing".
	uctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 2*time.Minute)
	defer cancel()
	result, err := ex.Undo(uctx, h)
	sctx, scancel := context.WithTimeout(context.WithoutCancel(r.Context()), 15*time.Second)
	defer scancel()
	if errors.Is(err, undo.ErrOutcomeUnknown) {
		metrics.UndoRuns.WithLabelValues(h.Kind, "unknown").Inc()
		s.Log.Error("undo outcome unknown; handle left in 'undoing' for manual review", "action_id", actionID, "err", err)
		writeError(w, http.StatusBadGateway, "undo outcome unknown (it may have been applied); the handle is left in 'undoing' — do not retry, review manually")
		return
	}
	if err != nil {
		metrics.UndoRuns.WithLabelValues(h.Kind, "failed").Inc()
		if rerr := s.Undo.Release(sctx, actionID, actor, req.Reason+": "+err.Error()); rerr != nil {
			s.Log.Error("undo release failed", "action_id", actionID, "err", rerr)
		}
		code := http.StatusBadGateway
		if errors.Is(err, undo.ErrNothingToUndo) {
			code = http.StatusConflict
		}
		writeError(w, code, "undo failed: "+err.Error())
		return
	}
	if result == nil {
		result = map[string]any{}
	}
	result["reason"] = req.Reason
	if err := s.Undo.Complete(sctx, actionID, actor, result); err != nil {
		s.Log.Error("undo EXECUTED but its completion could not be recorded; handle left in 'undoing' for manual review",
			"action_id", actionID, "kind", h.Kind, "err", err)
		writeError(w, http.StatusInternalServerError, "undo was executed but could not be recorded; the handle is left in 'undoing' — do not retry, review manually")
		return
	}
	metrics.UndoRuns.WithLabelValues(h.Kind, "ok").Inc()
	writeJSON(w, 200, map[string]any{"action_id": actionID, "kind": h.Kind, "status": undo.StatusUsed, "result": result})
}

// --- helpers ----------------------------------------------------------------

func decodeStrict(r *http.Request, v any) error { return httpx.DecodeStrict(r, v, maxBody) }

func limit(v string, def, max int) int {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func writeJSON(w http.ResponseWriter, code int, v any) { httpx.WriteJSON(w, code, v) }

func writeError(w http.ResponseWriter, code int, msg string) { httpx.WriteError(w, code, msg) }

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.Log.Error("api internal error", "err", err)
	writeError(w, http.StatusInternalServerError, "internal error")
}
