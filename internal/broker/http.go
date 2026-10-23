package broker

import (
	"errors"
	"log/slog"
	"net/http"

	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/httpx"
)

// maxIssueBody bounds POST /v1/credentials/issue bodies.
const maxIssueBody = 64 << 10

// HeaderActionID carries the decided action's id on refusals and 503s.
const HeaderActionID = "X-Fortik-Action-Id"

// Handler serves POST /v1/credentials/issue for agents authenticated with
// their agent token (authz principal of kind agent, set by the gateway's
// auth middleware). The agent and instance ids come from the principal,
// never from the body.
type Handler struct {
	broker Broker
	log    *slog.Logger
}

func NewHandler(b Broker, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Handler{broker: b, log: log}
}

// Register mounts the route on mux.
func (h *Handler) Register(mux *http.ServeMux) {
	mux.Handle("POST /v1/credentials/issue", h)
}

// RefusalBody is the 403 shape shared with the gateway (docs/PHASE2_DESIGN.md §3).
type RefusalBody struct {
	Code     string `json:"code"` // "fortik_refused"
	Decision string `json:"decision"`
	Class    string `json:"class"`
	RuleID   string `json:"rule_id"`
	Reason   string `json:"reason"`
	ActionID string `json:"action_id"`
	Held     bool   `json:"held"`
}

// WriteRefusal writes 403 {"error":{"code":"fortik_refused",...}} and X-Fortik-Action-Id.
func WriteRefusal(w http.ResponseWriter, out decide.Outcome) {
	w.Header().Set(HeaderActionID, out.Action.ActionID)
	httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": RefusalBody{
		Code: "fortik_refused", Decision: string(out.Result.Decision), Class: string(out.Result.Class),
		RuleID: out.Result.RuleID, Reason: out.Result.Reason, ActionID: out.Action.ActionID, Held: out.Held,
	}})
}

// WriteNotConfigured writes 503 {"error":{"code":"integration_not_configured","system":...}}.
func WriteNotConfigured(w http.ResponseWriter, system, actionID string) {
	if actionID != "" {
		w.Header().Set(HeaderActionID, actionID)
	}
	httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{
		"code": "integration_not_configured", "system": system,
	}})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.From(r.Context())
	if !ok {
		httpx.WriteError(w, http.StatusUnauthorized, "authentication required")
		return
	}
	if p.Kind != authz.KindAgent || p.Name == "" {
		httpx.WriteError(w, http.StatusForbidden, "an agent token is required to request credentials")
		return
	}
	var req IssueRequest
	if err := httpx.DecodeStrict(r, &req, maxIssueBody); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.AgentID, req.InstanceID = p.Name, p.InstanceID
	ctx := decide.WithActor(r.Context(), p.Actor())
	cred, err := h.broker.Issue(ctx, req)
	var refusal *Refusal
	var notConfigured *NotConfiguredError
	switch {
	case err == nil:
		httpx.WriteJSON(w, http.StatusOK, cred)
	case errors.As(err, &refusal):
		WriteRefusal(w, refusal.Outcome)
	case errors.As(err, &notConfigured):
		WriteNotConfigured(w, notConfigured.System, notConfigured.ActionID)
	case errors.Is(err, ErrNotConfigured):
		WriteNotConfigured(w, req.System, "")
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrUnsupported):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
	case errors.Is(err, ErrMintFailed):
		httpx.WriteError(w, http.StatusBadGateway, ErrMintFailed.Error())
	default:
		h.log.Error("credential issue failed", "agent_id", p.Name, "system", req.System, "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "internal error")
	}
}
