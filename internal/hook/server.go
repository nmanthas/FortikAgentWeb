// Package hook is Fortik's Claude Code PreToolUse hook (docs/PHASE3_DESIGN.md
// §3): the client (`fortik hook claude-code`, RunClaudeCode), the gateway
// endpoint POST /v1/hook/claude-code (Handler) and the shell classifier.
//
// This is a DEFENSIVE component. The classifier names dangerous commands as
// data (detection patterns) so they can be recognised and refused before an
// AI coding agent runs them; Fortik never executes anything it classifies.
package hook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/httpx"
	"fortik/internal/shadow"
)

// Route is the gateway pattern the handler is mounted at.
const Route = "POST /v1/hook/claude-code"

// MaxBodyBytes bounds the wrapper body (and the client's stdin).
const MaxBodyBytes = 1 << 20

const defaultDecideTimeout = 2500 * time.Millisecond

// envKeys are the environment hints the client may send.
var envKeys = set("PGHOST", "PGPORT", "PGDATABASE", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE", "HOME", "CLAUDE_PROJECT_DIR")

// Handler serves POST /v1/hook/claude-code for an authenticated agent.
type Handler struct {
	dec      decide.Decider
	verbs    MCPVerbs
	proxies  []HostPort
	internal []string
	log      *slog.Logger
	timeout  time.Duration
	shadow   shadow.TrafficRecorder
}

// Option customises a Handler.
type Option func(*Handler)

// WithInternalHosts names hosts inside the company ("corp.example",
// "*.corp.example"): they are never external.
func WithInternalHosts(hosts []string) Option {
	return func(h *Handler) { h.internal = append([]string(nil), hosts...) }
}

// WithDecideTimeout bounds one decision (default 2.5s, under the client's 3s).
func WithDecideTimeout(d time.Duration) Option {
	return func(h *Handler) {
		if d > 0 {
			h.timeout = d
		}
	}
}

// WithShadow records requests that reach the handler without an
// authenticated agent but with a well-formed bearer token as shadow-discovery
// traffic findings (token hash prefix, address and user agent only). When
// the handler is mounted on the gateway, the gateway records them first and
// this path is a backstop. nil disables recording.
func WithShadow(r shadow.TrafficRecorder) Option { return func(h *Handler) { h.shadow = r } }

// NewHandler builds the endpoint. verbs classifies MCP tools
// (agentgw.LoadToolVerbs(cfg.Policy.Dir)); nil makes every MCP tool UNKNOWN
// (denied).
func NewHandler(cfg config.HookConfig, dec decide.Decider, verbs MCPVerbs, log *slog.Logger, opts ...Option) (*Handler, error) {
	if dec == nil {
		return nil, errors.New("hook: a decider is required")
	}
	proxies, err := ParseProxyHosts(cfg.ProxyHosts)
	if err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{dec: dec, verbs: verbs, proxies: proxies, log: log.With("component", "hook"), timeout: defaultDecideTimeout}
	for _, o := range opts {
		o(h)
	}
	return h, nil
}

// wrapper is the body the client posts.
type wrapper struct {
	Event json.RawMessage   `json:"event"`
	Env   map[string]string `json:"env"`
}

// Response is the handler's answer.
type Response struct {
	Decision    string         `json:"decision"`
	Class       string         `json:"class"`
	RuleID      string         `json:"rule_id"`
	Reason      string         `json:"reason"`
	ActionID    string         `json:"action_id"`
	ReducedForm map[string]any `json:"reduced_form,omitempty"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p, ok := authz.From(r.Context())
	if !ok || p.Kind != authz.KindAgent || p.Name == "" {
		h.recordAuthFailure(r)
		httpx.WriteError(w, http.StatusUnauthorized, "agent authentication required")
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxBodyBytes))
	if err != nil {
		httpx.WriteError(w, http.StatusRequestEntityTooLarge, "body too large or unreadable")
		return
	}
	var wr wrapper
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&wr); err != nil || dec.More() || len(wr.Event) == 0 {
		httpx.WriteError(w, http.StatusBadRequest, "body must be {\"event\": {...}, \"env\": {...}}")
		return
	}
	var ev Event
	if err := json.Unmarshal(wr.Event, &ev); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, "event is not a PreToolUse object")
		return
	}
	env := map[string]string{}
	for k, v := range wr.Env {
		if envKeys[k] && len(v) <= 4096 {
			env[k] = v
		}
	}
	m := h.mapEvent(ev, env, p.Name)
	a := action.Action{AgentID: p.Name, InstanceID: p.InstanceID, System: m.System, Verb: m.Verb, Target: m.Target, Source: action.SourceHook}
	if ev.AgentID != "" {
		a.Target["subagent"] = clip(ev.AgentID)
	}
	ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
	defer cancel()
	ctx = delegation.WithToken(ctx, r.Header.Get(delegation.Header))
	ctx = decide.WithActor(ctx, p.Actor())
	out, err := h.dec.Decide(ctx, a)
	if err != nil {
		h.log.Warn("hook action rejected", "agent", p.Name, "tool", ev.ToolName, "err", err)
		httpx.WriteError(w, http.StatusBadRequest, "invalid action: refused")
		return
	}
	httpx.WriteJSON(w, http.StatusOK, Response{
		Decision: string(out.Result.Decision), Class: string(out.Result.Class), RuleID: out.Result.RuleID,
		Reason: out.Result.Reason, ActionID: out.Action.ActionID, ReducedForm: out.Result.ReducedForm,
	})
}

func (h *Handler) recordAuthFailure(r *http.Request) {
	if h.shadow == nil {
		return
	}
	scheme, tok, ok := strings.Cut(strings.TrimSpace(r.Header.Get("Authorization")), " ")
	tok = strings.TrimSpace(tok)
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" || len(tok) > 512 || strings.ContainsAny(tok, " \t\r\n") {
		return
	}
	h.shadow.RecordTraffic(shadow.TrafficEvent{Source: shadow.SourceHook, Kind: shadow.KindUnknownToken, TokenRef: shadow.TokenRef(tok),
		Host: shadow.HostOf(r.RemoteAddr), UserAgent: r.UserAgent(), Detail: "path=/v1/hook/claude-code"})
}
