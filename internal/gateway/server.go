package gateway

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/shadow"
)

// ActionIDHeader carries the Fortik action id on every decided response.
const ActionIDHeader = "X-Fortik-Action-Id"

// EventNotExecuted is written when Decide allowed an action but the gateway
// could not execute it (integration missing, reduced form not honoured,
// identity missing). The decision itself is already in the Diary.
const EventNotExecuted = "gateway.not_executed"

// NotConfiguredError is returned by Adapter.Forward when the system's
// integration (or one of its secrets) is missing. It matches
// integrations.ErrNotConfigured with errors.Is.
type NotConfiguredError struct{ System string }

func (e *NotConfiguredError) Error() string { return "integration not configured: " + e.System }
func (e *NotConfiguredError) Unwrap() error { return integrations.ErrNotConfigured }

// RefusedError is returned by Adapter.Forward to refuse an allowed action for
// a reason only the adapter can see (e.g. the agent has no workspace
// identity). It becomes a 403 fortik_refused response.
type RefusedError struct {
	RuleID string // e.g. "GW-IDENTITY"
	Reason string // shown to the agent; never secret
}

func (e *RefusedError) Error() string { return "refused: " + e.Reason }

// Option customises a Server.
type Option func(*Server)

// WithDiary records gateway.not_executed events (recommended in production).
func WithDiary(d *diary.Diary) Option { return func(s *Server) { s.diary = d } }

// WithShadow records failed agent authentications that presented a
// well-formed bearer token as shadow-discovery traffic findings (only a
// keyed hash prefix of the token, the caller's address and user agent are
// recorded). The recorder must not block; nil disables recording.
func WithShadow(r shadow.TrafficRecorder) Option { return func(s *Server) { s.shadow = r } }

// Server is the agent-facing gateway: every request is authenticated as an
// agent, mapped by the adapter for /gw/<prefix>/, decided, and only then
// forwarded. Extra agent-authenticated endpoints are added with Mount.
type Server struct {
	cfg      config.GatewayConfig
	dec      decide.Decider
	auth     Authenticator
	adapters map[string]Adapter
	log      *slog.Logger
	diary    *diary.Diary
	shadow   shadow.TrafficRecorder
	mux      *http.ServeMux
}

var prefixPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)

// NewServer builds the gateway. Adapter prefixes must be unique.
func NewServer(cfg config.GatewayConfig, dec decide.Decider, auth Authenticator, adapters []Adapter, log *slog.Logger, opts ...Option) (*Server, error) {
	if dec == nil || auth == nil {
		return nil, errors.New("gateway: decider and authenticator are required")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 25 << 20
	}
	s := &Server{cfg: cfg, dec: dec, auth: auth, adapters: map[string]Adapter{}, log: log, mux: http.NewServeMux()}
	for _, a := range adapters {
		p := a.Prefix()
		if !prefixPattern.MatchString(p) {
			return nil, fmt.Errorf("gateway: invalid adapter prefix %q", p)
		}
		if _, dup := s.adapters[p]; dup {
			return nil, fmt.Errorf("gateway: duplicate adapter prefix %q", p)
		}
		s.adapters[p] = a
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Mount adds an agent-authenticated handler outside /gw/ (e.g.
// "POST /v1/credentials/issue"). The handler finds the agent with
// authz.From(r.Context()); the request body is limited to MaxBodyBytes.
func (s *Server) Mount(pattern string, h http.HandlerFunc) {
	s.mux.HandleFunc(pattern, h)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" && r.Method == http.MethodGet {
		httpx.WriteJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	p, err := s.auth.Authenticate(r)
	switch {
	case errors.Is(err, ErrBadInstanceID):
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, ErrAuthUnavailable):
		s.log.Error("refusing gateway request: agent authentication unavailable")
		httpx.WriteError(w, http.StatusServiceUnavailable, err.Error())
		return
	case err != nil:
		s.recordAuthFailure(r)
		w.Header().Set("WWW-Authenticate", `Bearer realm="fortik-gateway"`)
		httpx.WriteError(w, http.StatusUnauthorized, ErrUnauthenticated.Error())
		return
	}
	r = r.WithContext(authz.With(r.Context(), p))
	r.Body = http.MaxBytesReader(w, r.Body, s.cfg.MaxBodyBytes)
	if strings.HasPrefix(r.URL.Path, "/gw/") {
		s.serveAdapter(w, r, p)
		return
	}
	if _, pattern := s.mux.Handler(r); pattern == "" {
		httpx.WriteError(w, http.StatusNotFound, "not found")
		return
	}
	s.mux.ServeHTTP(w, r)
}

// recordAuthFailure reports a well-formed but unknown agent token to shadow
// discovery. Malformed or missing credentials are not findings.
func (s *Server) recordAuthFailure(r *http.Request) {
	if s.shadow == nil {
		return
	}
	token, ok := bearer(r.Header.Get("Authorization"))
	if !ok {
		return
	}
	src, path := shadow.SourceGateway, r.URL.Path
	if strings.HasPrefix(path, "/v1/hook/") {
		src = shadow.SourceHook
	}
	if strings.HasPrefix(path, "/gw/") {
		prefix, _, _ := strings.Cut(strings.TrimPrefix(path, "/gw/"), "/")
		path = "/gw/" + prefix
	}
	s.shadow.RecordTraffic(shadow.TrafficEvent{Source: src, Kind: shadow.KindUnknownToken, TokenRef: shadow.TokenRef(token),
		Host: shadow.HostOf(r.RemoteAddr), UserAgent: r.UserAgent(), Detail: "path=" + path})
}

func (s *Server) serveAdapter(w http.ResponseWriter, r *http.Request, p authz.Principal) {
	prefix, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/gw/"), "/")
	ad, ok := s.adapters[prefix]
	if !ok {
		httpx.WriteError(w, http.StatusNotFound, "no gateway adapter for this path")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			httpx.WriteError(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("request body exceeds %d bytes", s.cfg.MaxBodyBytes))
			return
		}
		httpx.WriteError(w, http.StatusBadRequest, "could not read request body")
		return
	}
	ctx := decide.WithActor(r.Context(), p.Actor())
	log := s.log.With("agent_id", p.Name, "adapter", prefix)

	// Map and Enrich must never bypass Decide: a failure becomes an UNKNOWN
	// action, which is recorded and denied (POL-002).
	op, err := ad.Map(ctx, p, r, body)
	if err != nil {
		log.Warn("adapter could not map request; deciding it as UNKNOWN", "err", err)
		op = unknownOp(prefix, r, "map_failed", "")
	} else if err := ad.Enrich(ctx, p, &op); err != nil {
		log.Warn("pre-decision lookup failed; deciding it as UNKNOWN", "err", err)
		op = unknownOp(prefix, r, "enrich_failed", string(op.Action.Verb))
	}
	a := op.Action
	a.AgentID, a.InstanceID = p.Name, p.InstanceID
	a.Source = action.SourceAppGateway
	a.ActionID = action.NewID("act")
	a.TS = time.Time{}
	if a.System == "" {
		a.System = prefix
	}
	if a.Verb == "" {
		a.Verb = "UNKNOWN"
	}
	if a.Target == nil {
		a.Target = map[string]any{}
	}
	op.Action = a

	out, err := s.dec.Decide(ctx, a)
	if err != nil {
		// Never forward without a decision.
		if errors.Is(err, action.ErrInvalid) {
			log.Warn("gateway action rejected as invalid", "err", err)
			httpx.WriteError(w, http.StatusBadRequest, "request could not be expressed as a valid action: refused")
			return
		}
		log.Error("decide failed; refusing", "err", err)
		httpx.WriteError(w, http.StatusInternalServerError, "Fortik could not decide: refused")
		return
	}
	op.Action = out.Action
	w.Header().Set(ActionIDHeader, out.Action.ActionID)
	if !out.Result.Decision.Executes() {
		log.Info("gateway refused action", "action_id", out.Action.ActionID, "decision", out.Result.Decision, "rule_id", out.Result.RuleID)
		writeRefusal(w, out, string(out.Result.Decision), out.Result.RuleID, out.Result.Reason)
		return
	}

	tw := &trackingWriter{ResponseWriter: w}
	err = ad.Forward(ctx, p, &op, out, tw, r)
	if err == nil {
		return
	}
	var (
		nc  *NotConfiguredError
		rf  ErrReducedFormUnsupported
		rfp *ErrReducedFormUnsupported
		ref *RefusedError
	)
	switch {
	case errors.As(err, &nc) || errors.Is(err, integrations.ErrNotConfigured):
		system := prefix
		if nc != nil {
			system = nc.System
		}
		s.notExecuted(ctx, p, out, "integration_not_configured", "integration "+system+" is not configured")
		if !tw.wrote {
			httpx.WriteJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]any{
				"code": "integration_not_configured", "system": system, "action_id": out.Action.ActionID,
				"message": "integration not configured: an administrator must configure it in the Fortik console",
			}})
		}
	case errors.As(err, &rf) || errors.As(err, &rfp):
		key := rf.Key
		if rfp != nil {
			key = rfp.Key
		}
		reason := fmt.Sprintf("reduced form %q cannot be honoured for this request: refused (%s)", key, out.Result.Reason)
		s.notExecuted(ctx, p, out, "reduced_form_unsupported", reason)
		if !tw.wrote {
			writeRefusal(w, out, string(policy.Deny), out.Result.RuleID, reason)
		}
	case errors.As(err, &ref):
		s.notExecuted(ctx, p, out, "refused", ref.Reason)
		if !tw.wrote {
			writeRefusal(w, out, string(policy.Deny), ref.RuleID, ref.Reason)
		}
	default:
		log.Error("gateway forward failed", "action_id", out.Action.ActionID, "err", err, "response_started", tw.wrote)
		if !tw.wrote {
			s.notExecuted(ctx, p, out, "upstream_failed", "the upstream request failed")
			httpx.WriteJSON(w, http.StatusBadGateway, map[string]any{"error": map[string]any{
				"code": "upstream_failed", "action_id": out.Action.ActionID, "message": "the upstream request failed",
			}})
		}
	}
}

// unknownOp is the fail-closed mapping for a request an adapter could not
// classify: verb UNKNOWN, which policy denies without a ladder change.
func unknownOp(prefix string, r *http.Request, reason, mappedVerb string) Op {
	endpoint := r.Method + " " + r.URL.EscapedPath()
	if len(endpoint) > 512 {
		endpoint = endpoint[:512]
	}
	t := map[string]any{"endpoint": endpoint, "reason": reason}
	if mappedVerb != "" {
		t["mapped_verb"] = mappedVerb
	}
	return Op{Action: action.Action{System: prefix, Verb: "UNKNOWN", Target: t}}
}

func writeRefusal(w http.ResponseWriter, out decide.Outcome, decision, ruleID, reason string) {
	httpx.WriteJSON(w, http.StatusForbidden, map[string]any{"error": map[string]any{
		"code":      "fortik_refused",
		"decision":  decision,
		"class":     string(out.Result.Class),
		"rule_id":   ruleID,
		"reason":    reason,
		"action_id": out.Action.ActionID,
		"held":      out.Held,
	}})
}

// notExecuted records that an allowed action was not executed. Best effort:
// the response to the agent is a refusal either way.
func (s *Server) notExecuted(ctx context.Context, p authz.Principal, out decide.Outcome, code, reason string) {
	s.log.Warn("allowed action not executed", "agent_id", p.Name, "action_id", out.Action.ActionID, "code", code)
	if s.diary == nil {
		return
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if _, err := s.diary.Append(dctx, diary.Event{AgentID: p.Name, EventType: EventNotExecuted, Actor: "system:gateway",
		Data: map[string]any{"action_id": out.Action.ActionID, "system": out.Action.System, "verb": string(out.Action.Verb),
			"code": code, "reason": reason}}); err != nil {
		s.log.Error("could not record gateway.not_executed", "action_id", out.Action.ActionID, "err", err)
	}
}

// trackingWriter records whether the adapter started the response.
type trackingWriter struct {
	http.ResponseWriter
	wrote bool
}

func (t *trackingWriter) WriteHeader(code int) {
	t.wrote = true
	t.ResponseWriter.WriteHeader(code)
}

func (t *trackingWriter) Write(b []byte) (int, error) {
	t.wrote = true
	return t.ResponseWriter.Write(b)
}

func (t *trackingWriter) Flush() {
	if f, ok := t.ResponseWriter.(http.Flusher); ok {
		t.wrote = true
		f.Flush()
	}
}

func (t *trackingWriter) Unwrap() http.ResponseWriter { return t.ResponseWriter }
