// Package agentgw is Fortik's callout for agentgateway (docs/PHASE3_DESIGN.md
// §4): one gRPC server implementing Envoy ext_authz v3 Authorization/Check
// (A2A and HTTP egress routes), agentgateway's ext_mcp guardrails (MCP
// routes), and an Envoy ext_proc v3 observer on A2A routes that closes
// delegation hops when a delegated task visibly ends (a2aresp.go). Every request is authenticated with the agent's Fortik token,
// mapped to an Action, decided, and refused unless Decide says it may run.
//
// Identity: the agent comes only from the bearer token; client-supplied
// x-fortik-agent-id / x-fortik-instance-id headers are ignored and the
// verified values are injected upstream. The target agent / MCP server comes
// only from route-set gRPC metadata (x-fortik-route-agent, x-fortik-route-mcp,
// x-fortik-route-http), which agentgateway attaches to the callout request
// from its config; clients cannot set it. Errors of any kind deny.
package agentgw

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"fortik/internal/action"
	"fortik/internal/agentgw/extmcp"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/policy"
)

// Route metadata keys set by the generated agentgateway config on the
// callout's gRPC request (never taken from the client's HTTP headers).
const (
	MetaRouteAgent = "x-fortik-route-agent" // A2A route key -> AgentGWConfig.A2ATargets
	MetaRouteMCP   = "x-fortik-route-mcp"   // MCP route key -> AgentGWConfig.MCPServers
	MetaRouteHTTP  = "x-fortik-route-http"  // HTTP egress route: its domain
)

// Headers the callout injects into (or strips from) the upstream request.
const (
	HeaderAgentID    = "x-fortik-agent-id"
	HeaderInstanceID = "x-fortik-instance-id"
	HeaderActionID   = "x-fortik-action-id"
	headerDelegation = "x-fortik-delegation" // lowercase form of delegation.Header
)

// EventNotExecuted is written when Decide allowed an action but the callout
// refused it anyway (bad delegation token, no token issued, reduced form).
const EventNotExecuted = "agentgw.not_executed"

// Rule ids for refusals the callout itself makes after an allow.
const (
	RuleDelegationToken = "AGW-DELEGATION"
	RuleReducedForm     = "AGW-REDUCED-FORM"
)

const (
	defaultDecideTimeout = 240 * time.Millisecond
	maxDelegationToken   = 4096
)

// Option customises a Server.
type Option func(*Server)

// WithDiary records agentgw.not_executed events (recommended in production).
func WithDiary(d *diary.Diary) Option { return func(s *Server) { s.diary = d } }

// WithDecideTimeout bounds one decision (default 240ms, just under the
// gateway's 250ms requestTimeout: a decision the gateway already gave up on
// is cancelled and fails closed instead of being recorded as allowed).
func WithDecideTimeout(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.timeout = d
		}
	}
}

// WithPool enables the A2A response observer (ext_proc on A2A routes), which
// closes delegation hops when a delegated task visibly ends. Without it the
// observer passes traffic through unchanged and hops close only on expiry.
func WithPool(p *pgxpool.Pool) Option { return func(s *Server) { s.pool = p } }

// WithTransportCredentials serves the callout over TLS/mTLS. Required when
// agentgw.listen is not a loopback address.
func WithTransportCredentials(c credentials.TransportCredentials) Option {
	return func(s *Server) { s.creds = c }
}

// Server is the callout. It is safe for concurrent use.
type Server struct {
	cfg      config.AgentGWConfig
	dec      decide.Decider
	auth     gateway.Authenticator
	deleg    DelegationStore
	verbs    *ToolVerbs
	log      *slog.Logger
	diary    *diary.Diary
	timeout  time.Duration
	creds    credentials.TransportCredentials
	pool     *pgxpool.Pool
	internal hostMatcher
}

var agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

// New builds the callout. auth is the gateway's agent authenticator
// (gateway.NewAgentAuth); deleg is the delegation store (*delegation.PGStore);
// verbs is the MCP verb table (LoadToolVerbs(cfg.Policy.Dir)).
func New(cfg config.AgentGWConfig, dec decide.Decider, auth gateway.Authenticator, deleg DelegationStore, verbs *ToolVerbs, log *slog.Logger, opts ...Option) (*Server, error) {
	if dec == nil || auth == nil || deleg == nil || verbs == nil {
		return nil, errors.New("agentgw: decider, authenticator, delegation store and MCP verb table are required")
	}
	if log == nil {
		log = slog.Default()
	}
	for route, agent := range cfg.A2ATargets {
		if route == "" || !agentIDPattern.MatchString(agent) {
			return nil, fmt.Errorf("agentgw: a2a_targets[%q] = %q is not a valid agent id", route, agent)
		}
	}
	for route, server := range cfg.MCPServers {
		if route == "" || server == "" || !printable(server) || len(server) > 128 {
			return nil, fmt.Errorf("agentgw: mcp_servers[%q] = %q is not a valid server name", route, server)
		}
	}
	s := &Server{cfg: cfg, dec: dec, auth: auth, deleg: deleg, verbs: verbs, log: log.With("component", "agentgw"),
		timeout: defaultDecideTimeout, internal: newHostMatcher(cfg.InternalHosts)}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

// Register adds the callout services to g: ext_authz (A2A, HTTP), ext_mcp
// (MCP) and the ext_proc A2A response observer.
func (s *Server) Register(g *grpc.Server) {
	authv3.RegisterAuthorizationServer(g, &authzService{s: s})
	extmcp.RegisterExtMcpServer(g, &mcpService{s: s})
	procv3.RegisterExternalProcessorServer(g, &procService{s: s})
}

// GRPCServer returns a gRPC server with both services registered.
func (s *Server) GRPCServer() *grpc.Server {
	opts := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(4 << 20),
		grpc.KeepaliveParams(keepalive.ServerParameters{Time: 30 * time.Second, Timeout: 10 * time.Second}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{MinTime: 10 * time.Second, PermitWithoutStream: true}),
	}
	if s.creds != nil {
		opts = append(opts, grpc.Creds(s.creds))
	}
	g := grpc.NewServer(opts...)
	s.Register(g)
	return g
}

// ListenAndServe serves on cfg.Listen until ctx is cancelled. A non-loopback
// listener needs WithTransportCredentials.
func (s *Server) ListenAndServe(ctx context.Context) error {
	if !isLoopback(s.cfg.Listen) && s.creds == nil {
		return fmt.Errorf("agentgw: refusing to serve plaintext gRPC on non-loopback %q (configure transport credentials)", s.cfg.Listen)
	}
	lis, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("agentgw: listen %s: %w", s.cfg.Listen, err)
	}
	return s.Serve(ctx, lis)
}

// Serve serves on lis until ctx is cancelled, then stops gracefully (bounded).
func (s *Server) Serve(ctx context.Context, lis net.Listener) error {
	g := s.GRPCServer()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			stopped := make(chan struct{})
			go func() { g.GracefulStop(); close(stopped) }()
			select {
			case <-stopped:
			case <-time.After(5 * time.Second):
				g.Stop()
			}
		case <-done:
		}
	}()
	s.log.Info("agentgateway callout listening", "addr", lis.Addr().String())
	err := g.Serve(lis)
	close(done)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}
	return err
}

func isLoopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// routeMeta returns the single value of a route metadata key ("" if absent).
// More than one value is an error: the route identity must be unambiguous.
func routeMeta(ctx context.Context, key string) (string, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	v := md.Get(key)
	switch len(v) {
	case 0:
		return "", nil
	case 1:
		if v[0] == "" || len(v[0]) > 253 || !printable(v[0]) {
			return "", fmt.Errorf("malformed route metadata %s", key)
		}
		return v[0], nil
	default:
		return "", fmt.Errorf("route metadata %s has %d values", key, len(v))
	}
}

// --- shared decision pipeline ---------------------------------------------------

// verdict is the callout's answer, rendered by each protocol.
type verdict struct {
	Allow    bool
	Status   int    // HTTP status of a refusal
	Code     string // fortik_refused | unauthenticated | auth_unavailable | bad_request | fortik_error
	Decision string
	Class    string
	RuleID   string
	Reason   string
	ActionID string
	Held     bool

	// Allowed only.
	AgentID    string
	InstanceID string
	Token      string // delegation token issued for an allowed DELEGATE (bearer secret)
}

func refuse(status int, code, reason string) verdict {
	return verdict{Status: status, Code: code, Decision: string(policy.Deny), Reason: reason}
}

// authenticate runs the gateway's agent authentication on the headers the
// gateway forwarded. Only Authorization and X-Fortik-Instance-Id are used.
func (s *Server) authenticate(ctx context.Context, authHeader, instance string) (authz.Principal, *verdict) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://agentgw.invalid/", nil)
	if err != nil {
		v := refuse(http.StatusInternalServerError, "fortik_error", "Fortik could not authenticate the request: refused")
		return authz.Principal{}, &v
	}
	if authHeader != "" {
		r.Header.Set("Authorization", authHeader)
	}
	if instance != "" {
		r.Header.Set(gateway.InstanceHeader, instance)
	}
	p, err := s.auth.Authenticate(r)
	switch {
	case err == nil && p.Kind == authz.KindAgent && agentIDPattern.MatchString(p.Name):
		return p, nil
	case errors.Is(err, gateway.ErrBadInstanceID):
		v := refuse(http.StatusBadRequest, "bad_request", gateway.ErrBadInstanceID.Error())
		return authz.Principal{}, &v
	case errors.Is(err, gateway.ErrAuthUnavailable):
		s.log.Error("refusing callout request: agent authentication unavailable")
		v := refuse(http.StatusServiceUnavailable, "auth_unavailable", gateway.ErrAuthUnavailable.Error())
		return authz.Principal{}, &v
	default:
		v := refuse(http.StatusUnauthorized, "unauthenticated", gateway.ErrUnauthenticated.Error())
		return authz.Principal{}, &v
	}
}

// rateRules are refusals reported as 429 / RESOURCE_EXHAUSTED (spawn and
// action rate limits, docs/PHASE3_DESIGN.md §2.4).
var rateRules = map[string]bool{"POL-703": true, "POL-704": true}

// decide decides one mapped request for agent p. inbound is a presented
// delegation token ("" if none).
func (s *Server) decide(ctx context.Context, p authz.Principal, m mapped, inbound string) verdict {
	log := s.log.With("agent_id", p.Name, "system", m.System)
	if m.NoDecide && m.Malformed == "" {
		return verdict{Allow: true, AgentID: p.Name, InstanceID: p.InstanceID}
	}
	if len(inbound) > maxDelegationToken || (inbound != "" && !printable(inbound)) {
		return refuse(http.StatusBadRequest, "bad_request", "malformed "+delegation.Header+" token: refused")
	}

	a := action.Action{
		ActionID:       action.NewID("act"),
		AgentID:        p.Name,
		InstanceID:     p.InstanceID,
		System:         m.System,
		Verb:           m.Verb,
		Target:         m.Target,
		PayloadSummary: action.PayloadSummary{Bytes: m.Bytes},
		Source:         action.SourceAgentGateway,
	}
	if a.Target == nil {
		a.Target = map[string]any{}
	}
	ctx = decide.WithActor(ctx, p.Actor())

	// The token goes to the delegation enricher (which denies a bad one with
	// POL-604 and records the attempt); the callout also verifies it so a
	// bad token can never pass even if the enricher is not wired.
	tokenErr := error(nil)
	depth := 1
	if inbound != "" {
		claims, err := s.deleg.Verify(ctx, inbound, p.Name)
		if err != nil {
			tokenErr = err
		} else {
			depth = claims.Depth + 1
		}
		ctx = delegation.WithToken(ctx, inbound)
	}
	var sink *delegation.Sink
	if m.Delegate {
		a.Target["depth"] = depth
		ctx, sink = delegation.WithTokenSink(ctx)
	}

	dctx, cancel := context.WithTimeout(ctx, s.timeout)
	out, err := s.dec.Decide(dctx, a)
	cancel()
	if err != nil {
		if errors.Is(err, action.ErrInvalid) {
			log.Warn("callout action rejected as invalid", "err", err)
			return refuse(http.StatusBadRequest, "bad_request", "request could not be expressed as a valid action: refused")
		}
		log.Error("decide failed; refusing", "err", err)
		return refuse(http.StatusForbidden, "fortik_error", "Fortik could not decide: refused")
	}
	res := out.Result
	v := verdict{Decision: string(res.Decision), Class: string(res.Class), RuleID: res.RuleID, Reason: res.Reason,
		ActionID: out.Action.ActionID, Held: out.Held, Code: "fortik_refused", Status: http.StatusForbidden}
	switch {
	case m.Malformed != "":
		v.Status = http.StatusBadRequest
	case rateRules[res.RuleID]:
		v.Status = http.StatusTooManyRequests
	}
	if !res.Decision.Executes() {
		log.Info("callout refused action", "action_id", v.ActionID, "decision", v.Decision, "rule_id", v.RuleID)
		return v
	}
	notExecuted := func(rule, reason string) verdict {
		s.notExecuted(ctx, p, out, rule, reason)
		v.Decision, v.RuleID, v.Reason, v.Held = string(policy.Deny), rule, reason, false
		return v
	}
	switch {
	case m.Malformed != "":
		// UNKNOWN is always denied by policy; this is the backstop.
		return notExecuted("POL-002", "unclassified request: "+m.Malformed)
	case tokenErr != nil:
		log.Warn("delegation token rejected after an allow; refusing", "action_id", v.ActionID, "err", tokenErr)
		return notExecuted(RuleDelegationToken, "delegation token rejected: "+tokenReason(tokenErr))
	case res.Decision == policy.AllowReduced:
		return notExecuted(RuleReducedForm, fmt.Sprintf("agentgateway cannot honour a reduced form: refused (%s)", res.Reason))
	}
	if m.Delegate {
		tok, _, ok := sink.TokenFor(out)
		if !ok || tok == "" {
			log.Error("DELEGATE allowed but no delegation token was issued; refusing", "action_id", v.ActionID)
			return notExecuted(RuleDelegationToken, "no delegation token was issued for this delegation: refused (fail closed)")
		}
		v.Token = tok
	}
	v.Allow, v.AgentID, v.InstanceID = true, p.Name, p.InstanceID
	v.Status, v.Code = http.StatusOK, ""
	return v
}

func tokenReason(err error) string {
	switch {
	case errors.Is(err, delegation.ErrExpiredToken):
		return "expired"
	case errors.Is(err, delegation.ErrTokenAgent):
		return "issued to a different agent"
	default:
		return "invalid"
	}
}

// notExecuted records that an allowed action was refused by the callout.
// Best effort: the response is a refusal either way.
func (s *Server) notExecuted(ctx context.Context, p authz.Principal, out decide.Outcome, rule, reason string) {
	s.log.Warn("allowed action not executed", "agent_id", p.Name, "action_id", out.Action.ActionID, "rule_id", rule)
	if s.diary == nil {
		return
	}
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	if _, err := s.diary.Append(dctx, diary.Event{AgentID: p.Name, EventType: EventNotExecuted, Actor: "system:agentgw",
		Data: map[string]any{"action_id": out.Action.ActionID, "system": out.Action.System, "verb": string(out.Action.Verb),
			"rule_id": rule, "reason": reason}}); err != nil {
		s.log.Error("could not record agentgw.not_executed", "action_id", out.Action.ActionID, "err", err)
	}
}

// refusalText is the one-line refusal shown to agents (same shape as the hook).
func (v verdict) refusalText() string {
	var b strings.Builder
	b.WriteString("fortik: ")
	b.WriteString(v.Decision)
	if v.Class != "" {
		fmt.Fprintf(&b, " (%s)", v.Class)
	}
	if v.RuleID != "" {
		fmt.Fprintf(&b, " by %s", v.RuleID)
	}
	fmt.Fprintf(&b, ": %s", v.Reason)
	if v.ActionID != "" {
		fmt.Fprintf(&b, ". action_id=%s", v.ActionID)
	}
	return b.String()
}

func (v verdict) refusalJSON() map[string]any {
	m := map[string]any{"code": v.Code, "decision": v.Decision, "reason": v.Reason}
	if v.Class != "" {
		m["class"] = v.Class
	}
	if v.RuleID != "" {
		m["rule_id"] = v.RuleID
	}
	if v.ActionID != "" {
		m["action_id"] = v.ActionID
		m["held"] = v.Held
	}
	return m
}
