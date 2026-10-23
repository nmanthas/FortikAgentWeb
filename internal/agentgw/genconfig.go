package agentgw

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"fortik/internal/config"
)

// AgentGatewayVersion is the agentgateway release the generated config is
// written for and tested against (docs/spikes/agentgateway-spike.md). Pin the
// binary to it, with its checksum, and re-run the e2e tests on upgrades.
const (
	AgentGatewayVersion = "v1.6.0"
	AgentGatewaySHA256  = "6cebe8bd57262edce23a65a376d2f5a27b97cdfef609740642edbe75e1e9c685" // agentgateway-darwin-arm64
)

// Callout timeout bounds (spike condition: 100-250ms, fail closed).
const (
	MinRequestTimeout     = 100 * time.Millisecond
	MaxRequestTimeout     = 250 * time.Millisecond
	DefaultRequestTimeout = 250 * time.Millisecond
	DefaultMaxRequestBody = 64 << 10
)

// GenSpec is the small input to the config generator (`fortik agentgw config`).
type GenSpec struct {
	Version         string        `yaml:"version"`           // optional; must equal AgentGatewayVersion
	Port            int           `yaml:"port"`              // gateway listener port
	Callout         string        `yaml:"callout"`           // Fortik callout host:port (agentgw.listen)
	RequestTimeout  time.Duration `yaml:"request_timeout"`   // default 250ms; 100ms..250ms
	MaxRequestBytes int           `yaml:"max_request_bytes"` // extAuthz body limit (default 64 KiB); larger bodies get 413
	AdminAddr       string        `yaml:"admin_addr"`        // optional agentgateway admin/stats/readiness addresses
	StatsAddr       string        `yaml:"stats_addr"`
	ReadinessAddr   string        `yaml:"readiness_addr"`
	MCP             []MCPRoute    `yaml:"mcp"`
	A2A             []A2ARoute    `yaml:"a2a"`
	HTTP            []HTTPRoute   `yaml:"http"`
}

// MCPRoute exposes one MCP server (streamable HTTP) behind mcpGuardrails.
type MCPRoute struct {
	Name       string `yaml:"name"`        // route key (agentgw.mcp_servers key)
	PathPrefix string `yaml:"path_prefix"` // e.g. /mcp/memory
	Server     string `yaml:"server"`      // MCP server name policy sees (target.server, mcp access profile)
	URL        string `yaml:"url"`         // upstream MCP endpoint, e.g. http://127.0.0.1:8090/mcp
}

// A2ARoute exposes one A2A agent behind extAuthz.
type A2ARoute struct {
	Name       string `yaml:"name"`        // route key (agentgw.a2a_targets key)
	PathPrefix string `yaml:"path_prefix"` // e.g. /a2a/agent_b
	Agent      string `yaml:"agent"`       // Fortik agent id of the target agent
	Backend    string `yaml:"backend"`     // host:port of the agent's A2A server
}

// HTTPRoute is one egress destination behind extAuthz (matched by Host).
type HTTPRoute struct {
	Name    string `yaml:"name"`
	Domain  string `yaml:"domain"`  // request Host the route matches (= target.domain)
	Backend string `yaml:"backend"` // host:port to forward to
	TLS     bool   `yaml:"tls"`     // connect to the backend with TLS
}

var routeNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,62}$`)

// ParseGenSpec reads a generator spec (YAML, unknown fields rejected).
func ParseGenSpec(raw []byte) (GenSpec, error) {
	var s GenSpec
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return GenSpec{}, fmt.Errorf("agentgw: parse config spec: %w", err)
	}
	return s, s.normalize()
}

func (s *GenSpec) normalize() error {
	if s.Version == "" {
		s.Version = AgentGatewayVersion
	}
	if s.Version != AgentGatewayVersion {
		return fmt.Errorf("agentgw: spec is for agentgateway %s; this generator is pinned to %s", s.Version, AgentGatewayVersion)
	}
	if s.RequestTimeout == 0 {
		s.RequestTimeout = DefaultRequestTimeout
	}
	if s.MaxRequestBytes == 0 {
		s.MaxRequestBytes = DefaultMaxRequestBody
	}
	return s.validate()
}

func (s *GenSpec) validate() error {
	if s.Port <= 0 || s.Port > 65535 {
		return errors.New("agentgw: spec port must be 1..65535")
	}
	if _, _, err := net.SplitHostPort(s.Callout); err != nil || s.Callout == "" {
		return fmt.Errorf("agentgw: spec callout must be host:port (got %q)", s.Callout)
	}
	if s.RequestTimeout < MinRequestTimeout || s.RequestTimeout > MaxRequestTimeout {
		return fmt.Errorf("agentgw: request_timeout must be between %s and %s (got %s)", MinRequestTimeout, MaxRequestTimeout, s.RequestTimeout)
	}
	if s.MaxRequestBytes < 1024 || s.MaxRequestBytes > 4<<20 {
		return errors.New("agentgw: max_request_bytes must be between 1024 and 4 MiB")
	}
	for _, a := range []string{s.AdminAddr, s.StatsAddr, s.ReadinessAddr} {
		if a == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(a); err != nil {
			return fmt.Errorf("agentgw: invalid admin/stats/readiness address %q", a)
		}
	}
	if len(s.MCP)+len(s.A2A)+len(s.HTTP) == 0 {
		return errors.New("agentgw: spec has no routes")
	}
	names := map[string]bool{}
	paths := map[string]bool{}
	domains := map[string]bool{}
	name := func(n string) error {
		if !routeNamePattern.MatchString(n) {
			return fmt.Errorf("agentgw: route name %q must match %s", n, routeNamePattern)
		}
		if names[n] {
			return fmt.Errorf("agentgw: duplicate route name %q", n)
		}
		names[n] = true
		return nil
	}
	path := func(p string) error {
		if !strings.HasPrefix(p, "/") || len(p) < 2 || strings.ContainsAny(p, " ?#*") {
			return fmt.Errorf("agentgw: path_prefix %q must start with / and name a sub-path", p)
		}
		if paths[p] {
			return fmt.Errorf("agentgw: duplicate path_prefix %q", p)
		}
		paths[p] = true
		return nil
	}
	for _, r := range s.MCP {
		if err := name(r.Name); err != nil {
			return err
		}
		if err := path(r.PathPrefix); err != nil {
			return err
		}
		if r.Server == "" || !printable(r.Server) || len(r.Server) > 128 || strings.ContainsAny(r.Server, " \"'") {
			return fmt.Errorf("agentgw: mcp route %s: invalid server name", r.Name)
		}
		u, err := url.Parse(r.URL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("agentgw: mcp route %s: url must be an http(s) URL", r.Name)
		}
	}
	for _, r := range s.A2A {
		if err := name(r.Name); err != nil {
			return err
		}
		if err := path(r.PathPrefix); err != nil {
			return err
		}
		if !agentIDPattern.MatchString(r.Agent) {
			return fmt.Errorf("agentgw: a2a route %s: invalid agent id %q", r.Name, r.Agent)
		}
		if _, _, err := net.SplitHostPort(r.Backend); err != nil {
			return fmt.Errorf("agentgw: a2a route %s: backend must be host:port", r.Name)
		}
	}
	for _, r := range s.HTTP {
		if err := name(r.Name); err != nil {
			return err
		}
		d, err := normalizeHost(r.Domain)
		if err != nil || d != r.Domain {
			return fmt.Errorf("agentgw: http route %s: domain must be a lowercase host name without port", r.Name)
		}
		if domains[d] {
			return fmt.Errorf("agentgw: duplicate http domain %q", d)
		}
		domains[d] = true
		if _, _, err := net.SplitHostPort(r.Backend); err != nil {
			return fmt.Errorf("agentgw: http route %s: backend must be host:port", r.Name)
		}
	}
	return nil
}

// FortikConfig returns the agentgw section fortik.yaml needs for these routes
// (route keys -> target agent / MCP server). listen is the callout address.
func (s GenSpec) FortikConfig() config.AgentGWConfig {
	c := config.AgentGWConfig{Enabled: true, Listen: s.Callout, A2ATargets: map[string]string{}, MCPServers: map[string]string{}}
	for _, r := range s.A2A {
		c.A2ATargets[r.Name] = r.Agent
	}
	for _, r := range s.MCP {
		c.MCPServers[r.Name] = r.Server
	}
	return c
}

// --- agentgateway v1.6.0 config model (only what Fortik generates) ----------

type agwConfig struct {
	Config *agwAdmin `yaml:"config,omitempty"`
	Binds  []agwBind `yaml:"binds"`
}

type agwAdmin struct {
	AdminAddr     string `yaml:"adminAddr,omitempty"`
	StatsAddr     string `yaml:"statsAddr,omitempty"`
	ReadinessAddr string `yaml:"readinessAddr,omitempty"`
}

type agwBind struct {
	Port      int           `yaml:"port"`
	Listeners []agwListener `yaml:"listeners"`
}

type agwListener struct {
	Routes []agwRoute `yaml:"routes"`
}

type agwRoute struct {
	Name      string        `yaml:"name"`
	Hostnames []string      `yaml:"hostnames,omitempty"`
	Matches   []agwMatch    `yaml:"matches,omitempty"`
	Policies  agwPolicies   `yaml:"policies"`
	Backends  []agwBackends `yaml:"backends"`
}

type agwMatch struct {
	Path agwPath `yaml:"path"`
}

type agwPath struct {
	PathPrefix string `yaml:"pathPrefix"`
}

type agwPolicies struct {
	A2A                   *struct{}          `yaml:"a2a,omitempty"`
	RequestHeaderModifier *agwHeaderModifier `yaml:"requestHeaderModifier,omitempty"`
	ExtAuthz              *agwExtAuthz       `yaml:"extAuthz,omitempty"`
	ExtProc               *agwExtProc        `yaml:"extProc,omitempty"`
	MCPGuardrails         *agwGuardrails     `yaml:"mcpGuardrails,omitempty"`
}

type agwHeaderModifier struct {
	Set    map[string]string `yaml:"set,omitempty"`
	Remove []string          `yaml:"remove,omitempty"`
}

type agwExtAuthz struct {
	Host               string             `yaml:"host"`
	Protocol           map[string]any     `yaml:"protocol"`
	IncludeRequestBody *agwRequestBody    `yaml:"includeRequestBody"`
	FailureMode        string             `yaml:"failureMode"`
	Policies           agwCalloutPolicies `yaml:"policies"`
}

// agwExtProc is the A2A response observer (ext_proc). agentgateway v1.6.0
// always runs it FULL_DUPLEX_STREAMED and after extAuthz.
type agwExtProc struct {
	Host        string             `yaml:"host"`
	FailureMode string             `yaml:"failureMode"`
	Policies    agwCalloutPolicies `yaml:"policies"`
}

type agwRequestBody struct {
	MaxRequestBytes     int  `yaml:"maxRequestBytes"`
	AllowPartialMessage bool `yaml:"allowPartialMessage"`
}

type agwCalloutPolicies struct {
	HTTP                  agwHTTP            `yaml:"http"`
	RequestHeaderModifier *agwHeaderModifier `yaml:"requestHeaderModifier,omitempty"`
}

type agwHTTP struct {
	RequestTimeout string `yaml:"requestTimeout"`
}

type agwGuardrails struct {
	Processors []agwProcessor `yaml:"processors"`
}

type agwProcessor struct {
	Kind        string             `yaml:"kind"`
	Host        string             `yaml:"host"`
	Methods     map[string]string  `yaml:"methods"`
	FailureMode string             `yaml:"failureMode"`
	Policies    agwCalloutPolicies `yaml:"policies"`
}

type agwBackends struct {
	Host     string              `yaml:"host,omitempty"`
	MCP      *agwMCPBackend      `yaml:"mcp,omitempty"`
	Policies *agwBackendPolicies `yaml:"policies,omitempty"`
}

type agwMCPBackend struct {
	Targets []agwMCPTarget `yaml:"targets"`
}

type agwMCPTarget struct {
	Name     string             `yaml:"name"`
	MCP      agwMCPHost         `yaml:"mcp"`
	Policies agwBackendPolicies `yaml:"policies"`
}

type agwMCPHost struct {
	Host string `yaml:"host"`
}

type agwBackendPolicies struct {
	RequestHeaderModifier *agwHeaderModifier `yaml:"requestHeaderModifier,omitempty"`
	BackendTLS            *struct{}          `yaml:"backendTLS,omitempty"`
}

// routeHeaders are Fortik's route identity headers; a client copy is always
// stripped before anything reaches an upstream.
var routeHeaders = []string{MetaRouteAgent, MetaRouteMCP, MetaRouteHTTP}

func durationString(d time.Duration) string {
	if d%time.Second == 0 {
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

// GenerateConfig renders the agentgateway YAML for spec:
//   - MCP routes: mcpGuardrails (every method, request phase) with
//     failureMode failClosed; the route identity is sent to the callout as
//     gRPC metadata; the client's x-fortik-agent-id is stripped before the
//     guardrail and the agent's Fortik token / delegation token are stripped
//     at the MCP target (they also cover notifications, which skip the
//     guardrail).
//   - A2A and HTTP routes: extAuthz (gRPC) with the full body
//     (allowPartialMessage false) and failureMode deny.
//   - A2A routes also get extProc (failClosed), the response observer that
//     closes delegation hops when a delegated task ends; it echoes traffic
//     unchanged and never authorizes anything.
//   - Every callout: policies.http.requestTimeout (100-250ms).
func GenerateConfig(spec GenSpec) ([]byte, error) {
	if err := spec.normalize(); err != nil {
		return nil, err
	}
	timeout := durationString(spec.RequestTimeout)
	callout := func(set map[string]string) agwCalloutPolicies {
		return agwCalloutPolicies{HTTP: agwHTTP{RequestTimeout: timeout}, RequestHeaderModifier: &agwHeaderModifier{Set: set}}
	}
	extAuthz := func(set map[string]string) *agwExtAuthz {
		return &agwExtAuthz{
			Host:               spec.Callout,
			Protocol:           map[string]any{"grpc": struct{}{}},
			IncludeRequestBody: &agwRequestBody{MaxRequestBytes: spec.MaxRequestBytes, AllowPartialMessage: false},
			FailureMode:        "deny",
			Policies:           callout(set),
		}
	}
	var routes []agwRoute
	for _, r := range spec.MCP {
		routes = append(routes, agwRoute{
			Name:    r.Name,
			Matches: []agwMatch{{Path: agwPath{PathPrefix: r.PathPrefix}}},
			Policies: agwPolicies{
				RequestHeaderModifier: &agwHeaderModifier{Remove: append([]string{HeaderAgentID, HeaderActionID}, routeHeaders...)},
				MCPGuardrails: &agwGuardrails{Processors: []agwProcessor{{
					Kind: "remote", Host: spec.Callout, Methods: map[string]string{"*": "request"},
					FailureMode: "failClosed", Policies: callout(map[string]string{MetaRouteMCP: r.Name}),
				}}},
			},
			Backends: []agwBackends{{MCP: &agwMCPBackend{Targets: []agwMCPTarget{{
				Name: r.Server,
				MCP:  agwMCPHost{Host: r.URL},
				Policies: agwBackendPolicies{RequestHeaderModifier: &agwHeaderModifier{
					Remove: append([]string{"authorization", headerDelegation}, routeHeaders...),
				}},
			}}}}},
		})
	}
	for _, r := range spec.A2A {
		routes = append(routes, agwRoute{
			Name:    r.Name,
			Matches: []agwMatch{{Path: agwPath{PathPrefix: r.PathPrefix}}},
			Policies: agwPolicies{
				A2A:      &struct{}{},
				ExtAuthz: extAuthz(map[string]string{MetaRouteAgent: r.Name}),
				ExtProc: &agwExtProc{Host: spec.Callout, FailureMode: "failClosed",
					Policies: callout(map[string]string{MetaRouteAgent: r.Name})},
			},
			Backends: []agwBackends{{Host: r.Backend, Policies: &agwBackendPolicies{RequestHeaderModifier: &agwHeaderModifier{
				Remove: append([]string{"authorization"}, routeHeaders...),
			}}}},
		})
	}
	for _, r := range spec.HTTP {
		bp := &agwBackendPolicies{RequestHeaderModifier: &agwHeaderModifier{
			Remove: append([]string{"authorization", headerDelegation}, routeHeaders...),
		}}
		if r.TLS {
			bp.BackendTLS = &struct{}{}
		}
		routes = append(routes, agwRoute{
			Name:      r.Name,
			Hostnames: []string{r.Domain},
			Policies:  agwPolicies{ExtAuthz: extAuthz(map[string]string{MetaRouteHTTP: r.Domain})},
			Backends:  []agwBackends{{Host: r.Backend, Policies: bp}},
		})
	}
	cfg := agwConfig{Binds: []agwBind{{Port: spec.Port, Listeners: []agwListener{{Routes: routes}}}}}
	if spec.AdminAddr != "" || spec.StatsAddr != "" || spec.ReadinessAddr != "" {
		cfg.Config = &agwAdmin{AdminAddr: spec.AdminAddr, StatsAddr: spec.StatsAddr, ReadinessAddr: spec.ReadinessAddr}
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "# Generated by `fortik agentgw config` for agentgateway %s (pinned; darwin-arm64 sha256 %s).\n", AgentGatewayVersion, AgentGatewaySHA256)
	buf.WriteString("# Do not hand-edit: every route goes through the Fortik callout, which fails closed\n")
	buf.WriteString("# (failureMode deny / failClosed, requestTimeout " + timeout + ", allowPartialMessage false).\n")
	buf.WriteString("# Check edits with `fortik agentgw config -lint <file>`.\n")
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return nil, fmt.Errorf("agentgw: render config: %w", err)
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	out := buf.Bytes()
	if err := LintConfig(out); err != nil {
		return nil, fmt.Errorf("agentgw: generated config failed lint (bug): %w", err)
	}
	return out, nil
}

// LintConfig checks an agentgateway config for settings that would let a
// call bypass Fortik: a route without a callout, any fail-open mode, partial
// bodies, or a missing / out-of-range callout timeout. Use it in CI on any
// hand-edited config.
func LintConfig(raw []byte) error {
	var root map[string]any
	if err := yaml.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("lint: parse: %w", err)
	}
	var problems []string
	add := func(format string, args ...any) { problems = append(problems, fmt.Sprintf(format, args...)) }

	walkFailureModes(root, "", add)

	binds, _ := root["binds"].([]any)
	if len(binds) == 0 {
		add("no binds")
	}
	nRoutes := 0
	for bi, b := range binds {
		bm, _ := b.(map[string]any)
		listeners, _ := bm["listeners"].([]any)
		for li, l := range listeners {
			lm, _ := l.(map[string]any)
			routes, _ := lm["routes"].([]any)
			for ri, r := range routes {
				nRoutes++
				rm, _ := r.(map[string]any)
				where := fmt.Sprintf("binds[%d].listeners[%d].routes[%d] (%v)", bi, li, ri, rm["name"])
				pol, _ := rm["policies"].(map[string]any)
				ea, hasEA := pol["extAuthz"].(map[string]any)
				gr, hasGR := pol["mcpGuardrails"].(map[string]any)
				if !hasEA && !hasGR {
					add("%s: no extAuthz or mcpGuardrails callout (calls would bypass Fortik)", where)
				}
				if hasEA {
					lintExtAuthz(ea, where, add)
				}
				if hasGR {
					lintGuardrails(gr, where, add)
				}
				if ep, ok := pol["extProc"].(map[string]any); ok {
					lintTimeout(ep["policies"], where+".extProc", add)
				}
				for _, be := range asList(rm["backends"]) {
					if bm, ok := be.(map[string]any); ok && bm["mcp"] != nil && !hasGR {
						add("%s: MCP backend without mcpGuardrails", where)
					}
				}
			}
		}
	}
	if nRoutes == 0 {
		add("no routes")
	}
	if len(problems) > 0 {
		sort.Strings(problems)
		return fmt.Errorf("lint: %s", strings.Join(problems, "; "))
	}
	return nil
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// walkFailureModes flags any failureMode that is not fail-closed and any
// allowPartialMessage: true, wherever they appear.
func walkFailureModes(v any, path string, add func(string, ...any)) {
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			p := path + "." + k
			switch k {
			case "failureMode":
				switch fm := x.(type) {
				case string:
					if fm != "deny" && fm != "failClosed" {
						add("%s: failureMode %q fails open", p, fm)
					}
				case map[string]any:
					if _, ok := fm["denyWithStatus"]; !ok || len(fm) != 1 {
						add("%s: failureMode must be deny, failClosed or {denyWithStatus: N}", p)
					}
				default:
					add("%s: unrecognised failureMode", p)
				}
			case "allowPartialMessage":
				if b, ok := x.(bool); !ok || b {
					add("%s: allowPartialMessage must be false (Decide would judge truncated bodies)", p)
				}
			}
			walkFailureModes(x, p, add)
		}
	case []any:
		for i, x := range t {
			walkFailureModes(x, fmt.Sprintf("%s[%d]", path, i), add)
		}
	}
}

func lintTimeout(pol any, where string, add func(string, ...any)) {
	pm, _ := pol.(map[string]any)
	hm, _ := pm["http"].(map[string]any)
	s, _ := hm["requestTimeout"].(string)
	if s == "" {
		add("%s: callout has no policies.http.requestTimeout (defaults are 2s/10s)", where)
		return
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < MinRequestTimeout || d > MaxRequestTimeout {
		add("%s: callout requestTimeout %q must be between %s and %s", where, s, MinRequestTimeout, MaxRequestTimeout)
	}
}

func lintExtAuthz(ea map[string]any, where string, add func(string, ...any)) {
	if fm, ok := ea["failureMode"]; !ok || fm == nil {
		add("%s: extAuthz without an explicit failureMode", where)
	}
	if p, _ := ea["protocol"].(map[string]any); p == nil || p["grpc"] == nil {
		add("%s: extAuthz must use the gRPC protocol", where)
	}
	if _, ok := ea["includeRequestBody"].(map[string]any); !ok {
		add("%s: extAuthz without includeRequestBody (Decide cannot classify the call)", where)
	}
	lintTimeout(ea["policies"], where+".extAuthz", add)
}

func lintGuardrails(gr map[string]any, where string, add func(string, ...any)) {
	procs := asList(gr["processors"])
	if len(procs) == 0 {
		add("%s: mcpGuardrails without processors", where)
	}
	for i, p := range procs {
		pm, _ := p.(map[string]any)
		w := fmt.Sprintf("%s.mcpGuardrails.processors[%d]", where, i)
		if fm, _ := pm["failureMode"].(string); fm != "failClosed" {
			add("%s: failureMode must be failClosed", w)
		}
		methods, _ := pm["methods"].(map[string]any)
		if ph, _ := methods["*"].(string); ph != "request" && ph != "full" {
			add("%s: methods must gate \"*\" in the request phase", w)
		}
		lintTimeout(pm["policies"], w, add)
	}
}

// RunConfigCommand implements `fortik agentgw config`:
//
//	fortik agentgw config -spec routes.yaml [-out agentgateway.yaml] [-fortik-snippet]
//	fortik agentgw config -lint agentgateway.yaml
func RunConfigCommand(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("agentgw config", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "route spec (YAML) to generate the agentgateway config from")
	outPath := fs.String("out", "", "write the agentgateway config here instead of stdout")
	snippet := fs.Bool("fortik-snippet", false, "also print the agentgw section for fortik.yaml (to stderr)")
	lintPath := fs.String("lint", "", "lint an existing agentgateway config instead of generating one")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *lintPath != "" {
		raw, err := os.ReadFile(*lintPath)
		if err != nil {
			return err
		}
		if err := LintConfig(raw); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "agentgateway config OK: every route goes through the Fortik callout and fails closed")
		return nil
	}
	if *specPath == "" {
		fs.Usage()
		return errors.New("agentgw config: -spec or -lint is required")
	}
	raw, err := os.ReadFile(*specPath)
	if err != nil {
		return err
	}
	spec, err := ParseGenSpec(raw)
	if err != nil {
		return err
	}
	out, err := GenerateConfig(spec)
	if err != nil {
		return err
	}
	if *outPath != "" {
		if err := os.WriteFile(*outPath, out, 0o644); err != nil {
			return err
		}
	} else if _, err := stdout.Write(out); err != nil {
		return err
	}
	if *snippet {
		b, err := yaml.Marshal(map[string]any{"agentgw": fortikSnippet(spec.FortikConfig())})
		if err != nil {
			return err
		}
		fmt.Fprintf(stderr, "# add to fortik.yaml:\n%s", b)
	}
	return nil
}

func fortikSnippet(c config.AgentGWConfig) map[string]any {
	m := map[string]any{"enabled": c.Enabled, "listen": c.Listen}
	if len(c.A2ATargets) > 0 {
		m["a2a_targets"] = c.A2ATargets
	}
	if len(c.MCPServers) > 0 {
		m["mcp_servers"] = c.MCPServers
	}
	return m
}
