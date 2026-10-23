package agentgw

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// agentgatewayBinary is the pinned agentgateway v1.6.0 binary from the spike.
func agentgatewayBinary(t *testing.T) string {
	t.Helper()
	p := filepath.Join(repoRoot(), "spikes", "agentgateway", "bin", "agentgateway")
	if _, err := os.Stat(p); err != nil {
		t.Skipf("SKIP: agentgateway %s binary not found at %s (build or download it as in spikes/agentgateway/README.md): %v", AgentGatewayVersion, p, err)
	}
	return p
}

func testSpec(t *testing.T) GenSpec {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "spec.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseGenSpec(raw)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGenerateConfig(t *testing.T) {
	spec := testSpec(t)
	out, err := GenerateConfig(spec)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	for _, want := range []string{
		"agentgateway v1.6.0",
		"failureMode: failClosed",
		"failureMode: deny",
		"requestTimeout: 250ms",
		"allowPartialMessage: false",
		"x-fortik-route-mcp: memory",
		"x-fortik-route-agent: agent-b",
		"x-fortik-route-http: api.example.com",
		"'*': request",
		"extProc:",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("generated config lacks %q", want)
		}
	}
	for _, never := range []string{"failOpen", "failureMode: allow", "allowPartialMessage: true"} {
		if strings.Contains(text, never) {
			t.Errorf("generated config contains %q", never)
		}
	}
	if err := LintConfig(out); err != nil {
		t.Fatal(err)
	}
	// Structure: every route has its callout and the route identity is
	// injected only towards the callout (never trusted from the client).
	var root struct {
		Binds []struct {
			Listeners []struct {
				Routes []map[string]any `yaml:"routes"`
			} `yaml:"listeners"`
		} `yaml:"binds"`
	}
	if err := yaml.Unmarshal(out, &root); err != nil {
		t.Fatal(err)
	}
	routes := root.Binds[0].Listeners[0].Routes
	if len(routes) != 3 {
		t.Fatalf("routes: %d", len(routes))
	}
	fc := spec.FortikConfig()
	if fc.A2ATargets["agent-b"] != "agent_b" || fc.MCPServers["memory"] != "memory" || fc.Listen != spec.Callout {
		t.Fatalf("fortik snippet: %+v", fc)
	}

	// The pinned binary accepts it (its schema is strict about unknown fields).
	bin := agentgatewayBinary(t)
	f := filepath.Join(t.TempDir(), "agw.yaml")
	if err := os.WriteFile(f, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if b, err := exec.Command(bin, "--validate-only", "-f", f).CombinedOutput(); err != nil {
		t.Fatalf("agentgateway rejected the generated config: %v\n%s", err, b)
	}
}

func TestGenSpecValidation(t *testing.T) {
	base := func() GenSpec { return testSpec(t) }
	cases := map[string]func(*GenSpec){
		"version":         func(s *GenSpec) { s.Version = "v1.5.0" },
		"port":            func(s *GenSpec) { s.Port = 0 },
		"callout":         func(s *GenSpec) { s.Callout = "nowhere" },
		"timeout low":     func(s *GenSpec) { s.RequestTimeout = 50e6 },
		"timeout high":    func(s *GenSpec) { s.RequestTimeout = 2e9 },
		"body":            func(s *GenSpec) { s.MaxRequestBytes = 10 },
		"no routes":       func(s *GenSpec) { s.MCP, s.A2A, s.HTTP = nil, nil, nil },
		"dup name":        func(s *GenSpec) { s.A2A[0].Name = s.MCP[0].Name },
		"dup path":        func(s *GenSpec) { s.A2A[0].PathPrefix = s.MCP[0].PathPrefix },
		"bad name":        func(s *GenSpec) { s.MCP[0].Name = "Bad Name" },
		"bad path":        func(s *GenSpec) { s.MCP[0].PathPrefix = "mcp" },
		"bad mcp url":     func(s *GenSpec) { s.MCP[0].URL = "ftp://x" },
		"bad server":      func(s *GenSpec) { s.MCP[0].Server = "a b" },
		"bad agent":       func(s *GenSpec) { s.A2A[0].Agent = "bad agent" },
		"bad a2a backend": func(s *GenSpec) { s.A2A[0].Backend = "nohost" },
		"bad domain":      func(s *GenSpec) { s.HTTP[0].Domain = "API.example.com" },
		"bad admin":       func(s *GenSpec) { s.AdminAddr = "x" },
	}
	for name, mut := range cases {
		s := base()
		mut(&s)
		if _, err := GenerateConfig(s); err == nil {
			t.Errorf("%s: invalid spec accepted", name)
		}
	}
	if _, err := ParseGenSpec([]byte("port: 1\ncallout: 127.0.0.1:1\nunknown: 1\n")); err == nil {
		t.Error("unknown spec field accepted")
	}
}

func TestLintConfigCatchesBypasses(t *testing.T) {
	good, err := GenerateConfig(testSpec(t))
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][2]string{
		"extAuthz fail open":   {"failureMode: deny", "failureMode: allow"},
		"guardrails fail open": {"failureMode: failClosed", "failureMode: failOpen"},
		"partial bodies":       {"allowPartialMessage: false", "allowPartialMessage: true"},
		"slow callout":         {"requestTimeout: 250ms", "requestTimeout: 2s"},
		"response-only phase":  {"'*': request", "'*': response"},
		"no callout":           {"mcpGuardrails:", "mcpGuardrailsDisabled:"},
	}
	for name, c := range cases {
		bad := bytes.Replace(good, []byte(c[0]), []byte(c[1]), 1)
		if bytes.Equal(bad, good) {
			t.Fatalf("%s: substitution did not apply", name)
		}
		if err := LintConfig(bad); err == nil {
			t.Errorf("%s: lint passed", name)
		}
	}
	// A route without any callout.
	noCallout := []byte("binds:\n- port: 1\n  listeners:\n  - routes:\n    - name: x\n      backends:\n      - host: 127.0.0.1:1\n")
	if err := LintConfig(noCallout); err == nil || !strings.Contains(err.Error(), "bypass") {
		t.Errorf("route without callout: %v", err)
	}
	if err := LintConfig([]byte(":")); err == nil {
		t.Error("garbage passed lint")
	}
}

func TestRunConfigCommand(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "agw.yaml")
	var stdout, stderr bytes.Buffer
	if err := RunConfigCommand([]string{"-spec", filepath.Join("testdata", "spec.yaml"), "-out", out, "-fortik-snippet"}, &stdout, &stderr); err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "a2a_targets") || !strings.Contains(stderr.String(), "agent-b: agent_b") {
		t.Fatalf("snippet: %s", stderr.String())
	}
	stdout.Reset()
	if err := RunConfigCommand([]string{"-lint", out}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "OK") {
		t.Fatalf("lint: %v %s", err, stdout.String())
	}
	if err := RunConfigCommand(nil, &stdout, &stderr); err == nil {
		t.Fatal("no flags accepted")
	}
}
