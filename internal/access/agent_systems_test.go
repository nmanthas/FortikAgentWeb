package access_test

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"fortik/internal/access"
)

// Phase 3 systems (docs/PHASE3_DESIGN.md §1.5): a2a, http and mcp.

func TestAgentSystemsListed(t *testing.T) {
	for _, s := range []string{"a2a", "http", "mcp"} {
		if !slices.Contains(access.Systems, s) || !access.KnownSystem(s) {
			t.Errorf("%s is not a profiled system", s)
		}
	}
}

func TestValidateAgentSystems(t *testing.T) {
	cases := []struct{ system, in, want string }{
		{"a2a", `{"may_delegate_to":["agent_c","agent_b"],"max_depth":3}`, `{"may_delegate_to":["agent_b","agent_c"],"max_depth":3}`},
		{"a2a", `{"may_delegate_to":["*"],"max_depth":1}`, `{"may_delegate_to":["*"],"max_depth":1}`},
		{"a2a", `{"may_delegate_to":[],"max_depth":1}`, `{"may_delegate_to":[],"max_depth":1}`},
		{"http", `{"external":"none"}`, `{"external":"none","allowed_domains":[]}`},
		{"http", `{"external":"any","allowed_domains":[]}`, `{"external":"any","allowed_domains":[]}`},
		{"http", `{"external":"allowlist","allowed_domains":["API.Example.com.","*.example.org"]}`,
			`{"external":"allowlist","allowed_domains":["*.example.org","api.example.com"]}`},
		{"mcp", `{"servers":{"github-mcp":["*"],"memory":["search_nodes","read_graph"]}}`,
			`{"servers":{"github-mcp":["*"],"memory":["read_graph","search_nodes"]}}`},
		{"mcp", `{"servers":{}}`, `{"servers":{}}`},
		{"mcp", `{"servers":{"memory":[]}}`, `{"servers":{"memory":[]}}`},
	}
	for _, c := range cases {
		got, err := access.Validate(c.system, json.RawMessage(c.in))
		if err != nil {
			t.Errorf("%s %s: %v", c.system, c.in, err)
			continue
		}
		if string(got) != c.want {
			t.Errorf("%s %s: got %s want %s", c.system, c.in, got, c.want)
		}
	}
}

func TestValidateAgentSystemsRejects(t *testing.T) {
	cases := []struct{ system, in string }{
		{"a2a", `{}`},
		{"a2a", `{"max_depth":2}`},
		{"a2a", `{"may_delegate_to":["agent_b"]}`},
		{"a2a", `{"may_delegate_to":["agent_b"],"max_depth":0}`},
		{"a2a", `{"may_delegate_to":["agent_b"],"max_depth":33}`},
		{"a2a", `{"may_delegate_to":["agent_b"],"max_depth":1.5}`},
		{"a2a", `{"may_delegate_to":["*","agent_b"],"max_depth":2}`},
		{"a2a", `{"may_delegate_to":["agent b"],"max_depth":2}`},
		{"a2a", `{"may_delegate_to":["agent_b","agent_b"],"max_depth":2}`},
		{"a2a", `{"may_delegate_to":["agent_b"],"max_depth":2,"extra":true}`},
		{"a2a", `{"may_delegate_to":"agent_b","max_depth":2}`},
		{"http", `{}`},
		{"http", `{"external":"some"}`},
		{"http", `{"external":"allowlist"}`},
		{"http", `{"external":"allowlist","allowed_domains":[]}`},
		{"http", `{"external":"none","allowed_domains":["example.com"]}`},
		{"http", `{"external":"any","allowed_domains":["example.com"]}`},
		{"http", `{"external":"allowlist","allowed_domains":["*"]}`},
		{"http", `{"external":"allowlist","allowed_domains":["exa mple.com"]}`},
		{"http", `{"external":"allowlist","allowed_domains":["https://example.com"]}`},
		{"http", `{"external":"allowlist","allowed_domains":["ex*.com"]}`},
		{"http", `{"external":"allowlist","allowed_domains":["example.com","EXAMPLE.com"]}`},
		{"http", `{"external":"none","bogus":1}`},
		{"mcp", `{}`},
		{"mcp", `{"servers":{"memory":null}}`},
		{"mcp", `{"servers":{"memory":["*","read_graph"]}}`},
		{"mcp", `{"servers":{"bad server":["x"]}}`},
		{"mcp", `{"servers":{"memory":["read graph"]}}`},
		{"mcp", `{"servers":{"memory":["read_graph","read_graph"]}}`},
		{"mcp", `{"servers":{"memory":"*"}}`},
		{"mcp", `{"servers":{},"tools":[]}`},
	}
	for _, c := range cases {
		if _, err := access.Validate(c.system, json.RawMessage(c.in)); !errors.Is(err, access.ErrInvalidProfile) {
			t.Errorf("%s %s: accepted or wrong error: %v", c.system, c.in, err)
		}
	}
}

func TestWidensAgentSystems(t *testing.T) {
	cases := []struct {
		name, system, prev, next string
		want                     bool
	}{
		{"a2a from nothing", "a2a", ``, `{"may_delegate_to":[],"max_depth":1}`, true},
		{"a2a same", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":2}`, `{"may_delegate_to":["agent_b"],"max_depth":2}`, false},
		{"a2a new target", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":2}`, `{"may_delegate_to":["agent_b","agent_c"],"max_depth":2}`, true},
		{"a2a wildcard", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":2}`, `{"may_delegate_to":["*"],"max_depth":2}`, true},
		{"a2a narrower than wildcard", "a2a", `{"may_delegate_to":["*"],"max_depth":2}`, `{"may_delegate_to":["agent_b"],"max_depth":2}`, false},
		{"a2a deeper", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":2}`, `{"may_delegate_to":["agent_b"],"max_depth":3}`, true},
		{"a2a shallower, fewer", "a2a", `{"may_delegate_to":["agent_b","agent_c"],"max_depth":3}`, `{"may_delegate_to":["agent_c"],"max_depth":1}`, false},
		{"http from nothing", "http", `null`, `{"external":"none"}`, true},
		{"http none to allowlist", "http", `{"external":"none"}`, `{"external":"allowlist","allowed_domains":["example.com"]}`, true},
		{"http allowlist to any", "http", `{"external":"allowlist","allowed_domains":["example.com"]}`, `{"external":"any"}`, true},
		{"http any to allowlist", "http", `{"external":"any"}`, `{"external":"allowlist","allowed_domains":["example.com"]}`, false},
		{"http allowlist to none", "http", `{"external":"allowlist","allowed_domains":["example.com"]}`, `{"external":"none"}`, false},
		{"http new domain", "http", `{"external":"allowlist","allowed_domains":["example.com"]}`, `{"external":"allowlist","allowed_domains":["example.com","example.net"]}`, true},
		{"http subdomain covered", "http", `{"external":"allowlist","allowed_domains":["*.example.org"]}`, `{"external":"allowlist","allowed_domains":["api.example.org","*.x.example.org"]}`, false},
		{"http apex not covered by wildcard", "http", `{"external":"allowlist","allowed_domains":["*.example.org"]}`, `{"external":"allowlist","allowed_domains":["example.org"]}`, true},
		{"http host to wildcard", "http", `{"external":"allowlist","allowed_domains":["api.example.org"]}`, `{"external":"allowlist","allowed_domains":["*.example.org"]}`, true},
		{"mcp from nothing, empty", "mcp", ``, `{"servers":{}}`, false},
		{"mcp from nothing", "mcp", ``, `{"servers":{"memory":[]}}`, true},
		{"mcp new server", "mcp", `{"servers":{"memory":["read_graph"]}}`, `{"servers":{"memory":["read_graph"],"github-mcp":[]}}`, true},
		{"mcp new tool", "mcp", `{"servers":{"memory":["read_graph"]}}`, `{"servers":{"memory":["read_graph","create_entities"]}}`, true},
		{"mcp all tools", "mcp", `{"servers":{"memory":["read_graph"]}}`, `{"servers":{"memory":["*"]}}`, true},
		{"mcp narrower than all", "mcp", `{"servers":{"memory":["*"]}}`, `{"servers":{"memory":["read_graph"]}}`, false},
		{"mcp drop server", "mcp", `{"servers":{"memory":["*"],"github-mcp":["*"]}}`, `{"servers":{"memory":["*"]}}`, false},
	}
	for _, c := range cases {
		got, err := access.Widens(c.system, json.RawMessage(c.prev), json.RawMessage(c.next))
		if err != nil {
			t.Errorf("%s: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: widens=%v want %v", c.name, got, c.want)
		}
	}
	if w, err := access.Widens("a2a", nil, json.RawMessage(`{"may_delegate_to":["*"]}`)); err == nil || !w {
		t.Fatalf("invalid a2a next: widens=%v err=%v", w, err)
	}
	if w, err := access.Widens("http", json.RawMessage(`{"external":"maybe"}`), json.RawMessage(`{"external":"none"}`)); err == nil || !w {
		t.Fatalf("invalid http prev: widens=%v err=%v", w, err)
	}
}

func TestDomainAllowed(t *testing.T) {
	pats := []string{"api.example.com", "*.example.org"}
	for host, want := range map[string]bool{
		"api.example.com":      true,
		"API.Example.COM.":     true,
		"api.example.com:8443": true,
		"example.com":          false,
		"x.api.example.com":    false,
		"a.example.org":        true,
		"a.b.example.org":      true,
		"example.org":          false,
		"badexample.org":       false,
		"example.org.evil.com": false,
		"":                     false,
	} {
		if got := access.DomainAllowed(host, pats); got != want {
			t.Errorf("%q: %v want %v", host, got, want)
		}
	}
}
