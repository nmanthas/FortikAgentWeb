package access

import (
	"encoding/json"
	"regexp"
	"slices"
	"strings"
)

// Phase 3 profile systems (docs/PHASE3_DESIGN.md §1.5): who an agent may
// delegate to (a2a), where it may reach outside the company (http) and which
// MCP servers and tools it may use (mcp). The same rules as the Phase 2
// shapes apply: every field is required unless marked optional, decoding is
// strict, and values are normalised so Widens and policy compare like with like.

// A2AProfile: {"may_delegate_to":["agent_b"],"max_depth":3}. may_delegate_to
// lists agent ids, or is exactly ["*"] for any agent. max_depth bounds the
// depth of a delegation this agent creates (1 = only direct delegations).
// Delegating to itself (a Claude Code Task subagent) never needs the profile.
type A2AProfile struct {
	MayDelegateTo []string `json:"may_delegate_to"`
	MaxDepth      *int     `json:"max_depth"`
}

// HTTPProfile: {"external":"none|allowlist|any","allowed_domains":["api.example.com","*.example.org"]}.
// allowed_domains is optional and only allowed (and then required, non-empty)
// with external "allowlist". "*.example.org" matches any subdomain of
// example.org at any depth, not example.org itself.
type HTTPProfile struct {
	External       string   `json:"external"`
	AllowedDomains []string `json:"allowed_domains"`
}

// MCPProfile: {"servers":{"github-mcp":["*"],"memory":["read_graph","search_nodes"]}}.
// Each listed server maps to its allowed tools, or exactly ["*"] for all of
// them. An empty list allows only the server's non-tool requests
// (tools/list, resources/read, prompts/get); a server not listed allows nothing.
type MCPProfile struct {
	Servers map[string][]string `json:"servers"`
}

// HTTP external modes.
const (
	ExternalNone      = "none"
	ExternalAllowlist = "allowlist"
	ExternalAny       = "any"
)

// Wildcard grants every agent (a2a) or every tool (mcp). It must be the only entry.
const Wildcard = "*"

// MaxDelegationDepth bounds a2a max_depth (the global limit is
// delegation.max_depth in policy data; a profile cannot exceed this ceiling).
const MaxDelegationDepth = 32

const maxDomainLen = 253

var (
	// Agent ids as accepted by the action schema.
	agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	// Lowercase DNS names (labels of letters, digits and '-'), optionally
	// with a leading "*." wildcard label.
	domainPattern = regexp.MustCompile(`^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	// MCP server names as configured in agentgw.mcp_servers.
	mcpServerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	// MCP tool names (the MCP spec allows letters, digits, '_', '-', '.', '/').
	mcpToolPattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./-]{0,127}$`)
)

func parseA2A(raw json.RawMessage) (A2AProfile, error) {
	var p A2AProfile
	if err := decodeStrict(raw, &p); err != nil {
		return A2AProfile{}, err
	}
	if p.MayDelegateTo == nil {
		return A2AProfile{}, invalid("a2a: may_delegate_to is required (use [] for none)")
	}
	if p.MaxDepth == nil {
		return A2AProfile{}, invalid("a2a: max_depth is required")
	}
	if *p.MaxDepth < 1 || *p.MaxDepth > MaxDelegationDepth {
		return A2AProfile{}, invalid("a2a: max_depth must be between 1 and %d", MaxDelegationDepth)
	}
	to, err := wildcardList("a2a: may_delegate_to", p.MayDelegateTo, func(s string) (string, error) {
		if !agentIDPattern.MatchString(s) {
			return "", invalid("a2a: may_delegate_to entry %q is not an agent id", s)
		}
		return s, nil
	})
	if err != nil {
		return A2AProfile{}, err
	}
	p.MayDelegateTo = to
	return p, nil
}

func parseHTTP(raw json.RawMessage) (HTTPProfile, error) {
	var p HTTPProfile
	if err := decodeStrict(raw, &p); err != nil {
		return HTTPProfile{}, err
	}
	if err := oneOf("http: external", p.External, ExternalNone, ExternalAllowlist, ExternalAny); err != nil {
		return HTTPProfile{}, err
	}
	domains, err := normList("http: allowed_domains", p.AllowedDomains, NormalizeDomainPattern)
	if err != nil {
		return HTTPProfile{}, err
	}
	switch {
	case p.External == ExternalAllowlist && len(domains) == 0:
		return HTTPProfile{}, invalid("http: external allowlist needs at least one allowed_domains entry (use external none to refuse all)")
	case p.External != ExternalAllowlist && len(domains) > 0:
		return HTTPProfile{}, invalid("http: allowed_domains applies only to external allowlist (external is %s)", p.External)
	}
	if domains == nil {
		domains = []string{}
	}
	p.AllowedDomains = domains
	return p, nil
}

func parseMCP(raw json.RawMessage) (MCPProfile, error) {
	var p MCPProfile
	if err := decodeStrict(raw, &p); err != nil {
		return MCPProfile{}, err
	}
	if p.Servers == nil {
		return MCPProfile{}, invalid("mcp: servers is required (use {} for none)")
	}
	if len(p.Servers) > maxListLen {
		return MCPProfile{}, invalid("mcp: at most %d servers", maxListLen)
	}
	out := make(map[string][]string, len(p.Servers))
	for name, tools := range p.Servers {
		if !mcpServerPattern.MatchString(name) {
			return MCPProfile{}, invalid("mcp: server name %q is invalid", name)
		}
		if tools == nil {
			return MCPProfile{}, invalid("mcp: servers.%s must be a list of tools (use [] for none, [\"*\"] for all)", name)
		}
		norm, err := wildcardList("mcp: servers."+name, tools, func(s string) (string, error) {
			if !mcpToolPattern.MatchString(s) {
				return "", invalid("mcp: tool %q on server %s is invalid", s, name)
			}
			return s, nil
		})
		if err != nil {
			return MCPProfile{}, err
		}
		out[name] = norm
	}
	p.Servers = out
	return p, nil
}

// wildcardList is normList where the entry "*" is allowed only on its own.
func wildcardList(field string, in []string, norm func(string) (string, error)) ([]string, error) {
	out, err := normList(field, in, func(s string) (string, error) {
		if s == Wildcard {
			return s, nil
		}
		return norm(s)
	})
	if err != nil {
		return nil, err
	}
	if slices.Contains(out, Wildcard) && len(out) > 1 {
		return nil, invalid("%s: \"*\" must be the only entry", field)
	}
	return out, nil
}

// NormalizeDomainPattern lowercases an allowed_domains entry, drops a
// trailing dot and checks it is a DNS name or "*." followed by one. A bare
// "*" is refused (use external any).
func NormalizeDomainPattern(s string) (string, error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if len(d) == 0 || len(d) > maxDomainLen || !domainPattern.MatchString(d) {
		return "", invalid("http: allowed domain %q must be a host name such as api.example.com or *.example.org", s)
	}
	return d, nil
}

// DomainAllowed reports whether host (any case, optional trailing dot or
// :port) matches one of the normalised allowed_domains patterns. Policy
// (POL-028) applies the same rule; this is for Go callers and tests.
func DomainAllowed(host string, patterns []string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	if i := strings.LastIndexByte(h, ':'); i >= 0 && !strings.Contains(h[:i], ":") {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return false
	}
	for _, p := range patterns {
		if domainCovers(p, h) {
			return true
		}
	}
	return false
}

// domainCovers reports whether pattern p covers d, where d is a host or
// itself a pattern ("*.a.example.org" is covered by "*.example.org").
func domainCovers(p, d string) bool {
	if p == d {
		return true
	}
	suffix, ok := strings.CutPrefix(p, "*.")
	if !ok {
		return false
	}
	d = strings.TrimPrefix(d, "*.")
	return strings.HasSuffix(d, "."+suffix)
}

// widensA2A: a new delegation target (or "*" where there was none) or a
// deeper max_depth widens.
func widensA2A(n, p A2AProfile, hadPrev bool) bool {
	if !hadPrev {
		return true // any a2a profile grants delegation where there was none
	}
	if *n.MaxDepth > *p.MaxDepth {
		return true
	}
	if slices.Contains(p.MayDelegateTo, Wildcard) {
		return false
	}
	for _, a := range n.MayDelegateTo {
		if !slices.Contains(p.MayDelegateTo, a) {
			return true
		}
	}
	return false
}

var externalRank = map[string]int{ExternalNone: 0, ExternalAllowlist: 1, ExternalAny: 2}

// widensHTTP: a broader external mode, or (both allowlists) a domain the
// previous list did not cover.
func widensHTTP(n, p HTTPProfile, hadPrev bool) bool {
	if !hadPrev {
		// Internal requests need a profile at all (POL-020), so any profile widens.
		return true
	}
	if rank(externalRank, n.External) > rank(externalRank, p.External) {
		return true
	}
	if n.External == ExternalAllowlist && p.External == ExternalAllowlist {
		for _, d := range n.AllowedDomains {
			covered := false
			for _, pd := range p.AllowedDomains {
				if domainCovers(pd, d) {
					covered = true
					break
				}
			}
			if !covered {
				return true
			}
		}
	}
	return false
}

// widensMCP: a new server, "*" where there was none, or a new tool.
func widensMCP(n, p MCPProfile, hadPrev bool) bool {
	if !hadPrev {
		return len(n.Servers) > 0
	}
	for name, tools := range n.Servers {
		prev, ok := p.Servers[name]
		if !ok {
			return true
		}
		if slices.Contains(prev, Wildcard) {
			continue
		}
		for _, t := range tools {
			if !slices.Contains(prev, t) {
				return true
			}
		}
	}
	return false
}
