package access

import (
	"regexp"
	"slices"
	"strings"
)

// SaaSSystems are the business systems with a SaaSProfile.
var SaaSSystems = []string{"salesforce", "servicenow", "sap"}

// SaaSProfile (Salesforce, ServiceNow, SAP) applies to every transport (the
// REST gateway and the provider's MCP endpoint):
//
//	{"mode":"none|read_only|read_write",
//	 "objects":["*"] | names,          // Salesforce objects, ServiceNow tables, SAP <SERVICE>/<EntitySet>
//	 "integrations":["*"] | ids,       // optional: tenants (salesforce:acme); absent = every tenant
//	 "mcp_tools":["*"] | names}        // optional: MCP tools; absent = every tool the mode allows
//
// Object names compare case-insensitively.
type SaaSProfile struct {
	Mode         string   `json:"mode"`
	Objects      []string `json:"objects"`
	Integrations []string `json:"integrations,omitempty"`
	MCPTools     []string `json:"mcp_tools,omitempty"`
}

var (
	saasObject = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_./$-]{0,159}$`)
	saasTool   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,127}$`)
)

// AllowsIntegration reports whether integrations permits a tenant.
func (p SaaSProfile) AllowsIntegration(id string) bool {
	return p.Integrations == nil || slices.Contains(p.Integrations, "*") || slices.Contains(p.Integrations, id)
}

// AllowsTool reports whether mcp_tools permits an MCP tool.
func (p SaaSProfile) AllowsTool(tool string) bool {
	return p.MCPTools == nil || slices.Contains(p.MCPTools, "*") || slices.Contains(p.MCPTools, tool)
}

func parseSaaS(system string, raw []byte) (SaaSProfile, error) {
	var p SaaSProfile
	if err := decodeStrict(raw, &p); err != nil {
		return p, err
	}
	if err := oneOf("mode", p.Mode, ModeNone, ModeReadOnly, ModeReadWrite); err != nil {
		return p, err
	}
	if p.Objects == nil {
		return p, invalid("%s: objects is required (use [\"*\"] for every object)", system)
	}
	list := func(field string, in []string, re *regexp.Regexp, norm func(string) string) ([]string, error) {
		if in == nil {
			return nil, nil
		}
		if slices.Contains(in, "*") {
			if len(in) != 1 {
				return nil, invalid("%s: %s is either [\"*\"] or a list", system, field)
			}
			return in, nil
		}
		return normList(system+": "+field, in, func(s string) (string, error) {
			if !re.MatchString(s) {
				return "", invalid("%s: %s entry %q is not valid", system, field, s)
			}
			return norm(s), nil
		})
	}
	var err error
	if p.Objects, err = list("objects", p.Objects, saasObject, strings.ToLower); err != nil {
		return p, err
	}
	tenant := regexp.MustCompile(`^` + system + `:[a-z][a-z0-9_]{0,62}$`)
	if p.Integrations, err = list("integrations", p.Integrations, tenant, func(s string) string { return s }); err != nil {
		return p, err
	}
	if p.MCPTools, err = list("mcp_tools", p.MCPTools, saasTool, func(s string) string { return s }); err != nil {
		return p, err
	}
	return p, nil
}

// widensList: a restricted previous list widens when the next is absent,
// ["*"], or names anything new.
func widensList(prev, next []string) bool {
	if prev == nil || slices.Contains(prev, "*") {
		return false
	}
	if next == nil || slices.Contains(next, "*") {
		return true
	}
	for _, x := range next {
		if !slices.Contains(prev, x) {
			return true
		}
	}
	return false
}

func widensSaaS(n, p SaaSProfile, hadPrev bool) bool {
	if !hadPrev {
		return n.Mode != ModeNone
	}
	if rank(modeRank, n.Mode) > rank(modeRank, p.Mode) {
		return true
	}
	// objects is required: ["*"] is every object.
	if !slices.Contains(p.Objects, "*") {
		if slices.Contains(n.Objects, "*") {
			return true
		}
		for _, o := range n.Objects {
			if !slices.Contains(p.Objects, o) {
				return true
			}
		}
	}
	return widensList(p.Integrations, n.Integrations) || widensList(p.MCPTools, n.MCPTools)
}
