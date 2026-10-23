package agentgw

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"fortik/internal/action"
)

// ToolVerbsFile is the MCP verb table inside the policy bundle directory
// (read by Rego as data.fortik.mcp, by Go through LoadToolVerbs).
const ToolVerbsFile = "fortik/mcp/data.json"

// Verb sources reported in target.verb_source.
const (
	VerbFromMap       = "map"       // explicit {server: {tool: verb}} entry
	VerbFromHeuristic = "heuristic" // name heuristics
	VerbDefault       = "default"   // unmapped: EXECUTE (held until mapped)
)

// ToolVerbs classifies MCP tools. It is the single Go implementation of the
// table in policies/fortik/mcp/data.json; policies/fortik/mcp/mcp.rego
// re-checks every classification (POL-803), so every interception point that
// produces system "mcp" actions (agentgateway callout, Claude Code hook) must
// use it.
type ToolVerbs struct {
	verbs            map[string]map[string]action.Verb
	readPrefixes     []string
	rememberTools    map[string]bool
	rememberPrefixes []string
	deletePrefixes   []string
	unsafeTokens     []string
}

type toolVerbsFile struct {
	ToolVerbs        map[string]map[string]string `json:"tool_verbs"`
	ReadPrefixes     []string                     `json:"read_prefixes"`
	RememberTools    []string                     `json:"remember_tools"`
	RememberPrefixes []string                     `json:"remember_prefixes"`
	DeletePrefixes   []string                     `json:"delete_prefixes"`
	UnsafeNameTokens []string                     `json:"unsafe_name_tokens"`
}

// toolNamePattern bounds what a tool name may look like. Anything else is
// classified UNKNOWN (policy denies, POL-002).
var toolNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)

// LoadToolVerbs reads <policyDir>/fortik/mcp/data.json.
func LoadToolVerbs(policyDir string) (*ToolVerbs, error) {
	raw, err := os.ReadFile(filepath.Join(policyDir, filepath.FromSlash(ToolVerbsFile)))
	if err != nil {
		return nil, fmt.Errorf("agentgw: read MCP verb table: %w", err)
	}
	return ParseToolVerbs(raw)
}

// ParseToolVerbs parses the verb table. Unknown fields, unknown verbs and
// empty entries are errors (a table that cannot be read classifies nothing).
func ParseToolVerbs(raw []byte) (*ToolVerbs, error) {
	var f toolVerbsFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("agentgw: parse MCP verb table: %w", err)
	}
	if dec.More() {
		return nil, errors.New("agentgw: parse MCP verb table: trailing data")
	}
	if len(f.ReadPrefixes) == 0 || len(f.UnsafeNameTokens) == 0 {
		return nil, errors.New("agentgw: MCP verb table needs read_prefixes and unsafe_name_tokens")
	}
	tv := &ToolVerbs{
		verbs:            map[string]map[string]action.Verb{},
		readPrefixes:     lowerAll(f.ReadPrefixes),
		rememberTools:    map[string]bool{},
		rememberPrefixes: lowerAll(f.RememberPrefixes),
		deletePrefixes:   lowerAll(f.DeletePrefixes),
		unsafeTokens:     lowerAll(f.UnsafeNameTokens),
	}
	for _, t := range f.RememberTools {
		tv.rememberTools[strings.ToLower(t)] = true
	}
	for server, tools := range f.ToolVerbs {
		if server == "" {
			return nil, errors.New("agentgw: MCP verb table has an empty server name")
		}
		m := make(map[string]action.Verb, len(tools))
		for tool, v := range tools {
			verb := action.Verb(v)
			if !action.KnownVerb(verb) || tool == "" {
				return nil, fmt.Errorf("agentgw: MCP verb table: %s/%s has invalid verb %q", server, tool, v)
			}
			m[tool] = verb
		}
		tv.verbs[server] = m
	}
	for _, l := range [][]string{tv.readPrefixes, tv.rememberPrefixes, tv.deletePrefixes, tv.unsafeTokens} {
		for _, s := range l {
			if s == "" {
				return nil, errors.New("agentgw: MCP verb table has an empty prefix or token")
			}
		}
	}
	return tv, nil
}

func lowerAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = strings.ToLower(s)
	}
	return out
}

// Verb classifies tool on server. The explicit table wins (server entry,
// then "*"); then delete_* → DELETE, memory writes → REMEMBER, read
// prefixes → READ (only when no side-effect word appears in the name);
// everything else is EXECUTE, which policy holds until it is mapped.
// A malformed tool name is "UNKNOWN" (denied by POL-002).
func (tv *ToolVerbs) Verb(server, tool string) (action.Verb, string) {
	if tv == nil || !toolNamePattern.MatchString(tool) {
		return "UNKNOWN", VerbDefault
	}
	if v, ok := tv.verbs[server][tool]; ok {
		return v, VerbFromMap
	}
	if v, ok := tv.verbs["*"][tool]; ok {
		return v, VerbFromMap
	}
	name := strings.ToLower(tool)
	if hasAnyPrefix(name, tv.deletePrefixes) {
		return action.VerbDelete, VerbFromHeuristic
	}
	if tv.rememberTools[name] || hasAnyPrefix(name, tv.rememberPrefixes) {
		return action.VerbRemember, VerbFromHeuristic
	}
	if hasAnyPrefix(name, tv.readPrefixes) && !containsAny(name, tv.unsafeTokens) {
		return action.VerbRead, VerbFromHeuristic
	}
	return action.VerbExecute, VerbDefault
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func containsAny(s string, tokens []string) bool {
	for _, t := range tokens {
		if strings.Contains(s, t) {
			return true
		}
	}
	return false
}
