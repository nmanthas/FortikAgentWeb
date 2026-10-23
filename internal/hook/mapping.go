package hook

// Mapping of a Claude Code PreToolUse event onto a Fortik Action
// (docs/PHASE3_DESIGN.md §3.3). The mapping only describes what the tool
// call would do; policy decides whether it may run.

import (
	"encoding/json"
	"regexp"
	"strings"

	"fortik/internal/action"
	"fortik/internal/commap"
)

// Event is the PreToolUse JSON Claude Code writes to the hook's stdin.
// Decoded leniently: Claude Code may add fields.
type Event struct {
	SessionID      string          `json:"session_id"`
	TranscriptPath string          `json:"transcript_path"`
	Cwd            string          `json:"cwd"`
	PermissionMode string          `json:"permission_mode"`
	HookEventName  string          `json:"hook_event_name"`
	ToolUseID      string          `json:"tool_use_id"`
	ToolName       string          `json:"tool_name"`
	ToolInput      json.RawMessage `json:"tool_input"`
	AgentID        string          `json:"agent_id"`
	MCPServer      string          `json:"mcp_server"`
}

// toolInput is the union of the documented tool_input fields we read.
type toolInput struct {
	Command         string `json:"command"`
	RunInBackground bool   `json:"run_in_background"`
	FilePath        string `json:"file_path"`
	NotebookPath    string `json:"notebook_path"`
	Path            string `json:"path"`
	Pattern         string `json:"pattern"`
	URL             string `json:"url"`
	Query           string `json:"query"`
	SubagentType    string `json:"subagent_type"`
}

// internalTools touch nothing outside the Claude Code session: recorded as
// cheap green files READs (operation internal_tool), still decided.
var internalTools = set("TodoWrite", "TodoRead", "ExitPlanMode", "EnterPlanMode", "AskUserQuestion", "BashOutput",
	"KillShell", "KillBash", "SlashCommand", "ListMcpResourcesTool")

var writeTools = set("Write", "Edit", "MultiEdit", "NotebookEdit")

var readTools = set("Read", "Glob", "Grep", "NotebookRead", "LS")

// MCPVerbs classifies MCP tools (*agentgw.ToolVerbs, built from
// policies/fortik/mcp/data.json with agentgw.LoadToolVerbs).
type MCPVerbs interface {
	Verb(server, tool string) (action.Verb, string)
}

var mcpNamePattern = regexp.MustCompile(`^mcp__([A-Za-z0-9_.-]+?)__([A-Za-z0-9_.:/-]+)$`)

// mapped is the Action fields the mapping decides.
type mapped struct {
	System string
	Verb   action.Verb
	Target map[string]any
}

func unknownTool(tool, reason string) mapped {
	return mapped{System: action.SystemShell, Verb: "UNKNOWN", Target: map[string]any{"tool": clip(tool), "unknown_tool": true, "reason": reason}}
}

// mapEvent maps one event. env holds the hints the client sent (PGHOST,
// PGPORT, PGDATABASE, HOME, CLAUDE_PROJECT_DIR); agent is the acting agent.
func (h *Handler) mapEvent(ev Event, env map[string]string, agent string) mapped {
	if ev.HookEventName != "PreToolUse" {
		return unknownTool(ev.ToolName, "not a PreToolUse event")
	}
	var in toolInput
	if len(ev.ToolInput) > 0 && string(ev.ToolInput) != "null" {
		if err := json.Unmarshal(ev.ToolInput, &in); err != nil {
			return unknownTool(ev.ToolName, "tool_input is not an object of the documented shape")
		}
	}
	name := ev.ToolName
	home := cleanDir(env["HOME"])
	cwd := cleanDir(ev.Cwd)
	switch {
	case name == "Bash":
		if strings.TrimSpace(in.Command) == "" {
			return unknownTool(name, "Bash without a command")
		}
		vars := map[string]string{}
		for _, k := range []string{"PGHOST", "PGPORT", "PGDATABASE", "PGHOSTADDR", "PGSERVICE", "PGSERVICEFILE"} {
			if v := env[k]; v != "" {
				vars[k] = v
			}
		}
		proj := cleanDir(env["CLAUDE_PROJECT_DIR"])
		if proj == "" {
			proj = cwd
		}
		r := ClassifyShell(in.Command, ShellEnv{Cwd: cwd, ProjectDir: proj, Home: home, Vars: vars,
			ProxyHosts: h.proxies, InternalHosts: h.internal})
		t := r.Target(cwd)
		t["tool"] = name
		t["background"] = in.RunInBackground
		return mapped{System: action.SystemShell, Verb: r.Verb, Target: t}
	case writeTools[name] || readTools[name]:
		p := in.FilePath
		if p == "" {
			p = in.NotebookPath
		}
		if p == "" {
			p = in.Path
		}
		verb := action.VerbRead
		if writeTools[name] {
			verb = action.VerbWrite
			if p == "" {
				return unknownTool(name, "file tool without a path")
			}
		}
		return mapped{System: "files", Verb: verb, Target: fileTarget(name, p, in.Pattern, cwd, home)}
	case internalTools[name]:
		return mapped{System: "files", Verb: action.VerbRead, Target: map[string]any{"operation": "internal_tool", "tool": name}}
	case name == "WebFetch":
		host, ok := urlHost(in.URL)
		if !ok {
			return unknownTool(name, "WebFetch without a URL host")
		}
		t := map[string]any{"tool": name, "domain": clip(host), "external": isExternal(host, h.internal), "method": "GET"}
		// Only a summary of encoded-looking query parameters (POL-671),
		// never the query itself.
		if ps := commap.SummarizeURL(in.URL); len(ps) > 0 {
			t["encoded_params"] = ps
		}
		return mapped{System: action.SystemHTTP, Verb: action.VerbRead, Target: t}
	case name == "WebSearch":
		return mapped{System: action.SystemHTTP, Verb: action.VerbRead, Target: map[string]any{
			"tool": name, "domain": "search", "external": true, "method": "GET"}}
	case name == "Task" || name == "Agent":
		return mapped{System: action.SystemA2A, Verb: action.VerbDelegate, Target: map[string]any{
			"tool": name, "to_agent": agent, "channel": "hook_task", "subagent_type": clip(in.SubagentType)}}
	case strings.HasPrefix(name, "mcp__"):
		m := mcpNamePattern.FindStringSubmatch(name)
		if m == nil || h.verbs == nil {
			return unknownTool(name, "malformed MCP tool name")
		}
		verb, source := h.verbs.Verb(m[1], m[2])
		return mapped{System: action.SystemMCP, Verb: verb, Target: map[string]any{
			"tool": m[2], "server": m[1], "method": "tools/call", "verb_source": source, "channel": "claude_code"}}
	}
	return unknownTool(name, "tool is not known to Fortik")
}

// fileTarget describes a file tool's path (resolved against cwd/home).
func fileTarget(tool, p, pattern, cwd, home string) map[string]any {
	t := map[string]any{"tool": tool, "operation": strings.ToLower(tool)}
	resolved := p
	if abs, ok := cleanAbs(p, cwd, home); ok {
		resolved = abs
	}
	kind := sensitiveKind(resolved)
	if kind == "" && pattern != "" {
		kind = sensitiveKind(pattern)
		if kind != KindCredentials {
			kind = "" // only a credential-file glob counts
		}
	}
	if resolved == "" {
		resolved = cwd
	}
	t["path"] = clip(resolved)
	t["sensitive_path"] = kind != ""
	if kind != "" {
		t["sensitive_kind"] = kind
	}
	return t
}
