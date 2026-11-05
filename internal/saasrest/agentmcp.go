package saasrest

// Fortik's MCP endpoint for Agentforce agents: /mcp/agentforce/<tenant>.
//
// An MCP client (Claude Desktop through mcp-remote, an IDE, an agent
// framework) talks to a Salesforce Agentforce agent with three tools. Each
// tool call is turned into the equivalent gateway call
// (/gw/salesforce/einstein/ai-agent/v1/... or a BotDefinition query) and
// dispatched in-process through the gateway's decision pipeline, so a tool
// call and a REST call are decided, held, approved, refused and recorded
// identically. <tenant> names the Salesforce integration (salesforce:<tenant>;
// "default" for the connection keyed plain salesforce).

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/integrations"
)

// AgentMCPPath is the endpoint's pattern on the gateway.
const AgentMCPPath = "/mcp/agentforce/{name}"

// Dispatcher decides and forwards a /gw/ request for an authenticated agent
// (gateway.Server.Dispatch).
type Dispatcher func(w http.ResponseWriter, r *http.Request, p authz.Principal)

// AgentMCP serves the Agentforce MCP endpoint.
type AgentMCP struct {
	s        *Service
	dispatch Dispatcher
	version  string
}

// NewAgentMCP builds the endpoint over a gateway dispatcher.
func (s *Service) NewAgentMCP(d Dispatcher, version string) *AgentMCP {
	return &AgentMCP{s: s, dispatch: d, version: version}
}

// Mount registers the endpoint on the gateway's agent-authenticated mux.
func (m *AgentMCP) Mount(mount func(pattern string, h http.HandlerFunc)) {
	mount("POST "+AgentMCPPath, m.serve)
	mount("GET "+AgentMCPPath, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this MCP endpoint does not offer a GET stream", http.StatusMethodNotAllowed)
	})
	mount("DELETE "+AgentMCPPath, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
}

var (
	mcpVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}
	tenantName  = regexp.MustCompile(`^[a-z][a-z0-9_]{0,62}$`)
)

type mcpReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (m *AgentMCP) serve(w http.ResponseWriter, r *http.Request) {
	pr, ok := authz.From(r.Context())
	if !ok || pr.Kind != authz.KindAgent {
		rpcError(w, nil, -32001, "an agent token is required")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		rpcError(w, nil, -32700, "could not read the request body")
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) > 0 && body[0] == '[' {
		rpcError(w, nil, -32600, "JSON-RPC batches are not accepted")
		return
	}
	var req mcpReq
	if err := json.Unmarshal(body, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		rpcError(w, nil, -32600, "not a JSON-RPC 2.0 request")
		return
	}
	if len(req.ID) == 0 || string(req.ID) == "null" { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	name := r.PathValue("name")
	if !tenantName.MatchString(name) {
		rpcError(w, req.ID, -32602, "the tenant in /mcp/agentforce/<tenant> must be lower-case letters, digits and _")
		return
	}
	switch req.Method {
	case "initialize":
		var params struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &params)
		v := mcpVersions[1]
		if slices.Contains(mcpVersions, params.ProtocolVersion) {
			v = params.ProtocolVersion
		}
		rpcResult(w, req.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
			"serverInfo":      map[string]any{"name": "fortik-agentforce", "version": m.version},
			"instructions": "Talk to Salesforce Agentforce agents, governed by Fortik. Every call is checked before it reaches Salesforce. " +
				"A message that needs human approval returns an error saying it was held and NOT sent; after an approver approves it in the " +
				"Fortik console, call agentforce_send_message again with the same agent_id, the same message and the session_id it gave you.",
		})
	case "ping":
		rpcResult(w, req.ID, map[string]any{})
	case "tools/list":
		rpcResult(w, req.ID, map[string]any{"tools": agentTools})
	case "tools/call":
		ctx := decide.WithActor(r.Context(), pr.Actor())
		ctx = delegation.WithToken(ctx, r.Header.Get(delegation.Header))
		m.call(ctx, w, req, pr, name, r.Header)
	default:
		rpcError(w, req.ID, -32601, "method not supported by Fortik's Agentforce MCP endpoint (tools only)")
	}
}

var agentTools = []map[string]any{
	{
		"name":        "agentforce_list_agents",
		"description": "List the Agentforce agents in the connected Salesforce org (id, name, API name). Reads BotDefinition through Fortik.",
		"inputSchema": map[string]any{"type": "object", "properties": map[string]any{}, "additionalProperties": false},
		"annotations": map[string]any{"readOnlyHint": true},
	},
	{
		"name": "agentforce_send_message",
		"description": "Send a message to a Salesforce Agentforce agent and return its reply. Without session_id a new session is started; " +
			"pass the returned session_id to continue the conversation. The agent may act inside Salesforce. If Fortik holds the message " +
			"for approval, ask a human to approve it in the Fortik console, then repeat the call with the same message and session_id.",
		"inputSchema": map[string]any{
			"type": "object",
			"properties": map[string]any{
				"agent_id":   map[string]any{"type": "string", "description": "The agent's id (BotDefinition, 18 characters, starts with 0Xx)."},
				"message":    map[string]any{"type": "string", "description": "The text to send."},
				"session_id": map[string]any{"type": "string", "description": "A session id returned earlier; omit to start a new session."},
			},
			"required":             []string{"agent_id", "message"},
			"additionalProperties": false,
		},
	},
	{
		"name":        "agentforce_end_session",
		"description": "End an Agentforce session started with agentforce_send_message.",
		"inputSchema": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"session_id": map[string]any{"type": "string"}},
			"required":             []string{"session_id"},
			"additionalProperties": false,
		},
	},
}

// gwResult is one dispatched gateway call.
type gwResult struct {
	status   int
	body     []byte
	actionID string
	refusal  *struct {
		Code     string `json:"code"`
		Decision string `json:"decision"`
		RuleID   string `json:"rule_id"`
		Reason   string `json:"reason"`
		Message  string `json:"message"`
		Held     bool   `json:"held"`
	}
}

func (m *AgentMCP) gw(ctx context.Context, pr authz.Principal, hdr http.Header, tenant, method, path string, body any) gwResult {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, "/gw/salesforce"+path, rd).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(HeaderIntegration, "salesforce:"+tenant)
	if v := hdr.Get("X-Fortik-Instance-Id"); v != "" {
		req.Header.Set("X-Fortik-Instance-Id", v)
	}
	rec := httptest.NewRecorder()
	m.dispatch(rec, req, pr)
	res := gwResult{status: rec.Code, body: rec.Body.Bytes(), actionID: rec.Header().Get("X-Fortik-Action-Id")}
	if rec.Code >= 400 {
		var e struct {
			Error *struct {
				Code     string `json:"code"`
				Decision string `json:"decision"`
				RuleID   string `json:"rule_id"`
				Reason   string `json:"reason"`
				Message  string `json:"message"`
				Held     bool   `json:"held"`
			} `json:"error"`
		}
		if json.Unmarshal(res.body, &e) == nil && e.Error != nil && e.Error.Code != "" {
			res.refusal = e.Error
		}
	}
	return res
}

// problem explains a failed gateway call to the model.
func (g gwResult) problem(what string) string {
	if f := g.refusal; f != nil {
		switch {
		case f.Held || f.Decision == "hold":
			return fmt.Sprintf("%s was HELD by Fortik for human approval and was NOT executed (%s: %s).", what, f.RuleID, f.Reason)
		case f.Code == "fortik_refused":
			return fmt.Sprintf("%s was refused by Fortik (%s: %s).", what, f.RuleID, f.Reason)
		case f.Message != "":
			return fmt.Sprintf("%s failed: %s.", what, f.Message)
		}
	}
	return fmt.Sprintf("%s failed: Salesforce answered HTTP %d: %s", what, g.status, clip(strings.TrimSpace(string(g.body)), 400))
}

func (g gwResult) decision() string {
	if g.refusal != nil && g.refusal.Decision != "" {
		return g.refusal.Decision
	}
	if g.status < 300 {
		return "allow"
	}
	return "error"
}

var sfID = regexp.MustCompile(`^(?:[A-Za-z0-9]{15}|[A-Za-z0-9]{18})$`)

func (m *AgentMCP) call(ctx context.Context, w http.ResponseWriter, req mcpReq, pr authz.Principal, tenant string, hdr http.Header) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		rpcError(w, req.ID, -32602, "invalid tools/call parameters")
		return
	}
	var args struct {
		AgentID   string `json:"agent_id"`
		Message   string `json:"message"`
		SessionID string `json:"session_id"`
	}
	if len(params.Arguments) > 0 {
		dec := json.NewDecoder(bytes.NewReader(params.Arguments))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&args); err != nil {
			toolResult(w, req.ID, true, "", "", "invalid arguments: "+clip(err.Error(), 200), nil)
			return
		}
	}
	switch params.Name {
	case "agentforce_list_agents":
		ver := "62.0"
		if res, err := m.s.connectionFor(ctx, tenant); err == nil {
			if st, err := settingsFrom(res); err == nil {
				ver = st.APIVersion
			}
		}
		q := "SELECT Id, DeveloperName, MasterLabel FROM BotDefinition ORDER BY MasterLabel LIMIT 100"
		g := m.gw(ctx, pr, hdr, tenant, http.MethodGet, "/services/data/v"+ver+"/query?q="+url.QueryEscape(q), nil)
		if g.status >= 300 {
			toolResult(w, req.ID, true, g.actionID, g.decision(), g.problem("Listing Agentforce agents"), nil)
			return
		}
		var qr struct {
			Records []struct {
				ID            string `json:"Id"`
				DeveloperName string `json:"DeveloperName"`
				MasterLabel   string `json:"MasterLabel"`
			} `json:"records"`
		}
		_ = json.Unmarshal(g.body, &qr)
		agents := make([]map[string]string, 0, len(qr.Records))
		var lines []string
		for _, a := range qr.Records {
			agents = append(agents, map[string]string{"id": a.ID, "name": a.MasterLabel, "api_name": a.DeveloperName})
			lines = append(lines, fmt.Sprintf("%s  %s (%s)", a.ID, a.MasterLabel, a.DeveloperName))
		}
		text := "No Agentforce agents found."
		if len(lines) > 0 {
			text = "Agentforce agents:\n" + strings.Join(lines, "\n")
		}
		toolResult(w, req.ID, false, g.actionID, "allow", text, map[string]any{"agents": agents})
	case "agentforce_send_message":
		if !sfID.MatchString(args.AgentID) {
			toolResult(w, req.ID, true, "", "", "agent_id must be the agent's 15- or 18-character id (BotDefinition, starts with 0Xx)", nil)
			return
		}
		if strings.TrimSpace(args.Message) == "" {
			toolResult(w, req.ID, true, "", "", "message is empty", nil)
			return
		}
		sid, greeting := args.SessionID, ""
		if sid == "" {
			g := m.gw(ctx, pr, hdr, tenant, http.MethodPost, AgentAPIPrefix+"agents/"+args.AgentID+"/sessions", map[string]any{})
			if g.status >= 300 {
				toolResult(w, req.ID, true, g.actionID, g.decision(), g.problem("Starting a session with agent "+args.AgentID), nil)
				return
			}
			var sr struct {
				SessionID string `json:"sessionId"`
				Messages  []struct {
					Message string `json:"message"`
				} `json:"messages"`
			}
			_ = json.Unmarshal(g.body, &sr)
			if !agentSessionID.MatchString(sr.SessionID) {
				toolResult(w, req.ID, true, g.actionID, "allow", "Salesforce started no session (no sessionId in its answer)", nil)
				return
			}
			sid = sr.SessionID
			for _, x := range sr.Messages {
				greeting = strings.TrimSpace(greeting + "\n" + x.Message)
			}
		} else if !agentSessionID.MatchString(sid) {
			toolResult(w, req.ID, true, "", "", "session_id is not a valid session id", nil)
			return
		}
		g := m.gw(ctx, pr, hdr, tenant, http.MethodPost, AgentAPIPrefix+"sessions/"+sid+"/messages",
			map[string]any{"message": map[string]any{"type": "Text", "text": args.Message}})
		structured := map[string]any{"session_id": sid, "agent_id": args.AgentID}
		if g.status >= 300 {
			text := g.problem("The message") + " session_id: " + sid + "."
			if g.refusal != nil && (g.refusal.Held || g.refusal.Decision == "hold") {
				text += " After approval, call agentforce_send_message again with agent_id " + args.AgentID + ", exactly the same message and session_id " + sid + "."
			}
			toolResult(w, req.ID, true, g.actionID, g.decision(), text, structured)
			return
		}
		var mr struct {
			Messages []struct {
				Type    string `json:"type"`
				Message string `json:"message"`
			} `json:"messages"`
		}
		_ = json.Unmarshal(g.body, &mr)
		var replies []string
		for _, x := range mr.Messages {
			if strings.TrimSpace(x.Message) != "" {
				replies = append(replies, x.Message)
			}
		}
		structured["replies"] = replies
		if greeting != "" {
			structured["greeting"] = greeting
		}
		text := strings.Join(replies, "\n")
		if text == "" {
			text = "(the agent sent no text)"
		}
		toolResult(w, req.ID, false, g.actionID, "allow", text+"\n\n[session_id: "+sid+"]", structured)
	case "agentforce_end_session":
		if !agentSessionID.MatchString(args.SessionID) {
			toolResult(w, req.ID, true, "", "", "session_id is not a valid session id", nil)
			return
		}
		g := m.gw(ctx, pr, hdr, tenant, http.MethodDelete, AgentAPIPrefix+"sessions/"+args.SessionID, nil)
		if g.status >= 300 {
			toolResult(w, req.ID, true, g.actionID, g.decision(), g.problem("Ending the session"), nil)
			return
		}
		toolResult(w, req.ID, false, g.actionID, "allow", "Session "+args.SessionID+" ended.", map[string]any{"session_id": args.SessionID})
	default:
		rpcError(w, req.ID, -32602, "unknown tool "+clip(params.Name, 80))
	}
}

// connectionFor finds the Salesforce REST connection of a tenant.
func (s *Service) connectionFor(ctx context.Context, tenant string) (integrations.Resolved, error) {
	list, err := s.store.List(ctx, integrations.SystemSalesforce)
	if err != nil {
		return integrations.Resolved{}, err
	}
	for _, r := range list {
		if r.IntegrationID == "salesforce:"+tenant {
			return r, nil
		}
	}
	return integrations.Resolved{}, integrations.ErrNotConfigured
}

func toolResult(w http.ResponseWriter, id json.RawMessage, isErr bool, actionID, decision, text string, structured map[string]any) {
	res := map[string]any{"content": []map[string]any{{"type": "text", "text": text}}, "isError": isErr}
	if structured != nil {
		res["structuredContent"] = structured
	}
	meta := map[string]any{"fortik/executed": !isErr}
	if actionID != "" {
		meta["fortik/action_id"] = actionID
	}
	if decision != "" {
		meta["fortik/decision"] = decision
	}
	res["_meta"] = meta
	rpcResult(w, id, res)
}

func rpcResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func rpcError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}
