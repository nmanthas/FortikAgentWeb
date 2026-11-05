package nsquickstart

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/mcpclient"
	"fortik/internal/policy"
)

// Fortik's MCP endpoints for NetSuite on the app gateway (Streamable HTTP,
// agent token as Bearer): one per tenant, /mcp/netsuite/<name> for the
// logical integration netsuite:<name>; ProxyPath is the legacy endpoint of
// the default QuickStart connection.
const (
	ProxyPath         = "/mcp/netsuite_quickstart"
	TenantProxyPrefix = "/mcp/netsuite/"
)

// Diary events of executed calls (the decision itself is the action record).
const (
	EventToolExecuted = "mcp.tool.executed"
	EventToolFailed   = "mcp.tool.failed"
)

// ProfileSource returns an agent's current access profile for a system.
type ProfileSource interface {
	Current(ctx context.Context, agentID, system string) (access.Profile, error)
}

// Proxy is the MCP server agents connect to instead of QuickStart. It
// answers initialize, ping and tools/list itself; every tools/call is
// normalized and decided before Fortik calls QuickStart with its own token.
// Stateless: no session id is issued, so it survives restarts.
type Proxy struct {
	svc      *Service
	dec      decide.Decider
	mappings map[string]*Mapping // per connection type
	profiles ProfileSource
	diary    *diary.Diary
	grantTTL time.Duration
	log      *slog.Logger
}

// NewProxy builds the endpoint. grantTTL is how long an approved call may be
// retried (config approvals.grant_ttl).
func NewProxy(svc *Service, dec decide.Decider, mappings map[string]*Mapping, profiles ProfileSource, d *diary.Diary, grantTTL time.Duration, log *slog.Logger) *Proxy {
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{svc: svc, dec: dec, mappings: mappings, profiles: profiles, diary: d, grantTTL: grantTTL, log: log}
}

// mapping is the tool mapping of a connection type (QuickStart's when the
// connection is unknown: the call is then refused as not offered).
func (p *Proxy) mapping(system string) *Mapping {
	if m := p.mappings[system]; m != nil {
		return m
	}
	return p.mappings[integrations.SystemNetSuiteQuickStart]
}

// target is what an MCP request is for: one connection of one tenant.
type target struct {
	key, integrationID, problem string
}

// resolve finds the connection an endpoint path means: the tenant's MCP
// connection (/mcp/netsuite/<name>) or the default one (legacy path).
func (p *Proxy) resolve(ctx context.Context, r *http.Request) target {
	name := r.PathValue("name")
	if name == "" {
		key := p.svc.defaultKey(ctx)
		_, id, _ := integrations.LogicalID(key)
		return target{key: key, integrationID: id}
	}
	provider := integrations.ProviderNetSuite
	if parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/"); len(parts) == 3 {
		provider = parts[1] // /mcp/<provider>/<tenant>
	}
	id := provider + ":" + name
	in, err := p.svc.store.ConnectionFor(ctx, id, integrations.TransportMCP)
	if err != nil {
		return target{integrationID: id, problem: "integration " + clip(id, 80) + " has no MCP connection in Fortik"}
	}
	return target{key: in.Key, integrationID: id}
}

// Mount registers the endpoint on an agent-authenticated mux (the gateway's).
func (p *Proxy) Mount(mount func(pattern string, h http.HandlerFunc)) {
	noStream := func(w http.ResponseWriter, _ *http.Request) {
		// No server-initiated stream: every answer comes on the POST.
		w.Header().Set("Allow", "POST, DELETE")
		http.Error(w, "this MCP endpoint does not offer a GET stream", http.StatusMethodNotAllowed)
	}
	end := func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }
	paths := []string{ProxyPath}
	for _, prov := range Providers {
		paths = append(paths, "/mcp/"+prov+"/{name}")
	}
	for _, path := range paths {
		mount("POST "+path, p.serve)
		mount("GET "+path, noStream)
		mount("DELETE "+path, end)
	}
}

// Protocol versions the endpoint speaks (the client's is echoed when known).
var proxyVersions = []string{"2025-11-25", "2025-06-18", "2025-03-26"}

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	pr, ok := authz.From(r.Context())
	if !ok || pr.Kind != authz.KindAgent {
		writeRPCError(w, nil, -32001, "an agent token is required")
		return
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeRPCError(w, nil, -32700, "could not read the request body")
		return
	}
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		writeRPCError(w, nil, -32600, "JSON-RPC batches are not accepted")
		return
	}
	var req rpcReq
	if err := json.Unmarshal(trimmed, &req); err != nil || req.JSONRPC != "2.0" || req.Method == "" {
		writeRPCError(w, nil, -32600, "not a JSON-RPC 2.0 request")
		return
	}
	// Notifications (no id) get 202 and no body.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	ctx := decide.WithActor(r.Context(), pr.Actor())
	ctx = delegation.WithToken(ctx, r.Header.Get(delegation.Header))
	switch req.Method {
	case "initialize":
		p.initialize(w, req)
	case "ping":
		writeRPCResult(w, req.ID, map[string]any{})
	case "tools/list":
		p.listTools(ctx, w, req, pr, p.resolve(ctx, r))
	case "tools/call":
		p.callTool(ctx, w, req, pr, p.resolve(ctx, r))
	default:
		writeRPCError(w, req.ID, -32601, "method not supported by Fortik's MCP endpoint (tools only)")
	}
}

func (p *Proxy) initialize(w http.ResponseWriter, req rpcReq) {
	var params struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(req.Params, &params)
	v := proxyVersions[1]
	if slices.Contains(proxyVersions, params.ProtocolVersion) {
		v = params.ProtocolVersion
	}
	writeRPCResult(w, req.ID, map[string]any{
		"protocolVersion": v,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]any{"name": "fortik-netsuite", "version": p.svc.version},
		"instructions": "NetSuite tools, governed by Fortik. Every call is checked before it reaches NetSuite. " +
			"A call that needs human approval returns an error saying it was held and NOT executed; after an approver " +
			"approves it in the Fortik console, repeat exactly the same call (same tool, same arguments) and it runs once.",
	})
}

// listAction is the decision for tools/list: a READ of the catalog, so a
// suspended, killed or unprofiled agent cannot even see the tools.
func (p *Proxy) listAction(pr authz.Principal, cat Catalog) action.Action {
	system := cat.System
	if system == "" {
		system = IntegrationKey
	}
	return action.Action{
		ActionID: action.NewID("act"), AgentID: pr.Name, InstanceID: pr.InstanceID, System: providerOf(system), Verb: action.VerbRead,
		Source: action.SourceAppGateway,
		Target: map[string]any{
			"transport": Transport, "integration": system, "integration_id": cat.IntegrationID, "connection": cat.Key,
			"server_id": cat.ServerID, "tool": "tools/list",
			"operation": "list_tools", "tool_offered": true, "catalog_current": cat.Current, "understood": true,
			"mapping_version": p.mapping(system).Version,
		},
	}
}

func (p *Proxy) listTools(ctx context.Context, w http.ResponseWriter, req rpcReq, pr authz.Principal, tg target) {
	if tg.problem != "" {
		writeRPCError(w, req.ID, -32002, tg.problem)
		return
	}
	_, cat, err := p.svc.current(ctx, tg.key)
	if err != nil && !notConfigured(err) {
		p.log.Error("netsuite mcp: tools/list", "err", err)
		writeRPCError(w, req.ID, -32603, "Fortik could not read the NetSuite tool catalog: refused")
		return
	}
	if err != nil {
		writeRPCError(w, req.ID, -32002, "NetSuite MCP connection "+tg.key+" is not configured in Fortik")
		return
	}
	mapping := p.mapping(cat.System)
	out, err := p.dec.Decide(ctx, p.listAction(pr, cat))
	if err != nil {
		writeRPCError(w, req.ID, -32603, "Fortik could not decide: refused")
		return
	}
	if !out.Result.Decision.Executes() {
		writeRPCError(w, req.ID, -32003, fmt.Sprintf("Fortik refused tools/list (%s: %s)", out.Result.RuleID, out.Result.Reason))
		return
	}
	prof := p.agentProfile(ctx, pr.Name, providerOf(cat.System))
	tools := []map[string]any{}
	names := make([]string, 0, len(cat.Tools))
	for n := range cat.Tools {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		cls, mapped := mapping.Tools[n]
		if !mapped || prof == nil || !prof.allowsTool(n) || !prof.allowsIntegration(cat.IntegrationID) {
			continue
		}
		if cls.Verb != action.VerbRead && prof.mode != access.ModeReadWrite {
			continue
		}
		t := cat.Tools[n]
		desc := t.Description
		if cls.Verb != action.VerbRead {
			desc = "[Fortik: calls to this tool are held for human approval and are NOT executed until approved; after approval, repeat the identical call once.] " + desc
		}
		e := map[string]any{"name": t.Name, "description": desc, "inputSchema": t.InputSchema}
		if t.Title != "" {
			e["title"] = t.Title
		}
		if len(t.OutputSchema) > 0 {
			e["outputSchema"] = t.OutputSchema
		}
		if len(t.Annotations) > 0 {
			e["annotations"] = t.Annotations
		}
		tools = append(tools, e)
	}
	writeRPCResult(w, req.ID, map[string]any{"tools": tools})
}

// toolProfile is what an agent's access profile says about MCP tools of
// one provider (tools/list shows only what it allows; tools/call is decided
// by policy with the same profile).
type toolProfile struct {
	mode              string
	allowsTool        func(string) bool
	allowsIntegration func(string) bool
}

func (p *Proxy) agentProfile(ctx context.Context, agentID, provider string) *toolProfile {
	if p.profiles == nil {
		return nil
	}
	cur, err := p.profiles.Current(ctx, agentID, provider)
	if err != nil {
		return nil
	}
	v, err := access.Parse(provider, cur.Profile)
	if err != nil {
		return nil
	}
	switch pr := v.(type) {
	case access.NetSuiteProfile:
		return &toolProfile{mode: pr.Mode, allowsTool: pr.AllowsQuickStartTool, allowsIntegration: pr.AllowsIntegration}
	case access.SaaSProfile:
		return &toolProfile{mode: pr.Mode, allowsTool: pr.AllowsTool, allowsIntegration: pr.AllowsIntegration}
	}
	return nil
}

func (p *Proxy) callTool(ctx context.Context, w http.ResponseWriter, req rpcReq, pr authz.Principal, tg target) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil || params.Name == "" {
		writeRPCError(w, req.ID, -32602, "tools/call needs a tool name")
		return
	}
	var (
		st   Settings
		cat  = Catalog{Tools: map[string]storedTool{}, IntegrationID: tg.integrationID}
		cerr error
	)
	if tg.problem != "" {
		cerr = fmt.Errorf("%w: %s", integrations.ErrNotConfigured, tg.problem)
	} else {
		st, cat, cerr = p.svc.current(ctx, tg.key)
		if cerr != nil && !notConfigured(cerr) {
			p.log.Error("netsuite mcp: tools/call catalog", "err", cerr)
			writeRPCError(w, req.ID, -32603, "Fortik could not read the NetSuite tool catalog: refused")
			return
		}
		if cerr != nil {
			cat = Catalog{Tools: map[string]storedTool{}, Key: tg.key, IntegrationID: tg.integrationID}
		}
	}
	// Decided even when not configured (an empty catalog refuses it), so the
	// attempt is recorded.
	a := p.mapping(cat.System).Normalize(params.Name, params.Arguments, cat)
	if tg.problem != "" {
		// Never forwarded to a guessed tenant: decided as UNKNOWN, recorded, refused.
		a.Verb = "UNKNOWN"
		a.Target = map[string]any{"transport": Transport, "integration_id": tg.integrationID, "tool": clip(params.Name, maxNameLen), "reason": tg.problem}
	}
	a.AgentID, a.InstanceID, a.Source = pr.Name, pr.InstanceID, action.SourceAppGateway
	a.ActionID = action.NewID("act")
	out, err := p.dec.Decide(ctx, a)
	if err != nil {
		if errors.Is(err, action.ErrInvalid) {
			writeRPCError(w, req.ID, -32602, "the call could not be expressed as a valid action: refused")
			return
		}
		p.log.Error("netsuite mcp: decide failed; refusing", "err", err)
		writeRPCError(w, req.ID, -32603, "Fortik could not decide: refused")
		return
	}
	id := out.Action.ActionID
	if !out.Result.Decision.Executes() {
		text := p.refusalText(out)
		if tg.problem != "" {
			text += " " + tg.problem + "."
		}
		writeToolError(w, req.ID, id, string(out.Result.Decision), text)
		return
	}
	op, _ := out.Action.Target["operation"].(string)
	snapshot := false
	for k, v := range out.Result.ReducedForm {
		// record_snapshot (POL-1001 when MCP updates are not held): the
		// changed fields are read and kept before the update, as on REST.
		if k == "record_snapshot" && v == true && op == "update" && out.Action.Target["undo_possible"] == true {
			snapshot = true
			continue
		}
		p.notExecuted(ctx, out, "reduced_form_unsupported", "a reduced form was required that this MCP call cannot honour: "+k)
		writeToolError(w, req.ID, id, string(policy.Deny), "Fortik refused this call: the decision required a reduced form that cannot be applied to this MCP tool. It was not executed.")
		return
	}
	if cerr != nil {
		p.notExecuted(ctx, out, "integration_not_configured", tg.key+" is not configured")
		writeToolError(w, req.ID, id, "not_executed", "The NetSuite MCP connection is not configured in Fortik. The call was not executed.")
		return
	}
	args := params.Arguments
	if len(args) == 0 || string(args) == "null" {
		args = json.RawMessage("{}")
	}
	undoNote := ""
	if snapshot || op == "update" && out.Action.Target["undo_possible"] == true {
		if err := p.svc.prepareUndo(ctx, st, out.Action, args, pr.Actor()); err != nil {
			// The approver was told undo would be prepared: without it, do not run.
			p.notExecuted(ctx, out, "undo_snapshot_failed", clip(err.Error(), 200))
			writeToolError(w, req.ID, id, "not_executed", "Fortik could not snapshot the record before the update, so the update was NOT executed ("+clip(err.Error(), 200)+").")
			return
		}
		undoNote = "prepared"
	}
	start := time.Now()
	res, err := p.svc.callTool(ctx, st, params.Name, args)
	dur := time.Since(start)
	if err != nil {
		outcome := outcomeOf(err, out.Action.Verb)
		if undoNote != "" {
			p.svc.failUndo(context.WithoutCancel(ctx), id, "the update did not complete: "+outcome)
		}
		p.record(ctx, out, EventToolFailed, map[string]any{"outcome": outcome, "error": clip(err.Error(), 300), "duration_ms": dur.Milliseconds()})
		msg := "The NetSuite call failed (" + clip(err.Error(), 200) + ")."
		if outcome == "unknown" {
			msg += " It is NOT known whether NetSuite executed it: check the record before trying again."
		} else {
			msg += " It was not executed."
		}
		writeToolError(w, req.ID, id, "failed", msg)
		return
	}
	if undoNote != "" {
		if res.IsError {
			p.svc.failUndo(context.WithoutCancel(ctx), id, "NetSuite reported the update as failed")
			undoNote = ""
		} else if err := p.svc.activateUndo(context.WithoutCancel(ctx), id); err != nil {
			p.log.Error("netsuite mcp: activate undo", "action_id", id, "err", err)
			undoNote = ""
		} else {
			undoNote = "available"
		}
	}
	data := map[string]any{"outcome": "executed", "tool_is_error": res.IsError, "duration_ms": dur.Milliseconds(), "result_bytes": len(res.Raw)}
	if undoNote != "" {
		data["undo"] = undoNote
	}
	if out.Result.GrantID != "" {
		data["grant_id"] = out.Result.GrantID
	}
	p.record(ctx, out, EventToolExecuted, data)
	writeToolResult(w, req.ID, res.Raw, id, string(out.Result.Decision), undoNote)
}

func (p *Proxy) refusalText(out decide.Outcome) string {
	r := out.Result
	id := out.Action.ActionID
	if r.Decision == policy.Hold {
		approvers := ""
		if r.ApprovalsRequired > 1 {
			approvers = fmt.Sprintf(" It needs %d different approvers.", r.ApprovalsRequired)
		}
		retry := fmt.Sprintf(" After approval, repeat exactly the same call (same tool, same arguments) within %s; it will run once. Do not repeat it before approval: an unapproved repeat is held again.", p.grantTTL)
		if r.Class == policy.Red {
			retry = " Red actions are never released unchanged by an approval; ask a person to do it in NetSuite if it is really needed."
		}
		return fmt.Sprintf("Fortik held this call for human approval and did NOT execute it (action %s, %s: %s).%s%s", id, r.RuleID, r.Reason, approvers, retry)
	}
	return fmt.Sprintf("Fortik refused this call and did NOT execute it (action %s, %s: %s).", id, r.RuleID, r.Reason)
}

// outcomeOf says whether a failed call may have run on QuickStart: only
// refusals before or at the request (auth, permission, 4xx, our own checks)
// are known not to have executed; for READ the distinction does not matter.
func outcomeOf(err error, verb action.Verb) string {
	var e *mcpclient.Error
	if !errors.As(err, &e) {
		return "unknown"
	}
	switch e.Kind {
	case mcpclient.KindAuthFailed, mcpclient.KindTokenExpired, mcpclient.KindPermission, mcpclient.KindInitFailed, StateNotPermitted:
		return "not_executed"
	}
	if e.Step != "tools/call" {
		return "not_executed" // the session never opened
	}
	if e.HTTPStatus >= 400 && e.HTTPStatus < 500 && e.HTTPStatus != http.StatusRequestTimeout {
		return "not_executed"
	}
	if e.Kind == mcpclient.KindCallFailed && e.HTTPStatus >= 200 && e.HTTPStatus < 300 && strings.HasPrefix(e.Detail, "JSON-RPC error") {
		return "not_executed" // a protocol-level refusal of the call
	}
	if verb == action.VerbRead {
		return "failed"
	}
	return "unknown"
}

func (p *Proxy) record(ctx context.Context, out decide.Outcome, event string, data map[string]any) {
	data["action_id"] = out.Action.ActionID
	data["tool"] = out.Action.Target["tool"]
	data["integration"] = out.Action.Target["integration"]
	data["integration_id"] = out.Action.Target["integration_id"]
	data["connection"] = out.Action.Target["connection"]
	data["system"] = out.Action.System
	data["transport"] = Transport
	dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if _, err := p.diary.Append(dctx, diary.Event{AgentID: out.Action.AgentID, EventType: event, Actor: "system:netsuite_mcp", Data: data}); err != nil {
		p.log.Error("netsuite mcp: record execution", "action_id", out.Action.ActionID, "err", err)
	}
}

func (p *Proxy) notExecuted(ctx context.Context, out decide.Outcome, code, reason string) {
	p.record(ctx, out, EventToolFailed, map[string]any{"outcome": "not_executed", "code": code, "reason": reason})
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, msg string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": msg}})
}

// writeToolError answers a tools/call with a tool-level error the model can
// read (isError), carrying Fortik's action id and decision in _meta.
func writeToolError(w http.ResponseWriter, id json.RawMessage, actionID, decision, text string) {
	writeRPCResult(w, id, map[string]any{
		"content": []any{map[string]any{"type": "text", "text": text}},
		"isError": true,
		"_meta":   map[string]any{"fortik/action_id": actionID, "fortik/decision": decision, "fortik/executed": false},
	})
}

// writeToolResult passes QuickStart's result through, adding Fortik's
// action id, decision and undo availability under _meta.
func writeToolResult(w http.ResponseWriter, id json.RawMessage, raw json.RawMessage, actionID, decision, undo string) {
	var res map[string]any
	if json.Unmarshal(raw, &res) != nil || res == nil {
		res = map[string]any{"content": []any{}, "isError": true}
	}
	meta, _ := res["_meta"].(map[string]any)
	if meta == nil {
		meta = map[string]any{}
	}
	meta["fortik/action_id"] = actionID
	meta["fortik/decision"] = decision
	meta["fortik/executed"] = true
	if undo != "" {
		meta["fortik/undo"] = undo
	}
	res["_meta"] = meta
	writeRPCResult(w, id, res)
}
