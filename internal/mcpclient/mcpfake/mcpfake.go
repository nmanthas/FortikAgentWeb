// Package mcpfake is a LOCAL FAKE MCP server (Streamable HTTP) for tests
// and demos. It is not NetSuite QuickStart: its tool names follow Oracle's
// documented QuickStart tool list, but every description and input schema
// here is invented for testing and says so. Never present its answers as a
// real tenant's.
package mcpfake

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
)

// Documented QuickStart tool names (Oracle, "Set up the QuickStart MCP
// server"): available to read-only tokens, and added for read-write tokens.
var (
	ReadOnlyTools = []string{"notifications", "navigation_targets", "todo_list", "get_record_model", "list_records", "read_record",
		"read_record_sublist", "get_record_apply_candidates", "list_record_attachments", "discover_preferences", "read_preferences",
		"report_catalog", "describe_report", "report_filter_values", "configure_report", "run_report"}
	WriteTools = []string{"create_record", "dismiss_notification", "update_record", "delete_record", "execute_record_action",
		"execute_record_transform", "upload_temporary_file", "set_record_attachment", "send_record_email", "set_preferences",
		"submit_contact_support_request"}
)

// Server is a fake. Zero values give a well-behaved read-only server that
// answers with JSON; fields switch behaviours for tests.
type Server struct {
	Token     string // accepted bearer token
	ReadWrite bool   // also list WriteTools

	SSE             bool   // answer requests as text/event-stream (with a notification first)
	NoSession       bool   // do not issue Mcp-Session-Id
	PageSize        int    // tools per tools/list page (0: all)
	ProtocolVersion string // answered version ("" echoes a supported request, else 2025-06-18)
	NoToolsCap      bool   // omit the tools capability

	InitStatus     int    // non-zero: answer initialize with this HTTP status
	InitBody       string // body for InitStatus (text/plain)
	ExpiredToken   bool   // 401 "Token has expired" for the right token
	InitRPCError   bool   // initialize answers a JSON-RPC error
	ToolsRPCError  bool   // tools/list answers a JSON-RPC error
	ToolsMalformed bool   // tools/list result without a tools array
	ExtraTools     []json.RawMessage
	// Tools overrides the generated tool list.
	Tools []json.RawMessage
	// Call answers tools/call; nil uses the built-in fake record store
	// (read_record / update_record / list_records) and echoes other tools.
	Call func(name string, args json.RawMessage) (result any, errMsg string)
	// Records is the built-in fake store: recordType -> id -> fieldValues.
	Records map[string]map[string]map[string]any

	mu       sync.Mutex
	sessions map[string]bool
	calls    map[string]int
	auth     []string
	toolLog  []ToolCall
}

// ToolCall is one tools/call the fake received.
type ToolCall struct {
	Name string
	Args json.RawMessage
}

// ToolCalls returns every tools/call received, in order.
func (s *Server) ToolCalls() []ToolCall {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]ToolCall(nil), s.toolLog...)
}

// Record returns a copy of one record of the built-in store.
func (s *Server) Record(recordType, id string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]any{}
	for k, v := range s.Records[recordType][id] {
		out[k] = v
	}
	return out
}

// SetToken changes the accepted bearer token (safe while serving).
func (s *Server) SetToken(t string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Token = t
}

// Calls returns how often each JSON-RPC method (or "DELETE") was received.
func (s *Server) Calls() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]int{}
	for k, v := range s.calls {
		out[k] = v
	}
	return out
}

// AuthHeaders returns every Authorization header received.
func (s *Server) AuthHeaders() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.auth...)
}

func (s *Server) count(k string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == nil {
		s.calls = map[string]int{}
	}
	s.calls[k]++
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.auth = append(s.auth, r.Header.Get("Authorization"))
	s.mu.Unlock()
	const meta = `Bearer resource_metadata="http://fake/.well-known/oauth-protected-resource/mcp"`
	s.mu.Lock()
	want := s.Token
	s.mu.Unlock()
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	switch {
	case !ok || tok == "":
		w.Header().Set("WWW-Authenticate", meta)
		http.Error(w, "Bearer token not found", http.StatusUnauthorized)
		return
	case tok != want:
		w.Header().Set("WWW-Authenticate", meta)
		http.Error(w, "Token can't be parsed.", http.StatusUnauthorized)
		return
	case s.ExpiredToken:
		w.Header().Set("WWW-Authenticate", meta+`, error="invalid_token", error_description="Token has expired"`)
		http.Error(w, "Token has expired", http.StatusUnauthorized)
		return
	}
	if r.Method == http.MethodDelete {
		s.count("DELETE")
		s.mu.Lock()
		delete(s.sessions, r.Header.Get("Mcp-Session-Id"))
		s.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !strings.Contains(r.Header.Get("Accept"), "text/event-stream") || !strings.Contains(r.Header.Get("Accept"), "application/json") {
		http.Error(w, "Accept must list application/json and text/event-stream", http.StatusNotAcceptable)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	var req struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Method  string          `json:"method"`
		Params  json.RawMessage `json:"params"`
	}
	if json.Unmarshal(body, &req) != nil || req.JSONRPC != "2.0" {
		http.Error(w, "bad JSON-RPC", http.StatusBadRequest)
		return
	}
	s.count(req.Method)
	if req.Method != "initialize" {
		if !s.NoSession {
			s.mu.Lock()
			known := s.sessions[r.Header.Get("Mcp-Session-Id")]
			s.mu.Unlock()
			if !known {
				http.Error(w, "unknown session", http.StatusNotFound)
				return
			}
		}
		if r.Header.Get("MCP-Protocol-Version") == "" {
			http.Error(w, "missing MCP-Protocol-Version", http.StatusBadRequest)
			return
		}
	}
	switch req.Method {
	case "initialize":
		if s.InitStatus != 0 {
			http.Error(w, s.InitBody, s.InitStatus)
			return
		}
		if s.InitRPCError {
			s.reply(w, req.ID, nil, &rpcErr{Code: -32603, Message: "MCP server is not enabled for this company"})
			return
		}
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		v := s.ProtocolVersion
		if v == "" {
			v = "2025-06-18"
			if p.ProtocolVersion == "2025-03-26" || p.ProtocolVersion == "2025-06-18" {
				v = p.ProtocolVersion
			}
		}
		if !s.NoSession {
			b := make([]byte, 16)
			_, _ = rand.Read(b)
			id := hex.EncodeToString(b)
			s.mu.Lock()
			if s.sessions == nil {
				s.sessions = map[string]bool{}
			}
			s.sessions[id] = true
			s.mu.Unlock()
			w.Header().Set("Mcp-Session-Id", id)
		}
		caps := map[string]any{"tools": map[string]any{"listChanged": false}}
		if s.NoToolsCap {
			caps = map[string]any{}
		}
		s.reply(w, req.ID, map[string]any{
			"protocolVersion": v,
			"capabilities":    caps,
			"serverInfo":      map[string]any{"name": "fortik-local-fake-quickstart", "version": "0.0.0-fake"},
			"instructions":    "LOCAL FAKE MCP server for Fortik tests. Not NetSuite.",
		}, nil)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		if s.ToolsRPCError {
			s.reply(w, req.ID, nil, &rpcErr{Code: -32603, Message: "internal error"})
			return
		}
		if s.ToolsMalformed {
			s.reply(w, req.ID, map[string]any{"items": []any{}}, nil)
			return
		}
		var p struct {
			Cursor string `json:"cursor"`
		}
		_ = json.Unmarshal(req.Params, &p)
		all := s.tools()
		start := 0
		if p.Cursor != "" {
			if _, err := fmt.Sscanf(p.Cursor, "page-%d", &start); err != nil || start < 0 || start > len(all) {
				s.reply(w, req.ID, nil, &rpcErr{Code: -32602, Message: "invalid cursor"})
				return
			}
		}
		end := len(all)
		if s.PageSize > 0 && start+s.PageSize < end {
			end = start + s.PageSize
		}
		res := map[string]any{"tools": all[start:end]}
		if end < len(all) {
			res["nextCursor"] = fmt.Sprintf("page-%d", end)
		}
		s.reply(w, req.ID, res, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if json.Unmarshal(req.Params, &p) != nil || p.Name == "" {
			s.reply(w, req.ID, nil, &rpcErr{Code: -32602, Message: "invalid tools/call params"})
			return
		}
		s.mu.Lock()
		s.toolLog = append(s.toolLog, ToolCall{Name: p.Name, Args: p.Arguments})
		s.mu.Unlock()
		call := s.Call
		if call == nil {
			call = s.builtin
		}
		res, msg := call(p.Name, p.Arguments)
		if msg != "" {
			s.reply(w, req.ID, nil, &rpcErr{Code: -32602, Message: msg})
			return
		}
		s.reply(w, req.ID, res, nil)
	default:
		s.reply(w, req.ID, nil, &rpcErr{Code: -32601, Message: "method not found"})
	}
}

// builtin is the default tools/call behaviour: a tiny record store. Results
// use MCP's content + structuredContent shape; every text says LOCAL FAKE.
func (s *Server) builtin(name string, raw json.RawMessage) (any, string) {
	var a struct {
		RecordType  string         `json:"recordType"`
		ID          any            `json:"id"`
		FieldValues map[string]any `json:"fieldValues"`
	}
	_ = json.Unmarshal(raw, &a)
	id := fmt.Sprint(a.ID)
	text := func(t string, structured any) any {
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": t}}, "structuredContent": structured, "isError": false}
	}
	toolErr := func(t string) any {
		return map[string]any{"content": []any{map[string]any{"type": "text", "text": t}}, "isError": true}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	switch name {
	case "read_record":
		rec, ok := s.Records[a.RecordType][id]
		if !ok {
			return toolErr("LOCAL FAKE: record not found"), ""
		}
		fv := map[string]any{}
		for k, v := range rec {
			fv[k] = v
		}
		// Same shape as the live read_record (2026-10-25): the record under
		// "record", plain values, explicit nulls.
		return text("LOCAL FAKE record", map[string]any{"recordType": a.RecordType, "id": id,
			"record":           map[string]any{"recordType": a.RecordType, "id": id, "fieldValues": fv},
			"availableActions": []any{}, "availableEmailActions": []any{}}), ""
	case "update_record":
		rec, ok := s.Records[a.RecordType][id]
		if !ok {
			return toolErr("LOCAL FAKE: record not found"), ""
		}
		for k, v := range a.FieldValues {
			rec[k] = v
		}
		return text("LOCAL FAKE: updated", map[string]any{"recordType": a.RecordType, "id": id}), ""
	case "create_record":
		if s.Records == nil {
			s.Records = map[string]map[string]map[string]any{}
		}
		if s.Records[a.RecordType] == nil {
			s.Records[a.RecordType] = map[string]map[string]any{}
		}
		nid := fmt.Sprint(1000 + len(s.Records[a.RecordType]))
		rec := map[string]any{}
		if a.RecordType == "Contact" { // the live read returns empty fields as explicit nulls
			rec["workEmail"], rec["company"], rec["isInactive"] = nil, nil, false
		}
		for k, v := range a.FieldValues {
			rec[k] = v
		}
		s.Records[a.RecordType][nid] = rec
		return text("LOCAL FAKE: created", map[string]any{"recordType": a.RecordType, "id": nid}), ""
	case "execute_record_action":
		rec, ok := s.Records[a.RecordType][id]
		if !ok {
			return toolErr("LOCAL FAKE: record not found"), ""
		}
		var act struct {
			ActionID string `json:"actionId"`
		}
		_ = json.Unmarshal(raw, &act)
		if act.ActionID == "inactivate" {
			rec["isInactive"] = true
		}
		return text("LOCAL FAKE: action "+act.ActionID, map[string]any{"recordType": a.RecordType, "id": id}), ""
	case "list_records":
		var items []any
		for rid, rec := range s.Records[a.RecordType] {
			items = append(items, map[string]any{"recordType": a.RecordType, "id": rid, "fieldValues": rec})
		}
		return text("LOCAL FAKE list", map[string]any{"recordType": a.RecordType, "records": items, "returnedCount": len(items), "totalCount": len(items)}), ""
	}
	return text("LOCAL FAKE result of "+name, map[string]any{"tool": name}), ""
}

type rpcErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) reply(w http.ResponseWriter, id json.RawMessage, result any, e *rpcErr) {
	msg := map[string]any{"jsonrpc": "2.0", "id": id}
	if e != nil {
		msg["error"] = e
	} else {
		msg["result"] = result
	}
	b, _ := json.Marshal(msg)
	if !s.SSE {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(b)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", `{"jsonrpc":"2.0","method":"notifications/message","params":{"level":"info","data":"fake"}}`)
	fmt.Fprintf(w, "event: message\ndata: %s\n\n", b)
}

func (s *Server) tools() []json.RawMessage {
	if s.Tools != nil {
		return append(append([]json.RawMessage(nil), s.Tools...), s.ExtraTools...)
	}
	names := append([]string(nil), ReadOnlyTools...)
	if s.ReadWrite {
		names = append(names, WriteTools...)
	}
	out := make([]json.RawMessage, 0, len(names)+len(s.ExtraTools))
	for _, n := range names {
		out = append(out, Tool(n))
	}
	return append(out, s.ExtraTools...)
}

// fakeSchemas mirror the shape of the live QuickStart input schemas seen on
// 2026-10-25 (required arguments, additionalProperties false, id as string or
// integer) for the tools Fortik's tests exercise; other tools get an open
// object schema. The descriptions are invented.
var fakeSchemas = func() map[string]map[string]any {
	id := map[string]any{"oneOf": []any{map[string]any{"type": "string"}, map[string]any{"type": "integer"}}}
	str := map[string]any{"type": "string"}
	obj := map[string]any{"type": "object"}
	arr := map[string]any{"type": "array"}
	closed := func(required []string, props map[string]any) map[string]any {
		return map[string]any{"type": "object", "required": required, "properties": props, "additionalProperties": false}
	}
	return map[string]map[string]any{
		"read_record":             closed([]string{"recordType", "id"}, map[string]any{"recordType": str, "id": id}),
		"delete_record":           closed([]string{"recordType", "id"}, map[string]any{"recordType": str, "id": id}),
		"list_record_attachments": closed([]string{"recordType", "id"}, map[string]any{"recordType": str, "id": id, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50}}),
		"read_record_sublist":     closed([]string{"recordType", "id", "sublistId"}, map[string]any{"recordType": str, "id": id, "sublistId": str}),
		"list_records": closed([]string{"recordType"}, map[string]any{"recordType": str, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 50},
			"offset": map[string]any{"type": "integer", "minimum": 0}, "filter": obj, "sort": arr}),
		"create_record":         closed([]string{"recordType"}, map[string]any{"recordType": str, "fieldValues": obj, "sublistValues": obj}),
		"update_record":         closed([]string{"recordType", "id"}, map[string]any{"recordType": str, "id": id, "fieldValues": obj, "sublistValues": obj}),
		"execute_record_action": closed([]string{"recordType", "id", "actionId"}, map[string]any{"recordType": str, "id": id, "actionId": str, "parameters": obj}),
		"execute_record_transform": closed([]string{"sourceRecordType", "sourceId", "transformId"}, map[string]any{"sourceRecordType": str, "sourceId": id,
			"transformId": str, "fieldValues": obj, "sublistValues": obj}),
		"send_record_email": closed([]string{"recordType", "id", "actionId"}, map[string]any{"recordType": str, "id": id, "actionId": str,
			"to": arr, "cc": arr, "bcc": arr, "subject": str, "attachPdf": map[string]any{"type": "boolean"}, "sendCopy": map[string]any{"type": "boolean"}, "additionalNote": str}),
		"set_preferences": closed([]string{"preferenceKey", "value"}, map[string]any{"preferenceKey": str,
			"value": map[string]any{"oneOf": []any{str, map[string]any{"type": "boolean"}, obj}}}),
		"set_record_attachment": closed([]string{"recordType", "id", "operation"}, map[string]any{"recordType": str, "id": id, "lineId": id,
			"operation": map[string]any{"type": "string", "enum": []any{"append", "replace", "updateDescription", "delete"}}, "description": str, "contentHandle": str}),
		"run_report":     closed(nil, map[string]any{"reportId": str, "stateId": str, "cursor": str}),
		"report_catalog": closed([]string{"query"}, map[string]any{"query": str, "afterReportId": str}),
	}
}()

// Tool returns a fake definition for a tool name, marked as fake in its
// description.
func Tool(name string) json.RawMessage {
	schema, ok := fakeSchemas[name]
	if !ok {
		schema = map[string]any{"type": "object", "properties": map[string]any{}}
	}
	b, _ := json.Marshal(map[string]any{
		"name":        name,
		"description": "LOCAL FAKE definition of " + name + " (invented description; schema shaped like the live tool).",
		"inputSchema": schema,
	})
	return b
}
