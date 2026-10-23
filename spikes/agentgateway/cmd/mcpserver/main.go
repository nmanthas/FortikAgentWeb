// Command mcpserver is a tiny MCP server (streamable HTTP transport, JSON
// responses) used as the upstream "tool" behind agentgateway in the spike.
//
// It logs every JSON-RPC message it receives together with the x-fortik-*
// headers, so the spike can prove (a) allowed calls arrive with headers
// intact and (b) denied calls never arrive.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

var (
	addr  = flag.String("addr", "127.0.0.1:8090", "listen address")
	quiet = flag.Bool("quiet", false, "do not log every request (use for latency runs)")
	calls atomic.Int64
)

type rpcReq struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func handle(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// We do not offer a standalone server->client SSE stream (allowed by spec).
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	case http.MethodDelete:
		w.WriteHeader(http.StatusOK)
		return
	case http.MethodPost:
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var req rpcReq
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	var tool struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if req.Method == "tools/call" {
		_ = json.Unmarshal(req.Params, &tool)
		calls.Add(1)
	}
	if !*quiet {
		fortik := map[string]string{}
		for k, v := range r.Header {
			lk := strings.ToLower(k)
			if strings.HasPrefix(lk, "x-fortik-") || lk == "traceparent" || lk == "mcp-session-id" || strings.HasPrefix(lk, "mcp-") {
				fortik[lk] = strings.Join(v, ",")
			}
		}
		b, _ := json.Marshal(map[string]any{
			"ts": time.Now().Format(time.RFC3339Nano), "upstream_received": req.Method,
			"tool": tool.Name, "args": string(tool.Arguments), "headers": fortik,
		})
		fmt.Println(string(b))
	}

	if len(req.ID) == 0 { // notification
		w.WriteHeader(http.StatusAccepted)
		return
	}
	var result any
	switch req.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(req.Params, &p)
		if p.ProtocolVersion == "" {
			p.ProtocolVersion = "2025-06-18"
		}
		w.Header().Set("Mcp-Session-Id", newID())
		result = map[string]any{
			"protocolVersion": p.ProtocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "fortik-spike-mcp", "version": "0.0.1"},
		}
	case "ping":
		result = map[string]any{}
	case "tools/list":
		schema := map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}}
		result = map[string]any{"tools": []any{
			map[string]any{"name": "echo", "description": "echo text back", "inputSchema": schema},
			map[string]any{"name": "delete_everything", "description": "dangerous; must be blocked by Fortik", "inputSchema": schema},
		}}
	case "tools/call":
		text := fmt.Sprintf("executed %s args=%s", tool.Name, string(tool.Arguments))
		result = map[string]any{"content": []any{map[string]any{"type": "text", "text": text}}}
	default:
		writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "error": map[string]any{"code": -32601, "message": "method not found"}})
		return
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
}

// handleA2A is a stub A2A agent: it logs the JSON-RPC method and x-fortik-*
// headers and replies with a canned message, enough to prove the callout
// fires on A2A routes too.
func handleA2A(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	var req rpcReq
	_ = json.Unmarshal(body, &req)
	if !*quiet {
		b, _ := json.Marshal(map[string]any{
			"ts": time.Now().Format(time.RFC3339Nano), "a2a_upstream_received": req.Method,
			"agent": r.Header.Get("x-fortik-agent-id"), "instance": r.Header.Get("x-fortik-instance-id"),
			"decision": r.Header.Get("x-fortik-decision"),
		})
		fmt.Println(string(b))
	}
	writeJSON(w, map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{
		"kind": "message", "role": "agent", "messageId": newID(),
		"parts": []any{map[string]any{"kind": "text", "text": "a2a stub ok"}},
	}})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/mcp", handle)
	mux.HandleFunc("/a2a", handleA2A)
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, "{\"tools_call_received\":%d}\n", calls.Load())
	})
	fmt.Fprintf(os.Stderr, "mcpserver listening on http://%s/mcp\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, mux))
}
