// Command callout is a minimal stand-in for Fortik's Decide service.
//
// It serves two gRPC protocols on one port so the spike can exercise both of
// agentgateway's per-request policy hooks:
//
//   - envoy.service.auth.v3.Authorization/Check  (agentgateway `extAuthz`, Envoy ext_authz v3)
//   - agentgateway.dev.ext_mcp.ExtMcp/CheckRequest (agentgateway `mcpGuardrails`, MCP-native)
//
// Decision rule (deliberately trivial, this is a spike):
//
//	deny  if MCP tool name == "delete_everything"
//	deny  if header x-fortik-agent-id == "blocked_agent"
//	allow otherwise
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc"

	"fortik/spikes/agentgateway/internal/extmcp"
)

var (
	quiet   = flag.Bool("quiet", false, "do not log every request (use for latency runs)")
	addr    = flag.String("addr", "127.0.0.1:9001", "gRPC listen address")
	delay   = flag.Duration("delay", 0, "artificial decision latency (to test gateway timeouts)")
	nChecks atomic.Int64
)

type decision struct {
	Allow  bool
	Reason string
}

func decide(agentID, instanceID, method, tool string) decision {
	if *delay > 0 {
		time.Sleep(*delay)
	}
	switch {
	case agentID == "blocked_agent":
		return decision{false, "agent blocked by kill switch"}
	case method == "tools/call" && tool == "delete_everything":
		return decision{false, "tool delete_everything is red"}
	default:
		return decision{true, "green"}
	}
}

func logLine(v map[string]any) {
	if *quiet {
		return
	}
	v["ts"] = time.Now().Format(time.RFC3339Nano)
	b, _ := json.Marshal(v)
	fmt.Println(string(b))
}

// ---------------------------------------------------------------- ext_authz

type authzServer struct {
	authv3.UnimplementedAuthorizationServer
}

type jsonrpc struct {
	Method string `json:"method"`
	Params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	} `json:"params"`
}

func (authzServer) Check(_ context.Context, req *authv3.CheckRequest) (*authv3.CheckResponse, error) {
	nChecks.Add(1)
	h := req.GetAttributes().GetRequest().GetHttp()
	hdrs := h.GetHeaders()
	body := h.GetBody()
	if body == "" && len(h.GetRawBody()) > 0 {
		body = string(h.GetRawBody())
	}
	var rpc jsonrpc
	_ = json.Unmarshal([]byte(body), &rpc)
	d := decide(hdrs["x-fortik-agent-id"], hdrs["x-fortik-instance-id"], rpc.Method, rpc.Params.Name)

	fortik := map[string]string{}
	for k, v := range hdrs {
		if strings.HasPrefix(k, "x-fortik-") || k == "mcp-session-id" || k == ":path" || k == ":method" || k == "traceparent" {
			fortik[k] = v
		}
	}
	logLine(map[string]any{
		"hook": "extAuthz", "headers": fortik, "header_count": len(hdrs),
		"body": body, "body_bytes": len(body), "jsonrpc_method": rpc.Method, "tool": rpc.Params.Name,
		"allow": d.Allow, "reason": d.Reason,
	})

	if !d.Allow {
		return &authv3.CheckResponse{
			Status: &rpcstatus.Status{Code: int32(code.Code_PERMISSION_DENIED), Message: d.Reason},
			HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
				Status: &typev3.HttpStatus{Code: typev3.StatusCode_Forbidden},
				Headers: []*corev3.HeaderValueOption{{Header: &corev3.HeaderValue{Key: "x-fortik-decision", Value: "deny"}}},
				Body:    fmt.Sprintf(`{"fortik":"deny","reason":%q}`, d.Reason),
			}},
		}, nil
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(code.Code_OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			// Proves the callout can inject headers that reach the upstream.
			Headers: []*corev3.HeaderValueOption{{Header: &corev3.HeaderValue{Key: "x-fortik-decision", Value: "allow-extauthz"}}},
		}},
	}, nil
}

// ---------------------------------------------------------------- ext_mcp

type extMcpServer struct {
	extmcp.UnimplementedExtMcpServer
}

func (extMcpServer) CheckRequest(_ context.Context, req *extmcp.McpRequest) (*extmcp.McpRequestResult, error) {
	nChecks.Add(1)
	hdrs := map[string]string{}
	for _, h := range req.GetHeaders() {
		hdrs[strings.ToLower(h.GetKey())] = string(h.GetValue())
	}
	var params struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(req.GetMcpRequest(), &params)
	d := decide(hdrs["x-fortik-agent-id"], hdrs["x-fortik-instance-id"], req.GetMethod(), params.Name)

	fortik := map[string]string{}
	for k, v := range hdrs {
		if strings.HasPrefix(k, "x-fortik-") || k == "mcp-session-id" || k == "traceparent" {
			fortik[k] = v
		}
	}
	logLine(map[string]any{
		"hook": "mcpGuardrails", "method": req.GetMethod(), "service_names": req.GetServiceNames(),
		"params": string(req.GetMcpRequest()), "headers": fortik, "header_count": len(hdrs),
		"tool": params.Name, "allow": d.Allow, "reason": d.Reason,
	})

	if !d.Allow {
		return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Error{Error: &extmcp.AuthorizationError{
			Code: extmcp.AuthorizationError_PERMISSION_DENIED, Reason: "fortik: " + d.Reason,
		}}}, nil
	}
	return &extmcp.McpRequestResult{
		Result: &extmcp.McpRequestResult_Pass{Pass: &extmcp.Pass{}},
		HeaderMutation: &extmcp.HeaderMutation{Set: []*extmcp.McpHeader{
			{Key: "x-fortik-decision", Value: []byte("allow-mcpguardrails")},
		}},
	}, nil
}

func (extMcpServer) CheckResponse(_ context.Context, _ *extmcp.McpResponse) (*extmcp.McpResponseResult, error) {
	return &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Pass{Pass: &extmcp.Pass{}}}, nil
}

func main() {
	flag.Parse()
	lis, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	s := grpc.NewServer()
	authv3.RegisterAuthorizationServer(s, authzServer{})
	extmcp.RegisterExtMcpServer(s, extMcpServer{})
	fmt.Fprintf(os.Stderr, "callout listening on %s (ext_authz v3 + ext_mcp)\n", *addr)
	go func() {
		for range time.Tick(10 * time.Second) {
			fmt.Fprintf(os.Stderr, "callout: %d checks so far\n", nChecks.Load())
		}
	}()
	log.Fatal(s.Serve(lis))
}
