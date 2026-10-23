package agentgw

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/genproto/googleapis/rpc/code"
	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
)

// authzService implements Envoy ext_authz v3 for A2A and HTTP egress routes.
type authzService struct {
	authv3.UnimplementedAuthorizationServer
	s *Server
}

// Check never returns a gRPC error: every outcome, including internal
// failures, is an explicit allow or deny response (an error would also deny,
// via failureMode: deny, but with a less useful body).
func (a *authzService) Check(ctx context.Context, req *authv3.CheckRequest) (resp *authv3.CheckResponse, _ error) {
	s := a.s
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("ext_authz check panicked; denying", "panic", r)
			resp = deniedResponse(refuse(http.StatusInternalServerError, "fortik_error", "Fortik could not decide: refused"), false, nil)
		}
	}()
	h := req.GetAttributes().GetRequest().GetHttp()
	if h == nil {
		return deniedResponse(refuse(http.StatusBadRequest, "bad_request", "no HTTP request attributes: refused"), false, nil), nil
	}
	routeAgent, err1 := routeMeta(ctx, MetaRouteAgent)
	routeHTTP, err2 := routeMeta(ctx, MetaRouteHTTP)
	routeMCP, err3 := routeMeta(ctx, MetaRouteMCP)
	isA2A := routeAgent != ""
	switch {
	case err1 != nil || err2 != nil || err3 != nil:
		return deniedResponse(refuse(http.StatusForbidden, "fortik_error", "ambiguous or malformed route identity: refused"), false, nil), nil
	case routeMCP != "":
		return deniedResponse(refuse(http.StatusForbidden, "fortik_error", "MCP routes must use mcpGuardrails, not extAuthz: refused"), false, nil), nil
	case isA2A && routeHTTP != "":
		return deniedResponse(refuse(http.StatusForbidden, "fortik_error", "route is marked both A2A and HTTP: refused"), false, nil), nil
	case !isA2A && routeHTTP == "":
		return deniedResponse(refuse(http.StatusForbidden, "fortik_error", "route is not configured for Fortik (no route identity): refused"), false, nil), nil
	}

	hdr := lowerHeaders(h.GetHeaders())
	p, bad := s.authenticate(ctx, hdr["authorization"], hdr[HeaderInstanceID])
	if bad != nil {
		return deniedResponse(*bad, isA2A, nil), nil
	}
	body := []byte(h.GetBody())
	if len(body) == 0 && len(h.GetRawBody()) > 0 {
		body = h.GetRawBody()
	}
	method := strings.ToUpper(h.GetMethod())
	if method == "" {
		method = strings.ToUpper(hdr[":method"])
	}
	path := h.GetPath()
	if path == "" {
		path = hdr[":path"]
	}
	inbound := hdr[headerDelegation]

	var m mapped
	if isA2A {
		toAgent, ok := s.cfg.A2ATargets[routeAgent]
		if !ok {
			s.log.Warn("A2A route is not in agentgw.a2a_targets; refusing", "route", routeAgent)
			return deniedResponse(refuse(http.StatusForbidden, "fortik_error", "A2A route "+routeAgent+" is not configured in Fortik: refused"), true, nil), nil
		}
		m = mapA2A(method, path, routeAgent, toAgent, body)
		if m.MetaToken != "" {
			switch {
			case inbound == "":
				inbound = m.MetaToken
			case inbound != m.MetaToken:
				m = unknown(m.System, "conflicting delegation tokens (header and A2A metadata)", m.Target)
			}
		}
	} else {
		cl, _ := strconv.ParseInt(hdr["content-length"], 10, 64)
		if cl < 0 {
			cl = 0
		}
		hasBody := cl > 0 || len(body) > 0 || hdr["transfer-encoding"] != ""
		authority := h.GetHost()
		if authority == "" {
			authority = hdr[":authority"]
		}
		m = mapHTTP(s.internal, strings.ToLower(routeHTTP), routeHTTP, method, authority, path, hasBody, max(cl, int64(len(body))))
	}
	v := s.decide(ctx, p, m, inbound)
	if !v.Allow {
		return deniedResponse(v, isA2A, m.RPCID), nil
	}
	return okResponse(v, isA2A && m.Delegate), nil
}

// lowerHeaders lowercases header names (Envoy already does; be defensive).
func lowerHeaders(in map[string]string) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[strings.ToLower(k)] = v
	}
	return out
}

func setHeader(k, v string) *corev3.HeaderValueOption {
	return &corev3.HeaderValueOption{
		Header:       &corev3.HeaderValue{Key: k, Value: v},
		AppendAction: corev3.HeaderValueOption_OVERWRITE_IF_EXISTS_OR_ADD,
	}
}

// okResponse allows the request: the verified identity overwrites anything
// the client sent, the agent's Fortik token and any inbound delegation token
// are stripped, and an allowed A2A delegation carries its new hop token.
func okResponse(v verdict, delegate bool) *authv3.CheckResponse {
	headers := []*corev3.HeaderValueOption{setHeader(HeaderAgentID, v.AgentID)}
	remove := []string{"authorization", MetaRouteAgent, MetaRouteMCP, MetaRouteHTTP}
	if v.InstanceID != "" {
		headers = append(headers, setHeader(HeaderInstanceID, v.InstanceID))
	} else {
		remove = append(remove, HeaderInstanceID)
	}
	if v.ActionID != "" {
		headers = append(headers, setHeader(HeaderActionID, v.ActionID))
	} else {
		remove = append(remove, HeaderActionID)
	}
	if delegate && v.Token != "" {
		headers = append(headers, setHeader(headerDelegation, v.Token))
	} else {
		remove = append(remove, headerDelegation)
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(code.Code_OK)},
		HttpResponse: &authv3.CheckResponse_OkResponse{OkResponse: &authv3.OkHttpResponse{
			Headers:         headers,
			HeadersToRemove: remove,
		}},
	}
}

// deniedResponse renders a refusal. A2A routes get a JSON-RPC error object
// (with the refusal under error.data); HTTP routes get the gateway's shape.
func deniedResponse(v verdict, jsonRPC bool, rpcID json.RawMessage) *authv3.CheckResponse {
	var body any
	if jsonRPC {
		id := json.RawMessage("null")
		if len(rpcID) > 0 {
			id = rpcID
		}
		body = map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{
			"code": -32001, "message": v.refusalText(), "data": v.refusalJSON(),
		}}
	} else {
		body = map[string]any{"error": v.refusalJSON()}
	}
	b, err := json.Marshal(body)
	if err != nil {
		b = []byte(`{"error":{"code":"fortik_error","decision":"deny","reason":"refused"}}`)
	}
	status := v.Status
	if status < 400 {
		status = http.StatusForbidden
	}
	grpcCode := code.Code_PERMISSION_DENIED
	switch status {
	case http.StatusUnauthorized:
		grpcCode = code.Code_UNAUTHENTICATED
	case http.StatusTooManyRequests:
		grpcCode = code.Code_RESOURCE_EXHAUSTED
	case http.StatusServiceUnavailable:
		grpcCode = code.Code_UNAVAILABLE
	case http.StatusBadRequest:
		grpcCode = code.Code_INVALID_ARGUMENT
	}
	headers := []*corev3.HeaderValueOption{setHeader("content-type", "application/json"), setHeader("cache-control", "no-store")}
	if v.ActionID != "" {
		headers = append(headers, setHeader(HeaderActionID, v.ActionID))
	}
	if status == http.StatusUnauthorized {
		headers = append(headers, setHeader("www-authenticate", `Bearer realm="fortik-agentgw"`))
	}
	return &authv3.CheckResponse{
		Status: &rpcstatus.Status{Code: int32(grpcCode), Message: v.Reason},
		HttpResponse: &authv3.CheckResponse_DeniedResponse{DeniedResponse: &authv3.DeniedHttpResponse{
			Status:  &typev3.HttpStatus{Code: typev3.StatusCode(status)},
			Headers: headers,
			Body:    string(b),
		}},
	}
}
