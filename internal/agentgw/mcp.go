package agentgw

import (
	"context"
	"net/http"
	"strings"

	"fortik/internal/agentgw/extmcp"
)

// mcpService implements agentgateway's ext_mcp guardrail protocol for MCP
// routes: one CheckRequest per MCP method call, with the parsed method and
// params.
type mcpService struct {
	extmcp.UnimplementedExtMcpServer
	s *Server
}

// CheckRequest never returns a gRPC error; every outcome is a Pass or an
// AuthorizationError (MCP-native refusal the agent can read).
func (m *mcpService) CheckRequest(ctx context.Context, req *extmcp.McpRequest) (resp *extmcp.McpRequestResult, _ error) {
	s := m.s
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("ext_mcp check panicked; denying", "panic", r)
			resp = mcpDenied(refuse(http.StatusInternalServerError, "fortik_error", "Fortik could not decide: refused"))
		}
	}()
	route, err := routeMeta(ctx, MetaRouteMCP)
	if err != nil || route == "" {
		return mcpDenied(refuse(http.StatusForbidden, "fortik_error", "MCP route identity is missing or malformed: refused")), nil
	}
	if a, _ := routeMeta(ctx, MetaRouteAgent); a != "" {
		return mcpDenied(refuse(http.StatusForbidden, "fortik_error", "route is marked both MCP and A2A: refused")), nil
	}
	server, ok := s.cfg.MCPServers[route]
	if !ok {
		s.log.Warn("MCP route is not in agentgw.mcp_servers; refusing", "route", route)
		return mcpDenied(refuse(http.StatusForbidden, "fortik_error", "MCP route "+route+" is not configured in Fortik: refused")), nil
	}
	hdr, dup := mcpHeaders(req.GetHeaders())
	if dup != "" {
		return mcpDenied(refuse(http.StatusBadRequest, "bad_request", "repeated "+dup+" header: refused")), nil
	}
	p, bad := s.authenticate(ctx, hdr["authorization"], hdr[HeaderInstanceID])
	if bad != nil {
		return mcpDenied(*bad), nil
	}
	mp := mapMCP(s.verbs, server, route, req.GetMethod(), req.GetMcpRequest())
	v := s.decide(ctx, p, mp, hdr[headerDelegation])
	if !v.Allow {
		return mcpDenied(v), nil
	}
	set := []*extmcp.McpHeader{{Key: HeaderAgentID, Value: []byte(v.AgentID)}}
	remove := []string{"authorization", headerDelegation, MetaRouteAgent, MetaRouteMCP, MetaRouteHTTP}
	if v.InstanceID != "" {
		set = append(set, &extmcp.McpHeader{Key: HeaderInstanceID, Value: []byte(v.InstanceID)})
	} else {
		remove = append(remove, HeaderInstanceID)
	}
	if v.ActionID != "" {
		set = append(set, &extmcp.McpHeader{Key: HeaderActionID, Value: []byte(v.ActionID)})
	} else {
		remove = append(remove, HeaderActionID)
	}
	return &extmcp.McpRequestResult{
		Result:         &extmcp.McpRequestResult_Pass{Pass: &extmcp.Pass{}},
		HeaderMutation: &extmcp.HeaderMutation{Set: set, Remove: remove},
	}, nil
}

// CheckResponse passes responses through unchanged: every request was
// already decided in the request phase. The generated config does not enable
// the response phase.
func (m *mcpService) CheckResponse(context.Context, *extmcp.McpResponse) (*extmcp.McpResponseResult, error) {
	return &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Pass{Pass: &extmcp.Pass{}}}, nil
}

// mcpHeaders lowercases header names; a repeated identity-bearing header is
// reported (it must be unambiguous).
func mcpHeaders(in []*extmcp.McpHeader) (map[string]string, string) {
	out := make(map[string]string, len(in))
	for _, h := range in {
		k := strings.ToLower(h.GetKey())
		if _, seen := out[k]; seen && (k == "authorization" || k == HeaderInstanceID || k == headerDelegation) {
			return nil, k
		}
		out[k] = string(h.GetValue())
	}
	return out, ""
}

func mcpDenied(v verdict) *extmcp.McpRequestResult {
	c := extmcp.AuthorizationError_PERMISSION_DENIED
	switch v.Status {
	case http.StatusTooManyRequests:
		c = extmcp.AuthorizationError_RESOURCE_EXHAUSTED
	case http.StatusBadRequest:
		c = extmcp.AuthorizationError_INVALID
	}
	return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Error{Error: &extmcp.AuthorizationError{
		Code: c, Reason: v.refusalText(),
	}}}
}
