package agentgw

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"fortik/internal/action"
	"fortik/internal/agentgw/extmcp"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/gateway"
)

// Fail-closed behaviour that needs no database: Decide errors, timeouts,
// panics and an unavailable authenticator all deny.

type fakeAuth struct{ err error }

func (f fakeAuth) Authenticate(r *http.Request) (authz.Principal, error) {
	if f.err != nil {
		return authz.Principal{}, f.err
	}
	if r.Header.Get("Authorization") != "Bearer good" {
		return authz.Principal{}, gateway.ErrUnauthenticated
	}
	return authz.Principal{Kind: authz.KindAgent, Name: "agent_a"}, nil
}

type fakeDecider func(ctx context.Context, a action.Action) (decide.Outcome, error)

func (f fakeDecider) Decide(ctx context.Context, a action.Action) (decide.Outcome, error) {
	return f(ctx, a)
}

type fakeDeleg struct{}

func (fakeDeleg) Verify(context.Context, string, string) (delegation.Claims, error) {
	return delegation.Claims{}, delegation.ErrInvalidToken
}
func (fakeDeleg) Close(context.Context, string, string) error { return nil }
func (fakeDeleg) CloseTask(context.Context, string, string, string, string) (int, error) {
	return 0, nil
}

func fakeServer(t *testing.T, dec decide.Decider, auth gateway.Authenticator) *grpc.ClientConn {
	t.Helper()
	cfg := config.AgentGWConfig{A2ATargets: map[string]string{"agent-b": "agent_b"}, MCPServers: map[string]string{"memory": "memory"}}
	srv, err := New(cfg, dec, auth, fakeDeleg{}, mustVerbs(t), quietLog(), WithDecideTimeout(80*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, lis) }()
	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
	return conn
}

func TestFailClosed(t *testing.T) {
	blocking := fakeDecider(func(ctx context.Context, _ action.Action) (decide.Outcome, error) {
		<-ctx.Done()
		return decide.Outcome{}, ctx.Err()
	})
	failing := fakeDecider(func(context.Context, action.Action) (decide.Outcome, error) {
		return decide.Outcome{}, errors.New("database is down")
	})
	panicking := fakeDecider(func(context.Context, action.Action) (decide.Outcome, error) { panic("boom") })
	cases := map[string]struct {
		dec  decide.Decider
		auth gateway.Authenticator
		http int
	}{
		"decide timeout":     {blocking, fakeAuth{}, 403},
		"decide error":       {failing, fakeAuth{}, 403},
		"decide panic":       {panicking, fakeAuth{}, 500},
		"auth unavailable":   {failing, fakeAuth{err: gateway.ErrAuthUnavailable}, 503},
		"auth error unknown": {failing, fakeAuth{err: errors.New("weird")}, 401},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			conn := fakeServer(t, c.dec, c.auth)
			start := time.Now()
			resp, err := authv3.NewAuthorizationClient(conn).Check(a2aCtx("agent-b"), checkReq("POST", "/a2a", "gw",
				map[string]string{"authorization": "Bearer good"}, a2aBody("message/send", sendParams)))
			if err != nil {
				t.Fatalf("gRPC error instead of a deny: %v", err)
			}
			d := resp.GetDeniedResponse()
			if d == nil || int(d.GetStatus().GetCode()) != c.http {
				t.Fatalf("got %v", resp)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("the callout did not bound the decision")
			}
			res, err := extmcp.NewExtMcpClient(conn).CheckRequest(mcpCtx("memory"), &extmcp.McpRequest{Method: "tools/call",
				McpRequest: []byte(`{"name":"read_graph"}`), Headers: mcpHdrs("authorization", "Bearer good")})
			if err != nil || res.GetError() == nil || !strings.HasPrefix(res.GetError().GetReason(), "fortik: ") {
				t.Fatalf("ext_mcp: %v %v", res, err)
			}
		})
	}
}

func TestNewValidatesConfig(t *testing.T) {
	ok := fakeDecider(func(context.Context, action.Action) (decide.Outcome, error) { return decide.Outcome{}, nil })
	for name, cfg := range map[string]config.AgentGWConfig{
		"bad a2a agent":   {A2ATargets: map[string]string{"r": "bad agent"}},
		"empty a2a route": {A2ATargets: map[string]string{"": "agent_b"}},
		"bad mcp server":  {MCPServers: map[string]string{"r": ""}},
	} {
		if _, err := New(cfg, ok, fakeAuth{}, fakeDeleg{}, mustVerbs(t), nil); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := New(config.AgentGWConfig{}, nil, fakeAuth{}, fakeDeleg{}, mustVerbs(t), nil); err == nil {
		t.Error("nil decider accepted")
	}
	srv, err := New(config.AgentGWConfig{Listen: "0.0.0.0:0"}, ok, fakeAuth{}, fakeDeleg{}, mustVerbs(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.ListenAndServe(context.Background()); err == nil || !strings.Contains(err.Error(), "plaintext") {
		t.Fatalf("plaintext on a non-loopback address: %v", err)
	}
}
