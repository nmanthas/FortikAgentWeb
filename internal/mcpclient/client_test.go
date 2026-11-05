package mcpclient_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fortik/internal/mcpclient"
	"fortik/internal/mcpclient/mcpfake"
)

const token = "qs-test-token-0123456789"

func discover(t *testing.T, fake *mcpfake.Server, tok string) (*mcpclient.Discovery, error) {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return discoverURL(srv.URL+"/mcp", tok)
}

func discoverURL(u, tok string) (*mcpclient.Discovery, error) {
	c := &mcpclient.Client{HTTP: &http.Client{CheckRedirect: mcpclient.NoRedirects, Timeout: 5 * time.Second}, Endpoint: u, Token: tok}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.Discover(ctx)
}

func kind(t *testing.T, err error) *mcpclient.Error {
	t.Helper()
	var e *mcpclient.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *mcpclient.Error, got %v", err)
	}
	if strings.Contains(e.Error(), token) {
		t.Fatalf("error leaks the token: %s", e)
	}
	return e
}

func names(d *mcpclient.Discovery) []string {
	var out []string
	for _, t := range d.Tools {
		out = append(out, t.Name)
	}
	return out
}

func TestDiscoverJSONAndSSE(t *testing.T) {
	for _, sse := range []bool{false, true} {
		fake := &mcpfake.Server{Token: token, SSE: sse, PageSize: 5}
		d, err := discover(t, fake, token)
		if err != nil {
			t.Fatalf("sse=%v: %v", sse, err)
		}
		if len(d.Tools) != len(mcpfake.ReadOnlyTools) || d.Pages != 4 {
			t.Fatalf("sse=%v: %d tools in %d pages", sse, len(d.Tools), d.Pages)
		}
		if d.ProtocolVersion != mcpclient.RequestedVersion || !d.HasTools || !d.SessionID || d.ServerName != "fortik-local-fake-quickstart" {
			t.Fatalf("sse=%v: %+v", sse, d)
		}
		calls := fake.Calls()
		// The full handshake, and the session is closed; no tool is ever called.
		if calls["initialize"] != 1 || calls["notifications/initialized"] != 1 || calls["tools/list"] != 4 || calls["DELETE"] != 1 || calls["tools/call"] != 0 {
			t.Fatalf("sse=%v: calls %v", sse, calls)
		}
		for _, h := range fake.AuthHeaders() {
			if h != "Bearer "+token {
				t.Fatalf("upstream Authorization header %q", h)
			}
		}
	}
}

func TestDiscoverReadWriteAndNoSession(t *testing.T) {
	d, err := discover(t, &mcpfake.Server{Token: token, ReadWrite: true, NoSession: true}, token)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Tools) != len(mcpfake.ReadOnlyTools)+len(mcpfake.WriteTools) || d.SessionID {
		t.Fatalf("%d tools, session %v", len(d.Tools), d.SessionID)
	}
	// Sorted by name.
	if n := names(d); n[0] != "configure_report" {
		t.Fatalf("not sorted: %v", n[:3])
	}
}

func TestDiscoverAuthErrors(t *testing.T) {
	_, err := discover(t, &mcpfake.Server{Token: token}, "wrong-token-value")
	if e := kind(t, err); e.Kind != mcpclient.KindAuthFailed || e.HTTPStatus != 401 || !strings.Contains(e.Detail, "Token can't be parsed") {
		t.Fatalf("wrong token: %v", e)
	}
	_, err = discover(t, &mcpfake.Server{Token: token, ExpiredToken: true}, token)
	if e := kind(t, err); e.Kind != mcpclient.KindTokenExpired {
		t.Fatalf("expired: %v", e)
	}
	_, err = discover(t, &mcpfake.Server{Token: token, InitStatus: 403, InitBody: "MCP access denied for role"}, token)
	if e := kind(t, err); e.Kind != mcpclient.KindPermission || !strings.Contains(e.Detail, "MCP access denied") {
		t.Fatalf("403: %v", e)
	}
}

func TestDiscoverInitAndDiscoveryFailures(t *testing.T) {
	cases := []struct {
		name string
		fake *mcpfake.Server
		want string
		has  string
	}{
		{"unavailable 503", &mcpfake.Server{Token: token, InitStatus: 503, InitBody: "maintenance"}, mcpclient.KindUnavailable, "maintenance"},
		{"rate limited", &mcpfake.Server{Token: token, InitStatus: 429}, mcpclient.KindUnavailable, "unavailable"},
		{"404 endpoint", &mcpfake.Server{Token: token, InitStatus: 404, InitBody: "<html>Not Found</html>"}, mcpclient.KindInitFailed, "HTML error page"},
		{"initialize rpc error", &mcpfake.Server{Token: token, InitRPCError: true}, mcpclient.KindInitFailed, "not enabled"},
		{"unsupported version", &mcpfake.Server{Token: token, ProtocolVersion: "2024-11-05"}, mcpclient.KindInitFailed, "2024-11-05"},
		{"tools rpc error", &mcpfake.Server{Token: token, ToolsRPCError: true}, mcpclient.KindDiscoveryFailed, "JSON-RPC error"},
		{"tools malformed", &mcpfake.Server{Token: token, ToolsMalformed: true}, mcpclient.KindDiscoveryFailed, "no tools array"},
	}
	for _, c := range cases {
		_, err := discover(t, c.fake, token)
		e := kind(t, err)
		if e.Kind != c.want || !strings.Contains(e.Detail, c.has) {
			t.Errorf("%s: got %v", c.name, e)
		}
	}
}

func TestDiscoverUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := srv.URL
	srv.Close()
	_, err := discoverURL(u+"/mcp", token)
	if e := kind(t, err); e.Kind != mcpclient.KindUnavailable || e.HTTPStatus != 0 {
		t.Fatalf("got %v", e)
	}
}

func TestRedirectNotFollowed(t *testing.T) {
	target := httptest.NewServer(&mcpfake.Server{Token: token})
	defer target.Close()
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/mcp", http.StatusTemporaryRedirect)
	}))
	defer redir.Close()
	_, err := discoverURL(redir.URL+"/mcp", token)
	if e := kind(t, err); e.Kind != mcpclient.KindInitFailed || !strings.Contains(e.Detail, "redirect") {
		t.Fatalf("got %v", e)
	}
}

func TestMalformedToolsRejectedIndividually(t *testing.T) {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }
	fake := &mcpfake.Server{Token: token, Tools: []json.RawMessage{
		mcpfake.Tool("read_record"),
		raw(`{"name":"no_schema"}`),
		raw(`{"name":"bad_type","inputSchema":{"type":"string"}}`),
		raw(`{"name":"bad name!","inputSchema":{"type":"object"}}`),
		raw(`{"inputSchema":{"type":"object"}}`),
		raw(`"just a string"`),
		raw(`{"name":"dup","inputSchema":{"type":"object"}}`),
		raw(`{"name":"dup","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`),
		raw(`{"name":"bad_annotations","inputSchema":{"type":"object"},"annotations":[1]}`),
		raw(`{"name":"with_output","inputSchema":{"type":"object"},"outputSchema":{"type":"object"},"annotations":{"readOnlyHint":true}}`),
	}}
	d, err := discover(t, fake, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(names(d), ","); got != "read_record,with_output" {
		t.Fatalf("kept %s", got)
	}
	if len(d.Rejected) != 8 {
		t.Fatalf("rejected %+v", d.Rejected)
	}
	reasons := map[string]string{}
	for _, r := range d.Rejected {
		reasons[r.Name] += r.Reason + ";"
	}
	if !strings.Contains(reasons["no_schema"], "inputSchema is missing") || !strings.Contains(reasons["bad_type"], `"type": "object"`) ||
		!strings.Contains(reasons["dup"], "duplicate") || !strings.Contains(reasons["bad_annotations"], "annotations") {
		t.Fatalf("reasons %v", reasons)
	}
	if string(d.Tools[1].Annotations) != `{"readOnlyHint":true}` || string(d.Tools[1].OutputSchema) != `{"type":"object"}` {
		t.Fatalf("with_output %+v", d.Tools[1])
	}
}

func TestTokenScrubbedFromServerText(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad token "+token+" for this company", http.StatusBadRequest)
	}))
	defer srv.Close()
	_, err := discoverURL(srv.URL, token)
	e := kind(t, err) // fails if the token appears
	if !strings.Contains(e.Detail, "[redacted]") {
		t.Fatalf("got %v", e)
	}
}
