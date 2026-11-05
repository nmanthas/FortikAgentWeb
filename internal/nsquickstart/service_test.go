package nsquickstart

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/mcpclient/mcpfake"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
)

const (
	tokenA = "qsA-0123456789abcdef-token"
	tokenB = "qsB-fedcba9876543210-token"
)

type fixture struct {
	t     *testing.T
	pool  *pgxpool.Pool
	diary *diary.Diary
	sec   *secrets.EncFile
	store *integrations.PGStore
	svc   *Service
	api   string
}

func newFixture(t *testing.T, cfg config.MCPUpstreamsConfig) *fixture {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	d := diary.New(pool)
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	sec, err := secrets.NewEncFile(filepath.Join(t.TempDir(), "secrets"), k)
	if err != nil {
		t.Fatal(err)
	}
	st := integrations.NewPGStore(pool, d, sec)
	svc := New(pool, d, st, cfg, "test", nil)
	reg := integrations.NewRegistry()
	for _, tt := range svc.Testers() {
		if err := reg.Register(tt); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	integrations.NewHandler(st, reg, nil).Register(mux)
	svc.Register(mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if roles := r.Header.Get("X-Test-Roles"); roles != "" {
			p := authz.Principal{Kind: authz.KindUser, Name: "Sec", Email: "sec@example.com", AuthMethod: "dev", Roles: map[string]bool{}}
			for _, role := range strings.Split(roles, ",") {
				p.Roles[role] = true
			}
			r = r.WithContext(authz.With(r.Context(), p))
		}
		mux.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return &fixture{t: t, pool: pool, diary: d, sec: sec, store: st, svc: svc, api: srv.URL}
}

func loopback() config.MCPUpstreamsConfig {
	return config.MCPUpstreamsConfig{AllowedHosts: []string{"my.quickstartapi.netsuite.com"}, AllowLoopback: true}
}

func (f *fixture) do(method, path, roles string, body any) (int, map[string]any) {
	f.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, f.api+path, rd)
	req.Header.Set("Content-Type", "application/json")
	if roles != "" {
		req.Header.Set("X-Test-Roles", roles)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (f *fixture) configure(endpoint, token string, extra map[string]any) {
	f.t.Helper()
	cfg := map[string]any{"tenant_label": "Acme QuickStart test", "endpoint_url": endpoint}
	for k, v := range extra {
		cfg[k] = v
	}
	body := map[string]any{"config": cfg}
	if token != "" {
		body["secrets"] = map[string]any{"personal_access_token": token}
	}
	if code, out := f.do("PUT", "/v1/integrations/netsuite_quickstart", "security", body); code != 200 {
		f.t.Fatalf("configure: %d %v", code, out)
	}
}

func (f *fixture) test() map[string]any {
	f.t.Helper()
	code, out := f.do("POST", "/v1/integrations/netsuite_quickstart/test", "security", nil)
	if code != 200 {
		f.t.Fatalf("test: %d %v", code, out)
	}
	return out
}

func (f *fixture) status() View {
	f.t.Helper()
	v, err := f.svc.Status(context.Background(), IntegrationKey)
	if err != nil {
		f.t.Fatal(err)
	}
	return v
}

func (f *fixture) events(eventType string) []map[string]any {
	f.t.Helper()
	entries, err := f.diary.Query(context.Background(), diary.Filter{Limit: 10000})
	if err != nil {
		f.t.Fatal(err)
	}
	var out []map[string]any
	for _, e := range entries {
		if e.EventType != eventType {
			continue
		}
		var body map[string]any
		_ = json.Unmarshal(e.Body, &body)
		data, _ := body["data"].(map[string]any)
		out = append(out, data)
	}
	return out
}

// noTokenAnywhere fails if a token appears in Postgres (integrations,
// mcp_connections, Diary) or in the given API outputs.
func (f *fixture) noTokenAnywhere(outputs ...any) {
	f.t.Helper()
	var s string
	err := f.pool.QueryRow(context.Background(), `
		SELECT COALESCE((SELECT string_agg(i::text, E'\n') FROM integrations i), '') ||
		       COALESCE((SELECT string_agg(m::text, E'\n') FROM mcp_connections m), '') ||
		       COALESCE((SELECT string_agg(d::text, E'\n') FROM diary d), '')`).Scan(&s)
	if err != nil {
		f.t.Fatal(err)
	}
	for _, o := range outputs {
		b, _ := json.Marshal(o)
		s += string(b)
	}
	for _, tok := range []string{tokenA, tokenB} {
		if strings.Contains(s, tok) {
			f.t.Fatalf("token %s… leaked into the database, Diary or API output", tok[:4])
		}
	}
}

func fakeServer(t *testing.T, fake *mcpfake.Server) string {
	t.Helper()
	srv := httptest.NewServer(fake)
	t.Cleanup(srv.Close)
	return srv.URL + "/mcp"
}

func TestNotConfiguredAndSavedNotTested(t *testing.T) {
	f := newFixture(t, loopback())
	if v := f.status(); v.State != StateNotConfigured || v.Configured || !v.Enforcement.AgentCallsRouted || v.Activity == nil {
		t.Fatalf("%+v", v)
	}
	fake := &mcpfake.Server{Token: tokenA}
	f.configure(fakeServer(t, fake), tokenA, nil)
	v := f.status()
	if v.State != StateSavedNotTested || !v.Token.Set || v.Endpoint == "" || len(v.Tools) != 0 {
		t.Fatalf("%+v", v)
	}
	// Saving never contacts the server: "Connected" needs a live check.
	if len(fake.Calls()) != 0 {
		t.Fatalf("configure contacted the server: %v", fake.Calls())
	}
}

func TestConnectDiscoverRotateDisconnect(t *testing.T) {
	f := newFixture(t, loopback())
	fake := &mcpfake.Server{Token: tokenA, SSE: true, PageSize: 7}
	endpoint := fakeServer(t, fake)
	f.configure(endpoint, tokenA, map[string]any{"token_expires_on": time.Now().AddDate(0, 0, 20).Format("2006-01-02")})

	out := f.test()
	if out["ok"] != true {
		t.Fatalf("test: %v", out)
	}
	v := f.status()
	if v.State != StateConnected || v.StateLabel != "Connected" || v.ToolCount != len(DocumentedReadTools) || !v.ToolsCurrent {
		t.Fatalf("status %+v", v)
	}
	if v.PermissionMode != ModeReadOnly || v.Server == nil || v.Server.Name != "fortik-local-fake-quickstart" || v.Server.ProtocolVersion != "2025-06-18" {
		t.Fatalf("server/mode %+v %+v", v.Server, v.PermissionMode)
	}
	if v.LastSuccessAt == nil || v.LastToolsSyncAt == nil || v.Token.DaysLeft == nil || *v.Token.DaysLeft != 20 || v.Token.Warning != "" {
		t.Fatalf("times/token %+v %+v", v.LastSuccessAt, v.Token)
	}
	for _, tool := range v.Tools {
		if tool.DocumentedAccess != DocReadOnlyToken || len(tool.InputSchema) == 0 {
			t.Fatalf("tool %+v", tool)
		}
	}
	// The real protocol ran, with Fortik's token upstream, and no tool was called.
	calls := fake.Calls()
	if calls["initialize"] != 1 || calls["notifications/initialized"] != 1 || calls["tools/list"] != 3 || calls["tools/call"] != 0 {
		t.Fatalf("calls %v", calls)
	}
	for _, h := range fake.AuthHeaders() {
		if h != "Bearer "+tokenA {
			t.Fatalf("upstream auth %q", h)
		}
	}
	ev := f.events(EventToolsChanged)
	if len(ev) != 1 || ev[0]["first_discovery"] != true || ev[0]["system"] != "netsuite" || ev[0]["transport"] != "mcp" || ev[0]["permission_mode"] != ModeReadOnly {
		t.Fatalf("diary %v", ev)
	}

	// A second check with the same tools records no tool change.
	f.test()
	if n := len(f.events(EventToolsChanged)); n != 1 {
		t.Fatalf("%d tool-change events", n)
	}

	// Rotate to a read-write token: the old result no longer describes the settings.
	fake.Token, fake.ReadWrite = tokenB, true
	f.configure(endpoint, tokenB, nil)
	v = f.status()
	if v.State != StateSavedNotTested || v.LastCheckedState != StateConnected || v.ToolsCurrent || !strings.Contains(v.PermissionBasis, "last successful check") {
		t.Fatalf("after rotate %+v", v)
	}
	if code, out := f.do("POST", "/v1/saas/netsuite_quickstart/refresh", "security", nil); code != 200 || out["ok"] != true {
		t.Fatalf("refresh %d %v", code, out)
	}
	v = f.status()
	if v.State != StateConnected || v.PermissionMode != ModeReadWrite || v.ToolCount != len(DocumentedReadTools)+len(DocumentedWriteTools) {
		t.Fatalf("after refresh %+v", v)
	}
	ev = f.events(EventToolsChanged)
	if len(ev) != 2 || len(ev[1]["added"].([]any)) != len(DocumentedWriteTools) || ev[1]["permission_mode"] != ModeReadWrite {
		t.Fatalf("diary after rotate %v", ev)
	}
	_, statusOut := f.do("GET", "/v1/saas/netsuite_quickstart", "auditor", nil)
	_, listOut := f.do("GET", "/v1/integrations/netsuite_quickstart", "auditor", nil)
	f.noTokenAnywhere(statusOut, listOut, out)

	// Disconnect: secret and learned state are gone; the Diary keeps the record.
	if code, out := f.do("DELETE", "/v1/integrations/netsuite_quickstart", "security", nil); code != 200 {
		t.Fatalf("delete %d %v", code, out)
	}
	if v := f.status(); v.State != StateNotConfigured || len(v.Tools) != 0 {
		t.Fatalf("after delete %+v", v)
	}
	var n int
	_ = f.pool.QueryRow(context.Background(), `SELECT count(*) FROM mcp_connections`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d mcp_connections rows after delete", n)
	}
	if _, err := f.sec.Get(context.Background(), integrations.SecretName(IntegrationKey, "personal_access_token")); err == nil {
		t.Fatal("token still in the secret store")
	}
	if ev := f.events(EventForgotten); len(ev) != 1 || !strings.Contains(ev[0]["note"].(string), "not revoked") {
		t.Fatalf("forgotten %v", ev)
	}
	f.noTokenAnywhere()
}

func TestFailureStates(t *testing.T) {
	malformedTool := json.RawMessage(`{"name":"broken","inputSchema":{"type":"array"}}`)
	cases := []struct {
		name  string
		fake  *mcpfake.Server
		token string
		state string
	}{
		{"wrong token", &mcpfake.Server{Token: tokenA}, tokenB, StateAuthFailed},
		{"expired token", &mcpfake.Server{Token: tokenA, ExpiredToken: true}, tokenA, StateTokenExpired},
		{"forbidden", &mcpfake.Server{Token: tokenA, InitStatus: 403, InitBody: "MCP server access denied"}, tokenA, StatePermission},
		{"unavailable", &mcpfake.Server{Token: tokenA, InitStatus: 503}, tokenA, StateUnavailable},
		{"init refused", &mcpfake.Server{Token: tokenA, InitRPCError: true}, tokenA, StateInitFailed},
		{"discovery refused", &mcpfake.Server{Token: tokenA, ToolsRPCError: true}, tokenA, StateDiscoveryFailed},
		{"discovery malformed", &mcpfake.Server{Token: tokenA, ToolsMalformed: true}, tokenA, StateDiscoveryFailed},
		{"malformed tool", &mcpfake.Server{Token: tokenA, ExtraTools: []json.RawMessage{malformedTool}}, tokenA, StateConnectedLimit},
		{"no tools capability", &mcpfake.Server{Token: tokenA, NoToolsCap: true}, tokenA, StateConnectedLimit},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, loopback())
			f.configure(fakeServer(t, c.fake), c.token, nil)
			out := f.test()
			v := f.status()
			if v.State != c.state || out["ok"] != false {
				t.Fatalf("state %s (%s), ok %v; want %s", v.State, v.Detail, out["ok"], c.state)
			}
			integ := out["integration"].(map[string]any)
			if integ["status"] != integrations.StatusError || !strings.HasPrefix(integ["last_error"].(string), stateLabels[c.state]) {
				t.Fatalf("integration %v", integ)
			}
			if c.state == StateConnectedLimit {
				if v.ToolCount == 0 && !c.fake.NoToolsCap || v.LastToolsSyncAt == nil {
					t.Fatalf("limited %+v", v)
				}
				if c.fake.ExtraTools != nil && len(v.Rejected) != 1 {
					t.Fatalf("rejected %v", v.Rejected)
				}
			} else if v.LastSuccessAt != nil || len(v.Tools) != 0 {
				t.Fatalf("failure recorded tools: %+v", v)
			}
			f.noTokenAnywhere(out)
		})
	}
}

func TestFailedCheckKeepsLastKnownTools(t *testing.T) {
	f := newFixture(t, loopback())
	fake := &mcpfake.Server{Token: tokenA}
	f.configure(fakeServer(t, fake), tokenA, nil)
	f.test()
	fake.InitStatus = 503
	f.test()
	v := f.status()
	if v.State != StateUnavailable || v.ToolCount != len(DocumentedReadTools) || v.ToolsCurrent || v.LastSuccessAt == nil {
		t.Fatalf("%+v", v)
	}
}

func TestEndpointPolicy(t *testing.T) {
	// Loopback not allowed (production default): the fake is never contacted.
	f := newFixture(t, config.MCPUpstreamsConfig{AllowedHosts: []string{"my.quickstartapi.netsuite.com"}})
	fake := &mcpfake.Server{Token: tokenA}
	f.configure(fakeServer(t, fake), tokenA, nil)
	f.test()
	if v := f.status(); v.State != StateNotPermitted || v.EndpointPermitted || len(fake.AuthHeaders()) != 0 {
		t.Fatalf("loopback: %+v, %d requests", v, len(fake.AuthHeaders()))
	}

	// A host outside the allow list.
	f.configure("https://attacker.example.com/mcp", "", nil)
	f.test()
	if v := f.status(); v.State != StateNotPermitted || !strings.Contains(v.Detail, "allowed_hosts") {
		t.Fatalf("other host: %+v", v)
	}

	// An allowed host that resolves to an internal address (DNS rebinding).
	f.svc.lookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.1.2.3")}}, nil
	}
	f.configure("https://my.quickstartapi.netsuite.com/mcp", "", nil)
	f.test()
	if v := f.status(); v.State != StateNotPermitted || !strings.Contains(v.Detail, "non-public") {
		t.Fatalf("rebinding: %+v", v)
	}
	for _, ip := range []string{"127.0.0.1", "169.254.169.254", "192.168.1.1", "100.64.0.1", "::1", "fd00::1", "0.0.0.0"} {
		if f.svc.addressRefused(net.ParseIP(ip)) == "" {
			t.Errorf("%s permitted", ip)
		}
	}
	if r := f.svc.addressRefused(net.ParseIP("23.54.82.167")); r != "" {
		t.Errorf("public address refused: %s", r)
	}
}

func TestValidation(t *testing.T) {
	f := newFixture(t, loopback())
	bad := []map[string]any{
		{"config": map[string]any{"tenant_label": "x", "endpoint_url": "http://example.com/mcp"}, "secrets": map[string]any{"personal_access_token": tokenA}},
		{"config": map[string]any{"tenant_label": "x", "endpoint_url": "https://my.quickstartapi.netsuite.com"}, "secrets": map[string]any{"personal_access_token": tokenA}},
		{"config": map[string]any{"tenant_label": "x"}, "secrets": map[string]any{"personal_access_token": "Bearer " + tokenA}},
		{"config": map[string]any{"tenant_label": "x"}, "secrets": map[string]any{"personal_access_token": "short"}},
		{"config": map[string]any{"tenant_label": "x", "token_expires_on": "2026-13-40"}, "secrets": map[string]any{"personal_access_token": tokenA}},
		{"config": map[string]any{"tenant_label": "x", "transport": "sse"}, "secrets": map[string]any{"personal_access_token": tokenA}},
		{"config": map[string]any{}, "secrets": map[string]any{"personal_access_token": tokenA}},
	}
	for i, b := range bad {
		code, out := f.do("PUT", "/v1/integrations/netsuite_quickstart", "security", b)
		if code != 400 {
			t.Errorf("case %d: %d %v", i, code, out)
		}
		f.noTokenAnywhere(out)
	}
	// Defaults: the documented endpoint, Streamable HTTP, personal access token.
	code, out := f.do("PUT", "/v1/integrations/netsuite_quickstart", "security",
		map[string]any{"config": map[string]any{"tenant_label": "Acme"}, "secrets": map[string]any{"personal_access_token": tokenA}})
	if code != 200 {
		t.Fatalf("%d %v", code, out)
	}
	cfg := out["config"].(map[string]any)
	if cfg["endpoint_url"] != integrations.QuickStartEndpoint || cfg["transport"] != "streamable_http" || cfg["auth_type"] != "personal_access_token" || cfg["name"] != "NetSuite QuickStart" {
		t.Fatalf("defaults %v", cfg)
	}
	if out["secrets"].(map[string]any)["personal_access_token"].(map[string]any)["set"] != true {
		t.Fatalf("secret state %v", out["secrets"])
	}
	f.noTokenAnywhere(out)
}

func TestAuthorization(t *testing.T) {
	f := newFixture(t, loopback())
	if code, _ := f.do("GET", "/v1/saas/netsuite_quickstart", "", nil); code != 401 {
		t.Fatalf("anonymous status: %d", code)
	}
	if code, _ := f.do("POST", "/v1/saas/netsuite_quickstart/refresh", "auditor", nil); code != 403 {
		t.Fatalf("auditor refresh: %d", code)
	}
	if code, _ := f.do("POST", "/v1/saas/netsuite_quickstart/refresh", "security", nil); code != 404 {
		t.Fatalf("refresh unconfigured: %d", code)
	}
	if code, out := f.do("GET", "/v1/saas/netsuite_quickstart", "auditor", nil); code != 200 || out["state"] != StateNotConfigured {
		t.Fatalf("auditor status: %d %v", code, out)
	}
}

func TestSchemaChangeRecorded(t *testing.T) {
	f := newFixture(t, loopback())
	fake := &mcpfake.Server{Token: tokenA, Tools: []json.RawMessage{mcpfake.Tool("read_record"), mcpfake.Tool("list_records")}}
	f.configure(fakeServer(t, fake), tokenA, nil)
	f.test()
	fake.Tools = []json.RawMessage{
		json.RawMessage(`{"name":"read_record","inputSchema":{"type":"object","properties":{"record_type":{"type":"string"},"id":{"type":"string"},"fields":{"type":"array"}}}}`),
		mcpfake.Tool("run_report"),
	}
	f.test()
	ev := f.events(EventToolsChanged)
	if len(ev) != 2 {
		t.Fatalf("%v", ev)
	}
	got := func(k string) []string {
		var out []string
		for _, x := range ev[1][k].([]any) {
			out = append(out, x.(string))
		}
		return out
	}
	if !slices.Equal(got("added"), []string{"run_report"}) || !slices.Equal(got("removed"), []string{"list_records"}) || !slices.Equal(got("schema_changed"), []string{"read_record"}) {
		t.Fatalf("diff %v", ev[1])
	}
}

func TestInferMode(t *testing.T) {
	cases := []struct {
		names []string
		want  string
	}{
		{nil, ModeUnknown},
		{[]string{"read_record", "list_records"}, ModeReadOnly},
		{[]string{"read_record", "update_record"}, ModeReadWrite},
		{[]string{"read_record", "new_tool"}, ModeUnverified},
		{[]string{"new_tool", "delete_record"}, ModeReadWrite},
	}
	for _, c := range cases {
		if got, basis := inferMode(c.names); got != c.want || basis == "" {
			t.Errorf("%v: %s (%s)", c.names, got, basis)
		}
	}
	// The fake must follow the same documented lists.
	if !slices.Equal(mcpfake.ReadOnlyTools, DocumentedReadTools) || !slices.Equal(mcpfake.WriteTools, DocumentedWriteTools) {
		t.Fatal("mcpfake tool lists differ from the documented lists")
	}
}

func TestTokenView(t *testing.T) {
	now := time.Date(2026, 10, 25, 15, 0, 0, 0, time.UTC)
	if v := tokenView(true, "", now); v.Warning == "" || v.DaysLeft != nil {
		t.Fatalf("%+v", v)
	}
	if v := tokenView(true, "2026-10-30", now); *v.DaysLeft != 5 || !strings.Contains(v.Warning, "expires soon") {
		t.Fatalf("%+v", v)
	}
	if v := tokenView(true, "2026-10-24", now); *v.DaysLeft != -1 || !strings.Contains(v.Warning, "passed") {
		t.Fatalf("%+v", v)
	}
	if v := tokenView(true, "2026-11-24", now); *v.DaysLeft != 30 || v.Warning != "" {
		t.Fatalf("%+v", v)
	}
}

func TestCheckFitsInsideHandlerTimeout(t *testing.T) {
	if CheckTimeout >= integrations.TestTimeout {
		t.Fatalf("CheckTimeout %s must be shorter than integrations.TestTimeout %s", CheckTimeout, integrations.TestTimeout)
	}
}

func TestConcurrentTestsBothRecorded(t *testing.T) {
	f := newFixture(t, loopback())
	f.configure(fakeServer(t, &mcpfake.Server{Token: tokenA}), tokenA, nil)
	done := make(chan map[string]any, 2)
	for i := 0; i < 2; i++ {
		go func() {
			_, out := f.do("POST", "/v1/integrations/netsuite_quickstart/test", "security", nil)
			done <- out
		}()
	}
	for i := 0; i < 2; i++ {
		if out := <-done; out["ok"] != true {
			t.Fatalf("concurrent test %d: %v", i, out)
		}
	}
	if v := f.status(); v.State != StateConnected {
		t.Fatalf("%+v", v)
	}
}

func TestWorkerTickAlerts(t *testing.T) {
	f := newFixture(t, loopback())
	raiser := alerts.NewPGStore(f.pool, f.diary)
	fake := &mcpfake.Server{Token: tokenA}
	f.configure(fakeServer(t, fake), tokenA, map[string]any{"token_expires_on": time.Now().AddDate(0, 0, 3).Format("2006-01-02")})
	count := func(kind string) (n, total int) {
		t.Helper()
		_ = f.pool.QueryRow(context.Background(), `SELECT count(*), COALESCE(sum(count),0) FROM alerts WHERE kind = $1`, kind).Scan(&n, &total)
		return
	}
	if err := f.svc.Tick(context.Background(), raiser); err != nil {
		t.Fatal(err)
	}
	// The background check is a real check: the card becomes Connected.
	if v := f.status(); v.State != StateConnected || fake.Calls()["initialize"] != 1 {
		t.Fatalf("after tick: %s, calls %v", v.State, fake.Calls())
	}
	if n, _ := count(AlertTokenExpiry); n != 1 {
		t.Fatalf("token expiry alerts %d", n)
	}
	if n, _ := count(AlertConnection); n != 0 {
		t.Fatal("connection alert while connected")
	}
	// The server changes its tools: recorded and alerted.
	fake.ReadWrite = true
	if err := f.svc.Tick(context.Background(), raiser); err != nil {
		t.Fatal(err)
	}
	if n, _ := count(AlertToolsChanged); n != 1 || f.status().ToolCount != len(DocumentedReadTools)+len(DocumentedWriteTools) {
		t.Fatalf("tools changed alerts %d", n)
	}
	// The token stops working: alerted once, repeats bump the same alert.
	fake.ExpiredToken = true
	for i := 0; i < 2; i++ {
		if err := f.svc.Tick(context.Background(), raiser); err != nil {
			t.Fatal(err)
		}
	}
	if n, total := count(AlertConnection); n != 1 || total != 2 {
		t.Fatalf("connection alerts %d (count %d)", n, total)
	}
	if v := f.status(); v.State != StateTokenExpired {
		t.Fatalf("state %s", v.State)
	}
	var who string
	_ = f.pool.QueryRow(context.Background(), `SELECT body_json::json->>'actor' FROM diary WHERE event_type = 'integration.tested' ORDER BY seq DESC LIMIT 1`).Scan(&who)
	if who != WorkerActor {
		t.Fatalf("background test recorded as %q", who)
	}
	f.noTokenAnywhere()
}
