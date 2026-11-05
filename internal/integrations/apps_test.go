package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLogicalIDAndConnectionKey(t *testing.T) {
	for key, want := range map[string]string{
		"netsuite": "netsuite:default", "netsuite:acme": "netsuite:acme", "netsuite_mcp:acme": "netsuite:acme",
		"netsuite_quickstart": "netsuite:quickstart", "netsuite_quickstart:eu": "netsuite:eu",
		"github": "github:default", "postgres:orders": "postgres:orders", "memory:notes": "memory:notes",
	} {
		_, id, err := LogicalID(key)
		if err != nil || id != want {
			t.Errorf("LogicalID(%s) = %q %v, want %q", key, id, err, want)
		}
	}
	for _, c := range []struct{ system, id, want string }{
		{SystemNetSuite, "netsuite:default", "netsuite"},
		{SystemNetSuite, "netsuite:acme", "netsuite:acme"},
		{SystemNetSuiteMCP, "netsuite:acme", "netsuite_mcp:acme"},
		{SystemNetSuiteQuickStart, "netsuite:quickstart", "netsuite_quickstart"},
		{SystemGitHub, "github:default", "github"},
		{SystemPostgres, "postgres:orders", "postgres:orders"},
	} {
		if got, err := ConnectionKey(c.system, c.id); err != nil || got != c.want {
			t.Errorf("ConnectionKey(%s, %s) = %q %v, want %q", c.system, c.id, got, err, c.want)
		}
	}
	for _, c := range []struct{ system, id string }{
		{SystemGitHub, "github:second"}, {SystemNetSuiteMCP, "github:x"}, {"nope", "netsuite:x"}, {SystemNetSuite, "netsuite:Bad"},
	} {
		if _, err := ConnectionKey(c.system, c.id); !errors.Is(err, ErrInvalid) {
			t.Errorf("ConnectionKey(%s, %s) accepted", c.system, c.id)
		}
	}
	// netsuite_mcp always names its tenant.
	if _, err := ParseKey("netsuite_mcp"); !errors.Is(err, ErrInvalid) {
		t.Error("netsuite_mcp without a tenant accepted")
	}
}

func nsREST(t *testing.T, account string) ConfigureInput {
	return ConfigureInput{
		Config:  raw(map[string]any{"account_id": account, "client_id": "client-1", "certificate_id": "cert-1", "algorithm": "PS256"}),
		Secrets: map[string]*string{"private_key_pem": strp(testPEM(t))},
	}
}

func nsMCP(account string) ConfigureInput {
	return ConfigureInput{Config: raw(map[string]any{"account_id": account, "client_id": "public-client"})}
}

func qsInput(label string) ConfigureInput {
	return ConfigureInput{Config: raw(map[string]any{"tenant_label": label}), Secrets: map[string]*string{"personal_access_token": strp("qs-token-0123456789")}}
}

func appCount(t *testing.T, f fixture) int {
	t.Helper()
	var n int
	if err := f.pool.QueryRow(context.Background(), `SELECT count(*) FROM app_integrations`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAppIntegrationLinking(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	in, err := f.store.Configure(ctx, "netsuite:acme", nsREST(t, "1234567"), actor)
	if err != nil {
		t.Fatal(err)
	}
	if in.IntegrationID != "netsuite:acme" || in.Transport != TransportREST {
		t.Fatalf("REST connection: %+v", in)
	}
	a, err := f.store.GetApp(ctx, "netsuite:acme")
	if err != nil || a.TenantRef != "1234567" || a.Environment != EnvNetSuiteFull || a.CreatedExplicitly {
		t.Fatalf("implicit integration: %+v %v", a, err)
	}
	// The second transport joins the same integration: no duplicate.
	m, err := f.store.Configure(ctx, "netsuite_mcp:acme", nsMCP("1234567"), actor)
	if err != nil {
		t.Fatal(err)
	}
	if m.IntegrationID != "netsuite:acme" || m.Transport != TransportMCP || appCount(t, f) != 1 {
		t.Fatalf("MCP connection: %+v (%d integrations)", m, appCount(t, f))
	}
	conns, _ := f.store.ConnectionsOf(ctx, "netsuite:acme")
	if len(conns) != 2 {
		t.Fatalf("connections: %d", len(conns))
	}
	if c, err := f.store.ConnectionFor(ctx, "netsuite:acme", TransportMCP); err != nil || c.Key != "netsuite_mcp:acme" {
		t.Fatalf("ConnectionFor: %+v %v", c, err)
	}

	// Another account cannot join this integration, and the refusal comes
	// before any secret is replaced.
	before, _ := f.sec.Get(ctx, "integration/netsuite:acme/private_key_pem")
	if _, err := f.store.Configure(ctx, "netsuite:acme", nsREST(t, "7654321"), actor); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "same account") {
		t.Fatalf("account change: %v", err)
	}
	if after, _ := f.sec.Get(ctx, "integration/netsuite:acme/private_key_pem"); string(after) != string(before) {
		t.Fatal("a refused configuration replaced the private key")
	}
	if _, err := f.store.Configure(ctx, "netsuite_mcp:acme", nsMCP("7654321"), actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("MCP account change: %v", err)
	}
	// An account belongs to one integration only.
	if _, err := f.store.Configure(ctx, "netsuite_mcp:other", nsMCP("1234567"), actor); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "netsuite:acme") {
		t.Fatalf("second integration for the same account: %v", err)
	}
	// A QuickStart connection cannot join a full account's integration.
	if _, err := f.store.Configure(ctx, "netsuite_quickstart:acme", qsInput("Acme"), actor); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "QuickStart") {
		t.Fatalf("QuickStart into a full account: %v", err)
	}
	// QuickStart labels are names, not identities: two tenants may share one.
	if _, err := f.store.Configure(ctx, "netsuite_quickstart", qsInput("Test"), actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Configure(ctx, "netsuite_quickstart:second", qsInput("Test"), actor); err != nil {
		t.Fatalf("second QuickStart with the same label: %v", err)
	}
	// One connection per transport: the legacy key and its explicit form are
	// the same integration and the same transport.
	if _, err := f.store.Configure(ctx, "netsuite_quickstart:quickstart", qsInput("Test"), actor); !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "already has a mcp connection") {
		t.Fatalf("second MCP connection: %v", err)
	}
	if len(diaryBodies(t, f.diary, EventConfigured)) == 0 || diaryBodies(t, f.diary, EventConfigured)[0]["integration_id"] == nil {
		t.Fatal("integration.configured lacks integration_id")
	}

	// Removing one transport keeps the integration; the last removes an
	// implicitly created one.
	if _, err := f.store.Disconnect(ctx, "netsuite_mcp:acme", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetApp(ctx, "netsuite:acme"); err != nil {
		t.Fatalf("integration removed with one of two connections: %v", err)
	}
	if _, err := f.store.Disconnect(ctx, "netsuite:acme", actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.GetApp(ctx, "netsuite:acme"); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("implicit integration kept without connections: %v", err)
	}
}

func TestAppIntegrationExplicitLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	for _, bad := range []CreateAppInput{
		{Provider: "nope", Environment: "full", Name: "x", DisplayName: "X"},
		{Provider: "netsuite", Environment: "sandbox", Name: "x", DisplayName: "X"},
		{Provider: "netsuite", Environment: "full", Name: "Bad-Name", DisplayName: "X"},
		{Provider: "netsuite", Environment: "full", Name: "x", DisplayName: ""},
		{Provider: "netsuite", Environment: "full", Name: "x", DisplayName: "X", TenantRef: "not an account"},
	} {
		if _, err := f.store.CreateApp(ctx, bad, actor); !errors.Is(err, ErrInvalid) {
			t.Errorf("CreateApp(%+v) accepted: %v", bad, err)
		}
	}
	a, err := f.store.CreateApp(ctx, CreateAppInput{Provider: "netsuite", Environment: "full", Name: "globex", TenantRef: "7654321", DisplayName: "Globex"}, actor)
	if err != nil || a.IntegrationID != "netsuite:globex" || !a.CreatedExplicitly {
		t.Fatalf("create: %+v %v", a, err)
	}
	if _, err := f.store.CreateApp(ctx, CreateAppInput{Provider: "netsuite", Environment: "full", Name: "globex", DisplayName: "Again"}, actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate id: %v", err)
	}
	if _, err := f.store.CreateApp(ctx, CreateAppInput{Provider: "netsuite", Environment: "full", Name: "globex2", TenantRef: "7654321", DisplayName: "Dup"}, actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate account: %v", err)
	}
	// Its connections must name its account.
	if _, err := f.store.Configure(ctx, "netsuite_mcp:globex", nsMCP("1234567"), actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("wrong account: %v", err)
	}
	if _, err := f.store.Configure(ctx, "netsuite_mcp:globex", nsMCP("7654321"), actor); err != nil {
		t.Fatal(err)
	}
	if err := f.store.DeleteApp(ctx, "netsuite:globex", actor); !errors.Is(err, ErrHasConnections) {
		t.Fatalf("delete with connections: %v", err)
	}
	if _, err := f.store.UpdateApp(ctx, "netsuite:globex", "Globex Corp", actor); err != nil {
		t.Fatal(err)
	}
	// An explicitly created integration outlives its last connection.
	if _, err := f.store.Disconnect(ctx, "netsuite_mcp:globex", actor); err != nil {
		t.Fatal(err)
	}
	if a, err := f.store.GetApp(ctx, "netsuite:globex"); err != nil || a.DisplayName != "Globex Corp" {
		t.Fatalf("explicit integration: %+v %v", a, err)
	}
	if err := f.store.DeleteApp(ctx, "netsuite:globex", actor); err != nil {
		t.Fatal(err)
	}
	for _, ev := range []string{EventAppCreated, EventAppUpdated, EventAppDeleted} {
		if len(diaryBodies(t, f.diary, ev)) != 1 {
			t.Errorf("Diary %s missing", ev)
		}
	}
}

func TestDisconnectHooks(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	var seen []string
	f.store.OnBeforeDelete(func(_ context.Context, key, _ string) string {
		seen = append(seen, key)
		if key == "netsuite_mcp:acme" {
			return "grant revoked"
		}
		return ""
	})
	if _, err := f.store.Configure(ctx, "netsuite_mcp:acme", nsMCP("1234567"), actor); err != nil {
		t.Fatal(err)
	}
	notes, err := f.store.Disconnect(ctx, "netsuite_mcp:acme", actor)
	if err != nil || len(notes) != 1 || notes[0] != "grant revoked" {
		t.Fatalf("notes %v %v", notes, err)
	}
	if _, err := f.store.Disconnect(ctx, "netsuite_mcp:acme", actor); !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("second disconnect: %v", err)
	}
	if len(seen) != 1 {
		t.Fatalf("hook ran %d times", len(seen))
	}
}

func TestAppIntegrationsHTTP(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	h := NewHandler(f.store, NewRegistry(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	mux := http.NewServeMux()
	h.Register(mux)
	srv := httptest.NewServer(withTestPrincipal(mux))
	defer srv.Close()
	c := apiClient{t: t, url: srv.URL}

	if code, _ := c.do("GET", "/v1/app-integrations", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated: %d", code)
	}
	body := map[string]any{"provider": "netsuite", "environment": "full", "name": "acme", "tenant_ref": "1234567", "display_name": "Acme"}
	if code, _ := c.do("POST", "/v1/app-integrations", "auditor", body); code != http.StatusForbidden {
		t.Fatalf("auditor create: %d", code)
	}
	if code, out := c.do("POST", "/v1/app-integrations", "security", body); code != http.StatusCreated {
		t.Fatalf("create: %d %s", code, out)
	}
	if _, err := f.store.Configure(ctx, "netsuite:acme", nsREST(t, "1234567"), actor); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Configure(ctx, "netsuite_quickstart", qsInput("Acme QS"), actor); err != nil {
		t.Fatal(err)
	}
	code, out := c.do("GET", "/v1/app-integrations", "auditor", nil)
	if code != 200 {
		t.Fatalf("list: %d %s", code, out)
	}
	var list struct {
		Integrations []AppView      `json:"integrations"`
		Providers    []ProviderInfo `json:"providers"`
	}
	if err := json.Unmarshal([]byte(out), &list); err != nil {
		t.Fatal(err)
	}
	views := map[string]AppView{}
	for _, v := range list.Integrations {
		views[v.IntegrationID] = v
	}
	acme, qs := views["netsuite:acme"], views["netsuite:quickstart"]
	if len(acme.Connections) != 1 || acme.Health != HealthUntested || len(acme.Transports) != 2 {
		t.Fatalf("acme: %+v", acme)
	}
	for _, tv := range acme.Transports {
		switch tv.Transport {
		case TransportREST:
			if !tv.Configured || tv.ConnectionKey != "netsuite:acme" {
				t.Errorf("acme REST: %+v", tv)
			}
		case TransportMCP:
			// MCP is offered but not configured: working REST is no proof of MCP.
			if tv.Configured || tv.ConnectionKey != "netsuite_mcp:acme" || !tv.Available {
				t.Errorf("acme MCP: %+v", tv)
			}
		}
	}
	for _, tv := range qs.Transports {
		// QuickStart has no REST API: shown unavailable with a reason, and
		// working MCP is no proof of REST.
		if tv.Transport == TransportREST && (tv.Available || tv.Configured || tv.Reason == "") {
			t.Errorf("QuickStart REST: %+v", tv)
		}
	}
	if qs.Environment != EnvNetSuiteQuickStart || len(list.Providers) == 0 {
		t.Fatalf("quickstart: %+v", qs)
	}
	// Activity of one tenant only.
	if _, err := f.pool.Exec(ctx, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason, target, ts) VALUES
		('act_1', 'bot', 'netsuite', 'READ', 'h1', 'green', 'allow', 'POL-1000', 'r', '{"transport":"rest_api","integration_id":"netsuite:acme","operation":"get"}', now()),
		('act_2', 'bot', 'netsuite', 'READ', 'h2', 'green', 'deny', 'POL-1010', 'r', '{"transport":"mcp","integration_id":"netsuite:acme","tool":"read_record"}', now()),
		('act_3', 'bot', 'netsuite', 'READ', 'h3', 'green', 'allow', 'POL-1000', 'r', '{"transport":"mcp","integration_id":"netsuite:quickstart","tool":"read_record"}', now())`); err != nil {
		t.Fatal(err)
	}
	code, out = c.do("GET", "/v1/app-integrations/netsuite:acme/activity", "auditor", nil)
	var act AppActivity
	_ = json.Unmarshal([]byte(out), &act)
	if code != 200 || act.ByTransport["rest_api"]["allow"] != 1 || act.ByTransport["mcp"]["deny"] != 1 || len(act.Recent) != 2 {
		t.Fatalf("activity: %d %s", code, out)
	}
	// Rename; delete refused while connected.
	if code, _ := c.do("PATCH", "/v1/app-integrations/netsuite:acme", "security", map[string]any{"display_name": "Acme Corp"}); code != 200 {
		t.Fatalf("rename: %d", code)
	}
	if code, _ := c.do("DELETE", "/v1/app-integrations/netsuite:acme", "security", nil); code != http.StatusConflict {
		t.Fatalf("delete with a connection: %d", code)
	}
	if code, _ := c.do("GET", "/v1/app-integrations/netsuite:nosuch", "auditor", nil); code != http.StatusNotFound {
		t.Fatalf("unknown: %d", code)
	}
}

func TestSaaSProvidersOneTenantPerOrg(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rest := ConfigureInput{Config: raw(map[string]any{"instance_url": "https://acme.my.salesforce.com", "client_id": "c1"}),
		Secrets: map[string]*string{"client_secret": strp("s1-secret")}}
	in, err := f.store.Configure(ctx, "salesforce:acme", rest, actor)
	if err != nil || in.IntegrationID != "salesforce:acme" || in.Transport != TransportREST {
		t.Fatalf("REST: %+v %v", in, err)
	}
	mcp := func(instance string) ConfigureInput {
		return ConfigureInput{Config: raw(map[string]any{"endpoint_url": "https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads",
			"instance_url": instance, "client_id": "c1"})}
	}
	// The MCP connection must name the same org (My Domain) as REST.
	if _, err := f.store.Configure(ctx, "salesforce_mcp:acme", mcp("https://other.my.salesforce.com"), actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("another org accepted: %v", err)
	}
	if in, err := f.store.Configure(ctx, "salesforce_mcp:acme", mcp("https://ACME.my.salesforce.com/"), actor); err != nil || in.Transport != TransportMCP {
		t.Fatalf("same org: %+v %v", in, err)
	}
	if a, _ := f.store.GetApp(ctx, "salesforce:acme"); a.TenantRef != "acme.my.salesforce.com" || a.Environment != "" {
		t.Fatalf("tenant: %+v", a)
	}
	// One org, one tenant.
	if _, err := f.store.Configure(ctx, "salesforce:dup", rest, actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("second tenant for the same org: %v", err)
	}
	// ServiceNow MCP: the tenant is the instance serving it.
	if _, err := f.store.Configure(ctx, "servicenow_mcp", ConfigureInput{Config: raw(map[string]any{
		"endpoint_url": "https://acme.service-now.com/sncapps/mcp-server/mcp/sn_mcp_server_default", "auth_type": "bearer_token"})}, actor); err != nil {
		t.Fatal(err)
	}
	if a, _ := f.store.GetApp(ctx, "servicenow:default"); a.TenantRef != "acme.service-now.com" {
		t.Fatalf("servicenow tenant: %+v", a)
	}
	// Auth-dependent fields are checked at save time.
	if _, err := f.store.Configure(ctx, "servicenow", ConfigureInput{Config: raw(map[string]any{"instance_url": "https://acme.service-now.com", "auth_type": "basic"})}, actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("basic without a user name accepted: %v", err)
	}
	if _, err := f.store.Configure(ctx, "sap_mcp", ConfigureInput{Config: raw(map[string]any{"endpoint_url": "https://mcp.example.com/mcp", "auth_type": AuthOAuthCode, "client_id": "x"})}, actor); !errors.Is(err, ErrInvalid) {
		t.Fatalf("SAP OAuth without URLs accepted: %v", err)
	}
	// Explicit tenants take a URL or a host and keep the host.
	a, err := f.store.CreateApp(ctx, CreateAppInput{Provider: ProviderSAP, Name: "eu", TenantRef: "https://my123456-api.s4hana.cloud.sap/", DisplayName: "SAP EU"}, actor)
	if err != nil || a.TenantRef != "my123456-api.s4hana.cloud.sap" {
		t.Fatalf("sap tenant: %+v %v", a, err)
	}
	// Every provider has REST and MCP in the catalog; MCP is offered as available.
	for _, p := range []string{ProviderSalesforce, ProviderServiceNow, ProviderSAP} {
		pi, ok := providerByID(p)
		if !ok || len(pi.Environments) != 1 || len(pi.Environments[0].Transports) != 2 {
			t.Fatalf("%s catalog: %+v", p, pi)
		}
		for _, tr := range pi.Environments[0].Transports {
			if !tr.Available || tr.Verified != "test" || tr.System == "" {
				t.Errorf("%s %s: %+v", p, tr.Transport, tr)
			}
		}
	}
}
