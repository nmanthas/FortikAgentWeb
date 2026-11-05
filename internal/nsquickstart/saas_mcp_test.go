package nsquickstart

// Salesforce, ServiceNow and SAP MCP connections through the shared MCP
// transport, and one Salesforce tenant over REST (internal/saasrest) and MCP
// through one gateway. Every upstream is a LOCAL FAKE.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"fortik/internal/access"
	"fortik/internal/approvals"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/mcpclient/mcpfake"
	"fortik/internal/overrides"
	"fortik/internal/policy"
	"fortik/internal/saasrest"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

type senv struct {
	t     *testing.T
	ctx   context.Context
	ints  *integrations.PGStore
	acc   *access.PGStore
	ov    *overrides.PGStore
	svc   *Service
	gw    *httptest.Server
	api   *httptest.Server
	toks  map[string]string
	mcp   *mcpfake.Server
	oa    *mcpfake.OAuthServer
	sfURL string
	rest  int // REST record reads served
	q     func(sql string, args ...any) string
}

// newSEnv serves one fake Salesforce org on one host: OAuth
// (/services/oauth2/*), a Hosted MCP server (/platform/mcp/...) and the REST
// API (/services/data/).
func newSEnv(t *testing.T, mapped bool) *senv {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	d := diary.New(pool)
	ctl := control.NewStore(pool, d)
	acc := access.NewPGStore(pool, d)
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	enc, err := secrets.NewEncFile(t.TempDir(), k)
	if err != nil {
		t.Fatal(err)
	}
	ints := integrations.NewPGStore(pool, d, enc)
	ov := overrides.NewPGStore(pool, d, nil, log)
	und := undo.NewPGStore(pool, d)
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc}
	dec.Enrichers = []decide.Enricher{overrides.NewEnricher(ov), approvals.NewGrantEnricher(pool)}
	svc := New(pool, d, ints, config.MCPUpstreamsConfig{AllowedHosts: []string{"my.quickstartapi.netsuite.com"}, AllowLoopback: true}, "test", log)
	svc.EnableUndo(und, enc, time.Hour)
	rest := saasrest.New(pool, ints, saasrest.Guard{AllowLoopback: true}, log)
	m, err := LoadMappings(policyDir())
	if err != nil {
		t.Fatal(err)
	}
	if mapped {
		// TEST ONLY: the fake MCP server serves QuickStart-shaped tools.
		m[integrations.SystemSalesforceMCP] = m[integrations.SystemNetSuiteQuickStart]
	}
	e := &senv{t: t, ctx: ctx, ints: ints, acc: acc, ov: ov, svc: svc, toks: map[string]string{}}
	e.q = func(sql string, args ...any) string {
		var s string
		if err := pool.QueryRow(ctx, sql, args...).Scan(&s); err != nil {
			t.Fatalf("%s: %v", sql, err)
		}
		return s
	}
	hashes := map[string]string{}
	for _, agent := range []string{"bot_rw"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: agent, Type: "crm", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := ctl.SetLevel(ctx, agent, control.Full, "test", "test"); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		tok := "agt_" + hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(tok))
		hashes[agent] = hex.EncodeToString(sum[:])
		e.toks[agent] = tok
	}
	e.profile(`{"mode":"read_write","objects":["*"]}`)
	raw, _ := json.Marshal(hashes)
	gw, err := gateway.NewServer(config.GatewayConfig{}, dec, gateway.NewAgentAuth(memSecrets{"agent_tokens": raw}, "agent_tokens", log),
		rest.Adapters(), log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	NewProxy(svc, dec, m, acc, d, 10*time.Minute, log).Mount(gw.Mount)
	e.gw = httptest.NewServer(gw)
	t.Cleanup(e.gw.Close)

	reg := integrations.NewRegistry()
	for _, tt := range append(svc.Testers(), rest.Testers()...) {
		if err := reg.Register(tt); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	integrations.NewHandler(ints, reg, log).Register(mux)
	svc.Register(mux)
	rest.Register(mux)
	e.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authz.Principal{Kind: authz.KindUser, Name: "Sec", Email: "sec@acme.com", AuthMethod: "dev", Roles: map[string]bool{authz.RoleSecurity: true}}
		mux.ServeHTTP(w, r.WithContext(authz.With(r.Context(), p)))
	}))
	t.Cleanup(e.api.Close)

	e.mcp = &mcpfake.Server{Token: "nobody-yet", ReadWrite: true,
		Records: map[string]map[string]map[string]any{"customer": {"101": {"phone": "+1 555 0101", "companyName": "Acme"}}}}
	e.oa = &mcpfake.OAuthServer{MCP: e.mcp, ClientID: "sf-eca-client", ClientSecret: "sf-eca-secret-0123456789", RedirectURI: "http://127.0.0.1:9" + integrations.MCPCallbackPath,
		AuthorizePath: "/services/oauth2/authorize", TokenPath: "/services/oauth2/token", RevokePath: "/services/oauth2/revoke", MCPPrefix: "/platform/mcp/"}
	host := http.NewServeMux()
	host.Handle("/services/oauth2/", e.oa)
	host.Handle("/platform/mcp/", e.oa)
	host.HandleFunc("/services/data/", func(w http.ResponseWriter, r *http.Request) {
		tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !e.oa.ValidClientToken(tok) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/services/data/":
			_, _ = io.WriteString(w, `[{"version":"62.0"}]`)
		case r.URL.Path == "/services/data/v62.0/sobjects":
			_, _ = io.WriteString(w, `{"sobjects":[{"name":"Account","queryable":true,"updateable":true}]}`)
		case strings.HasPrefix(r.URL.Path, "/services/data/v62.0/sobjects/Account/"):
			e.rest++
			_, _ = io.WriteString(w, `{"Id":"001","Name":"Acme"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	srv := httptest.NewServer(host)
	t.Cleanup(srv.Close)
	e.sfURL = srv.URL
	return e
}

func (e *senv) profile(prof string) {
	e.t.Helper()
	if _, err := e.acc.Put(e.ctx, "bot_rw", "salesforce", json.RawMessage(prof), "user:sec@acme.com", "test"); err != nil {
		e.t.Fatal(err)
	}
}

func (e *senv) put(key string, cfg map[string]any, sec map[string]any) (int, map[string]any) {
	e.t.Helper()
	body := map[string]any{"config": cfg}
	if sec != nil {
		body["secrets"] = sec
	}
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("PUT", e.api.URL+"/v1/integrations/"+key, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *senv) post(path string) map[string]any {
	e.t.Helper()
	req, _ := http.NewRequest("POST", e.api.URL+path, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out
}

type sres struct {
	executed bool
	decision string
	rule     string
	system   string
	tenant   string
	body     string
}

func (e *senv) restCall(path, method string) sres {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.gw.URL+"/gw/salesforce"+path, nil)
	req.Header.Set("Authorization", "Bearer "+e.toks["bot_rw"])
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	r := sres{executed: res.StatusCode < 300, body: string(b)}
	e.fill(&r, res.Header.Get(gateway.ActionIDHeader))
	return r
}

func (e *senv) fill(r *sres, id string) {
	if id == "" {
		return
	}
	row := strings.Split(e.q(`SELECT decision || '|' || rule_id || '|' || system || '|' || COALESCE(target ->> 'integration_id', '') FROM actions WHERE action_id = $1`, id), "|")
	r.decision, r.rule, r.system, r.tenant = row[0], row[1], row[2], row[3]
}

func (e *senv) tool(tenant, name string, args any) sres {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": name, "arguments": args}})
	req, _ := http.NewRequest("POST", e.gw.URL+"/mcp/salesforce/"+tenant, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+e.toks["bot_rw"])
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	var out struct {
		Result struct {
			Meta    map[string]any `json:"_meta"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	_ = json.NewDecoder(res.Body).Decode(&out)
	r := sres{}
	r.executed, _ = out.Result.Meta["fortik/executed"].(bool)
	for _, c := range out.Result.Content {
		r.body += c.Text
	}
	id, _ := out.Result.Meta["fortik/action_id"].(string)
	e.fill(&r, id)
	return r
}

func (e *senv) connectBoth() {
	e.t.Helper()
	if code, out := e.put("salesforce:acme", map[string]any{"instance_url": e.sfURL, "client_id": e.oa.ClientID}, map[string]any{"client_secret": e.oa.ClientSecret}); code != 200 {
		e.t.Fatalf("REST: %d %v", code, out)
	}
	if code, out := e.put("salesforce_mcp:acme", map[string]any{"endpoint_url": e.sfURL + "/platform/mcp/v1/platform/sobject-all", "instance_url": e.sfURL,
		"client_id": e.oa.ClientID, "redirect_uri": e.oa.RedirectURI}, map[string]any{"client_secret": e.oa.ClientSecret}); code != 200 {
		e.t.Fatalf("MCP: %d %v", code, out)
	}
}

func (e *senv) authorize() {
	e.t.Helper()
	au, err := e.svc.StartOAuth(e.ctx, "salesforce_mcp:acme", "user:sec@acme.com")
	if err != nil {
		e.t.Fatal(err)
	}
	if !strings.HasPrefix(au, e.sfURL+"/services/oauth2/authorize?") || !strings.Contains(au, "scope=mcp_api+refresh_token") {
		e.t.Fatalf("authorize URL %s", au)
	}
	req, _ := http.NewRequest("GET", au, nil)
	cb := location(e.t, req).Query()
	if _, err := e.svc.CompleteOAuth(e.ctx, cb.Get("state"), cb.Get("code"), "user:sec@acme.com"); err != nil {
		e.t.Fatal(err)
	}
}

func TestSalesforceOneTenantRESTAndMCP(t *testing.T) {
	e := newSEnv(t, true)
	e.connectBoth()
	if n := e.q(`SELECT count(*)::text FROM app_integrations WHERE provider = 'salesforce'`); n != "1" {
		t.Fatalf("logical integrations: %s", n)
	}
	v, _ := e.svc.Status(e.ctx, "salesforce_mcp:acme")
	if v.State != StateAuthRequired || v.System != "salesforce" || v.IntegrationID != "salesforce:acme" || v.OAuth == nil {
		t.Fatalf("before authorization: %+v", v)
	}
	e.authorize()
	v, _ = e.svc.Status(e.ctx, "salesforce_mcp:acme")
	if v.State != StateConnected || len(v.Tools) == 0 || !v.OAuth.Authorized {
		t.Fatalf("after authorization: %s %s", v.State, v.Detail)
	}
	if out := e.post("/v1/integrations/salesforce:acme/test"); out["ok"] != true {
		t.Fatalf("REST test: %v", out)
	}

	// The same agent, the same tenant, two transports: same system, same tenant.
	r := e.restCall("/services/data/v62.0/sobjects/Account/001", "GET")
	m := e.tool("acme", "read_record", map[string]any{"recordType": "customer", "id": 101})
	if !r.executed || !m.executed || r.system != "salesforce" || m.system != "salesforce" || r.tenant != "salesforce:acme" || m.tenant != "salesforce:acme" {
		t.Fatalf("reads: REST %+v MCP %+v", r, m)
	}
	// Changes are held on both, by the same rule.
	w := e.restCall("/services/data/v62.0/sobjects/Account/001", "PATCH")
	u := e.tool("acme", "update_record", map[string]any{"recordType": "customer", "id": 101, "fieldValues": map[string]any{"phone": "x"}})
	if w.executed || u.executed || w.rule != "POL-1201" || u.rule != "POL-1201" {
		t.Fatalf("writes: REST %+v MCP %+v", w, u)
	}
	// The tenant restriction applies to both.
	e.profile(`{"mode":"read_write","objects":["*"],"integrations":["salesforce:other"]}`)
	r = e.restCall("/services/data/v62.0/sobjects/Account/001", "GET")
	m = e.tool("acme", "read_record", map[string]any{"recordType": "customer", "id": 101})
	if r.executed || m.executed || r.rule != "POL-1010" || m.rule != "POL-1010" {
		t.Fatalf("tenant restriction: REST %+v MCP %+v", r, m)
	}
	// A timed salesforce suspension stops both.
	e.profile(`{"mode":"read_write","objects":["*"]}`)
	if _, err := e.ov.Create(e.ctx, overrides.CreateRequest{Scope: overrides.ScopeAgent, ScopeID: "bot_rw", System: "salesforce", Mode: overrides.ModeSuspended,
		Duration: time.Hour, Reason: "incident"}, "user:sec@acme.com", nil); err != nil {
		t.Fatal(err)
	}
	r = e.restCall("/services/data/v62.0/sobjects/Account/001", "GET")
	m = e.tool("acme", "read_record", map[string]any{"recordType": "customer", "id": 101})
	if r.executed || m.executed || r.decision != "deny" || m.decision != "deny" {
		t.Fatalf("suspension: REST %+v MCP %+v", r, m)
	}

	// Disconnecting MCP revokes the grant and leaves REST and the tenant.
	req, _ := http.NewRequest("DELETE", e.api.URL+"/v1/integrations/salesforce_mcp:acme", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	resp.Body.Close()
	notes, _ := out["notes"].([]any)
	if len(notes) != 1 || !strings.Contains(notes[0].(string), "Salesforce MCP confirmed the revocation") || len(e.oa.Revoked()) != 1 {
		t.Fatalf("disconnect: %v", out)
	}
	if _, err := e.ints.GetApp(e.ctx, "salesforce:acme"); err != nil {
		t.Fatalf("tenant removed: %v", err)
	}
}

func TestSalesforceMCPUnmappedToolsRefused(t *testing.T) {
	e := newSEnv(t, false) // the shipped (empty) mapping
	e.connectBoth()
	e.authorize()
	m := e.tool("acme", "read_record", map[string]any{"recordType": "customer", "id": 101})
	if m.executed || m.rule != "POL-002" || m.system != "salesforce" {
		t.Fatalf("unmapped tool: %+v", m)
	}
	if n := len(e.mcp.ToolCalls()); n != 0 {
		t.Fatalf("an unmapped tool reached the server (%d calls)", n)
	}
	if v, _ := e.svc.Status(e.ctx, "salesforce_mcp:acme"); v.MappedTools != 0 || !strings.Contains(strings.Join(v.KnownGaps, " "), "No tool of this server is mapped") {
		t.Fatalf("status: %d %v", v.MappedTools, v.KnownGaps)
	}
	// An unknown tenant endpoint is refused.
	if x := e.tool("nosuch", "read_record", map[string]any{}); x.executed || !strings.Contains(x.body, "has no MCP connection") {
		t.Fatalf("unknown tenant: %+v", x)
	}
}

func TestServiceNowMCPClientCredentialsAndSAPBearer(t *testing.T) {
	f := newFixture(t, loopback())
	f.svc.SetSecrets(f.sec)
	// ServiceNow: client credentials against the instance's /oauth_token.do.
	mcp := &mcpfake.Server{Token: "nobody"}
	oa := &mcpfake.OAuthServer{MCP: mcp, ClientID: "sn-client", ClientSecret: "sn-secret-0123456789", TokenPath: "/oauth_token.do", MCPPrefix: "/sncapps/",
		ClientCredsForMCP: true}
	sn := httptest.NewServer(oa)
	t.Cleanup(sn.Close)
	cfg := map[string]any{"config": map[string]any{"endpoint_url": sn.URL + "/sncapps/mcp-server/mcp/sn_mcp_server_default", "auth_type": "oauth_client_credentials",
		"client_id": "sn-client"}, "secrets": map[string]any{"client_secret": "sn-secret-0123456789"}}
	if code, out := f.do("PUT", "/v1/integrations/servicenow_mcp", "security", cfg); code != 200 {
		t.Fatalf("configure: %d %v", code, out)
	}
	f.do("POST", "/v1/integrations/servicenow_mcp/test", "security", nil)
	v, _ := f.svc.Status(context.Background(), "servicenow_mcp")
	if v.State != StateConnected || v.System != "servicenow" || v.IntegrationID != "servicenow:default" || !v.Token.Set || oa.Issued() != 1 {
		t.Fatalf("servicenow: %s %s", v.State, v.Detail)
	}
	if _, err := f.svc.StartOAuth(context.Background(), "servicenow_mcp", "user:sec"); !errors.Is(err, integrations.ErrInvalid) {
		t.Fatalf("authorization started for a client credentials connection: %v", err)
	}
	code, out := f.do("DELETE", "/v1/integrations/servicenow_mcp", "security", nil)
	if notes, _ := out["notes"].([]any); code != 200 || len(notes) != 1 || !strings.Contains(notes[0].(string), "stays valid") {
		t.Fatalf("disconnect: %d %v", code, out)
	}

	// SAP: a customer-managed server with a bearer token.
	sap := &mcpfake.Server{Token: "sap-bearer-token-0123456789"}
	sapURL := fakeServer(t, sap)
	if code, out := f.do("PUT", "/v1/integrations/sap_mcp", "security", map[string]any{"config": map[string]any{"endpoint_url": sapURL},
		"secrets": map[string]any{"access_token": "sap-bearer-token-0123456789"}}); code != 200 {
		t.Fatalf("configure sap: %d %v", code, out)
	}
	f.do("POST", "/v1/integrations/sap_mcp/test", "security", nil)
	if v, _ := f.svc.Status(context.Background(), "sap_mcp"); v.State != StateConnected || v.System != "sap" || v.AuthType != AuthBearer {
		t.Fatalf("sap: %s %s", v.State, v.Detail)
	}
	// Without loopback, a host outside mcp_upstreams.allowed_hosts is refused.
	strict := newFixture(t, config.MCPUpstreamsConfig{AllowedHosts: []string{"my.quickstartapi.netsuite.com"}})
	strict.svc.SetSecrets(strict.sec)
	strict.do("PUT", "/v1/integrations/sap_mcp", "security", map[string]any{"config": map[string]any{"endpoint_url": "https://mcp.sap-partner.example/mcp"},
		"secrets": map[string]any{"access_token": "sap-bearer-token-0123456789"}})
	strict.do("POST", "/v1/integrations/sap_mcp/test", "security", nil)
	if v, _ := strict.svc.Status(context.Background(), "sap_mcp"); v.State != StateNotPermitted || !strings.Contains(v.Detail, "allowed_hosts") {
		t.Fatalf("strict: %s %s", v.State, v.Detail)
	}
	// Salesforce's own MCP host is permitted without configuration.
	if r := strict.svc.endpointRefused(context.Background(), "https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads", integrations.SystemSalesforceMCP); strings.Contains(r, "allowed_hosts") {
		t.Fatalf("api.salesforce.com refused: %s", r)
	}
	f.noTokenAnywhere()
}
