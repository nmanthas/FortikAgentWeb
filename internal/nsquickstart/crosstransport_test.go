package nsquickstart

// One NetSuite tenant reached over REST (SuiteTalk) and over MCP (the AI
// Connector Service) through ONE gateway and ONE decision pipeline. Both
// upstreams are LOCAL FAKES (internal/netsuite/fakens and mcpfake): these
// tests prove Fortik applies the same identity, profile, suspension, kill
// and tenant restriction whichever transport an agent uses, not anything
// about NetSuite.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

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
	"fortik/internal/netsuite"
	"fortik/internal/netsuite/fakens"
	"fortik/internal/overrides"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

const (
	acme   = "netsuite:acme"
	globex = "netsuite:globex"
)

type xenv struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	ctl  *control.Store
	acc  *access.PGStore
	ints *integrations.PGStore
	ov   *overrides.PGStore
	svc  *Service
	rest *fakens.Fake
	mcp  *mcpfake.Server
	oa   *mcpfake.OAuthServer
	gw   *httptest.Server
	api  *httptest.Server
	toks map[string]string
}

func newXEnv(t *testing.T) *xenv {
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
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	enc, err := secrets.NewEncFile(t.TempDir(), key)
	if err != nil {
		t.Fatal(err)
	}
	ints := integrations.NewPGStore(pool, d, enc)
	und := undo.NewPGStore(pool, d)
	ov := overrides.NewPGStore(pool, d, nil, log)
	dec := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc}
	dec.Enrichers = []decide.Enricher{overrides.NewEnricher(ov), approvals.NewGrantEnricher(pool)}

	svc := New(pool, d, ints, config.MCPUpstreamsConfig{AllowedHosts: []string{"my.quickstartapi.netsuite.com"}, AllowLoopback: true}, "test", log)
	svc.EnableUndo(und, enc, time.Hour)
	m, err := LoadMappings(policyDir())
	if err != nil {
		t.Fatal(err)
	}
	// TEST ONLY: the fake AI Connector serves QuickStart-shaped tools, so they
	// are mapped like QuickStart's. Fortik ships no AI Connector mapping.
	m[integrations.SystemNetSuiteMCP] = m[integrations.SystemNetSuiteQuickStart]
	ad, err := netsuite.NewAdapter(ints, netsuite.NewClient(nil), und, enc, 0, log)
	if err != nil {
		t.Fatal(err)
	}
	e := &xenv{t: t, ctx: ctx, pool: pool, ctl: ctl, acc: acc, ints: ints, ov: ov, svc: svc, toks: map[string]string{}}

	hashes := map[string]string{}
	for _, agent := range []string{"bot_rw", "bot_ro"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: agent, Type: "erp", Sponsor: "jane@acme.com"}, "test"); err != nil {
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
	e.profile("bot_rw", `{"mode":"read_write","record_types":["*"],"suiteql":false}`)
	e.profile("bot_ro", `{"mode":"read_only","record_types":["*"],"suiteql":false}`)
	raw, _ := json.Marshal(hashes)
	gw, err := gateway.NewServer(config.GatewayConfig{}, dec, gateway.NewAgentAuth(memSecrets{"agent_tokens": raw}, "agent_tokens", log),
		[]gateway.Adapter{ad}, log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	NewProxy(svc, dec, m, acc, d, 10*time.Minute, log).Mount(gw.Mount)
	e.gw = httptest.NewServer(gw)
	t.Cleanup(e.gw.Close)

	mux := http.NewServeMux()
	reg := integrations.NewRegistry()
	for _, tt := range svc.Testers() {
		if err := reg.Register(tt); err != nil {
			t.Fatal(err)
		}
	}
	integrations.NewHandler(ints, reg, nil).Register(mux)
	e.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authz.Principal{Kind: authz.KindUser, Name: "Sec", Email: "sec@acme.com", AuthMethod: "dev", Roles: map[string]bool{authz.RoleSecurity: true}}
		mux.ServeHTTP(w, r.WithContext(authz.With(r.Context(), p)))
	}))
	t.Cleanup(e.api.Close)

	// REST: the fake SuiteTalk account (OAuth 2.0 client credentials).
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	keyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	e.rest = fakens.New("fortik-client-id", "cert-123", &rk.PublicKey)
	rs := httptest.NewServer(e.rest)
	t.Cleanup(rs.Close)
	e.rest.BaseURL = rs.URL
	q := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	if _, err := ints.Configure(ctx, "netsuite:acme", integrations.ConfigureInput{
		Config: map[string]json.RawMessage{"account_id": q("1234567"), "client_id": q("fortik-client-id"), "certificate_id": q("cert-123"),
			"algorithm": q("PS256"), "api_base": q(rs.URL)},
		Secrets: map[string]*string{"private_key_pem": &keyPEM},
	}, "user:sec@acme.com"); err != nil {
		t.Fatalf("configure REST: %v", err)
	}

	// MCP: the fake AI Connector Service behind the fake OAuth endpoints.
	e.mcp = &mcpfake.Server{Token: "nobody-yet", ReadWrite: true,
		Records: map[string]map[string]map[string]any{"customer": {"101": {"phone": "+1 555 0101", "companyName": "Acme Retail"}}}}
	e.oa = &mcpfake.OAuthServer{MCP: e.mcp, ClientID: "fortik-public-client", RedirectURI: "http://127.0.0.1:9/v1/oauth/netsuite/callback"}
	ns := httptest.NewServer(e.oa)
	t.Cleanup(ns.Close)
	if _, err := ints.Configure(ctx, "netsuite_mcp:acme", integrations.ConfigureInput{
		Config: map[string]json.RawMessage{"account_id": q("1234567"), "client_id": q(e.oa.ClientID), "redirect_uri": q(e.oa.RedirectURI),
			"api_base": q(ns.URL)},
	}, "user:sec@acme.com"); err != nil {
		t.Fatalf("configure MCP: %v", err)
	}
	e.authorizeMCP()
	return e
}

func (e *xenv) profile(agent, prof string) {
	e.t.Helper()
	if _, err := e.acc.Put(e.ctx, agent, "netsuite", json.RawMessage(prof), "user:sec@acme.com", "test"); err != nil {
		e.t.Fatal(err)
	}
}

// authorizeMCP runs the OAuth flow against the fake (consent is immediate).
func (e *xenv) authorizeMCP() {
	e.t.Helper()
	au, err := e.svc.StartOAuth(e.ctx, "netsuite_mcp:acme", "user:sec@acme.com")
	if err != nil {
		e.t.Fatal(err)
	}
	req, _ := http.NewRequest("GET", au, nil)
	cb := location(e.t, req).Query()
	if _, err := e.svc.CompleteOAuth(e.ctx, cb.Get("state"), cb.Get("code"), "user:sec@acme.com"); err != nil {
		e.t.Fatal(err)
	}
	if v, _ := e.svc.Status(e.ctx, "netsuite_mcp:acme"); v.State != StateConnected {
		e.t.Fatalf("MCP state %s: %s", v.State, v.Detail)
	}
}

type xresult struct {
	executed bool
	decision string
	rule     string
	actionID string
	body     string
}

// restCall calls customer 101 over REST, naming the tenant when given.
func (e *xenv) restCall(agent, method, tenant, body string) xresult {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.gw.URL+"/gw/netsuite/services/rest/record/v1/customer/101", rd)
	req.Header.Set("Authorization", "Bearer "+e.toks[agent])
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if tenant != "" {
		req.Header.Set(netsuite.HeaderIntegration, tenant)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	r := xresult{executed: res.StatusCode < 300, actionID: res.Header.Get(gateway.ActionIDHeader), body: string(b)}
	_ = e.pool.QueryRow(e.ctx, `SELECT decision, rule_id FROM actions WHERE action_id = $1`, r.actionID).Scan(&r.decision, &r.rule)
	return r
}

// mcpCall calls a tool on the tenant's MCP endpoint.
func (e *xenv) mcpCall(agent, tenant, tool string, args any) xresult {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	req, _ := http.NewRequest("POST", e.gw.URL+TenantProxyPrefix+tenant, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+e.toks[agent])
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var out struct {
		Result struct {
			Meta    map[string]any `json:"_meta"`
			Content []struct {
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		e.t.Fatalf("tools/call %s: %s", tool, raw)
	}
	if out.Error != nil {
		return xresult{body: out.Error.Message}
	}
	r := xresult{}
	r.executed, _ = out.Result.Meta["fortik/executed"].(bool)
	r.actionID, _ = out.Result.Meta["fortik/action_id"].(string)
	for _, c := range out.Result.Content {
		r.body += c.Text
	}
	_ = e.pool.QueryRow(e.ctx, `SELECT decision, rule_id FROM actions WHERE action_id = $1`, r.actionID).Scan(&r.decision, &r.rule)
	return r
}

func (e *xenv) mcpRead(agent string) xresult {
	return e.mcpCall(agent, "acme", "read_record", map[string]any{"recordType": "customer", "id": 101})
}

func (e *xenv) target(actionID string) map[string]any {
	e.t.Helper()
	var raw []byte
	if err := e.pool.QueryRow(e.ctx, `SELECT target FROM actions WHERE action_id = $1`, actionID).Scan(&raw); err != nil {
		e.t.Fatalf("action %s: %v", actionID, err)
	}
	var t map[string]any
	_ = json.Unmarshal(raw, &t)
	return t
}

func TestCrossTransportOneIntegrationTwoConnections(t *testing.T) {
	e := newXEnv(t)
	var n int
	if err := e.pool.QueryRow(e.ctx, `SELECT count(*) FROM app_integrations WHERE provider = 'netsuite'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("logical integrations: %d %v", n, err)
	}
	conns, err := e.ints.ConnectionsOf(e.ctx, acme)
	if err != nil || len(conns) != 2 {
		t.Fatalf("connections: %v %v", conns, err)
	}
	res, err := http.Get(e.api.URL + "/v1/app-integrations/" + acme)
	if err != nil {
		t.Fatal(err)
	}
	var v integrations.AppView
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	if v.TenantRef != "1234567" || v.Environment != integrations.EnvNetSuiteFull || len(v.Connections) != 2 {
		t.Fatalf("app view: %+v", v)
	}
	configured := map[string]bool{}
	for _, tv := range v.Transports {
		configured[tv.Transport] = tv.Configured
	}
	if !configured[integrations.TransportREST] || !configured[integrations.TransportMCP] {
		t.Fatalf("transports: %+v", v.Transports)
	}
}

func TestCrossTransportSameDecisions(t *testing.T) {
	e := newXEnv(t)
	// Reads: allowed on both, recorded under the same tenant and system.
	r, m := e.restCall("bot_rw", "GET", acme, ""), e.mcpRead("bot_rw")
	if !r.executed || !m.executed {
		t.Fatalf("reads: REST %+v MCP %+v", r, m)
	}
	rt, mt := e.target(r.actionID), e.target(m.actionID)
	if rt["integration_id"] != acme || mt["integration_id"] != acme || rt["transport"] != integrations.TransportREST || mt["transport"] != integrations.TransportMCP {
		t.Fatalf("targets: REST %v MCP %v", rt, mt)
	}
	if rt["tenant"] != "1234567" {
		t.Fatalf("REST tenant: %v", rt["tenant"])
	}
	var systems []string
	rows, _ := e.pool.Query(e.ctx, `SELECT DISTINCT system FROM actions`)
	for rows.Next() {
		var s string
		_ = rows.Scan(&s)
		systems = append(systems, s)
	}
	rows.Close()
	if len(systems) != 1 || systems[0] != "netsuite" {
		t.Fatalf("both transports must be decided as system netsuite: %v", systems)
	}

	// A read-only profile refuses writes on both, before either upstream.
	before, beforeMCP := e.rest.Requests["PATCH record"], len(e.mcp.ToolCalls())
	rw := e.restCall("bot_ro", "PATCH", acme, `{"phone":"x"}`)
	mw := e.mcpCall("bot_ro", "acme", "update_record", map[string]any{"recordType": "customer", "id": 101, "fieldValues": map[string]any{"phone": "x"}})
	if rw.executed || mw.executed || rw.rule != "POL-021" || mw.rule != "POL-021" {
		t.Fatalf("read-only writes: REST %+v MCP %+v", rw, mw)
	}
	if e.rest.Requests["PATCH record"] != before || len(e.mcp.ToolCalls()) != beforeMCP {
		t.Fatal("a refused write reached an upstream")
	}

	// A timed suspension of the agent's NetSuite access stops both transports.
	if _, err := e.ov.Create(e.ctx, overrides.CreateRequest{Scope: overrides.ScopeAgent, ScopeID: "bot_rw", System: "netsuite", Mode: overrides.ModeSuspended,
		Duration: time.Hour, Reason: "incident"}, "user:sec@acme.com", nil); err != nil {
		t.Fatal(err)
	}
	if r, m := e.restCall("bot_rw", "GET", acme, ""), e.mcpRead("bot_rw"); r.executed || m.executed || r.decision != "deny" || m.decision != "deny" {
		t.Fatalf("suspended: REST %+v MCP %+v", r, m)
	}
	// Killing the other agent stops both transports.
	if _, err := e.ctl.SetLevel(e.ctx, "bot_ro", control.Killed, "test kill", "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	if r, m := e.restCall("bot_ro", "GET", acme, ""), e.mcpRead("bot_ro"); r.executed || m.executed || r.rule != "POL-010" || m.rule != "POL-010" {
		t.Fatalf("killed: REST %+v MCP %+v", r, m)
	}
}

func TestCrossTransportTenantRestriction(t *testing.T) {
	e := newXEnv(t)
	// The profile allows only another tenant: both transports refuse acme.
	e.profile("bot_rw", `{"mode":"read_write","record_types":["*"],"suiteql":false,"integrations":["netsuite:globex"]}`)
	r, m := e.restCall("bot_rw", "GET", acme, ""), e.mcpRead("bot_rw")
	if r.executed || m.executed || r.rule != "POL-1010" || m.rule != "POL-1010" {
		t.Fatalf("restricted: REST %+v MCP %+v", r, m)
	}
	// Allowed again when acme is listed.
	e.profile("bot_rw", `{"mode":"read_write","record_types":["*"],"suiteql":false,"integrations":["netsuite:acme"]}`)
	if r, m := e.restCall("bot_rw", "GET", acme, ""), e.mcpRead("bot_rw"); !r.executed || !m.executed {
		t.Fatalf("allowed: REST %+v MCP %+v", r, m)
	}
	// An unknown tenant is refused on both, never routed to another one.
	if r := e.restCall("bot_rw", "GET", globex, ""); r.executed || r.decision != "deny" || !strings.Contains(e.target(r.actionID)["reason"].(string), "no NetSuite REST connection") {
		t.Fatalf("unknown REST tenant: %+v", r)
	}
	if m := e.mcpCall("bot_rw", "globex", "read_record", map[string]any{"recordType": "customer", "id": 101}); m.executed {
		t.Fatalf("unknown MCP tenant: %+v", m)
	}
}

func TestCrossTransportAmbiguousRESTTenantRefused(t *testing.T) {
	e := newXEnv(t)
	// One REST connection: the header may be omitted.
	if r := e.restCall("bot_rw", "GET", "", ""); !r.executed {
		t.Fatalf("single tenant without header: %+v", r)
	}
	// A second REST tenant (another account): requests must name one.
	q := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	k := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if _, err := e.ints.Configure(e.ctx, "netsuite:globex", integrations.ConfigureInput{
		Config: map[string]json.RawMessage{"account_id": q("7654321"), "client_id": q("other"), "certificate_id": q("cert-9"),
			"algorithm": q("PS256"), "api_base": q(e.rest.BaseURL)},
		Secrets: map[string]*string{"private_key_pem": &k},
	}, "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	before := e.rest.Requests["GET record"]
	r := e.restCall("bot_rw", "GET", "", "")
	if r.executed || r.decision != "deny" || !strings.Contains(e.target(r.actionID)["reason"].(string), netsuite.HeaderIntegration) {
		t.Fatalf("ambiguous: %+v", r)
	}
	if e.rest.Requests["GET record"] != before {
		t.Fatal("an ambiguous request reached NetSuite")
	}
	if r := e.restCall("bot_rw", "GET", acme, ""); !r.executed {
		t.Fatalf("named tenant: %+v", r)
	}
	// globex's own credentials are used for globex: the fake refuses them
	// (wrong client), so the request fails at globex and never uses acme's.
	g := e.restCall("bot_rw", "GET", globex, "")
	if g.executed || e.target(g.actionID)["connection"] != "netsuite:globex" {
		t.Fatalf("globex: %+v %v", g, e.target(g.actionID))
	}
}

func TestCrossTransportFailureIsolation(t *testing.T) {
	e := newXEnv(t)
	// The MCP authorization lapses (refresh refused): MCP calls fail, REST
	// keeps working, and the integration reports the difference.
	e.oa.RefuseRefresh = true
	tk, _ := e.svc.loadTokens(e.ctx, "netsuite_mcp:acme")
	tk.AccessExpiresAt = time.Now().Add(-time.Minute)
	_ = e.svc.saveTokens(e.ctx, "netsuite_mcp:acme", tk)
	e.svc.up("netsuite_mcp:acme").drop()
	if m := e.mcpRead("bot_rw"); m.executed {
		t.Fatalf("MCP call with a lapsed authorization: %+v", m)
	}
	if r := e.restCall("bot_rw", "GET", acme, ""); !r.executed {
		t.Fatalf("REST affected by the MCP failure: %+v", r)
	}
	res, _ := http.Post(e.api.URL+"/v1/integrations/netsuite_mcp:acme/test", "application/json", nil)
	res.Body.Close()
	res, _ = http.Post(e.api.URL+"/v1/integrations/netsuite:acme/test", "application/json", nil)
	res.Body.Close()
	res, _ = http.Get(e.api.URL + "/v1/app-integrations/" + acme)
	var v integrations.AppView
	_ = json.NewDecoder(res.Body).Decode(&v)
	res.Body.Close()
	status := map[string]string{}
	for _, c := range v.Connections {
		status[c.Transport] = c.Status
	}
	if status[integrations.TransportMCP] != integrations.StatusError || v.Health == integrations.HealthHealthy {
		t.Fatalf("health %s, statuses %v", v.Health, status)
	}

	// Disconnecting MCP leaves REST and the integration in place.
	req, _ := http.NewRequest("DELETE", e.api.URL+"/v1/integrations/netsuite_mcp:acme", nil)
	res, _ = http.DefaultClient.Do(req)
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("disconnect MCP: %d", res.StatusCode)
	}
	if _, err := e.ints.GetApp(e.ctx, acme); err != nil {
		t.Fatalf("integration removed with one of two connections: %v", err)
	}
	if r := e.restCall("bot_rw", "GET", acme, ""); !r.executed {
		t.Fatalf("REST after MCP disconnect: %+v", r)
	}
	if m := e.mcpRead("bot_rw"); m.executed || !strings.Contains(m.body, "no MCP connection") {
		t.Fatalf("MCP after disconnect: %+v", m)
	}
}

func TestCrossTransportUpdatesDifferOnlyAsConfigured(t *testing.T) {
	e := newXEnv(t)
	// REST updates run with a snapshot (POL-1001); MCP updates are held
	// (POL-1120) while netsuite.mcp_writes_require_approval is true (the
	// default). Rego tests cover the setting turned off.
	r := e.restCall("bot_rw", "PATCH", acme, `{"phone":"+1 555 9999"}`)
	if !r.executed || r.decision != "allow_reduced" || r.rule != "POL-1001" {
		t.Fatalf("REST update: %+v", r)
	}
	m := e.mcpCall("bot_rw", "acme", "update_record", map[string]any{"recordType": "customer", "id": 101, "fieldValues": map[string]any{"phone": "+1 555 8888"}})
	if m.executed || m.decision != "hold" || m.rule != "POL-1120" {
		t.Fatalf("MCP update: %+v", m)
	}
}
