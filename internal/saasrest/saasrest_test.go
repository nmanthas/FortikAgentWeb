package saasrest

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
	"path/filepath"
	"runtime"
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
	"fortik/internal/overrides"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

type memSecrets map[string][]byte

func (m memSecrets) Get(_ context.Context, name string) ([]byte, error) {
	if v, ok := m[name]; ok {
		return v, nil
	}
	return nil, secrets.ErrNotFound
}

func policyDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "policies")
}

type env struct {
	t      *testing.T
	ctx    context.Context
	pool   *pgxpool.Pool
	ints   *integrations.PGStore
	acc    *access.PGStore
	ctl    *control.Store
	ov     *overrides.PGStore
	appr   *approvals.Service
	svc    *Service
	api    *httptest.Server
	gw     *httptest.Server
	toks   map[string]string
	sf     *fakeSalesforce
	sfURL  string
	sn     *fakeServiceNow
	snURL  string
	sap    *fakeSAP
	sapURL string
	key    *rsa.PrivateKey
}

func setup(t *testing.T) *env {
	t.Helper()
	pool, _ := testutil.FortikDB(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	d := diary.New(pool)
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	enc, err := secrets.NewEncFile(t.TempDir(), k)
	if err != nil {
		t.Fatal(err)
	}
	ints := integrations.NewPGStore(pool, d, enc)
	e := &env{t: t, ctx: ctx, pool: pool, ints: ints, toks: map[string]string{}}
	e.svc = New(pool, ints, Guard{AllowLoopback: true}, log)
	reg := integrations.NewRegistry()
	for _, tt := range e.svc.Testers() {
		if err := reg.Register(tt); err != nil {
			t.Fatal(err)
		}
	}
	mux := http.NewServeMux()
	integrations.NewHandler(ints, reg, log).Register(mux)
	e.svc.Register(mux)
	e.api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := authz.Principal{Kind: authz.KindUser, Name: "Sec", Email: "sec@acme.com", AuthMethod: "dev", Roles: map[string]bool{authz.RoleSecurity: true}}
		mux.ServeHTTP(w, r.WithContext(authz.With(r.Context(), p)))
	}))
	t.Cleanup(e.api.Close)

	// Gateway with the shared decision pipeline.
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	e.ctl = control.NewStore(pool, d)
	e.acc = access.NewPGStore(pool, d)
	e.ov = overrides.NewPGStore(pool, d, nil, log)
	und := undo.NewPGStore(pool, d)
	dec := &decide.Service{Pool: pool, Policy: eng, Control: e.ctl, Diary: d, Log: log, Access: e.acc}
	dec.Enrichers = []decide.Enricher{overrides.NewEnricher(e.ov), approvals.NewGrantEnricher(pool)}
	dec.Observers = []decide.Observer{approvals.NewGrantObserver(d)}
	e.appr = approvals.New(pool, d, und, ints, approvals.Config{GrantTTL: 10 * time.Minute}, log)
	hashes := map[string]string{}
	for _, agent := range []string{"bot_rw", "bot_ro"} {
		if _, err := e.ctl.Register(ctx, control.Agent{AgentID: agent, Type: "crm", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := e.ctl.SetLevel(ctx, agent, control.Full, "test", "test"); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		tok := "agt_" + hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(tok))
		hashes[agent] = hex.EncodeToString(sum[:])
		e.toks[agent] = tok
	}
	for _, sys := range Systems {
		e.profile("bot_rw", sys, `{"mode":"read_write","objects":["*"]}`)
		e.profile("bot_ro", sys, `{"mode":"read_only","objects":["*"]}`)
	}
	raw, _ := json.Marshal(hashes)
	gw, err := gateway.NewServer(config.GatewayConfig{}, dec, gateway.NewAgentAuth(memSecrets{"agent_tokens": raw}, "agent_tokens", log),
		e.svc.Adapters(), log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	e.svc.NewAgentMCP(gw.Dispatch, "test").Mount(gw.Mount)
	e.svc.NewServiceNowMCP(gw.Dispatch, "test").Mount(gw.Mount)
	e.gw = httptest.NewServer(gw)
	t.Cleanup(e.gw.Close)

	e.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	e.sf = &fakeSalesforce{ClientID: "sf-client", ClientSecret: "sf-secret-value-123", Username: "fortik@acme.example", Audience: "https://login.salesforce.com", PublicKey: &e.key.PublicKey}
	e.sn = &fakeServiceNow{User: "fortik.integration", Password: "sn-password-value-123", ClientID: "sn-client", ClientSecret: "sn-secret-value-123",
		Forbidden: map[string]bool{"change_request": true}}
	e.sap = &fakeSAP{User: "COMM_USER", Password: "sap-password-value-123"}
	for _, f := range []struct {
		h http.Handler
		u *string
	}{{e.sf, &e.sfURL}, {e.sn, &e.snURL}, {e.sap, &e.sapURL}} {
		s := httptest.NewServer(f.h)
		t.Cleanup(s.Close)
		*f.u = s.URL
	}
	return e
}

func (e *env) profile(agent, system, prof string) {
	e.t.Helper()
	if _, err := e.acc.Put(e.ctx, agent, system, json.RawMessage(prof), "user:sec@acme.com", "test"); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) do(method, path string, body any) (int, map[string]any) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.api.URL+path, rd)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out
}

func (e *env) configure(key string, cfg map[string]any, sec map[string]any) {
	e.t.Helper()
	body := map[string]any{"config": cfg}
	if sec != nil {
		body["secrets"] = sec
	}
	if code, out := e.do("PUT", "/v1/integrations/"+key, body); code != 200 {
		e.t.Fatalf("configure %s: %d %v", key, code, out)
	}
}

func (e *env) test(key string) {
	e.t.Helper()
	if code, out := e.do("POST", "/v1/integrations/"+key+"/test", nil); code != 200 {
		e.t.Fatalf("test %s: %d %v", key, code, out)
	}
}

func (e *env) status(key string) View {
	e.t.Helper()
	v, err := e.svc.Status(e.ctx, key)
	if err != nil {
		e.t.Fatal(err)
	}
	return v
}

func (e *env) pemKey() string {
	der, _ := x509.MarshalPKCS8PrivateKey(e.key)
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func (e *env) salesforce() {
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client"}, map[string]any{"client_secret": "sf-secret-value-123"})
}

// noSecretAnywhere fails if a credential reached Postgres or an output.
func (e *env) noSecretAnywhere(outputs ...any) {
	e.t.Helper()
	var s string
	if err := e.pool.QueryRow(e.ctx, `
		SELECT COALESCE((SELECT string_agg(i::text, E'\n') FROM integrations i), '') ||
		       COALESCE((SELECT string_agg(r::text, E'\n') FROM rest_connections r), '') ||
		       COALESCE((SELECT string_agg(a::text, E'\n') FROM actions a), '') ||
		       COALESCE((SELECT string_agg(d::text, E'\n') FROM diary d), '')`).Scan(&s); err != nil {
		e.t.Fatal(err)
	}
	for _, o := range outputs {
		b, _ := json.Marshal(o)
		s += string(b)
	}
	for _, v := range []string{"sf-secret-value-123", "sn-password-value-123", "sn-secret-value-123", "sap-password-value-123", "PRIVATE KEY", "sf-token-", "sn-token-", "sfagentsig", "agent-secret-value-456"} {
		if strings.Contains(s, v) {
			e.t.Fatalf("a credential (%s…) leaked into the database, Diary or an output", v[:6])
		}
	}
}

func TestSalesforceClientCredentials(t *testing.T) {
	e := setup(t)
	if v := e.status("salesforce"); v.State != StateNotConfigured || v.Configured {
		t.Fatalf("%+v", v)
	}
	e.salesforce()
	if v := e.status("salesforce"); v.State != StateSavedNotTested {
		t.Fatalf("saved settings shown as %s", v.State)
	}
	if len(e.sf.requests) != 0 {
		t.Fatal("saving contacted Salesforce")
	}
	e.test("salesforce")
	v := e.status("salesforce")
	if v.State != StateConnected || !v.CapabilitiesCurrent || v.Identity["organization_id"] != "00Dxx0000001gPL" {
		t.Fatalf("%+v", v)
	}
	objs, _ := v.Capabilities["common_objects"].(map[string]any)
	acct, _ := objs["Account"].(map[string]any)
	if v.Capabilities["objects_visible"] != float64(3) || acct["update"] != true || acct["delete"] != false {
		t.Fatalf("capabilities %v", v.Capabilities)
	}
	if in, _ := e.ints.GetIntegration(e.ctx, "salesforce"); in.Status != integrations.StatusOK || in.IntegrationID != "salesforce:default" || in.Transport != integrations.TransportREST {
		t.Fatalf("integration %+v", in)
	}
	// A changed setting makes the result stale until the next test.
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "api_version": "61.0"}, nil)
	if v := e.status("salesforce"); v.State != StateSavedNotTested || v.LastCheckedState != StateConnected {
		t.Fatalf("after change %+v", v)
	}
	e.noSecretAnywhere(v)
}

func TestSalesforceJWTAndFailures(t *testing.T) {
	e := setup(t)
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "auth_flow": "jwt_bearer", "username": "fortik@acme.example"},
		map[string]any{"private_key_pem": e.pemKey()})
	e.test("salesforce")
	if v := e.status("salesforce"); v.State != StateConnected || v.Auth != "jwt_bearer" {
		t.Fatalf("jwt: %+v", v)
	}
	// Wrong username: the token request is refused.
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "auth_flow": "jwt_bearer", "username": "someone@else"}, nil)
	e.test("salesforce")
	if v := e.status("salesforce"); v.State != StateAuthFailed || !strings.Contains(v.Detail, "invalid_client") {
		t.Fatalf("bad jwt: %+v", v)
	}
	// Client credentials without a secret: never sent upstream.
	before := len(e.sf.requests)
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "auth_flow": "client_credentials"}, nil)
	e.test("salesforce")
	if v := e.status("salesforce"); v.State != StateInvalid || len(e.sf.requests) != before {
		t.Fatalf("missing secret: %+v", v)
	}
	// API disabled for the run-as user.
	e.sf.NoSObjects = true
	e.salesforce()
	e.test("salesforce")
	if v := e.status("salesforce"); v.State != StatePermission || !strings.Contains(v.Detail, "API_DISABLED_FOR_ORG") {
		t.Fatalf("no api: %+v", v)
	}
	// An API version the org does not offer.
	e.sf.NoSObjects = false
	e.configure("salesforce", map[string]any{"instance_url": e.sfURL, "client_id": "sf-client", "api_version": "99.0"}, nil)
	e.test("salesforce")
	if v := e.status("salesforce"); v.State != StateNotFound {
		t.Fatalf("version: %+v", v)
	}
	// Cross-field validation at save time.
	if code, _ := e.do("PUT", "/v1/integrations/salesforce", map[string]any{"config": map[string]any{"instance_url": e.sfURL, "client_id": "x", "auth_flow": "jwt_bearer"}}); code != 400 {
		t.Fatalf("jwt without username accepted: %d", code)
	}
}

func TestServiceNowBasicAndOAuth(t *testing.T) {
	e := setup(t)
	e.configure("servicenow", map[string]any{"instance_url": e.snURL, "username": "fortik.integration"}, map[string]any{"password": "sn-password-value-123"})
	e.test("servicenow")
	v := e.status("servicenow")
	tables, _ := v.Capabilities["tables"].(map[string]any)
	if v.State != StateConnected || tables["incident"] != "readable" || tables["change_request"] != "no read access (ACL)" {
		t.Fatalf("basic: %+v", v)
	}
	// OAuth client credentials.
	e.configure("servicenow", map[string]any{"instance_url": e.snURL, "auth_type": "oauth_client_credentials", "client_id": "sn-client", "test_tables": []string{"incident"}},
		map[string]any{"client_secret": "sn-secret-value-123"})
	e.test("servicenow")
	if v := e.status("servicenow"); v.State != StateConnected || v.Auth != "oauth_client_credentials" {
		t.Fatalf("oauth: %+v", v)
	}
	// Every table refused by ACLs: permission denied, not connected.
	e.configure("servicenow", map[string]any{"instance_url": e.snURL, "auth_type": "basic", "username": "fortik.integration", "test_tables": []string{"change_request"}}, nil)
	e.test("servicenow")
	if v := e.status("servicenow"); v.State != StatePermission {
		t.Fatalf("acl: %+v", v)
	}
	// Wrong password.
	e.configure("servicenow", map[string]any{"instance_url": e.snURL, "username": "fortik.integration", "test_tables": []string{"incident"}}, map[string]any{"password": "wrong-password"})
	e.test("servicenow")
	if v := e.status("servicenow"); v.State != StateAuthFailed {
		t.Fatalf("bad password: %+v", v)
	}
	e.noSecretAnywhere(v)
}

func TestSAPMetadata(t *testing.T) {
	e := setup(t)
	e.configure("sap", map[string]any{"api_base_url": e.sapURL, "username": "COMM_USER",
		"services": []string{"/sap/opu/odata/sap/API_BUSINESS_PARTNER", "/sap/opu/odata/sap/API_SALES_ORDER_SRV"}},
		map[string]any{"password": "sap-password-value-123"})
	e.test("sap")
	v := e.status("sap")
	svcs, _ := v.Capabilities["services"].(map[string]any)
	bp, _ := svcs["/sap/opu/odata/sap/API_BUSINESS_PARTNER"].(map[string]any)
	if v.State != StateConnected || bp["entity_sets"] != float64(2) || !strings.Contains(svcs["/sap/opu/odata/sap/API_SALES_ORDER_SRV"].(string), "not found") {
		t.Fatalf("sap: %+v", v)
	}
	e.configure("sap", map[string]any{"api_base_url": e.sapURL, "username": "COMM_USER", "services": []string{"/sap/opu/odata/sap/API_SALES_ORDER_SRV"}}, nil)
	e.test("sap")
	if v := e.status("sap"); v.State != StateNotFound {
		t.Fatalf("no service: %+v", v)
	}
	e.configure("sap", map[string]any{"api_base_url": e.sapURL, "username": "COMM_USER"}, map[string]any{"password": "wrong"})
	e.test("sap")
	if v := e.status("sap"); v.State != StateAuthFailed {
		t.Fatalf("bad password: %+v", v)
	}
}

func TestGuard(t *testing.T) {
	g := Guard{AllowedHosts: []string{"gateway.acme.internal"}}
	for _, c := range []struct {
		provider, url string
		ok            bool
	}{
		{"salesforce", "https://acme.my.salesforce.com", true},
		{"salesforce", "https://acme--uat.sandbox.my.salesforce.com/services/oauth2/token", true},
		{"salesforce", "https://evil.example.com", false},
		{"salesforce", "http://acme.my.salesforce.com", false},
		{"servicenow", "https://acme.service-now.com", true},
		{"servicenow", "https://acme.salesforce.com", false},
		{"sap", "https://my123456-api.s4hana.cloud.sap", true},
		{"sap", "https://gateway.acme.internal/sap/opu/odata/sap/X", true},
		{"sap", "https://other.internal", false},
		{"sap", "http://127.0.0.1:8080", false},
		{"sap", "https://user:pw@my123456-api.s4hana.cloud.sap", false},
	} {
		if got := g.Refused(c.provider, c.url) == ""; got != c.ok {
			t.Errorf("%s %s: permitted=%v", c.provider, c.url, got)
		}
	}
	// A listed host that resolves to a private address is refused at dial time.
	cl := Guard{AllowedHosts: []string{"10.1.2.3"}}.Client(2 * time.Second)
	if _, err := cl.Get("https://10.1.2.3/"); err == nil || !refusedErr(err) {
		t.Fatalf("private address dialled: %v", err)
	}

	e := setup(t)
	e.svc.guard = Guard{} // no loopback: the fake is not a permitted host
	e.salesforce()
	e.test("salesforce")
	if v := e.status("salesforce"); v.State != StateNotPermitted || len(e.sf.requests) != 0 || v.EndpointPermitted {
		t.Fatalf("guard: %+v", v)
	}
}

func TestDisconnectForgets(t *testing.T) {
	e := setup(t)
	e.salesforce()
	e.test("salesforce")
	if code, _ := e.do("DELETE", "/v1/integrations/salesforce", nil); code != 200 {
		t.Fatalf("delete: %d", code)
	}
	var n int
	_ = e.pool.QueryRow(e.ctx, `SELECT count(*) FROM rest_connections`).Scan(&n)
	if n != 0 || len(e.svc.tokens) != 0 {
		t.Fatalf("check results or tokens survived: %d %d", n, len(e.svc.tokens))
	}
	if v := e.status("salesforce"); v.State != StateNotConfigured {
		t.Fatalf("%+v", v)
	}
	// The status API refuses other connection types.
	if code, _ := e.do("GET", "/v1/integrations/netsuite/check", nil); code != 400 {
		t.Fatalf("netsuite check: %d", code)
	}
}

// --- gateway --------------------------------------------------------------------

type gwResp struct {
	status   int
	body     string
	actionID string
	decision string
	rule     string
}

func (e *env) call(agent, method, path, body string, hdr map[string]string) gwResp {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.gw.URL+path, rd)
	req.Header.Set("Authorization", "Bearer "+e.toks[agent])
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	r := gwResp{status: res.StatusCode, body: string(b), actionID: res.Header.Get(gateway.ActionIDHeader)}
	_ = e.pool.QueryRow(e.ctx, `SELECT decision, rule_id FROM actions WHERE action_id = $1`, r.actionID).Scan(&r.decision, &r.rule)
	return r
}

func (e *env) approve(actionID string) {
	e.t.Helper()
	p := authz.Principal{Kind: authz.KindUser, Email: "sec@acme.com", Name: "Sec", Roles: map[string]bool{authz.RoleSecurity: true}}
	if _, err := e.appr.Approve(e.ctx, p, actionID, approvals.ApproveRequest{Reason: "checked with the account owner"}); err != nil {
		e.t.Fatalf("approve: %v", err)
	}
}

func TestGatewaySalesforce(t *testing.T) {
	e := setup(t)
	acct := "/gw/salesforce/services/data/v62.0/sobjects/Account/001xx"
	if r := e.call("bot_rw", "GET", acct, "", nil); r.status != http.StatusServiceUnavailable {
		t.Fatalf("not configured: %d %s", r.status, r.body)
	}
	e.salesforce()
	// A read runs with Fortik's token; the agent never sees it.
	r := e.call("bot_rw", "GET", acct, "", nil)
	if r.status != 200 || !strings.Contains(r.body, "Acme") || r.decision != "allow" {
		t.Fatalf("read: %+v", r)
	}
	var tgt map[string]any
	var raw []byte
	_ = e.pool.QueryRow(e.ctx, `SELECT target FROM actions WHERE action_id = $1`, r.actionID).Scan(&raw)
	_ = json.Unmarshal(raw, &tgt)
	if tgt["integration_id"] != "salesforce:default" || tgt["transport"] != "rest_api" || tgt["object"] != "Account" || tgt["operation"] != "get" {
		t.Fatalf("target %v", tgt)
	}
	// An update is held, not sent; approved, the identical retry runs once.
	before := e.sf.count("PATCH")
	u := e.call("bot_rw", "PATCH", acct, `{"Name":"Acme 2"}`, nil)
	if u.status != 403 || u.decision != "hold" || u.rule != "POL-1201" || e.sf.count("PATCH") != before {
		t.Fatalf("update: %+v", u)
	}
	e.approve(u.actionID)
	if r := e.call("bot_rw", "PATCH", acct, `{"Name":"Acme 2"}`, nil); r.status != 204 || e.sf.count("PATCH") != before+1 {
		t.Fatalf("approved retry: %+v", r)
	}
	if r := e.call("bot_rw", "PATCH", acct, `{"Name":"Acme 2"}`, nil); r.status != 403 || e.sf.count("PATCH") != before+1 {
		t.Fatalf("second retry ran: %+v", r)
	}
	// Deletes are red holds; paths outside the API are refused.
	if d := e.call("bot_rw", "DELETE", acct, "", nil); d.status != 403 || d.rule != "POL-1202" {
		t.Fatalf("delete: %+v", d)
	}
	if x := e.call("bot_rw", "GET", "/gw/salesforce/services/apexrest/Custom", "", nil); x.status != 403 || x.decision != "deny" {
		t.Fatalf("outside the API: %+v", x)
	}
	// Read-only profile; object restriction.
	if w := e.call("bot_ro", "PATCH", acct, `{"Name":"x"}`, nil); w.rule != "POL-021" {
		t.Fatalf("read-only write: %+v", w)
	}
	e.profile("bot_ro", "salesforce", `{"mode":"read_only","objects":["contact"]}`)
	if o := e.call("bot_ro", "GET", acct, "", nil); o.rule != "POL-1211" {
		t.Fatalf("object restriction: %+v", o)
	}
	// A timed salesforce suspension stops the agent.
	if _, err := e.ov.Create(e.ctx, overrides.CreateRequest{Scope: overrides.ScopeAgent, ScopeID: "bot_rw", System: "salesforce", Mode: overrides.ModeSuspended,
		Duration: time.Hour, Reason: "incident"}, "user:sec@acme.com", nil); err != nil {
		t.Fatal(err)
	}
	if s := e.call("bot_rw", "GET", acct, "", nil); s.decision != "deny" {
		t.Fatalf("suspended: %+v", s)
	}
	e.noSecretAnywhere()
}

func TestGatewayTenantsServiceNowSAP(t *testing.T) {
	e := setup(t)
	e.configure("servicenow", map[string]any{"instance_url": e.snURL, "username": "fortik.integration"}, map[string]any{"password": "sn-password-value-123"})
	if r := e.call("bot_rw", "GET", "/gw/servicenow/api/now/table/incident?sysparm_limit=1", "", nil); r.status != 200 || r.decision != "allow" {
		t.Fatalf("servicenow read: %+v", r)
	}
	// A second tenant: requests must name one.
	e.configure("servicenow:eu", map[string]any{"instance_url": strings.Replace(e.snURL, "127.0.0.1", "localhost", 1), "username": "fortik.integration"},
		map[string]any{"password": "sn-password-value-123"})
	if r := e.call("bot_rw", "GET", "/gw/servicenow/api/now/table/incident", "", nil); r.decision != "deny" {
		t.Fatalf("ambiguous: %+v", r)
	}
	if r := e.call("bot_rw", "GET", "/gw/servicenow/api/now/table/incident", "", map[string]string{HeaderIntegration: "servicenow:eu"}); r.status != 200 {
		t.Fatalf("named tenant: %+v", r)
	}
	e.profile("bot_rw", "servicenow", `{"mode":"read_write","objects":["*"],"integrations":["servicenow:default"]}`)
	if r := e.call("bot_rw", "GET", "/gw/servicenow/api/now/table/incident", "", map[string]string{HeaderIntegration: "servicenow:eu"}); r.rule != "POL-1010" {
		t.Fatalf("tenant restriction: %+v", r)
	}

	// SAP: a change is held, then runs once with a CSRF token Fortik fetches.
	e.configure("sap", map[string]any{"api_base_url": e.sapURL, "username": "COMM_USER"}, map[string]any{"password": "sap-password-value-123"})
	set := "/gw/sap/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartner('1000001')"
	if r := e.call("bot_rw", "GET", set, "", nil); r.status != 200 {
		t.Fatalf("sap read: %+v", r)
	}
	u := e.call("bot_rw", "PATCH", set, `{"BusinessPartnerFullName":"x"}`, nil)
	if u.rule != "POL-1201" || e.sap.count("PATCH") != 0 {
		t.Fatalf("sap update: %+v", u)
	}
	e.approve(u.actionID)
	if r := e.call("bot_rw", "PATCH", set, `{"BusinessPartnerFullName":"x"}`, nil); r.status != 204 || e.sap.count("PATCH") != 1 {
		t.Fatalf("sap approved update: %+v", r)
	}
}

func TestMapPath(t *testing.T) {
	for _, c := range []struct {
		system, method, path, query string
		op, obj, id                 string
		ok                          bool
	}{
		{"salesforce", "GET", "/services/data/v62.0/sobjects/Account/001", "", "get", "Account", "001", true},
		{"salesforce", "POST", "/services/data/v62.0/sobjects/Contact", "", "create", "Contact", "", true},
		{"salesforce", "GET", "/services/data/v62.0/query", "q=SELECT+Id+FROM+Opportunity", "query", "Opportunity", "", true},
		{"salesforce", "POST", "/services/data/v62.0/actions/standard/emailSimple", "", "action", "actions/standard/emailSimple", "", true},
		{"salesforce", "GET", "/services/data/v62.0/sobjects/Account/describe", "", "describe", "Account", "", true},
		{"salesforce", "GET", "/services/apexrest/x", "", "", "", "", false},
		{"servicenow", "GET", "/api/now/table/incident/abc", "", "get", "incident", "abc", true},
		{"servicenow", "DELETE", "/api/now/table/incident/abc", "", "delete", "incident", "abc", true},
		{"servicenow", "GET", "/api/sn_sc/servicecatalog/items", "", "", "", "", false},
		{"sap", "GET", "/sap/opu/odata/sap/API_BUSINESS_PARTNER/A_BusinessPartner('1')", "", "get", "API_BUSINESS_PARTNER/A_BusinessPartner", "'1'", true},
		{"sap", "POST", "/sap/opu/odata/sap/API_BUSINESS_PARTNER/$batch", "", "batch", "API_BUSINESS_PARTNER/$batch", "", true},
		{"sap", "GET", "/sap/opu/odata/sap/API_BUSINESS_PARTNER/$metadata", "", "describe", "API_BUSINESS_PARTNER", "", true},
		{"sap", "GET", "/sap/bc/adt/whatever", "", "", "", "", false},
	} {
		r, ok := mapPath(c.system, c.method, c.path, c.query)
		if ok != c.ok || (ok && (r.Operation != c.op || r.Object != c.obj || r.RecordID != c.id)) {
			t.Errorf("%s %s %s: %+v %v", c.system, c.method, c.path, r, ok)
		}
	}
}
