package netsuite_test

// Milestone 1 tests. Every NetSuite response here comes from the LOCAL FAKE
// (internal/netsuite/fakens), never from a real account: they prove Fortik's
// side (mapping, policy, gateway enforcement, snapshot/undo, ingestion) and
// the documented protocol shapes, not NetSuite's behaviour.

import (
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

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/netsuite"
	"fortik/internal/netsuite/fakens"
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
	ctl    *control.Store
	ints   *integrations.PGStore
	und    *undo.PGStore
	enc    secrets.Store
	fake   *fakens.Fake
	fsrv   *httptest.Server
	ad     *netsuite.Adapter
	conn   *netsuite.Connector
	sync   *netsuite.Syncer
	srv    *httptest.Server
	toks   map[string]string
	keyPEM string
}

const (
	rwProfile = `{"mode":"read_write","record_types":["*"],"suiteql":true}`
	roProfile = `{"mode":"read_only","record_types":["*"],"suiteql":true}`
)

func setup(t *testing.T) *env {
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
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc}
	und := undo.NewPGStore(pool, d)
	client := netsuite.NewClient(nil)
	ad, err := netsuite.NewAdapter(ints, client, und, enc, 0, log)
	if err != nil {
		t.Fatal(err)
	}
	conn := netsuite.NewConnector(ints, client, log)
	e := &env{t: t, ctx: ctx, pool: pool, ctl: ctl, ints: ints, und: und, enc: enc, ad: ad, conn: conn, toks: map[string]string{}}
	e.sync = netsuite.NewSyncer(pool, d, conn, svc, alerts.NewPGStore(pool, d), log)

	hashes := map[string]string{}
	for agent, prof := range map[string]string{"order_bot": rwProfile, "ap_bot": roProfile} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: agent, Type: "erp", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := acc.Put(ctx, agent, "netsuite", json.RawMessage(prof), "user:sec@acme.com", "test"); err != nil {
			t.Fatal(err)
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		tok := "agt_" + hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(tok))
		hashes[agent] = hex.EncodeToString(sum[:])
		e.toks[agent] = tok
	}
	raw, _ := json.Marshal(hashes)
	gw, err := gateway.NewServer(config.GatewayConfig{}, svc, gateway.NewAgentAuth(memSecrets{"agent_tokens": raw}, "agent_tokens", log),
		[]gateway.Adapter{ad}, log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(gw)
	t.Cleanup(e.srv.Close)

	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, _ := x509.MarshalPKCS8PrivateKey(rk)
	e.keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	e.fake = fakens.New("fortik-client-id", "cert-123", &rk.PublicKey)
	e.fsrv = httptest.NewServer(e.fake)
	t.Cleanup(e.fsrv.Close)
	e.fake.BaseURL = e.fsrv.URL
	return e
}

func (e *env) configure(cert string) {
	e.t.Helper()
	q := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	k := e.keyPEM
	if _, err := e.ints.Configure(e.ctx, netsuite.IntegrationKey, integrations.ConfigureInput{
		Config: map[string]json.RawMessage{"account_id": q("1234567_SB1"), "client_id": q("fortik-client-id"), "certificate_id": q(cert),
			"algorithm": q("PS256"), "api_base": q(e.fsrv.URL), "agent_map": q([]string{"order_bot=3", "ap_bot=4"})},
		Secrets: map[string]*string{"private_key_pem": &k},
	}, "user:sec@acme.com"); err != nil {
		e.t.Fatalf("configure: %v", err)
	}
}

type resp struct {
	status   int
	body     string
	actionID string
	rule     string
	decision string
}

func (e *env) call(agent, method, path, body string) resp {
	e.t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+"/gw/netsuite"+path, rd)
	req.Header.Set("Authorization", "Bearer "+e.toks[agent])
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if strings.Contains(path, "suiteql") {
		req.Header.Set("Prefer", "transient")
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	r := resp{status: res.StatusCode, body: string(b), actionID: res.Header.Get(gateway.ActionIDHeader)}
	var ref struct {
		Error struct {
			RuleID   string `json:"rule_id"`
			Decision string `json:"decision"`
		} `json:"error"`
	}
	if json.Unmarshal(b, &ref) == nil {
		r.rule, r.decision = ref.Error.RuleID, ref.Error.Decision
	}
	return r
}

func (e *env) str(q string, args ...any) string {
	e.t.Helper()
	var s string
	if err := e.pool.QueryRow(e.ctx, q, args...).Scan(&s); err != nil {
		e.t.Fatalf("%s: %v", q, err)
	}
	return s
}

func TestNotConfiguredFailsClosed(t *testing.T) {
	e := setup(t)
	if r := e.call("order_bot", "GET", "/services/rest/record/v1/customer/101", ""); r.status != 503 {
		t.Fatalf("not configured: %d %s", r.status, r.body)
	}
}

func TestGatewayEnforcementAndUndo(t *testing.T) {
	e := setup(t)
	e.configure("cert-123")

	// A read goes through with Fortik's token; the agent never sees it.
	r := e.call("order_bot", "GET", "/services/rest/record/v1/customer/101", "")
	if r.status != 200 || !strings.Contains(r.body, "Acme Retail") || strings.Contains(r.body, "fake-ns-token") {
		t.Fatalf("read: %d %s", r.status, r.body)
	}
	if q := e.call("order_bot", "POST", "/services/rest/query/v1/suiteql", `{"q":"SELECT id, companyname FROM customer"}`); q.status != 200 || !strings.Contains(q.body, "Globex") {
		t.Fatalf("suiteql: %d %s", q.status, q.body)
	}

	// An update is snapshotted first, runs, and can be undone.
	u := e.call("order_bot", "PATCH", "/services/rest/record/v1/customer/101", `{"phone":"+1 555 9999"}`)
	if u.status != 204 {
		t.Fatalf("update: %d %s", u.status, u.body)
	}
	if rec, _ := e.fake.Record("customer", "101"); rec["phone"] != "+1 555 9999" {
		t.Fatalf("update not applied: %v", rec)
	}
	if got := e.str(`SELECT decision || ' ' || rule_id FROM actions WHERE action_id = $1`, u.actionID); got != "allow_reduced POL-1001" {
		t.Fatalf("update decision: %s", got)
	}
	h, err := e.und.Get(e.ctx, u.actionID)
	if err != nil || h.Status != "active" || strings.Contains(string(h.Data), "555 0101") {
		t.Fatalf("undo handle (must be active and hold no field values): %+v %v", h, err)
	}
	if _, err := e.und.Claim(e.ctx, u.actionID, "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	res, err := e.ad.UndoExecutor().Undo(e.ctx, h)
	if err != nil {
		t.Fatalf("undo: %v", err)
	}
	if rec, _ := e.fake.Record("customer", "101"); rec["phone"] != "+1 555 0101" {
		t.Fatalf("undo did not restore: %v %v", rec, res)
	}
	if _, err := e.enc.Get(e.ctx, "netsuite_undo_"+strings.ToLower(u.actionID)); err == nil {
		t.Fatal("snapshot not deleted after undo")
	}

	// Payments, bank details, deletes: held before execution.
	if p := e.call("order_bot", "POST", "/services/rest/record/v1/vendorPayment", `{"entity":{"id":"201"},"total":1200}`); p.status != 403 || p.rule != "POL-1003" {
		t.Fatalf("payment: %d %s", p.status, p.body)
	}
	if n := e.str(`SELECT approvals_required::text FROM held_actions WHERE rule_id = 'POL-1003'`); n != "2" {
		t.Fatalf("payment approvals: %s", n)
	}
	if b := e.call("order_bot", "PATCH", "/services/rest/record/v1/vendor/201", `{"achAccountNumber":"999"}`); b.status != 403 || b.rule != "POL-1004" {
		t.Fatalf("bank change: %d %s", b.status, b.body)
	}
	if rec, _ := e.fake.Record("vendor", "201"); rec["achAccountNumber"] != "000123456789" {
		t.Fatal("a held bank change reached NetSuite")
	}
	if d := e.call("order_bot", "DELETE", "/services/rest/record/v1/customer/102", ""); d.status != 403 || d.rule != "POL-1002" {
		t.Fatalf("delete: %d %s", d.status, d.body)
	}
	if _, ok := e.fake.Record("customer", "102"); !ok {
		t.Fatal("a held delete reached NetSuite")
	}
	if st, _ := e.ctl.Get(e.ctx, "order_bot"); st.Level != control.ReadOnly {
		t.Fatalf("order_bot after a red delete: %v", st.Level)
	}

	// A read-only agent's write is refused by its profile; nothing is sent.
	before := e.fake.Requests["PATCH record"]
	if w := e.call("ap_bot", "PATCH", "/services/rest/record/v1/customer/101", `{"phone":"x"}`); w.status != 403 || w.rule != "POL-021" {
		t.Fatalf("read-only write: %d %s", w.status, w.body)
	}
	if e.fake.Requests["PATCH record"] != before {
		t.Fatal("a refused write reached NetSuite")
	}
	// Unknown endpoints are refused, never forwarded on a guess.
	if x := e.call("order_bot", "GET", "/services/rest/system/v1/whatever", ""); x.status != 403 {
		t.Fatalf("unknown endpoint: %d %s", x.status, x.body)
	}
	// Killed: every call refused.
	if _, err := e.ctl.SetLevel(e.ctx, "ap_bot", control.Killed, "test kill", "user:sec@acme.com"); err != nil {
		t.Fatal(err)
	}
	if k := e.call("ap_bot", "GET", "/services/rest/record/v1/customer/101", ""); k.status != 403 || k.rule != "POL-010" {
		t.Fatalf("killed read: %d %s", k.status, k.body)
	}
}

func TestWrongCertificateRefusedByTokenEndpoint(t *testing.T) {
	e := setup(t)
	e.configure("cert-WRONG")
	if r := e.call("order_bot", "GET", "/services/rest/record/v1/customer/101", ""); r.status < 500 {
		t.Fatalf("wrong certificate id must fail upstream, got %d %s", r.status, r.body)
	}
	if e.fake.BadTokens == 0 {
		t.Fatal("the fake token endpoint was not asked")
	}
}

func TestProbesInventoryAndActivitySync(t *testing.T) {
	e := setup(t)
	e.configure("cert-123")
	ps, err := e.conn.Probes(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range ps {
		got[p.Name] = p.OK
	}
	for _, n := range []string{"oauth2_client_credentials", "suiteql", "activity_system_notes", "agent_entities"} {
		if !got[n] {
			t.Errorf("probe %s failed: %+v", n, ps)
		}
	}
	if got["agent_inventory_api"] {
		t.Error("agent inventory must be reported as NOT verified")
	}
	inv, err := e.conn.Inventory(e.ctx)
	if err != nil || len(inv.Agents) != 2 || inv.Complete {
		t.Fatalf("inventory: %+v %v", inv, err)
	}

	// Changes made directly in NetSuite (not through Fortik) by the agents'
	// entities: the read-only agent's change is a violation, seen afterwards.
	direct := func(entity, field string) {
		body := strings.NewReader(`{"Entity":"` + entity + `","RecordType":"customer","RecordID":"101","Field":"` + field + `"}`)
		res, err := http.Post(e.fsrv.URL+"/fake/direct-change", "application/json", body)
		if err != nil || res.StatusCode != 200 {
			t.Fatalf("direct change: %v", err)
		}
		res.Body.Close()
	}
	direct("4", "phone")
	direct("3", "email")
	// A gateway change (made with Fortik's own integration entity) is not an agent's.
	e.call("order_bot", "PATCH", "/services/rest/record/v1/customer/102", `{"phone":"+1 555 7777"}`)

	res, err := e.sync.Sync(e.ctx, "test")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if res.Events != 2 || res.Violations != 1 {
		t.Fatalf("sync result: %+v %s", res, e.str(`SELECT string_agg(agent_id || ': ' || rule_id || ' ' || (decision_json->'after_execution')::text, ' | ') FROM actions WHERE source = 'vendor_audit'`))
	}
	if got := e.str(`SELECT decision || ' ' || rule_id || ' ' || observed::text FROM actions WHERE agent_id = 'ap_bot' AND source = 'vendor_audit'`); got != "allow POL-021 true" {
		t.Fatalf("observed violation recorded as: %s", got)
	}
	if n := e.str(`SELECT count(*)::text FROM alerts WHERE kind = 'saas_policy_violation' AND agent_id = 'ap_bot'`); n != "1" {
		t.Fatalf("violation alerts: %s", n)
	}
	if again, err := e.sync.Sync(e.ctx, "test"); err != nil || again.Events != 0 {
		t.Fatalf("second sync must find nothing new: %+v %v", again, err)
	}
	if s := e.str(`SELECT (last_success_at IS NOT NULL)::text FROM saas_sync_state WHERE system = 'netsuite'`); s != "true" {
		t.Fatal("last successful sync not recorded")
	}
}

func TestMapRequest(t *testing.T) {
	for _, tc := range []struct {
		method, path, body, op, verb, typ string
	}{
		{"GET", "/services/rest/record/v1/customer", "", "list", "READ", "customer"},
		{"GET", "/services/rest/record/v1/salesOrder/17", "", "get", "READ", "salesorder"},
		{"POST", "/services/rest/record/v1/customer", `{"companyName":"X"}`, "create", "WRITE", "customer"},
		{"PATCH", "/services/rest/record/v1/customer/17", `{"phone":"1"}`, "update", "WRITE", "customer"},
		{"PUT", "/services/rest/record/v1/customer/eid:C-9", `{"phone":"1"}`, "upsert", "WRITE", "customer"},
		{"DELETE", "/services/rest/record/v1/customer/17", "", "delete", "DELETE", "customer"},
		{"POST", "/services/rest/record/v1/vendorBill/5/!transform/vendorPayment", `{}`, "transform", "WRITE", "vendorbill"},
		{"POST", "/services/rest/query/v1/suiteql", `{"q":"SELECT id FROM customer c JOIN employee e ON 1=1"}`, "query", "READ", ""},
		{"GET", "/services/rest/record/v1/../secret", "", "unknown", "UNKNOWN", ""},
		{"PATCH", "/services/rest/record/v1/customer/17", `{"bad key":"1"}`, "unknown", "UNKNOWN", ""},
		{"GET", "/services/rest/query/v1/suiteql", "", "unknown", "UNKNOWN", ""},
		{"POST", "/services/rest/record/v1/customer/abc;drop", `{}`, "unknown", "UNKNOWN", ""},
	} {
		m := netsuite.MapRequest(tc.method, tc.path, "", []byte(tc.body))
		if m.Operation != tc.op || string(m.Verb) != tc.verb || (tc.typ != "" && m.RecordType != tc.typ) {
			t.Errorf("%s %s: got %s %s %s", tc.method, tc.path, m.Operation, m.Verb, m.RecordType)
		}
	}
	q := netsuite.MapRequest("POST", "/services/rest/query/v1/suiteql", "limit=5", []byte(`{"q":"SELECT id FROM customer c JOIN employee e ON 1=1"}`))
	if strings.Join(q.Tables, ",") != "customer,employee" || q.Limit != 5 {
		t.Errorf("query tables/limit: %v %d", q.Tables, q.Limit)
	}
	if m := netsuite.MapRequest("PATCH", "/services/rest/record/v1/customer/1", "", []byte(`{"phone":"secret-value"}`)); strings.Contains(strings.Join(m.Fields, ","), "secret-value") {
		t.Error("field values must never reach the target")
	}
}

func TestAccountURL(t *testing.T) {
	s := netsuite.Settings{AccountID: "1234567_SB1"}
	if got := s.BaseURL(); got != "https://1234567-sb1.suitetalk.api.netsuite.com" {
		t.Fatalf("base URL: %s", got)
	}
	if got := s.TokenURL(); got != "https://1234567-sb1.suitetalk.api.netsuite.com/services/rest/auth/oauth2/v1/token" {
		t.Fatalf("token URL: %s", got)
	}
}
