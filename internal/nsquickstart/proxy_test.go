package nsquickstart

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
	"fortik/internal/alerts"
	"fortik/internal/approvals"
	"fortik/internal/authz"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/delegation"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	"fortik/internal/integrations"
	"fortik/internal/mcpclient/mcpfake"
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

const (
	rwProfile = `{"mode":"read_write","record_types":["*"],"suiteql":false}`
	roProfile = `{"mode":"read_only","record_types":["*"],"suiteql":false}`
)

var approver = authz.Principal{Kind: authz.KindUser, Email: "sec@acme.com", Name: "Sec", Roles: map[string]bool{authz.RoleSecurity: true}}

type penv struct {
	t     *testing.T
	ctx   context.Context
	pool  *pgxpool.Pool
	d     *diary.Diary
	ctl   *control.Store
	acc   *access.PGStore
	ints  *integrations.PGStore
	und   *undo.PGStore
	ov    *overrides.PGStore
	appr  *approvals.Service
	dec   *decide.Service
	svc   *Service
	fake  *mcpfake.Server
	gw    *httptest.Server
	toks  map[string]string
	exec  *UndoExecutor
	fakeU string
}

func newPEnv(t *testing.T) *penv {
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
	dcfg := config.DelegationConfig{SigningKeySecret: "delegation_key", TokenTTL: 15 * time.Minute, MaxDepth: 5, BypassOriginLevel: "SUPERVISED"}
	dstore, err := delegation.NewPGStore(ctx, pool, d, enc, dcfg)
	if err != nil {
		t.Fatal(err)
	}
	dobs, err := delegation.NewObserver(dstore, ctl, d, alerts.NewPGStore(pool, d), dcfg.BypassOriginLevel)
	if err != nil {
		t.Fatal(err)
	}
	dec.Enrichers = []decide.Enricher{delegation.NewEnricher(dstore), overrides.NewEnricher(ov), approvals.NewGrantEnricher(pool)}
	dec.Observers = []decide.Observer{dobs, approvals.NewGrantObserver(d)}
	appr := approvals.New(pool, d, und, ints, approvals.Config{GrantTTL: 10 * time.Minute}, log)

	svc := New(pool, d, ints, config.MCPUpstreamsConfig{AllowedHosts: []string{"my.quickstartapi.netsuite.com"}, AllowLoopback: true}, "test", log)
	svc.EnableUndo(und, enc, time.Hour)
	m, err := LoadMappings(policyDir())
	if err != nil {
		t.Fatal(err)
	}
	e := &penv{t: t, ctx: ctx, pool: pool, d: d, ctl: ctl, acc: acc, ints: ints, und: und, ov: ov, appr: appr, svc: svc, toks: map[string]string{}, exec: svc.UndoExecutor(), dec: dec}

	e.fake = &mcpfake.Server{Token: tokenA, ReadWrite: true, SSE: true,
		Records: map[string]map[string]map[string]any{"customer": {"12": {"phone": "+1 555 0101", "companyName": "Acme", "addressbook": map[string]any{"city": "X"}}}}}
	fs := httptest.NewServer(e.fake)
	t.Cleanup(fs.Close)
	e.fakeU = fs.URL + "/mcp"
	e.configure(tokenA)

	hashes := map[string]string{}
	for agent, prof := range map[string]string{"qs_rw": rwProfile, "qs_ro": roProfile, "qs_noprof": ""} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: agent, Type: "erp", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := ctl.SetLevel(ctx, agent, control.Full, "test", "test"); err != nil {
			t.Fatal(err)
		}
		if prof != "" {
			if _, err := acc.Put(ctx, agent, "netsuite", json.RawMessage(prof), "user:sec@acme.com", "test"); err != nil {
				t.Fatal(err)
			}
		}
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		tok := "agt_" + hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(tok))
		hashes[agent] = hex.EncodeToString(sum[:])
		e.toks[agent] = tok
	}
	raw, _ := json.Marshal(hashes)
	gw, err := gateway.NewServer(config.GatewayConfig{}, dec, gateway.NewAgentAuth(memSecrets{"agent_tokens": raw}, "agent_tokens", log), nil, log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	NewProxy(svc, dec, m, acc, d, 10*time.Minute, log).Mount(gw.Mount)
	e.gw = httptest.NewServer(gw)
	t.Cleanup(e.gw.Close)
	return e
}

func (e *penv) configure(token string) {
	e.t.Helper()
	q := func(v any) json.RawMessage { b, _ := json.Marshal(v); return b }
	if _, err := e.ints.Configure(e.ctx, IntegrationKey, integrations.ConfigureInput{
		Config:  map[string]json.RawMessage{"tenant_label": q("Acme test"), "endpoint_url": q(e.fakeU)},
		Secrets: map[string]*string{"personal_access_token": &token},
	}, "user:sec@acme.com"); err != nil {
		e.t.Fatal(err)
	}
	r, err := e.ints.Resolve(e.ctx, IntegrationKey)
	if err != nil {
		e.t.Fatal(err)
	}
	if err := e.svc.Test(e.ctx, r); err != nil {
		e.t.Fatalf("connection check: %v", err)
	}
}

// rpc sends one JSON-RPC request as agent and returns the decoded reply.
func (e *penv) rpc(agent, method string, params any) map[string]any {
	e.t.Helper()
	return e.rpcH(agent, method, params, nil)
}

func (e *penv) rpcH(agent, method string, params any, hdr map[string]string) map[string]any {
	e.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 7, "method": method, "params": params})
	req, _ := http.NewRequest("POST", e.gw.URL+ProxyPath, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if agent != "" {
		req.Header.Set("Authorization", "Bearer "+e.toks[agent])
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		out = map[string]any{"http_status": resp.StatusCode, "raw": string(raw)}
	}
	out["http_status"] = resp.StatusCode
	if strings.Contains(string(raw), tokenA) || strings.Contains(string(raw), tokenB) {
		e.t.Fatal("the QuickStart token appeared in a reply to the agent")
	}
	return out
}

func (e *penv) call(agent, tool string, args any) (result map[string]any, meta map[string]any, text string) {
	e.t.Helper()
	out := e.rpc(agent, "tools/call", map[string]any{"name": tool, "arguments": args})
	res, _ := out["result"].(map[string]any)
	if res == nil {
		e.t.Fatalf("tools/call %s: no result: %v", tool, out)
	}
	meta, _ = res["_meta"].(map[string]any)
	for _, c := range res["content"].([]any) {
		if m, ok := c.(map[string]any); ok {
			text += m["text"].(string)
		}
	}
	return res, meta, text
}

func (e *penv) toolCalls(name string) int {
	n := 0
	for _, c := range e.fake.ToolCalls() {
		if c.Name == name {
			n++
		}
	}
	return n
}

func (e *penv) approve(actionID string) {
	e.t.Helper()
	if _, err := e.appr.Approve(e.ctx, approver, actionID, approvals.ApproveRequest{Reason: "checked the change with finance"}); err != nil {
		e.t.Fatalf("approve %s: %v", actionID, err)
	}
}

func (e *penv) decision(actionID string) (decision, rule string, target map[string]any) {
	e.t.Helper()
	var raw []byte
	if err := e.pool.QueryRow(e.ctx, `SELECT decision, rule_id, target FROM actions WHERE action_id = $1`, actionID).Scan(&decision, &rule, &raw); err != nil {
		e.t.Fatalf("action %s: %v", actionID, err)
	}
	_ = json.Unmarshal(raw, &target)
	return
}

func integrationsInput(label json.RawMessage, endpoint string, token *string) integrations.ConfigureInput {
	ep, _ := json.Marshal(endpoint)
	return integrations.ConfigureInput{Config: map[string]json.RawMessage{"tenant_label": label, "endpoint_url": ep},
		Secrets: map[string]*string{"personal_access_token": token}}
}

func approvalsReq() approvals.ApproveRequest {
	return approvals.ApproveRequest{Reason: "checked the change with finance"}
}
