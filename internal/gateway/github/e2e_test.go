package github_test

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
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/authz"
	"fortik/internal/broker"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/broker/github/fakegithub"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/gateway"
	ghgw "fortik/internal/gateway/github"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/secrets"
	"fortik/internal/testutil"
	"fortik/internal/undo"
)

// memSecrets is an in-memory secrets.Provider for the agent token hashes.
type memSecrets map[string][]byte

func (m memSecrets) Get(_ context.Context, name string) ([]byte, error) {
	if v, ok := m[name]; ok {
		return v, nil
	}
	return nil, secrets.ErrNotFound
}

const (
	writerProfile = `{"repos":["acme/api"],"permissions":{"contents":"write","pull_requests":"write","issues":"write","metadata":"read"}}`
	readerProfile = `{"repos":["acme/api"],"permissions":{"contents":"read","metadata":"read"}}`
)

type env struct {
	t     *testing.T
	ctx   context.Context
	pool  *pgxpool.Pool
	ctl   *control.Store
	ints  *integrations.PGStore
	und   *undo.PGStore
	f     *fakegithub.Server
	ad    *ghgw.Adapter
	brk   *broker.Service
	srv   *httptest.Server
	toks  map[string]string // agent -> Fortik agent token
	seen  [][]byte          // every response (headers + body) the agents received
	mainS string            // initial sha of acme/api main
}

func policyDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "policies")
}

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

	client := ghbroker.NewClient(nil)
	gh, err := ghbroker.NewAdapter(ghbroker.AdapterConfig{Client: client, Source: ints, Profiles: acc, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gh.Close)
	brk := broker.New(svc, pool, d, acc, map[string]broker.Adapter{"github": gh}, log)
	ad, err := ghgw.New(ghgw.Config{Source: ints, Profiles: acc, Undo: und, Recorder: brk, Client: client, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	gh.OnRevokeAgent(ad.DropAgent)

	e := &env{t: t, ctx: ctx, pool: pool, ctl: ctl, ints: ints, und: und, ad: ad, brk: brk, toks: map[string]string{}}
	hashes := map[string]string{}
	profiles := map[string]string{"coder": writerProfile, "pusher": writerProfile, "reckless": writerProfile,
		"ci_editor": writerProfile, "reader": readerProfile}
	for agent, prof := range profiles {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: agent, Type: "coding", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
		if _, err := acc.Put(ctx, agent, "github", json.RawMessage(prof), "user:sec@acme.com", "test setup"); err != nil {
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
	auth := gateway.NewAgentAuth(memSecrets{"agent_tokens": raw}, "agent_tokens", log)
	gw, err := gateway.NewServer(config.GatewayConfig{}, svc, auth, []gateway.Adapter{ad}, log, gateway.WithDiary(d))
	if err != nil {
		t.Fatal(err)
	}
	e.srv = httptest.NewServer(gw)
	t.Cleanup(e.srv.Close)

	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	f.AddRepo("acme", "secret")
	e.mainS = f.BranchSHA("acme/api", "main")
	f.SetBranch("acme/api", "main", e.mainS, true)
	f.SetBranch("acme/api", "feat/x", f.NextSHA(), false)
	f.SetBranch("acme/api", "feat/old", f.NextSHA(), false)
	f.SetBranch("acme/api", "feat/z", f.NextSHA(), false)
	f.SetBranch("acme/api", "release/2.0", f.NextSHA(), false)
	f.AddPull("acme/api", 7, "main", "feat/x")
	f.AddPull("acme/api", 8, "main", "feat/old")
	f.AddPull("acme/api", 9, "main", "feat/x")
	e.f = f
	return e
}

func (e *env) configure() {
	e.t.Helper()
	pem := e.f.PrivateKeyPEM
	q := func(s string) json.RawMessage { b, _ := json.Marshal(s); return b }
	_, err := e.ints.Configure(e.ctx, "github", integrations.ConfigureInput{
		Config:  map[string]json.RawMessage{"api_base_url": q(e.f.URL), "app_id": q(e.f.AppID), "installation_id": q(e.f.InstallationID)},
		Secrets: map[string]*string{"private_key_pem": &pem},
	}, "user:sec@acme.com")
	if err != nil {
		e.t.Fatalf("configure github integration: %v", err)
	}
}

type resp struct {
	status   int
	body     []byte
	actionID string
	refusal  struct {
		Code     string `json:"code"`
		Decision string `json:"decision"`
		RuleID   string `json:"rule_id"`
		Reason   string `json:"reason"`
		Held     bool   `json:"held"`
	}
}

func (e *env) do(agent, method, path, body string) resp {
	e.t.Helper()
	req, _ := http.NewRequest(method, e.srv.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.toks[agent])
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	hr, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer hr.Body.Close()
	b, _ := io.ReadAll(hr.Body)
	var hdr bytes.Buffer
	_ = hr.Header.Write(&hdr)
	e.seen = append(e.seen, append(hdr.Bytes(), b...))
	r := resp{status: hr.StatusCode, body: b, actionID: hr.Header.Get(gateway.ActionIDHeader)}
	var wrap struct {
		Error json.RawMessage `json:"error"`
	}
	if json.Unmarshal(b, &wrap) == nil && len(wrap.Error) > 0 && wrap.Error[0] == '{' {
		_ = json.Unmarshal(wrap.Error, &r.refusal)
	}
	return r
}

func (e *env) decision(actionID string) (decision, rule string) {
	e.t.Helper()
	if err := e.pool.QueryRow(e.ctx, `SELECT decision, rule_id FROM actions WHERE action_id = $1`, actionID).Scan(&decision, &rule); err != nil {
		e.t.Fatalf("action %s not recorded: %v", actionID, err)
	}
	return decision, rule
}

func (e *env) level(agent string) control.Level {
	e.t.Helper()
	st, err := e.ctl.Get(e.ctx, agent)
	if err != nil {
		e.t.Fatal(err)
	}
	return st.Level
}

// undoAction runs the same sequence as POST /v1/undo/{id}.
func (e *env) undoAction(actionID string) map[string]any {
	e.t.Helper()
	h, err := e.und.Claim(e.ctx, actionID, "user:sec@acme.com")
	if err != nil {
		e.t.Fatalf("claim undo: %v", err)
	}
	res, err := e.ad.UndoExecutor().Undo(e.ctx, h)
	if err != nil {
		_ = e.und.Release(e.ctx, actionID, "user:sec@acme.com", err.Error())
		e.t.Fatalf("undo: %v", err)
	}
	if err := e.und.Complete(e.ctx, actionID, "user:sec@acme.com", res); err != nil {
		e.t.Fatal(err)
	}
	return res
}

// undoRefused runs the undo sequence and expects the executor to refuse.
func (e *env) undoRefused(actionID string) error {
	e.t.Helper()
	h, err := e.und.Claim(e.ctx, actionID, "user:sec@acme.com")
	if err != nil {
		e.t.Fatalf("claim undo: %v", err)
	}
	res, err := e.ad.UndoExecutor().Undo(e.ctx, h)
	if err == nil {
		e.t.Fatalf("undo succeeded but must refuse: %v", res)
	}
	_ = e.und.Release(e.ctx, actionID, "user:sec@acme.com", err.Error())
	return err
}

func (e *env) handle(actionID string) (undo.Handle, map[string]any) {
	e.t.Helper()
	h, err := e.und.Get(e.ctx, actionID)
	if err != nil {
		e.t.Fatalf("no undo handle for %s: %v", actionID, err)
	}
	var data map[string]any
	_ = json.Unmarshal(h.Data, &data)
	return h, data
}

func TestGatewayEndToEnd(t *testing.T) {
	e := setup(t)
	f := e.f

	t.Run("integration not configured: 503 after the decision is recorded", func(t *testing.T) {
		r := e.do("coder", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/x", `{"sha":"`+f.NextSHA()+`"}`)
		if r.status != http.StatusServiceUnavailable || !strings.Contains(string(r.body), "integration_not_configured") {
			t.Fatalf("want 503 integration_not_configured, got %d %s", r.status, r.body)
		}
		if dec, _ := e.decision(r.actionID); dec != "allow" {
			t.Fatalf("decision = %s", dec)
		}
		if len(f.Calls()) != 0 {
			t.Fatal("GitHub was called without an integration")
		}
	})

	e.configure()

	t.Run("push to a feature branch is allowed and forwarded", func(t *testing.T) {
		sha := f.NextSHA()
		r := e.do("coder", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/x", `{"sha":"`+sha+`"}`)
		if r.status != http.StatusOK {
			t.Fatalf("status %d %s", r.status, r.body)
		}
		if got := f.BranchSHA("acme/api", "feat/x"); got != sha {
			t.Fatalf("branch not updated: %s", got)
		}
		dec, rule := e.decision(r.actionID)
		if dec != "allow" {
			t.Fatalf("decision %s %s", dec, rule)
		}
		var scope string
		if err := e.pool.QueryRow(e.ctx, `SELECT scope_json::text FROM credential_issuances WHERE action_id = $1 AND agent_id = 'coder'`, r.actionID).Scan(&scope); err != nil {
			t.Fatalf("gateway-minted token not recorded: %v", err)
		}
		if !strings.Contains(scope, `"mode": "gateway"`) || !strings.Contains(scope, `"acme/api"`) {
			t.Fatalf("issuance scope: %s", scope)
		}
		// A second push reuses the cached token (no new mint, no new issuance).
		before := len(f.Tokens())
		r2 := e.do("coder", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/x", `{"sha":"`+f.NextSHA()+`"}`)
		if r2.status != http.StatusOK || len(f.Tokens()) != before {
			t.Fatalf("second push: status %d, tokens %d -> %d", r2.status, before, len(f.Tokens()))
		}
	})

	t.Run("token is narrowed to one repo and the operation's permissions", func(t *testing.T) {
		found := false
		for _, tk := range f.Tokens() {
			if tk.Permissions["contents"] == "write" && len(tk.Permissions) == 1 {
				found = true
				if len(tk.Repos) != 1 || !tk.Repos["api"] {
					t.Fatalf("push token repos: %v", tk.Repos)
				}
			}
			if tk.Repos == nil {
				t.Fatal("a token covering all repositories was minted")
			}
		}
		if !found {
			t.Fatal("no contents:write-only token minted")
		}
	})

	t.Run("force_push to protected main is refused (POL-301) and the agent stepped down", func(t *testing.T) {
		r := e.do("pusher", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/main", `{"sha":"`+f.NextSHA()+`","force":true}`)
		if r.status != http.StatusForbidden || r.refusal.RuleID != "POL-301" || r.refusal.Code != "fortik_refused" {
			t.Fatalf("want 403 POL-301, got %d %s", r.status, r.body)
		}
		if f.BranchSHA("acme/api", "main") != e.mainS {
			t.Fatal("main was rewritten")
		}
		if lvl := e.level("pusher"); lvl != control.Isolated {
			t.Fatalf("pusher level = %s, want ISOLATED", lvl)
		}
		w := e.do("pusher", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/x", `{"sha":"`+f.NextSHA()+`"}`)
		if w.status != http.StatusForbidden || w.refusal.RuleID != "POL-012" {
			t.Fatalf("write after step-down: want POL-012, got %d %s", w.status, w.body)
		}
		if rd := e.do("pusher", "GET", "/gw/github/repos/acme/api", ""); rd.status != http.StatusOK {
			t.Fatalf("internal read after step-down: %d %s", rd.status, rd.body)
		}
	})

	t.Run("push to release/x records the ref and undo restores it", func(t *testing.T) {
		prev := f.BranchSHA("acme/api", "release/2.0")
		next := f.NextSHA()
		r := e.do("coder", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/release/2.0", `{"sha":"`+next+`"}`)
		if r.status != http.StatusOK {
			t.Fatalf("status %d %s", r.status, r.body)
		}
		if dec, rule := e.decision(r.actionID); dec != "allow_reduced" || rule != "POL-302" {
			t.Fatalf("decision %s %s", dec, rule)
		}
		h, data := e.handle(r.actionID)
		if h.Kind != ghgw.KindRef || h.Status != undo.StatusActive || data["previous_sha"] != prev || data["ref"] != "heads/release/2.0" {
			t.Fatalf("handle: %+v %v", h, data)
		}
		if f.BranchSHA("acme/api", "release/2.0") != next {
			t.Fatal("push not applied")
		}
		res := e.undoAction(r.actionID)
		if f.BranchSHA("acme/api", "release/2.0") != prev {
			t.Fatalf("undo did not restore the ref: %v", res)
		}
	})

	t.Run("contents API on the default (protected) branch is enriched, recorded and undoable", func(t *testing.T) {
		prev := f.BranchSHA("acme/api", "main")
		r := e.do("coder", "PUT", "/gw/github/repos/acme/api/contents/README.md", `{"message":"docs","content":"aGVsbG8="}`)
		if r.status != http.StatusCreated {
			t.Fatalf("status %d %s", r.status, r.body)
		}
		var branch, protected string
		if err := e.pool.QueryRow(e.ctx, `SELECT target->>'branch', target->>'protected' FROM actions WHERE action_id = $1`, r.actionID).Scan(&branch, &protected); err != nil {
			t.Fatal(err)
		}
		if branch != "main" || protected != "true" {
			t.Fatalf("enrichment: branch=%q protected=%q", branch, protected)
		}
		if dec, rule := e.decision(r.actionID); dec != "allow_reduced" || rule != "POL-302" {
			t.Fatalf("decision %s %s", dec, rule)
		}
		_, data := e.handle(r.actionID)
		if data["previous_sha"] != prev || data["ref"] != "heads/main" {
			t.Fatalf("handle data %v", data)
		}
		e.undoAction(r.actionID)
		if f.BranchSHA("acme/api", "main") != prev {
			t.Fatal("undo did not restore main")
		}
	})

	t.Run("close_pr records the state and undo reopens", func(t *testing.T) {
		r := e.do("coder", "PATCH", "/gw/github/repos/acme/api/pulls/8", `{"state":"closed"}`)
		if r.status != http.StatusOK {
			t.Fatalf("status %d %s", r.status, r.body)
		}
		h, data := e.handle(r.actionID)
		if h.Kind != ghgw.KindPR || data["previous_state"] != "open" {
			t.Fatalf("handle %+v %v", h, data)
		}
		if st, _ := f.PullState("acme/api", 8); st != "closed" {
			t.Fatal("PR not closed")
		}
		e.undoAction(r.actionID)
		if st, _ := f.PullState("acme/api", 8); st != "open" {
			t.Fatal("undo did not reopen the PR")
		}
	})

	t.Run("merge_pr into protected main records the base ref and undo restores it", func(t *testing.T) {
		prev := f.BranchSHA("acme/api", "main")
		r := e.do("coder", "PUT", "/gw/github/repos/acme/api/pulls/7/merge", `{"merge_method":"merge"}`)
		if r.status != http.StatusOK {
			t.Fatalf("status %d %s", r.status, r.body)
		}
		if dec, rule := e.decision(r.actionID); dec != "allow_reduced" || rule != "POL-302" {
			t.Fatalf("decision %s %s", dec, rule)
		}
		_, data := e.handle(r.actionID)
		if data["ref"] != "heads/main" || data["previous_sha"] != prev || data["operation"] != "merge_pr" {
			t.Fatalf("handle %v", data)
		}
		if _, merged := f.PullState("acme/api", 7); !merged || f.BranchSHA("acme/api", "main") == prev {
			t.Fatal("merge not applied")
		}
		e.undoAction(r.actionID)
		if f.BranchSHA("acme/api", "main") != prev {
			t.Fatal("undo did not restore the base ref")
		}
	})

	t.Run("delete_branch records the ref and undo recreates the branch", func(t *testing.T) {
		prev := f.BranchSHA("acme/api", "feat/old")
		r := e.do("coder", "DELETE", "/gw/github/repos/acme/api/git/refs/heads/feat/old", "")
		if r.status != http.StatusNoContent {
			t.Fatalf("status %d %s", r.status, r.body)
		}
		if f.BranchSHA("acme/api", "feat/old") != "" {
			t.Fatal("branch not deleted")
		}
		e.undoAction(r.actionID)
		if f.BranchSHA("acme/api", "feat/old") != prev {
			t.Fatal("undo did not recreate the branch")
		}
	})

	t.Run("undo never discards commits pushed after the action", func(t *testing.T) {
		check := func(name, branch, method, path, body string, wantStatus int) {
			t.Helper()
			r := e.do("coder", method, path, body)
			if r.status != wantStatus {
				t.Fatalf("%s: status %d %s", name, r.status, r.body)
			}
			later := f.PushCommit("acme/api", branch) // a human/CI push after the agent
			err := e.undoRefused(r.actionID)
			if !errors.Is(err, undo.ErrNothingToUndo) {
				t.Fatalf("%s: want ErrNothingToUndo, got %v", name, err)
			}
			if got := f.BranchSHA("acme/api", branch); got != later {
				t.Fatalf("%s: undo rewound %s past a later commit (now %s, want %s)", name, branch, got, later)
			}
		}
		check("push", "release/2.0", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/release/2.0", `{"sha":"`+f.NextSHA()+`"}`, http.StatusOK)
		check("contents", "main", "PUT", "/gw/github/repos/acme/api/contents/README.md", `{"message":"docs","content":"aGVsbG8="}`, http.StatusCreated)
		check("merge_pr", "main", "PUT", "/gw/github/repos/acme/api/pulls/9/merge", `{"merge_method":"merge"}`, http.StatusOK)

		// delete_branch, then someone recreates the branch: undo must not move it.
		f.SetBranch("acme/api", "feat/gone", f.NextSHA(), false)
		r := e.do("coder", "DELETE", "/gw/github/repos/acme/api/git/refs/heads/feat/gone", "")
		if r.status != http.StatusNoContent {
			t.Fatalf("delete: status %d %s", r.status, r.body)
		}
		recreated := f.NextSHA()
		f.SetBranch("acme/api", "feat/gone", recreated, false)
		if err := e.undoRefused(r.actionID); !errors.Is(err, undo.ErrNothingToUndo) {
			t.Fatalf("delete: want ErrNothingToUndo, got %v", err)
		}
		if f.BranchSHA("acme/api", "feat/gone") != recreated {
			t.Fatal("delete: undo moved a recreated branch")
		}
	})

	t.Run("repo not in the profile is refused by the access gate (POL-024)", func(t *testing.T) {
		r := e.do("coder", "PATCH", "/gw/github/repos/acme/secret/git/refs/heads/main", `{"sha":"`+f.NextSHA()+`"}`)
		if r.status != http.StatusForbidden || r.refusal.RuleID != "POL-024" {
			t.Fatalf("want 403 POL-024, got %d %s", r.status, r.body)
		}
		rd := e.do("coder", "GET", "/gw/github/repos/acme/secret/contents/x", "")
		if rd.status != http.StatusForbidden || rd.refusal.RuleID != "POL-024" {
			t.Fatalf("read outside profile: want POL-024, got %d %s", rd.status, rd.body)
		}
		for _, tk := range f.Tokens() {
			if tk.Repos["secret"] {
				t.Fatal("a token was minted for a repository outside the profile")
			}
		}
	})

	t.Run("missing permission is refused (POL-024)", func(t *testing.T) {
		r := e.do("reader", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/x", `{"sha":"`+f.NextSHA()+`"}`)
		if r.status != http.StatusForbidden || r.refusal.RuleID != "POL-024" {
			t.Fatalf("want 403 POL-024, got %d %s", r.status, r.body)
		}
		if rd := e.do("reader", "GET", "/gw/github/repos/acme/api/branches/main", ""); rd.status != http.StatusOK {
			t.Fatalf("reader read: %d %s", rd.status, rd.body)
		}
	})

	t.Run("delete_repo is refused", func(t *testing.T) {
		r := e.do("reckless", "DELETE", "/gw/github/repos/acme/api", "")
		if r.status != http.StatusForbidden || r.refusal.RuleID != "POL-304" {
			t.Fatalf("want 403 POL-304, got %d %s", r.status, r.body)
		}
		if f.RepoDeleted("acme/api") || exactCalls(f, "DELETE", "/repos/acme/api") != 0 {
			t.Fatal("delete reached GitHub")
		}
	})

	t.Run("workflow change is refused (POL-303)", func(t *testing.T) {
		r := e.do("ci_editor", "PUT", "/gw/github/repos/acme/api/contents/.github/workflows/ci.yml", `{"message":"ci","content":"eA==","branch":"feat/x"}`)
		if r.status != http.StatusForbidden || r.refusal.RuleID != "POL-303" {
			t.Fatalf("want 403 POL-303, got %d %s", r.status, r.body)
		}
	})

	t.Run("unknown endpoint is refused (POL-002) without a step-down", func(t *testing.T) {
		before := len(f.Calls())
		r := e.do("coder", "POST", "/gw/github/repos/acme/api/labels", `{"name":"x"}`)
		if r.status != http.StatusForbidden || r.refusal.RuleID != "POL-002" {
			t.Fatalf("want 403 POL-002, got %d %s", r.status, r.body)
		}
		g := e.do("coder", "POST", "/gw/github/graphql", `{"query":"mutation { deleteRepository }"}`)
		// No repository in the target: the access gate's POL-024 or POL-002,
		// both a plain deny.
		if g.status != http.StatusForbidden || g.refusal.Decision != "deny" || (g.refusal.RuleID != "POL-002" && g.refusal.RuleID != "POL-024") {
			t.Fatalf("graphql: want deny POL-002/POL-024, got %d %s", g.status, g.body)
		}
		if len(f.Calls()) != before || e.level("coder") != control.Full {
			t.Fatal("unknown request reached GitHub or stepped the agent down")
		}
	})

	t.Run("failed pre-decision lookup fails closed", func(t *testing.T) {
		f.SetFailBranches(true)
		defer f.SetFailBranches(false)
		prev := f.BranchSHA("acme/api", "feat/z")
		r := e.do("coder", "PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/z", `{"sha":"`+f.NextSHA()+`"}`)
		// The gateway server decides an enrich failure as UNKNOWN without the
		// repo, so the access gate (POL-024) or POL-002 denies it.
		if r.status != http.StatusForbidden || r.refusal.Decision != "deny" || (r.refusal.RuleID != "POL-002" && r.refusal.RuleID != "POL-024") {
			t.Fatalf("want 403 deny (enrich failed -> UNKNOWN), got %d %s", r.status, r.body)
		}
		var verb string
		if err := e.pool.QueryRow(e.ctx, `SELECT verb FROM actions WHERE action_id = $1`, r.actionID).Scan(&verb); err != nil || verb != "UNKNOWN" {
			t.Fatalf("enrich failure must be recorded as UNKNOWN: %q %v", verb, err)
		}
		if f.BranchSHA("acme/api", "feat/z") != prev {
			t.Fatal("ref changed although the protection lookup failed")
		}
	})

	t.Run("a token echoed by the upstream is redacted", func(t *testing.T) {
		r := e.do("coder", "GET", "/gw/github/repos/acme/api/fortik-test/echo-auth", "")
		if r.status != http.StatusOK || !strings.Contains(string(r.body), "[redacted-by-fortik]") {
			t.Fatalf("echo: %d %s", r.status, r.body)
		}
		if strings.Contains(string(r.body), e.toks["coder"]) {
			t.Fatal("the agent's Fortik token was forwarded upstream")
		}
	})

	t.Run("RevokeAll drops and revokes the gateway's cached tokens", func(t *testing.T) {
		if e.ad.CachedTokens("coder") == 0 {
			t.Fatal("expected cached tokens for coder")
		}
		res, err := e.brk.RevokeAll(e.ctx, "coder", "user:sec@acme.com", "test")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res["github"], "github gateway: dropped") || !strings.Contains(res["github"], "expire within 1h") {
			t.Fatalf("description: %v", res)
		}
		if e.ad.CachedTokens("coder") != 0 {
			t.Fatal("cache not dropped")
		}
		// Every token minted for an agent is now revoked; only Fortik's
		// own read-only lookup tokens remain live.
		for _, tk := range f.Tokens() {
			if !tk.Revoked {
				for k, v := range tk.Permissions {
					if v != "read" {
						t.Fatalf("a write-capable token is still live: %s:%s", k, v)
					}
				}
			}
		}
		// The next allowed request mints a fresh token.
		if r := e.do("coder", "GET", "/gw/github/repos/acme/api", ""); r.status != http.StatusOK {
			t.Fatalf("read after revoke: %d %s", r.status, r.body)
		}
	})

	t.Run("no token ever reached an agent or Postgres", func(t *testing.T) {
		toks := f.Tokens()
		if len(toks) == 0 {
			t.Fatal("no tokens minted")
		}
		for _, tk := range toks {
			for _, s := range e.seen {
				if bytes.Contains(s, []byte(tk.Value)) {
					t.Fatalf("installation token leaked to an agent: %s", s)
				}
			}
			var n int
			if err := e.pool.QueryRow(e.ctx, `SELECT
				(SELECT count(*) FROM diary WHERE strpos(body_json, $1) > 0) +
				(SELECT count(*) FROM credential_issuances WHERE strpos(scope_json::text, $1) > 0) +
				(SELECT count(*) FROM actions WHERE strpos(target::text, $1) > 0 OR strpos(decision_json::text, $1) > 0) +
				(SELECT count(*) FROM undo_handles WHERE strpos(handle_json::text, $1) > 0) +
				(SELECT count(*) FROM integrations WHERE strpos(config_json::text, $1) > 0)`, tk.Value).Scan(&n); err != nil {
				t.Fatal(err)
			}
			if n != 0 {
				t.Fatal("an installation token is stored in Postgres")
			}
		}
		var keyRows int
		if err := e.pool.QueryRow(e.ctx, `SELECT count(*) FROM integrations WHERE strpos(config_json::text, 'PRIVATE KEY') > 0`).Scan(&keyRows); err != nil {
			t.Fatal(err)
		}
		if keyRows != 0 {
			t.Fatal("the app private key is stored in Postgres")
		}
	})
}

func exactCalls(f *fakegithub.Server, method, path string) int {
	n := 0
	for _, c := range f.Calls() {
		if c.Method == method && c.Path == path {
			n++
		}
	}
	return n
}

// TestForwardBacksUpPolicy drives Forward directly with an allow decision the
// policy would never produce, proving the adapter's own checks hold even if
// the access gate is missing or wrong.
func TestForwardBacksUpPolicy(t *testing.T) {
	e := setup(t)
	e.configure()
	p := authz.Principal{Kind: authz.KindAgent, Name: "coder"}
	run := func(method, path, body string, rf map[string]any) error {
		r := httptest.NewRequest(method, "http://gw"+path, strings.NewReader(body))
		op, err := e.ad.Map(e.ctx, p, r, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if err := e.ad.Enrich(e.ctx, p, &op); err != nil {
			t.Fatal(err)
		}
		a := op.Action
		a.ActionID = action.NewID("act")
		out := decide.Outcome{Action: a, Result: policy.Result{Decision: policy.Allow, ReducedForm: rf}}
		if len(rf) > 0 {
			out.Result.Decision = policy.AllowReduced
		}
		return e.ad.Forward(e.ctx, p, &op, out, httptest.NewRecorder(), r)
	}
	var refused *gateway.RefusedError
	if err := run("PATCH", "/gw/github/repos/acme/secret/git/refs/heads/main", `{"sha":"`+e.f.NextSHA()+`"}`, nil); !errors.As(err, &refused) || refused.RuleID != ghgw.RuleProfile {
		t.Fatalf("repo outside profile: want %s refusal, got %v", ghgw.RuleProfile, err)
	}
	if err := run("DELETE", "/gw/github/repos/acme/api", "", nil); !errors.As(err, &refused) || refused.RuleID != ghgw.RuleProfile {
		t.Fatalf("delete_repo needs administration:write: want %s refusal, got %v", ghgw.RuleProfile, err)
	}
	if err := run("POST", "/gw/github/repos/acme/api/labels", `{}`, nil); !errors.As(err, &refused) || refused.RuleID != ghgw.RuleUnknown {
		t.Fatalf("unknown: want %s refusal, got %v", ghgw.RuleUnknown, err)
	}
	if err := run("GET", "/gw/github/user", "", nil); !errors.As(err, &refused) || refused.RuleID != ghgw.RuleScope {
		t.Fatalf("non-repo read: want %s refusal, got %v", ghgw.RuleScope, err)
	}
	var unsupported gateway.ErrReducedFormUnsupported
	if err := run("PATCH", "/gw/github/repos/acme/api/git/refs/heads/feat/x", `{"sha":"`+e.f.NextSHA()+`"}`, map[string]any{"delay_send_seconds": 120.0}); !errors.As(err, &unsupported) {
		t.Fatalf("unknown reduced form: want ErrReducedFormUnsupported, got %v", err)
	}
	if err := run("POST", "/gw/github/repos/acme/api/pulls", `{"title":"t","head":"feat/x","base":"main"}`, map[string]any{"record_ref": true}); !errors.As(err, &unsupported) {
		t.Fatalf("record_ref on create_pr: want ErrReducedFormUnsupported, got %v", err)
	}
	if n := len(e.f.Tokens()); n != 1 { // only Fortik's protection-lookup token for feat/x
		t.Fatalf("refused Forward calls must not mint agent tokens (tokens=%d)", n)
	}
	if e.f.CallsMatching("PATCH", "/repos/") != 0 || e.f.CallsMatching("POST", "/repos/") != 0 || e.f.CallsMatching("DELETE", "/repos/") != 0 {
		t.Fatal("a refused request reached GitHub")
	}
	// A different principal than the decided agent is refused.
	r := httptest.NewRequest("GET", "http://gw/gw/github/repos/acme/api", nil)
	op, _ := e.ad.Map(e.ctx, p, r, nil)
	op.Action.ActionID = action.NewID("act")
	other := authz.Principal{Kind: authz.KindAgent, Name: "reader"}
	err := e.ad.Forward(e.ctx, other, &op, decide.Outcome{Action: op.Action, Result: policy.Result{Decision: policy.Allow}}, httptest.NewRecorder(), r)
	if !errors.As(err, &refused) || refused.RuleID != ghgw.RuleRefused {
		t.Fatalf("principal mismatch: %v", err)
	}
	// A non-executing decision is refused.
	err = e.ad.Forward(e.ctx, p, &op, decide.Outcome{Action: op.Action, Result: policy.Result{Decision: policy.Hold}}, httptest.NewRecorder(), r)
	if !errors.As(err, &refused) {
		t.Fatalf("hold decision forwarded: %v", err)
	}
}
