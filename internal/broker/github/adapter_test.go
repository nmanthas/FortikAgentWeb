package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"fortik/internal/access"
	"fortik/internal/broker"
	ghbroker "fortik/internal/broker/github"
	"fortik/internal/broker/github/fakegithub"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/testutil"
)

// staticSource is an integrations.Source returning one fixed integration.
type staticSource struct {
	res integrations.Resolved
	err error
}

func (s staticSource) Get(_ context.Context, key string) (integrations.Resolved, error) {
	if key != "github" {
		return integrations.Resolved{}, integrations.ErrNotConfigured
	}
	return s.res, s.err
}

func (s staticSource) List(context.Context, string) ([]integrations.Resolved, error) { return nil, nil }

// stubProfiles is a ghbroker.ProfileSource over fixed JSON profiles.
type stubProfiles map[string]string

func (p stubProfiles) Current(_ context.Context, agentID, system string) (access.Profile, error) {
	raw, ok := p[agentID]
	if !ok || system != "github" {
		return access.Profile{}, access.ErrNotFound
	}
	return access.Profile{AgentID: agentID, System: system, Version: 3, Profile: json.RawMessage(raw)}, nil
}

const directProfile = `{"repos":["acme/api"],"permissions":{"contents":"read","issues":"write"},"allow_direct_token":true}`

func newBrokerAdapter(t *testing.T, f *fakegithub.Server, profiles stubProfiles) *ghbroker.Adapter {
	t.Helper()
	a, err := ghbroker.NewAdapter(ghbroker.AdapterConfig{Source: staticSource{res: resolved(f)}, Profiles: profiles})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.Close)
	return a
}

func TestMintNarrowsToProfile(t *testing.T) {
	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	f.AddRepo("acme", "web")
	a := newBrokerAdapter(t, f, stubProfiles{"bot": directProfile})
	cred, err := a.Mint(context.Background(), "bot", map[string]any{
		"repos":       []string{"acme/api", "acme/web"},
		"permissions": map[string]string{"contents": "write", "issues": "write", "pull_requests": "write"},
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cred.System != "github" || cred.Secret["token"] == "" || cred.IssuanceID == "" {
		t.Fatalf("credential: %+v", cred.Scope)
	}
	toks := f.Tokens()
	if len(toks) != 1 {
		t.Fatalf("want one token, got %d", len(toks))
	}
	tk := toks[0]
	if len(tk.Repos) != 1 || !tk.Repos["api"] {
		t.Fatalf("token must cover only acme/api (profile ∩ request): %v", tk.Repos)
	}
	if tk.Permissions["contents"] != "read" || tk.Permissions["issues"] != "write" || tk.Permissions["pull_requests"] != "" {
		t.Fatalf("permissions must be lowered to the profile: %v", tk.Permissions)
	}
	if b, _ := json.Marshal(cred.Scope); strings.Contains(string(b), cred.Secret["token"]) {
		t.Fatal("scope contains the secret")
	}
	if cred.Scope["profile_version"] != 3 || cred.ExpiresAt.Sub(time.Now()) > time.Hour+time.Minute {
		t.Fatalf("scope/expiry: %+v %s", cred.Scope, cred.ExpiresAt)
	}
	if a.LiveTokens("bot") != 1 {
		t.Fatal("token not registered for revocation")
	}
}

func TestMintRefusals(t *testing.T) {
	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	noDirect := `{"repos":["acme/api"],"permissions":{"contents":"write"},"allow_direct_token":false}`
	a := newBrokerAdapter(t, f, stubProfiles{"bot": directProfile, "gw_only": noDirect})
	ctx := context.Background()
	scope := map[string]any{"repos": []string{"acme/api"}, "permissions": map[string]string{"contents": "read"}}

	cases := []struct {
		agent string
		scope map[string]any
		want  error
	}{
		{"gw_only", scope, ghbroker.ErrDirectTokenNotAllowed},
		{"nobody", scope, ghbroker.ErrNoProfile},
		{"bot", map[string]any{"repos": []string{"acme/web"}, "permissions": map[string]string{"contents": "read"}}, ghbroker.ErrEmptyScope},
		{"bot", map[string]any{"repos": []string{"acme/api"}, "permissions": map[string]string{"administration": "write"}}, ghbroker.ErrEmptyScope},
		{"bot", map[string]any{"repos": []string{"acme/api"}}, ghbroker.ErrBadScope},
		{"bot", map[string]any{"repos": []string{"not a repo"}, "permissions": map[string]string{"contents": "read"}}, ghbroker.ErrBadScope},
	}
	for _, c := range cases {
		_, err := a.Mint(ctx, c.agent, c.scope, 0)
		if !errors.Is(err, c.want) || !errors.Is(err, broker.ErrScopeDenied) {
			t.Fatalf("%s %v: want %v (wrapping ErrScopeDenied), got %v", c.agent, c.scope, c.want, err)
		}
	}
	if len(f.Tokens()) != 0 {
		t.Fatal("a refused mint reached GitHub")
	}

	// Wrong owner: the profile lists it, but the installation is on "acme".
	evil := newBrokerAdapter(t, f, stubProfiles{"bot": `{"repos":["evil/api"],"permissions":{"contents":"read"},"allow_direct_token":true}`})
	if _, err := evil.Mint(ctx, "bot", map[string]any{"repos": []string{"evil/api"}, "permissions": map[string]string{"contents": "read"}}, 0); !errors.Is(err, ghbroker.ErrWrongOwner) {
		t.Fatalf("wrong owner: %v", err)
	}

	unconfigured, _ := ghbroker.NewAdapter(ghbroker.AdapterConfig{Source: staticSource{err: integrations.ErrNotConfigured}, Profiles: stubProfiles{"bot": directProfile}})
	if _, err := unconfigured.Mint(ctx, "bot", scope, 0); !errors.Is(err, broker.ErrNotConfigured) {
		t.Fatalf("not configured: %v", err)
	}
}

func TestMintUsesScopeProfile(t *testing.T) {
	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	a := newBrokerAdapter(t, f, nil) // no ProfileSource: the scope's profile must be used
	cred, err := a.Mint(context.Background(), "bot", map[string]any{
		"repos": []string{"acme/api"}, "permissions": map[string]string{"contents": "read"},
		broker.ScopeProfile: json.RawMessage(directProfile), broker.ScopeProfileVersion: 9,
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Scope["profile_version"] != 9 {
		t.Fatalf("profile version: %v", cred.Scope["profile_version"])
	}
	_, err = a.Mint(context.Background(), "bot", map[string]any{
		"repos": []string{"acme/api"}, "permissions": map[string]string{"contents": "read"},
		broker.ScopeProfile: json.RawMessage(`{"repos":["acme/api"],"permissions":{},"allow_direct_token":false}`),
	}, 0)
	if !errors.Is(err, ghbroker.ErrDirectTokenNotAllowed) {
		t.Fatalf("scope profile without allow_direct_token: %v", err)
	}
}

func TestRevokeAgentAndHooks(t *testing.T) {
	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	a := newBrokerAdapter(t, f, stubProfiles{"bot": directProfile, "other": directProfile})
	ctx := context.Background()
	scope := map[string]any{"repos": []string{"acme/api"}, "permissions": map[string]string{"contents": "read"}}
	for _, agent := range []string{"bot", "bot", "other"} {
		if _, err := a.Mint(ctx, agent, scope, 0); err != nil {
			t.Fatal(err)
		}
	}
	hookCalled := ""
	a.OnRevokeAgent(func(_ context.Context, agentID string) (string, error) {
		hookCalled = agentID
		return "github gateway: dropped 0 cached token(s)", nil
	})
	desc, err := a.RevokeAgent(ctx, "bot")
	if err != nil {
		t.Fatal(err)
	}
	if hookCalled != "bot" {
		t.Fatal("revoke hook not called")
	}
	if !strings.Contains(desc, "revoked 2 direct token(s)") || !strings.Contains(desc, "expire within 1h") || !strings.Contains(desc, "github gateway") {
		t.Fatalf("description: %s", desc)
	}
	if f.LiveTokens() != 1 || a.LiveTokens("bot") != 0 || a.LiveTokens("other") != 1 {
		t.Fatalf("live tokens after revoke: fake=%d bot=%d other=%d", f.LiveTokens(), a.LiveTokens("bot"), a.LiveTokens("other"))
	}
	if f.CallsMatching("DELETE", "/installation/token") != 2 {
		t.Fatal("expected two DELETE /installation/token calls")
	}
}

func TestShortTTLRevokedEarly(t *testing.T) {
	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	a := newBrokerAdapter(t, f, stubProfiles{"bot": directProfile})
	cred, err := a.Mint(context.Background(), "bot", map[string]any{"repos": []string{"acme/api"}, "permissions": map[string]string{"contents": "read"}}, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := cred.Scope["revoke_scheduled_at"]; !ok {
		t.Fatal("early revocation not announced in scope")
	}
	deadline := time.Now().Add(5 * time.Second)
	for f.LiveTokens() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("token with a 150ms ttl was not revoked")
		}
		time.Sleep(20 * time.Millisecond)
	}
	if a.LiveTokens("bot") != 0 {
		t.Fatal("expired token still registered")
	}
}

func policyDir() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "policies")
}

// TestBrokerServiceIssueAndRevoke runs the real broker core (decide + policy
// + access gate + Postgres) with this adapter: a direct token is issued only
// within the profile, recorded without its secret, and RevokeAll revokes it.
func TestBrokerServiceIssueAndRevoke(t *testing.T) {
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
	for _, id := range []string{"bot", "gw_only"} {
		if _, err := ctl.Register(ctx, control.Agent{AgentID: id, Type: "test", Sponsor: "jane@acme.com"}, "test"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := acc.Put(ctx, "bot", "github", json.RawMessage(directProfile), "test", "setup"); err != nil {
		t.Fatal(err)
	}
	if _, err := acc.Put(ctx, "gw_only", "github", json.RawMessage(`{"repos":["acme/api"],"permissions":{"contents":"write"}}`), "test", "setup"); err != nil {
		t.Fatal(err)
	}
	svc := &decide.Service{Pool: pool, Policy: eng, Control: ctl, Diary: d, Log: log, Access: acc}

	f := fakegithub.New(t)
	f.AddRepo("acme", "api")
	gh := newBrokerAdapter(t, f, nil)
	b := broker.New(svc, pool, d, acc, map[string]broker.Adapter{"github": gh}, log)

	cred, err := b.Issue(ctx, broker.IssueRequest{AgentID: "bot", System: "github",
		GitHub: &broker.GHRequest{Repos: []string{"acme/api"}, Permissions: map[string]string{"contents": "read"}}})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	secret := cred.Secret["token"]
	if secret == "" || cred.ActionID == "" {
		t.Fatalf("credential: %+v", cred.Scope)
	}
	var scopeJSON string
	if err := pool.QueryRow(ctx, `SELECT scope_json::text FROM credential_issuances WHERE issuance_id = $1`, cred.IssuanceID).Scan(&scopeJSON); err != nil {
		t.Fatal(err)
	}
	var leaks int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM diary WHERE strpos(body_json, $1) > 0`, secret).Scan(&leaks); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(scopeJSON, secret) || leaks != 0 {
		t.Fatal("token stored in Postgres")
	}

	// Beyond the profile: refused by policy (POL-024) before any mint.
	_, err = b.Issue(ctx, broker.IssueRequest{AgentID: "bot", System: "github",
		GitHub: &broker.GHRequest{Repos: []string{"acme/api"}, Permissions: map[string]string{"contents": "write"}}})
	var ref *broker.Refusal
	if !errors.As(err, &ref) || ref.Outcome.Result.RuleID != "POL-024" {
		t.Fatalf("over-profile request: want POL-024 refusal, got %v", err)
	}
	_, err = b.Issue(ctx, broker.IssueRequest{AgentID: "gw_only", System: "github",
		GitHub: &broker.GHRequest{Repos: []string{"acme/api"}, Permissions: map[string]string{"contents": "read"}}})
	if !errors.As(err, &ref) || ref.Outcome.Result.RuleID != "POL-024" {
		t.Fatalf("allow_direct_token false: want POL-024 refusal, got %v", err)
	}
	if len(f.Tokens()) != 1 {
		t.Fatalf("refused requests must not mint: %d tokens", len(f.Tokens()))
	}

	res, err := b.RevokeAll(ctx, "bot", "user:sec@acme.com", "test kill")
	if err != nil {
		t.Fatalf("revoke all: %v", err)
	}
	if !strings.Contains(res["github"], "revoked 1 direct token(s)") {
		t.Fatalf("revocation description: %v", res)
	}
	if f.LiveTokens() != 0 {
		t.Fatal("direct token still live after RevokeAll")
	}
	var revoked bool
	if err := pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM credential_issuances WHERE issuance_id = $1`, cred.IssuanceID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("issuance not marked revoked")
	}
}
