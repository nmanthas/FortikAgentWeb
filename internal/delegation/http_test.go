package delegation_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"fortik/internal/authz"
	"fortik/internal/delegation"
)

func TestDelegationAPI(t *testing.T) {
	e := newE2E(t)
	ctx := context.Background()
	e.putProfile(t, "agent_a", "http", `{"external":"none"}`)
	e.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["agent_b"],"max_depth":2}`)
	e.putProfile(t, "agent_b", "http", `{"external":"any"}`)
	tok := e.mustDelegate(t, "", "agent_a", "agent_b")
	wantDenied(t, e.act(t, tok, httpAction("agent_b")), "POL-601")
	if _, _, err := e.store.Open(ctx, delegation.Hop{From: "agent_c", To: "agent_d", Chain: []string{"agent_c", "agent_d"}, Channel: "a2a"}); err != nil {
		t.Fatal(err)
	}

	var who *authz.Principal
	mux := http.NewServeMux()
	delegation.NewHandler(e.store, slog.New(slog.NewTextHandler(io.Discard, nil))).Register(mux)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if who != nil {
			r = r.WithContext(authz.With(r.Context(), *who))
		}
		mux.ServeHTTP(w, r)
	}))
	defer srv.Close()
	get := func(p *authz.Principal, path string) (int, map[string]any, string) {
		t.Helper()
		who = p
		resp, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, _ := io.ReadAll(resp.Body)
		var out map[string]any
		_ = json.Unmarshal(raw, &out)
		return resp.StatusCode, out, string(raw)
	}

	security := authz.Principal{Kind: authz.KindUser, Email: "sec@acme.com", Roles: map[string]bool{authz.RoleSecurity: true}}
	auditor := authz.Principal{Kind: authz.KindUser, Email: "audit@acme.com", Roles: map[string]bool{authz.RoleAuditor: true}}
	owner := authz.Principal{Kind: authz.KindUser, Email: "OWNER@acme.com"} // sponsor of every fixture agent
	stranger := authz.Principal{Kind: authz.KindUser, Email: "eve@acme.com"}
	tokenNamedOwner := authz.Principal{Kind: authz.KindToken, Name: "owner@acme.com", Email: "owner@acme.com"}

	if code, _, _ := get(nil, "/v1/agents/agent_a/delegations"); code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", code)
	}
	for _, p := range []*authz.Principal{&stranger, &tokenNamedOwner} {
		if code, _, _ := get(p, "/v1/agents/agent_a/delegations"); code != http.StatusForbidden {
			t.Fatalf("%s: %d", p.Actor(), code)
		}
	}
	// Unknown agents: 403 for non-privileged callers (no enumeration), 404 otherwise.
	if code, _, _ := get(&stranger, "/v1/agents/nobody/delegations"); code != http.StatusForbidden {
		t.Fatalf("stranger unknown agent: %d", code)
	}
	if code, _, _ := get(&security, "/v1/agents/nobody/delegations"); code != http.StatusNotFound {
		t.Fatalf("security unknown agent: %d", code)
	}
	for _, q := range []string{"?direction=sideways", "?status=pending", "?limit=0", "?limit=501", "?limit=x"} {
		if code, _, _ := get(&security, "/v1/agents/agent_a/delegations"+q); code != http.StatusBadRequest {
			t.Fatalf("%s: %d", q, code)
		}
	}

	for _, p := range []*authz.Principal{&security, &auditor, &owner} {
		code, body, raw := get(p, "/v1/agents/agent_a/delegations")
		if code != http.StatusOK {
			t.Fatalf("%s: %d %s", p.Actor(), code, raw)
		}
		hops := body["hops"].([]any)
		if len(hops) != 1 || hops[0].(map[string]any)["to_agent"] != "agent_b" {
			t.Fatalf("%s hops: %v", p.Actor(), hops)
		}
		// agent_a is the origin of B's refused action: it is listed for A too.
		blocked := body["blocked"].([]any)
		if len(blocked) != 1 {
			t.Fatalf("%s blocked: %v", p.Actor(), blocked)
		}
		b := blocked[0].(map[string]any)
		if b["executor"] != "agent_b" || b["rule_id"] != "POL-601" || b["delegation"].(map[string]any)["source"] != "token" {
			t.Fatalf("blocked entry: %v", b)
		}
		if strings.Contains(raw, tok) || strings.Contains(raw, strings.SplitN(tok, ".", 2)[1]) {
			t.Fatal("token in API response")
		}
		// Owners without auditor/security never see chain agents' levels or profiles.
		ch := b["delegation"].(map[string]any)["chain"].([]any)
		if len(ch) != 1 || ch[0].(map[string]any)["agent_id"] != "agent_a" {
			t.Fatalf("%s chain: %v", p.Actor(), ch)
		}
		_, hasAccess := ch[0].(map[string]any)["access"]
		if hasAccess == (p == &owner) || strings.Contains(raw, `"external"`) == (p == &owner) {
			t.Fatalf("%s: access profile exposure %v in %s", p.Actor(), hasAccess, raw)
		}
	}
	_, body, _ := get(&security, "/v1/agents/agent_b/delegations?direction=outbound")
	if len(body["hops"].([]any)) != 0 {
		t.Fatalf("outbound for agent_b: %v", body["hops"])
	}
	_, body, _ = get(&security, "/v1/agents/agent_b/delegations?direction=inbound&status=open&limit=5")
	if len(body["hops"].([]any)) != 1 || len(body["blocked"].([]any)) != 1 {
		t.Fatalf("inbound for agent_b: %v", body)
	}
	_, body, _ = get(&security, "/v1/agents/agent_d/delegations")
	if len(body["hops"].([]any)) != 1 || len(body["blocked"].([]any)) != 0 {
		t.Fatalf("agent_d: %v", body)
	}
}
