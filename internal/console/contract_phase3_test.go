//go:build consolecontract

// Phase 3 consumer-contract test: the real approvals, overrides, population,
// alerts and delegation handlers mounted on the API exactly as main.go will,
// checked against the JSON fields web/console/src/api/normalize.ts reads.
package console_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/api"
	"fortik/internal/approvals"
	"fortik/internal/config"
	"fortik/internal/delegation"
	"fortik/internal/overrides"
	"fortik/internal/pgsql"
	"fortik/internal/population"
	"fortik/internal/undo"
)

func TestConsoleContractPhase3(t *testing.T) {
	ctx := context.Background()
	var (
		alertStore *alerts.PGStore
		delegStore *delegation.PGStore
	)
	e := newContractEnv(t, func(e *contractEnv, srv *api.Server) {
		alertStore = alerts.NewPGStore(e.pool, e.diary)
		pop, err := population.New(e.pool, e.diary, alertStore, population.NewMemoryCounters(), config.PopulationConfig{}, e.log)
		if err != nil {
			t.Fatal(err)
		}
		delegStore, err = delegation.NewPGStore(ctx, e.pool, e.diary, e.store, config.DelegationConfig{SigningKeySecret: "delegation_signing_key"})
		if err != nil {
			t.Fatal(err)
		}
		srv.Mount(approvals.NewHandler(approvals.New(e.pool, e.diary, undo.NewPGStore(e.pool, e.diary), nil, approvals.Config{}, e.log)).Register)
		srv.Mount(overrides.NewHandler(overrides.NewPGStore(e.pool, e.diary, nil, e.log), e.log).Register)
		srv.Mount(population.NewAPIHandler(pop, e.log).Register)
		srv.Mount(alerts.NewHandler(alertStore, e.log).Register)
		srv.Mount(delegation.NewHandler(delegStore, e.log).Register)
	})
	c := e.c
	e.login()

	for _, id := range []string{"bot", "helper"} {
		c.json(http.MethodPost, "/v1/agents", map[string]any{"agent_id": id, "name": id, "type": "support", "platform": "test",
			"sponsor": "owner@example.com", "business_unit": "Ops", "workspace_user": "", "copy_cap": 1}, 201)
	}

	t.Run("approvals", func(t *testing.T) {
		if _, err := e.access.Put(ctx, "bot", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_write"}}`), "user:sec@example.com", "contract"); err != nil {
			t.Fatal(err)
		}
		out, err := e.svc.Decide(ctx, dropTable(t, "bot"))
		if err != nil {
			t.Fatal(err)
		}
		if !out.Held {
			t.Fatalf("DROP TABLE in prod was not held (decision %s by %s): the approval flow cannot be checked", out.Result.Decision, out.Result.RuleID)
		}
		held := c.json(http.MethodGet, "/v1/held?status=pending&limit=1000", nil, 200)
		h := first(t, "/v1/held", held, "held")
		requireKeys(t, "held[0]", h, "action_id", "agent_id", "rule_id", "reason", "class", "system", "verb", "safe_form", "outcome",
			"created_at", "expires_at", "approvals_required", "approver_role")
		sf, _ := h["safe_form"].(map[string]any)
		requireKeys(t, "held[0].safe_form", sf, "kind", "sql")
		id, _ := h["action_id"].(string)

		code, _, raw := c.do(http.MethodPost, "/v1/held/"+id+"/approve", map[string]any{"reason": "contract", "use_safe_form": false})
		if code != http.StatusConflict || !strings.Contains(string(raw), `"error"`) {
			t.Fatalf("approve red unchanged: %d %s (the console shows the {error} message)", code, raw)
		}
		denied := c.json(http.MethodPost, "/v1/held/"+id+"/deny", map[string]any{"reason": "contract"}, 200)
		requireKeys(t, "deny", denied, "action_id", "outcome", "approvals", "approvals_required")
		if denied["outcome"] != "denied" {
			t.Fatalf("deny: %v", denied)
		}
	})

	t.Run("overrides", func(t *testing.T) {
		created := c.json(http.MethodPost, "/v1/overrides", map[string]any{"scope": "agent", "scope_id": "bot", "system": "github", "mode": "suspended",
			"duration_seconds": 1800, "reason": "contract"}, 201)
		requireKeys(t, "POST /v1/overrides", created, "override_id", "scope", "scope_id", "system", "mode", "starts_at", "expires_at", "reason", "created_by", "status", "revoke_result")
		rr, ok := created["revoke_result"].(map[string]any)
		if !ok {
			t.Fatalf("revoke_result is not {system: {agent: summary}}: %v", created["revoke_result"])
		}
		if per, ok := rr["github"].(map[string]any); !ok || per["bot"] == nil {
			t.Fatalf("revoke_result shape changed (normOverride flattens {system: {agent: summary}}): %v", rr)
		}
		id, _ := created["override_id"].(string)
		list := c.json(http.MethodGet, "/v1/overrides?agent_id=bot", nil, 200)
		requireKeys(t, "overrides[0]", first(t, "/v1/overrides", list, "overrides"), "override_id", "system", "mode", "expires_at", "status", "created_by")

		ext := c.json(http.MethodPost, "/v1/overrides/"+id+"/extend", map[string]any{"duration_seconds": 3600, "reason": "contract"}, 200)
		if ext["expires_at"] == created["expires_at"] {
			t.Fatalf("extend did not move expires_at: %v", ext)
		}
		perm := c.json(http.MethodPost, "/v1/overrides/"+id+"/permanent", map[string]any{"reason": "contract"}, 200)
		if _, ok := perm["expires_at"]; ok {
			t.Fatalf("permanent override still has expires_at (the console reads its absence as until released): %v", perm)
		}
		rel := c.json(http.MethodPost, "/v1/overrides/"+id+"/release", map[string]any{"reason": "contract"}, 200)
		if rel["status"] != "released" {
			t.Fatalf("release: %v", rel)
		}
		// until_released without a duration.
		c.json(http.MethodPost, "/v1/overrides", map[string]any{"scope": "agent", "scope_id": "bot", "system": "drive", "mode": "read_only",
			"until_released": true, "reason": "contract"}, 201)
	})

	t.Run("population", func(t *testing.T) {
		now := time.Now()
		for i, id := range []string{"bot-1", "bot-2"} {
			if _, err := e.pool.Exec(ctx, `INSERT INTO instances (instance_id, agent_id, host, started_at, last_heartbeat, status) VALUES ($1, 'bot', 'laptop', $2, $2, 'live')`,
				id, now.Add(time.Duration(i)*time.Second)); err != nil {
				t.Fatal(err)
			}
		}
		insts := c.json(http.MethodGet, "/v1/agents/bot/instances", nil, 200)
		requireKeys(t, "instances", insts, "agent_id", "copy_cap", "live", "instances")
		requireKeys(t, "instances[0]", first(t, "instances", insts, "instances"), "instance_id", "agent_id", "host", "started_at", "last_heartbeat", "status", "new_host")
		if insts["live"] != float64(2) || insts["copy_cap"] != float64(1) {
			t.Fatalf("instances live/cap: %v", insts)
		}
		paused := c.json(http.MethodPost, "/v1/agents/bot/instances/pause-extra", map[string]any{"reason": "contract"}, 200)
		requireKeys(t, "pause-extra", paused, "copy_cap", "live_after", "paused")
		if p, _ := paused["paused"].([]any); len(p) != 1 || p[0] != "bot-2" {
			t.Fatalf("pause-extra paused %v, want the newest copy", paused["paused"])
		}

		put := c.json(http.MethodPut, "/v1/agent-types/support", map[string]any{"expected_max_instances": 10, "max_agents": 5,
			"spawn_rate_per_min": 2, "action_rate_per_min": 120, "reason": "contract"}, 200)
		requireKeys(t, "PUT agent type", put, "type", "expected_max_instances", "max_agents", "spawn_rate_per_min", "action_rate_per_min")
		types := c.json(http.MethodGet, "/v1/agent-types", nil, 200)
		requireKeys(t, "agent_types[0]", first(t, "agent-types", types, "agent_types"), "type", "expected_max_instances", "max_agents", "spawn_rate_per_min", "action_rate_per_min")
	})

	t.Run("alerts", func(t *testing.T) {
		if _, err := alertStore.Raise(ctx, alerts.Alert{Kind: alerts.KindSpawnSpike, Severity: alerts.SevHigh, AgentID: "bot", AgentType: "support",
			Summary: "contract spike", Details: json.RawMessage(`{"spawns":40}`)}); err != nil {
			t.Fatal(err)
		}
		list := c.json(http.MethodGet, "/v1/alerts?limit=1000&status=open", nil, 200)
		a := first(t, "/v1/alerts", list, "alerts")
		requireKeys(t, "alerts[0]", a, "alert_id", "kind", "severity", "agent_id", "agent_type", "summary", "count", "status", "created_at", "updated_at")
		id, _ := a["alert_id"].(string)
		acked := c.json(http.MethodPost, "/v1/alerts/"+id+"/ack", map[string]any{}, 200)
		if acked["status"] != "acknowledged" || acked["acked_by"] == nil {
			t.Fatalf("ack: %v", acked)
		}
		resolved := c.json(http.MethodPost, "/v1/alerts/"+id+"/resolve", map[string]any{}, 200)
		if resolved["status"] != "resolved" {
			t.Fatalf("resolve: %v", resolved)
		}
	})

	t.Run("delegations", func(t *testing.T) {
		_, token, err := delegStore.Open(ctx, delegation.Hop{From: "bot", To: "helper", Chain: []string{"bot", "helper"}, Channel: "a2a", TaskID: "t1"})
		if err != nil {
			t.Fatal(err)
		}
		code, _, raw := c.do(http.MethodGet, "/v1/agents/helper/delegations?direction=all&limit=200", nil)
		if code != 200 {
			t.Fatalf("delegations: %d %s", code, raw)
		}
		if strings.Contains(string(raw), token) {
			t.Fatal("the delegations view contains the bearer delegation token")
		}
		var view map[string]any
		if err := json.Unmarshal(raw, &view); err != nil {
			t.Fatal(err)
		}
		requireKeys(t, "delegations", view, "agent_id", "hops", "blocked")
		requireKeys(t, "hops[0]", first(t, "delegations", view, "hops"), "delegation_id", "root_agent", "from_agent", "to_agent", "chain", "depth",
			"channel", "status", "created_at", "expires_at")
		if code, _, _ := c.do(http.MethodGet, "/v1/agents/nobody/delegations", nil); code != http.StatusNotFound {
			t.Fatalf("unknown agent: %d, want 404 (the console only falls back to the Diary when the route is missing)", code)
		}

		// The Diary fallback and the bypass step-down details read body.data.
		from := url.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339))
		code, _, raw = c.do(http.MethodGet, "/v1/diary?from="+from+"&limit=10000", nil)
		if code != 200 {
			t.Fatalf("diary: %d %s", code, raw)
		}
		if strings.Contains(string(raw), token) {
			t.Fatal("the Diary contains the bearer delegation token")
		}
		var d struct {
			Entries []struct {
				EventType string `json:"event_type"`
				Seq       int64  `json:"seq"`
				Body      struct {
					Data map[string]any `json:"data"`
				} `json:"body"`
			} `json:"entries"`
		}
		if err := json.Unmarshal(raw, &d); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, en := range d.Entries {
			if en.EventType == delegation.EventOpened {
				found = true
				requireKeys(t, "delegation.opened body.data", en.Body.Data, "delegation_id", "chain", "root", "from", "to", "channel", "depth")
			}
		}
		if !found {
			t.Fatal("no delegation.opened entry in GET /v1/diary")
		}
	})
}

// dropTable is the Action the Postgres proxy builds for a DROP TABLE in
// production (same classifier, same target keys and safe form).
func dropTable(t *testing.T, agent string) action.Action {
	t.Helper()
	sts, err := pgsql.Classify("DROP TABLE public.invoices")
	if err != nil {
		t.Fatal(err)
	}
	st := &sts[0]
	target := map[string]any{
		"upstream": "acme_prod", "database": "acme", "environment": "prod",
		"statement_type": st.StatementType, "tables": append([]string{}, st.Tables...),
		"schema": st.Schema, "table": st.Table, "has_where": st.HasWhere, "where_narrow": false,
		"undo_preparable": st.SnapshotPreparable(), "dangerous_functions": append([]string{}, st.DangerousFunctions...),
		"protocol": "simple", "statement_count": len(sts), "fingerprint": st.Fingerprint, "normalized_sql": st.Normalized,
		"on_conflict_update": st.OnConflictUpdate, "merge_has_delete": st.MergeHasDelete, "volatile_where": st.VolatileWhere,
	}
	if q, trash, err := pgsql.SafeRenameSQL(st, time.Now()); err == nil {
		target["safe_form"] = map[string]any{"kind": undo.KindPGRename, "sql": q, "trash_table": trash}
	}
	return action.Action{AgentID: agent, System: action.SystemPostgres, Verb: st.Verb, Target: target, Source: action.SourcePGProxy}
}
