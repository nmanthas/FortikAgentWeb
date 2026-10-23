package access_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"testing"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/policy"
)

// PGStore is what production wires into decide.Service.Access.
var _ decide.AccessSource = (*access.PGStore)(nil)

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

func pgAction(agent, stype string, verb action.Verb, upstream string) action.Action {
	return action.Action{AgentID: agent, System: "postgres", Verb: verb, Source: "pgproxy", Target: map[string]any{
		"statement_type": stype, "environment": "prod", "upstream": upstream, "database": upstream,
		"tables": []string{"public.orders"}, "table": "orders", "schema": "public", "on_conflict_update": false,
	}}
}

// Through the real decide.Service and policy engine: no profile = POL-020;
// a read_only profile allows reads and refuses writes (POL-026); the next
// decision reflects a profile change immediately.
func TestDecideAppliesAccessProfiles(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	svc := &decide.Service{Pool: f.pool, Policy: eng, Control: f.ctl, Diary: f.d, Log: log, Access: f.store}

	out, err := svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "acme_prod"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision != policy.Deny || out.Result.RuleID != "POL-020" || out.FailClosed {
		t.Fatalf("no profile: %+v", out.Result)
	}
	if out.LevelAfter != control.Full {
		t.Fatalf("access denial stepped the agent down: %v", out.LevelAfter)
	}
	if n := count(t, f, `SELECT count(*) FROM actions WHERE action_id = $1 AND decision = 'deny' AND rule_id = 'POL-020'`, out.Action.ActionID); n != 1 {
		t.Fatal("denial not recorded")
	}

	if _, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_only"}}`), "user:sec@acme.com", "prod reads"); err != nil {
		t.Fatal(err)
	}
	out, err = svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "acme_prod"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision != policy.Allow {
		t.Fatalf("read with profile: %+v", out.Result)
	}
	out, err = svc.Decide(ctx, pgAction("claude_code_01", "INSERT", action.VerbWrite, "acme_prod"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision != policy.Deny || out.Result.RuleID != "POL-026" {
		t.Fatalf("write on read_only: %+v", out.Result)
	}
	out, err = svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "acme_other"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision != policy.Deny || out.Result.RuleID != "POL-026" {
		t.Fatalf("other upstream: %+v", out.Result)
	}

	// Another agent is unaffected by this agent's profile.
	out, err = svc.Decide(ctx, pgAction("finance_agent_07", "SELECT", action.VerbRead, "acme_prod"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.RuleID != "POL-020" {
		t.Fatalf("other agent: %+v", out.Result)
	}

	// Widen to read_write: the very next decision reflects it.
	if _, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_write"}}`), "user:sec@acme.com", "backfill"); err != nil {
		t.Fatal(err)
	}
	out, err = svc.Decide(ctx, pgAction("claude_code_01", "INSERT", action.VerbWrite, "acme_prod"))
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision != policy.Allow {
		t.Fatalf("write on read_write: %+v", out.Result)
	}

	// Systems without profiles are untouched by the gate.
	out, err = svc.Decide(ctx, action.Action{AgentID: "claude_code_01", System: "memory", Verb: action.VerbRead, Source: "api"})
	if err != nil {
		t.Fatal(err)
	}
	if out.Result.Decision != policy.Allow {
		t.Fatalf("memory read: %+v", out.Result)
	}
}

// A failing access source makes Decide fail closed (never "no gate").
func TestDecideFailsClosedWhenProfilesUnavailable(t *testing.T) {
	f := setup(t)
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.Put(ctx, "claude_code_01", "postgres", json.RawMessage(`{"upstreams":{"acme_prod":"read_write"}}`), "u", "r"); err != nil {
		t.Fatal(err)
	}
	svc := &decide.Service{Pool: f.pool, Policy: eng, Control: f.ctl, Diary: f.d, Log: log, Access: f.store}
	// Make the profile store fail: rename its table out from under it.
	if _, err := f.pool.Exec(ctx, `ALTER TABLE access_profiles RENAME TO access_profiles_gone`); err != nil {
		t.Fatal(err)
	}
	out, err := svc.Decide(ctx, pgAction("claude_code_01", "SELECT", action.VerbRead, "acme_prod"))
	if err != nil {
		t.Fatal(err)
	}
	if !out.FailClosed || out.Result.Decision != policy.Deny || out.Result.RuleID != decide.RuleFailClosed {
		t.Fatalf("got %+v", out)
	}
}
