//go:build consolecontract

// Phase 4 consumer-contract test: the real containment handler mounted on
// the API exactly as main.go will, checked against the JSON fields
// web/console/src/api/normalize.ts reads (normContainmentOp, normStep,
// normContainmentOps) and the request bodies endpoints.ts sends. Credential
// revocation and running copies are test doubles: what is checked here is
// the HTTP contract, not the steps themselves (internal/containment tests
// those against real systems).
package console_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"fortik/internal/api"
	"fortik/internal/containment"
	"fortik/internal/undo"
)

// fakeRevoker reports an honest "nothing to revoke" per system.
type fakeRevoker struct{}

func (fakeRevoker) RevokeAll(context.Context, string, string, string) (map[string]string, error) {
	return map[string]string{"aws": "no live credentials"}, nil
}

// fakeInstances reports that the agent has no running copies.
type fakeInstances struct{}

func (fakeInstances) SuspendInstances(context.Context, string, string, string, string) ([]string, string, error) {
	return nil, "no running copies", nil
}

func (fakeInstances) ResumeInstances(context.Context, string, string, string, string, string) ([]string, string, error) {
	return nil, "no suspended copies", nil
}

func (fakeInstances) SuspendedBy(context.Context, string, string) (string, bool, error) {
	return "", false, nil
}

func (fakeInstances) StopInstances(context.Context, string, string, string, string) ([]string, string, error) {
	return nil, "no running copies", nil
}

func (fakeInstances) PauseExtra(context.Context, string, string, string) ([]string, string, error) {
	return nil, "no copies over the cap", nil
}

// Fields normContainmentOp and normStep read.
var (
	opKeys   = []string{"op_id", "op", "target_type", "target_id", "actor", "reason", "status", "steps", "created_at"}
	stepKeys = []string{"name", "status", "duration_ms"}
	stepOK   = map[string]bool{"done": true, "skipped": true, "failed": true}
	opOK     = map[string]bool{"running": true, "done": true, "partial": true, "failed": true}
)

func checkOp(t *testing.T, what string, op map[string]any) {
	t.Helper()
	requireKeys(t, what, op, opKeys...)
	if s, _ := op["status"].(string); !opOK[s] {
		t.Errorf("%s: status %q is not one the console knows (shown as unknown)", what, s)
	}
	steps, ok := op["steps"].([]any)
	if !ok {
		t.Fatalf("%s: steps is not a list: %v", what, op["steps"])
	}
	for i, raw := range steps {
		st, _ := raw.(map[string]any)
		requireKeys(t, what+".steps", st, stepKeys...)
		if s, _ := st["status"].(string); !stepOK[s] {
			t.Errorf("%s: steps[%d].status %q is not done/skipped/failed (shown as unknown)", what, i, s)
		}
	}
}

func TestConsoleContractPhase4(t *testing.T) {
	e := newContractEnv(t, func(e *contractEnv, srv *api.Server) {
		m, err := containment.New(e.pool, e.diary, e.ctl, fakeRevoker{}, nil, nil, fakeInstances{}, e.log)
		if err != nil {
			t.Fatal(err)
		}
		srv.Mount(containment.NewHandler(m, e.log).Register)
		srv.Undo = undo.NewPGStore(e.pool, e.diary)
	})
	c := e.c
	e.login()

	for _, id := range []string{"bot", "helper"} {
		c.json(http.MethodPost, "/v1/agents", map[string]any{"agent_id": id, "name": id, "type": "support", "platform": "test",
			"sponsor": "owner@example.com", "business_unit": "Ops", "workspace_user": "", "copy_cap": 1}, 201)
	}

	t.Run("agent routes", func(t *testing.T) {
		// endpoints.ts agentOp: POST /v1/agents/{id}/{op} {reason}.
		op := c.json(http.MethodPost, "/v1/agents/bot/suspend", map[string]any{"reason": "contract"}, 200)
		checkOp(t, "suspend", op)
		if op["op"] != "suspend" || op["target_type"] != "agent" || op["target_id"] != "bot" {
			t.Errorf("suspend: unexpected op %v", op)
		}
		checkOp(t, "resume", c.json(http.MethodPost, "/v1/agents/bot/resume", map[string]any{"reason": "contract"}, 200))
		// cancelQueue: {reason}; with no queue system configured the step must say so, not claim success.
		cq := c.json(http.MethodPost, "/v1/agents/bot/queue/cancel", map[string]any{"reason": "contract"}, 200)
		checkOp(t, "cancel_queue", cq)
	})

	t.Run("memory routes accept the console's bodies", func(t *testing.T) {
		// removeMemory: {reason, memory_mode}; restoreMemory: {reason[, rollback_snapshot_id]}.
		// No memory service is wired here: the op must still come back with an honest failed step.
		code, _, raw := c.do(http.MethodPost, "/v1/agents/bot/memory/remove", map[string]any{"reason": "contract", "memory_mode": "staging_only"})
		if code == http.StatusBadRequest {
			t.Fatalf("memory/remove refused the console's body: %s", raw)
		}
		code, _, raw = c.do(http.MethodPost, "/v1/agents/bot/memory/restore", map[string]any{"reason": "contract"})
		if code == http.StatusBadRequest {
			t.Fatalf("memory/restore refused the console's body: %s", raw)
		}
	})

	t.Run("team routes", func(t *testing.T) {
		checkOp(t, "team suspend", c.json(http.MethodPost, "/v1/teams/Ops/suspend", map[string]any{"reason": "contract"}, 200))
		checkOp(t, "team resume", c.json(http.MethodPost, "/v1/teams/Ops/resume", map[string]any{"reason": "contract"}, 200))
	})

	t.Run("fleet e-stop needs the typed confirmation", func(t *testing.T) {
		code, _, raw := c.do(http.MethodPost, "/v1/fleet/estop", map[string]any{"reason": "contract", "confirm": "stop all agents"})
		if code != http.StatusBadRequest || !strings.Contains(string(raw), `"error"`) {
			t.Fatalf("e-stop with the wrong phrase: %d %s (the console shows the {error} message)", code, raw)
		}
		// fleetEStop: {reason, confirm}.
		op := c.json(http.MethodPost, "/v1/fleet/estop", map[string]any{"reason": "contract", "confirm": "STOP ALL AGENTS"}, 200)
		checkOp(t, "estop", op)
		if op["target_type"] != "fleet" {
			t.Errorf("estop target_type = %v", op["target_type"])
		}
		// fleetRelease: {reason} (op_id optional: every e-stop).
		checkOp(t, "estop_release", c.json(http.MethodPost, "/v1/fleet/release", map[string]any{"reason": "contract"}, 200))
	})

	t.Run("history", func(t *testing.T) {
		// listContainment reads ops | containment | operations | items.
		out := c.json(http.MethodGet, "/v1/containment?target_type=agent&target_id=bot&limit=100", nil, 200)
		checkOp(t, "history[0]", first(t, "/v1/containment", out, "operations"))
		all := c.json(http.MethodGet, "/v1/containment?limit=500", nil, 200)
		if l, _ := all["operations"].([]any); len(l) < 5 {
			t.Errorf("/v1/containment?limit=500 returned %d ops, want every op run above", len(l))
		}
		checkOp(t, "fleet history[0]", first(t, "/v1/containment?target_type=fleet", c.json(http.MethodGet, "/v1/containment?target_type=fleet&limit=50", nil, 200), "operations"))
	})

	t.Run("lifting containment and multi-line reasons (D1-D3)", func(t *testing.T) {
		owner := e.loginAs(t, "owner@example.com")
		agentView := func(c *client) map[string]any {
			t.Helper()
			out := c.json(http.MethodGet, "/v1/agents/helper", nil, 200)
			if a, ok := out["agent"].(map[string]any); ok {
				return a
			}
			return out
		}
		// normAgent reads these to mirror D2 (who imposed the suspension / memory cut).
		viewKeys := []string{"suspended", "suspended_at", "suspended_by", "suspended_reason", "memory_access", "memory_access_changed_by"}

		// D3: OpDialog/ReasonDialog send multi-line reasons (newlines, tabs) of up to 1000 bytes.
		head := "incident 42:\n\t- exfil attempt\n\t- "
		reason := head + strings.Repeat("é", (1000-len(head))/2) + strings.Repeat("x", (1000-len(head))%2)
		if len(reason) != 1000 {
			t.Fatalf("test reason is %d bytes", len(reason))
		}
		checkOp(t, "suspend (multi-line reason)", c.json(http.MethodPost, "/v1/agents/helper/suspend", map[string]any{"reason": reason}, 200))
		if code, _, raw := c.do(http.MethodPost, "/v1/agents/helper/suspend", map[string]any{"reason": reason + "x"}); code != http.StatusBadRequest {
			t.Errorf("1001-byte reason: %d %s, want 400 (the console refuses it before sending)", code, raw)
		}
		v := agentView(c)
		requireKeys(t, "/v1/agents/helper", v, viewKeys...)
		if v["suspended"] != true || v["suspended_by"] != "user:sec@example.com" || v["suspended_reason"] != reason {
			t.Errorf("agent view after a security suspend: suspended=%v by=%v reason=%q", v["suspended"], v["suspended_by"], v["suspended_reason"])
		}
		for _, a := range c.json(http.MethodGet, "/v1/agents", nil, 200)["agents"].([]any) {
			if m, _ := a.(map[string]any); m["agent_id"] == "helper" {
				requireKeys(t, "/v1/agents[helper]", m, viewKeys...)
			}
		}

		// D2: the owner may not lift a suspension security imposed (permissions.ts disables Resume).
		code, _, raw := owner.do(http.MethodPost, "/v1/agents/helper/resume", map[string]any{"reason": "mine"})
		if code != http.StatusForbidden || !strings.Contains(string(raw), "requires the security role") {
			t.Errorf("owner resume of a security suspension: %d %s, want 403 \"... requires the security role\"", code, raw)
		}
		// D1: rollback_snapshot_id needs security (the console hides the selector from owners).
		code, _, raw = owner.do(http.MethodPost, "/v1/agents/helper/memory/restore", map[string]any{"reason": "mine", "rollback_snapshot_id": "msnap_contract"})
		if code != http.StatusForbidden {
			t.Errorf("owner memory restore with a rollback: %d %s, want 403", code, raw)
		}

		// D2: what the owner imposed, the owner may lift.
		checkOp(t, "security resume", c.json(http.MethodPost, "/v1/agents/helper/resume", map[string]any{"reason": "lifted"}, 200))
		checkOp(t, "owner suspend", owner.json(http.MethodPost, "/v1/agents/helper/suspend", map[string]any{"reason": "mine"}, 200))
		if v := agentView(c); v["suspended_by"] != "user:owner@example.com" {
			t.Errorf("suspended_by after the owner's suspend = %v, want user:owner@example.com (actorOf in permissions.ts)", v["suspended_by"])
		}
		checkOp(t, "owner resume of own suspension", owner.json(http.MethodPost, "/v1/agents/helper/resume", map[string]any{"reason": "mine"}, 200))
	})

	t.Run("undo list", func(t *testing.T) {
		// listUndo reads {undo: [...]}; undoable/why_not/description are added by the lead (PHASE4 §5).
		out := c.json(http.MethodGet, "/v1/undo?limit=500", nil, 200)
		if _, ok := out["undo"].([]any); !ok {
			t.Fatalf("/v1/undo: \"undo\" is not a list: %v", out)
		}
	})
}
