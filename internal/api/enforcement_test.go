package api_test

import "testing"

// Phase 6: per-agent observe mode is set by security only, needs a reason,
// is audited in the Diary and shows in the agent view.
func TestAgentEnforcementMode(t *testing.T) {
	e := setupP2(t, p2Options{})
	e.registerBot(t)
	owner := e.login(t, userOwner)
	set := func(h map[string]string, mode, reason string) (int, map[string]any) {
		t.Helper()
		return e.do(t, nil, "PUT", "/v1/agents/bot/enforcement", map[string]any{"mode": mode, "reason": reason}, h)
	}
	if c, _ := e.do(t, owner, "PUT", "/v1/agents/bot/enforcement", map[string]any{"mode": "observe", "reason": "pilot"}, nil); c != 403 {
		t.Fatalf("owner may not change enforcement: %d", c)
	}
	if c, _ := set(bearer(tokSecurity), "observe", ""); c != 400 {
		t.Fatalf("reason required: %d", c)
	}
	if c, _ := set(bearer(tokSecurity), "lenient", "x"); c != 400 {
		t.Fatalf("bad mode: %d", c)
	}
	if c, out := set(bearer(tokSecurity), "observe", "design partner pilot, week 1"); c != 200 || out["effective_enforcement"] != "observe" {
		t.Fatalf("set observe: %d %v", c, out)
	}
	if c, out := e.do(t, nil, "GET", "/v1/agents/bot", nil, bearer(tokAuditor)); c != 200 {
		t.Fatalf("agent view: %d %v", c, out)
	} else if a, _ := out["agent"].(map[string]any); a["enforcement"] != "observe" || a["effective_enforcement"] != "observe" {
		t.Fatalf("agent view: %v", a)
	}
	if c, out := e.do(t, nil, "GET", "/v1/enforcement", nil, bearer(tokAuditor)); c != 200 || out["mode"] != "enforce" {
		t.Fatalf("deployment view: %d %v", c, out)
	}
	if c, _ := set(bearer(tokSecurity), "observe", "again"); c != 200 {
		t.Fatalf("idempotent: %d", c)
	}
	if evs := e.diaryEvents(t, "enforcement.changed"); len(evs) != 1 {
		t.Fatalf("diary events: %d", len(evs))
	}
	if c, _ := set(bearer(tokSecurity), "default", "back to enforce"); c != 200 {
		t.Fatal(c)
	}
	if c, _ := e.do(t, nil, "PUT", "/v1/agents/ghost/enforcement", map[string]any{"mode": "observe", "reason": "x"}, bearer(tokSecurity)); c != 404 {
		t.Fatalf("unknown agent: %d", c)
	}
}
