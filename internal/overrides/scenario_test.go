package overrides

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/policy"
)

func policyDir() string {
	_, f, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(f), "..", "..", "policies")
}

type scenario struct {
	*fixture
	svc *decide.Service
}

func newScenario(t *testing.T) *scenario {
	t.Helper()
	f := setup(t)
	f.store.minDuration = time.Second // the plan's 30 minutes, shortened for the test
	ctx := context.Background()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	eng, err := policy.NewEngine(ctx, policyDir(), log)
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	gh := json.RawMessage(`{"repos":["acme/api"],"permissions":{"contents":"write"}}`)
	for _, agent := range []string{"code_agent_12", "code_agent_13", "code_agent_14"} {
		if _, err := f.profiles.Put(ctx, agent, "github", gh, secActor, "seed"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.profiles.Put(ctx, agent, "drive", json.RawMessage(`{"mode":"read_write","share":"internal_only"}`), secActor, "seed"); err != nil {
			t.Fatal(err)
		}
	}
	svc := &decide.Service{Pool: f.pool, Policy: eng, Control: f.ctl, Diary: f.d, Log: log, Access: f.profiles,
		Enrichers: []decide.Enricher{NewEnricher(f.store)}}
	return &scenario{fixture: f, svc: svc}
}

func ghPush(agent, branch, op string) action.Action {
	return action.Action{AgentID: agent, System: "github", Verb: action.VerbWrite, Source: action.SourceAppGateway,
		Target: map[string]any{"repo": "acme/api", "branch": branch, "operation": op}}
}

func ghRead(agent string) action.Action {
	return action.Action{AgentID: agent, System: "github", Verb: action.VerbRead, Source: action.SourceAppGateway,
		Target: map[string]any{"repo": "acme/api", "operation": "get_contents"}}
}

func driveRead(agent string) action.Action {
	return action.Action{AgentID: agent, System: "drive", Verb: action.VerbRead, Source: action.SourceAppGateway,
		Target: map[string]any{"operation": "get", "file_id": "f1"}}
}

func (s *scenario) decide(t *testing.T, a action.Action) decide.Outcome {
	t.Helper()
	out, err := s.svc.Decide(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	if out.FailClosed {
		t.Fatalf("decision failed closed: %+v", out.Result)
	}
	return out
}

func (s *scenario) expectAllowed(t *testing.T, what string, a action.Action) {
	t.Helper()
	if out := s.decide(t, a); !out.Result.Decision.Executes() {
		t.Fatalf("%s: want allowed, got %s by %s: %s", what, out.Result.Decision, out.Result.RuleID, out.Result.Reason)
	}
}

func (s *scenario) expectDenied(t *testing.T, what string, a action.Action, rule string, reasonParts ...string) decide.Outcome {
	t.Helper()
	out := s.decide(t, a)
	if out.Result.Decision != policy.Deny || out.Result.RuleID != rule {
		t.Fatalf("%s: want deny by %s, got %s by %s: %s", what, rule, out.Result.Decision, out.Result.RuleID, out.Result.Reason)
	}
	for _, p := range reasonParts {
		if !strings.Contains(out.Result.Reason, p) {
			t.Fatalf("%s: reason %q lacks %q", what, out.Result.Reason, p)
		}
	}
	return out
}

func (s *scenario) waitStatus(t *testing.T, id, want string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for {
		got := status(t, s.fixture, id)
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("override %s: status %s, want %s", id, got, want)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (s *scenario) startWorker(t *testing.T) {
	t.Helper()
	w, err := NewWorker(s.store, s.profiles, s.alerts, 100*time.Millisecond, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
}

// Plan scenario 4 through the real Decide service and policy bundle:
// "GitHub suspended for 30 minutes" for code_agent_12 (2s here) denies
// GitHub while active, leaves other systems and agents alone, revokes GitHub
// credentials only, and restores automatically with a Diary event; "Drive
// suspended until released" stays in force past its would-be expiry and is
// lifted only by release.
func TestScenario4TimedSuspensions(t *testing.T) {
	s := newScenario(t)
	ctx := context.Background()

	s.expectAllowed(t, "push before", ghPush("code_agent_12", "feat/x", "push"))
	s.expectAllowed(t, "drive before", driveRead("code_agent_12"))

	gh := mustCreate(t, s.fixture, agentReq("code_agent_12", "github", ModeSuspended, 2*time.Second))
	if got := s.revokers["github"].Calls(); !slices.Equal(got, []string{"code_agent_12"}) {
		t.Fatalf("github revocations %v", got)
	}
	for _, sys := range []string{"drive", "gmail", "aws", "postgres"} {
		if c := s.revokers[sys].Calls(); len(c) != 0 {
			t.Fatalf("%s revoked: %v", sys, c)
		}
	}
	restoreAt := gh.ExpiresAt.UTC().Format("15:04 MST on 2006-01-02")
	out := s.expectDenied(t, "push while suspended", ghPush("code_agent_12", "feat/x", "push"), "POL-030",
		"github suspended until "+restoreAt, "by "+secActor+": incident 42", gh.OverrideID)
	if out.LevelAfter != control.Full {
		t.Fatalf("a suspension denial stepped the agent down: %v", out.LevelAfter)
	}
	s.expectDenied(t, "read while suspended", ghRead("code_agent_12"), "POL-030")
	s.expectAllowed(t, "drive unaffected", driveRead("code_agent_12"))
	s.expectAllowed(t, "other agent unaffected", ghPush("code_agent_13", "feat/x", "push"))
	// The decision records the override context it was made with.
	if n := s.count(t, `SELECT count(*) FROM actions WHERE action_id = $1
		AND jsonb_array_length(decision_json->'context'->'overrides'->'active') = 1`, out.Action.ActionID); n != 1 {
		t.Fatal("override context not recorded with the decision")
	}

	// Drive: created timed, then made "until released" before it expires.
	drv := mustCreate(t, s.fixture, agentReq("code_agent_12", "drive", ModeSuspended, 2*time.Second))
	driveWouldExpire := *drv.ExpiresAt
	if _, err := s.store.MakePermanent(ctx, drv.OverrideID, secActor, "until the investigation ends", nil); err != nil {
		t.Fatal(err)
	}
	s.expectDenied(t, "drive suspended", driveRead("code_agent_12"), "POL-030", "drive suspended until released")

	s.startWorker(t)
	s.waitStatus(t, gh.OverrideID, StatusRestored)
	s.expectAllowed(t, "push after automatic restore", ghPush("code_agent_12", "feat/x", "push"))
	restored := s.events(t, EventRestored)
	if len(restored) != 1 || restored[0]["override_id"] != gh.OverrideID || restored[0]["system"] != "github" {
		t.Fatalf("override.restored: %v", restored)
	}

	// Past Drive's would-be expiry, plus a few sweeps: still in force.
	time.Sleep(time.Until(driveWouldExpire) + 400*time.Millisecond)
	if st := status(t, s.fixture, drv.OverrideID); st != StatusActive {
		t.Fatalf("drive override %s after its would-be expiry", st)
	}
	s.expectDenied(t, "drive after would-be expiry", driveRead("code_agent_12"), "POL-030", "until released")

	if _, err := s.store.Release(ctx, drv.OverrideID, secActor, "investigation closed", nil); err != nil {
		t.Fatal(err)
	}
	s.expectAllowed(t, "drive after release", driveRead("code_agent_12"))
	if ev := s.events(t, EventReleased); len(ev) != 1 || ev[0]["override_id"] != drv.OverrideID {
		t.Fatalf("override.released: %v", ev)
	}
	s.verifyDiary(t)
}

// A red action attempted during the suspension blocks the automatic
// restore: the override stays in force, and an alert is raised.
func TestScenario4RedActionBlocksRestore(t *testing.T) {
	s := newScenario(t)
	ctx := context.Background()
	o := mustCreate(t, s.fixture, agentReq("code_agent_14", "github", ModeSuspended, 2*time.Second))

	red := s.expectDenied(t, "force push while suspended", ghPush("code_agent_14", "main", "force_push"), "POL-030")
	if red.Result.Class != policy.Red {
		t.Fatalf("force push to main classified %s", red.Result.Class)
	}

	s.startWorker(t)
	s.waitStatus(t, o.OverrideID, StatusBlocked)
	got, err := s.store.Get(ctx, o.OverrideID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.BlockedReason, red.Action.ActionID) || !strings.Contains(got.BlockedReason, "POL-301") {
		t.Fatalf("blocked reason %q", got.BlockedReason)
	}
	s.expectDenied(t, "read while restore blocked", ghRead("code_agent_14"), "POL-030", "automatic restore was blocked")
	if n := s.count(t, `SELECT count(*) FROM alerts WHERE kind = 'override_restore_blocked' AND agent_id = 'code_agent_14'`); n != 1 {
		t.Fatal("override_restore_blocked alert missing")
	}
	if ev := s.events(t, EventRestoreBlocked); len(ev) != 1 || ev[0]["red_action_id"] != red.Action.ActionID {
		t.Fatalf("override.restore_blocked: %v", ev)
	}
	if ev := s.events(t, EventRestored); len(ev) != 0 {
		t.Fatalf("restored despite the red action: %v", ev)
	}

	// Only a human lifts it.
	if _, err := s.store.Release(ctx, o.OverrideID, secActor, "reviewed", nil); err != nil {
		t.Fatal(err)
	}
	s.expectAllowed(t, "read after release", ghRead("code_agent_14"))
	s.verifyDiary(t)
}

// A broken overrides store fails the decision closed (never "no override").
func TestScenarioEnricherFailureFailsClosed(t *testing.T) {
	s := newScenario(t)
	if _, err := s.pool.Exec(context.Background(), `ALTER TABLE access_overrides RENAME TO access_overrides_gone`); err != nil {
		t.Fatal(err)
	}
	out, err := s.svc.Decide(context.Background(), ghPush("code_agent_12", "feat/x", "push"))
	if err != nil {
		t.Fatal(err)
	}
	if !out.FailClosed || out.Result.Decision != policy.Deny || out.Result.RuleID != decide.RuleFailClosed {
		t.Fatalf("got %+v", out.Result)
	}
}

// A malformed override timestamp makes evaluation error (strict builtins),
// which Decide turns into a fail-closed refusal, never "no override".
func TestPolicyMalformedOverrideErrors(t *testing.T) {
	eng, err := policy.NewEngine(context.Background(), policyDir(), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("policy bundle: %v", err)
	}
	a := ghPush("code_agent_12", "feat/x", "push")
	a.Normalize(time.Now())
	in := policy.Input{Action: a, Agent: control.State{AgentID: "code_agent_12", Registered: true},
		Context: map[string]any{"overrides": map[string]any{"active": []any{map[string]any{
			"override_id": "ovr_x", "system": "github", "mode": "suspended", "status": "active", "expires_at": "11:55 tomorrow",
		}}}}}
	if res, err := eng.Eval(context.Background(), in); err == nil || !strings.Contains(err.Error(), "parse_rfc3339") {
		t.Fatalf("malformed expires_at evaluated to %+v (err %v)", res, err)
	}
	in.Context["overrides"].(map[string]any)["active"].([]any)[0].(map[string]any)["expires_at"] = "2026-10-11T11:55:00Z"
	res, err := eng.Eval(context.Background(), in)
	if err != nil || res.RuleID != "POL-030" || !strings.Contains(res.Reason, "until 11:55 UTC on 2026-10-11") {
		t.Fatalf("valid expires_at: %+v %v", res, err)
	}
}
