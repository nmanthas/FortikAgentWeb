package temporalsdk

import (
	"context"
	"errors"
	"testing"
	"time"

	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

// stepsWorkflow runs three steps a minute apart, waiting at the gate before
// each, and returns the (workflow) time each step started.
func stepsWorkflow(ctx workflow.Context, checkMarker bool) ([]time.Time, error) {
	gate := New(ctx, Options{CheckMarker: checkMarker})
	var at []time.Time
	for range 3 {
		if err := gate.Wait(ctx); err != nil {
			return at, err
		}
		at = append(at, workflow.Now(ctx))
		if err := workflow.Sleep(ctx, time.Minute); err != nil {
			return at, err
		}
	}
	return at, nil
}

func newEnv(t *testing.T) *testsuite.TestWorkflowEnvironment {
	var s testsuite.WorkflowTestSuite
	env := s.NewTestWorkflowEnvironment()
	env.RegisterWorkflow(stepsWorkflow)
	env.SetTypedSearchAttributesOnStart(temporal.NewSearchAttributes(AgentKey.ValueSet("agent-a")))
	return env
}

func queryState(t *testing.T, env *testsuite.TestWorkflowEnvironment) State {
	t.Helper()
	v, err := env.QueryWorkflow(StateQuery)
	if err != nil {
		t.Fatal(err)
	}
	var s State
	if err := v.Get(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGatePauseResumeSignals(t *testing.T) {
	env := newEnv(t)
	var start time.Time
	var paused, resumed State
	env.RegisterDelayedCallback(func() {
		start = env.Now()
		env.SignalWorkflow(PauseSignal, Signal{AgentID: "agent-a", Reason: "suspicious"})
	}, 30*time.Second)
	env.RegisterDelayedCallback(func() { paused = queryState(t, env) }, 5*time.Minute)
	env.RegisterDelayedCallback(func() {
		env.SignalWorkflow(ResumeSignal, Signal{AgentID: "agent-a", Reason: "cleared"})
	}, 10*time.Minute)
	env.RegisterDelayedCallback(func() { resumed = queryState(t, env) }, 10*time.Minute+time.Second)
	env.ExecuteWorkflow(stepsWorkflow, false)
	if err := env.GetWorkflowError(); err != nil {
		t.Fatal(err)
	}
	var at []time.Time
	if err := env.GetWorkflowResult(&at); err != nil {
		t.Fatal(err)
	}
	if len(at) != 3 {
		t.Fatalf("steps: %v", at)
	}
	// Step 1 ran immediately; step 2 waited for the resume at 10 minutes.
	if d := at[1].Sub(start); d < 9*time.Minute {
		t.Errorf("step 2 ran %s after the pause, before the resume", d)
	}
	if paused != (State{AgentID: "agent-a", Paused: true, Reason: "suspicious"}) || resumed.Paused {
		t.Errorf("states: %+v %+v", paused, resumed)
	}
}

func TestGateCancelledWhilePaused(t *testing.T) {
	env := newEnv(t)
	env.RegisterDelayedCallback(func() { env.SignalWorkflow(PauseSignal, Signal{Reason: "r"}) }, 10*time.Second)
	env.RegisterDelayedCallback(env.CancelWorkflow, 5*time.Minute)
	env.ExecuteWorkflow(stepsWorkflow, false)
	if err := env.GetWorkflowError(); !temporal.IsCanceledError(err) {
		t.Fatalf("want cancellation, got %v", err)
	}
}

func TestGateMarker(t *testing.T) {
	t.Run("paused at start", func(t *testing.T) {
		env := newEnv(t)
		env.RegisterActivityWithOptions(func(_ context.Context, agent string) (MarkerState, error) {
			if agent != "agent-a" {
				return MarkerState{}, errors.New("wrong agent")
			}
			return MarkerState{Paused: true, Reason: "suspended"}, nil
		}, activity.RegisterOptions{Name: CheckMarkerActivity})
		var st State
		env.RegisterDelayedCallback(func() { st = queryState(t, env) }, time.Minute)
		env.RegisterDelayedCallback(func() { env.SignalWorkflow(ResumeSignal, Signal{}) }, time.Hour)
		t0 := env.Now()
		env.ExecuteWorkflow(stepsWorkflow, true)
		var at []time.Time
		if err := env.GetWorkflowResult(&at); err != nil {
			t.Fatal(err)
		}
		if st != (State{AgentID: "agent-a", Paused: true, Reason: "suspended"}) {
			t.Errorf("state before resume: %+v", st)
		}
		if len(at) != 3 || at[0].Sub(t0) < time.Hour {
			t.Errorf("first step did not wait for the resume: started %v, steps %v", t0, at)
		}
	})
	t.Run("check fails closed", func(t *testing.T) {
		env := newEnv(t)
		calls := 0
		env.RegisterActivityWithOptions(func(context.Context, string) (MarkerState, error) {
			calls++
			if calls <= 3 { // the first check's three attempts fail
				return MarkerState{}, errors.New("temporal unreachable")
			}
			return MarkerState{}, nil
		}, activity.RegisterOptions{Name: CheckMarkerActivity})
		t0 := env.Now()
		env.ExecuteWorkflow(stepsWorkflow, true)
		var at []time.Time
		if err := env.GetWorkflowResult(&at); err != nil {
			t.Fatal(err)
		}
		if len(at) != 3 || calls != 4 {
			t.Fatalf("steps %v, %d checks", at, calls)
		}
		// The first step waited for the recheck 30s later.
		if at[0].Sub(t0) < markerRecheck {
			t.Errorf("step ran before the marker was confirmed absent: started %v, steps %v", t0, at)
		}
	})
}
