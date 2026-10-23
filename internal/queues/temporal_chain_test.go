package queues

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/operatorservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"fortik/internal/queues/temporalsdk"
)

const (
	chainWorkflowType = "ChainWorkflow"
	bumpSignal        = "bump"
	genQuery          = "gen"
)

// chainWorkflow honours Fortik's pause through the helper and continues as
// new (gen+1) whenever it receives "bump", like a long-running entity
// workflow.
func chainWorkflow(ctx workflow.Context, gen int) error {
	temporalsdk.New(ctx, temporalsdk.Options{})
	if err := workflow.SetQueryHandler(ctx, genQuery, func() (int, error) { return gen, nil }); err != nil {
		return err
	}
	bump := workflow.GetSignalChannel(ctx, bumpSignal)
	for {
		bumped := false
		sel := workflow.NewSelector(ctx)
		sel.AddReceive(bump, func(c workflow.ReceiveChannel, _ bool) { c.Receive(ctx, nil); bumped = true })
		sel.AddReceive(ctx.Done(), func(workflow.ReceiveChannel, bool) {})
		sel.Select(ctx)
		if err := ctx.Err(); err != nil {
			return err
		}
		if bumped {
			return workflow.NewContinueAsNewError(ctx, chainWorkflowType, gen+1)
		}
	}
}

func currentRun(t *testing.T, c client.Client, id string) (string, enumspb.WorkflowExecutionStatus) {
	t.Helper()
	d, err := c.DescribeWorkflowExecution(context.Background(), id, "")
	if err != nil {
		t.Fatalf("describe %s: %v", id, err)
	}
	info := d.GetWorkflowExecutionInfo()
	return info.GetExecution().GetRunId(), info.GetStatus()
}

func genOf(t *testing.T, c client.Client, id string) int {
	t.Helper()
	v, err := c.QueryWorkflow(context.Background(), id, "", genQuery)
	if err != nil {
		return -1
	}
	var n int
	_ = v.Get(&n)
	return n
}

// TestTemporalChainsAndTruncation covers F17 (operations follow a workflow
// that continues as new between the visibility list and the call, and only
// a closed chain counts as gone) and F22 (a safety cap makes the operation
// fail with ErrTruncated instead of reporting a partial success as done),
// against a real Temporal dev server.
func TestTemporalChainsAndTruncation(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a Temporal dev server")
	}
	addr := startTemporal(t)
	c := dialTemporal(t, addr, "default")
	ctx := context.Background()
	if _, err := c.OperatorService().AddSearchAttributes(ctx, &operatorservice.AddSearchAttributesRequest{
		Namespace:        "default",
		SearchAttributes: map[string]enumspb.IndexedValueType{temporalsdk.SearchAttribute: enumspb.INDEXED_VALUE_TYPE_KEYWORD},
	}); err != nil {
		t.Fatalf("register search attribute: %v", err)
	}
	waitFor(t, "search attribute", 30*time.Second, func() bool { return runningCount(t, c, "nobody") == 0 })
	w := worker.New(c, testTaskQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(chainWorkflow, workflow.RegisterOptions{Name: chainWorkflowType})
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)

	start := func(id, agent string) {
		t.Helper()
		if _, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
			ID: id, TaskQueue: testTaskQueue, TypedSearchAttributes: agentAttrs(agent),
		}, chainWorkflowType, 0); err != nil {
			t.Fatalf("start %s: %v", id, err)
		}
		t.Cleanup(func() { _ = c.TerminateWorkflow(context.Background(), id, "", "test cleanup") })
	}
	// bump continues id as new and waits until the new run is running.
	bump := func(id string) {
		t.Helper()
		before, _ := currentRun(t, c, id)
		g := genOf(t, c, id)
		if err := c.SignalWorkflow(ctx, id, "", bumpSignal, nil); err != nil {
			t.Fatalf("bump %s: %v", id, err)
		}
		waitFor(t, id+" continued as new", 20*time.Second, func() bool {
			run, st := currentRun(t, c, id)
			return run != before && st == enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING && genOf(t, c, id) == g+1
		})
	}

	src := newSource()
	src.set(t, SystemTemporal, map[string]any{"host_port": addr, "namespace": "default"}, nil)

	t.Run("F17_ContinueAsNewBetweenListAndCall", func(t *testing.T) {
		tp := NewTemporal(src, nil)
		start("chain-1", "agent-c")
		start("reused-1", "agent-c")
		waitFor(t, "agent-c visible", 30*time.Second, func() bool { return runningCount(t, c, "agent-c") == 2 })
		waitFor(t, "chain-1 running", 20*time.Second, func() bool { return genOf(t, c, "chain-1") == 0 })

		// Pause: the listed run continues as new before the signal; the
		// current run must be paused, not reported as finished.
		tp.afterList = func(context.Context) { bump("chain-1") }
		res, err := tp.Pause(ctx, "agent-c", "suspicious")
		if err != nil {
			t.Fatalf("pause: %v (%+v)", err, res)
		}
		if !strings.Contains(res.Detail, "signalled 2 workflows") || strings.Contains(res.Detail, "finished before") {
			t.Fatalf("pause detail: %+v", res)
		}
		waitFor(t, "current run paused", 15*time.Second, func() bool { return gateState(t, c, "chain-1").Paused })

		// Cancel: chain-1 continues as new again, and reused-1 is closed and
		// its id reused by another agent's workflow, between list and call.
		tp.afterList = func(context.Context) {
			bump("chain-1")
			if err := c.TerminateWorkflow(ctx, "reused-1", "", "test: closed"); err != nil {
				t.Errorf("terminate reused-1: %v", err)
			}
			start("reused-1", "agent-d")
			waitFor(t, "reused-1 restarted", 20*time.Second, func() bool {
				_, st := currentRun(t, c, "reused-1")
				return st == enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING && genOf(t, c, "reused-1") == 0
			})
		}
		res, err = tp.Cancel(ctx, "agent-c", "kill")
		if err != nil {
			t.Fatalf("cancel: %v (%+v)", err, res)
		}
		if !strings.Contains(res.Detail, "requested cancellation of 1 workflow") || !strings.Contains(res.Detail, "1 workflow finished before the request") {
			t.Fatalf("cancel detail: %+v", res)
		}
		waitFor(t, "chain-1's current run cancelled", 20*time.Second, func() bool {
			_, st := currentRun(t, c, "chain-1")
			return st == enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED
		})
		// The other agent's workflow that reused the id is untouched.
		time.Sleep(500 * time.Millisecond)
		if _, st := currentRun(t, c, "reused-1"); st != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
			t.Fatalf("agent-d's workflow reusing the id: %v", st)
		}
	})

	t.Run("F22_CapsAreNotDone", func(t *testing.T) {
		tp := NewTemporal(src, nil)
		tp.maxWorkflows, tp.maxSchedules = 1, 1
		start("trunc-1", "agent-t")
		start("trunc-2", "agent-t")
		waitFor(t, "agent-t visible", 30*time.Second, func() bool { return runningCount(t, c, "agent-t") == 2 })
		res, err := tp.Pause(ctx, "agent-t", "suspicious")
		if !errors.Is(err, ErrTruncated) || errors.Is(err, ErrNotConfigured) ||
			!strings.HasPrefix(err.Error(), "temporal: only the first 1 workflows were signalled, the rest were NOT") {
			t.Fatalf("pause beyond the workflow cap: %v (%+v)", err, res)
		}
		if res.Affected != 1 || !strings.Contains(res.Detail, "only the first 1 workflows were signalled") {
			t.Fatalf("pause result: %+v", res)
		}

		hourly := client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: time.Hour}}}
		for _, id := range []string{"sched-t1", "sched-t2"} {
			if _, err := c.ScheduleClient().Create(ctx, client.ScheduleOptions{ID: id, Spec: hourly,
				Action: &client.ScheduleWorkflowAction{ID: id + "-wf", Workflow: chainWorkflowType, TaskQueue: testTaskQueue,
					Args: []any{0}, TypedSearchAttributes: agentAttrs("agent-s")}}); err != nil {
				t.Fatalf("create schedule %s: %v", id, err)
			}
			t.Cleanup(func() { _ = c.ScheduleClient().GetHandle(context.Background(), id).Delete(context.Background()) })
		}
		waitFor(t, "schedules listed", 30*time.Second, func() bool {
			it, err := c.ScheduleClient().List(ctx, client.ScheduleListOptions{})
			if err != nil {
				return false
			}
			n := 0
			for it.HasNext() {
				if _, err := it.Next(); err != nil {
					return false
				}
				n++
			}
			return n == 2
		})
		res, err = tp.Cancel(ctx, "agent-s", "kill")
		if !errors.Is(err, ErrTruncated) || errors.Is(err, ErrNotConfigured) ||
			!strings.Contains(err.Error(), "only the first 1 schedules of the namespace were inspected, schedules beyond them were NOT deleted") {
			t.Fatalf("cancel beyond the schedule cap: %v (%+v)", err, res)
		}
		// Without the caps the same operation is complete and succeeds.
		full := NewTemporal(src, nil)
		if res, err := full.Cancel(ctx, "agent-s", "kill"); err != nil || !strings.Contains(res.Detail, "deleted") {
			t.Fatalf("uncapped cancel: %v (%+v)", err, res)
		}
	})
}
