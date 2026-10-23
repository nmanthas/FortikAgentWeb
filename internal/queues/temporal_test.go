package queues

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/operatorservice/v1"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"

	"fortik/internal/queues/temporalsdk"
)

const (
	testTaskQueue = "fortik-test-agents"
	stepsQuery    = "steps"
)

// agentWorkflow is a customer workflow that honours Fortik's pause through
// the temporalsdk helper: it does one "unit of work" every 150ms while not
// paused.
func agentWorkflow(ctx workflow.Context) error {
	gate := temporalsdk.New(ctx, temporalsdk.Options{CheckMarker: true})
	steps := 0
	if err := workflow.SetQueryHandler(ctx, stepsQuery, func() (int, error) { return steps, nil }); err != nil {
		return err
	}
	for {
		if err := gate.Wait(ctx); err != nil {
			return err
		}
		steps++
		if err := workflow.Sleep(ctx, 150*time.Millisecond); err != nil {
			return err
		}
	}
}

// startTemporal runs a real Temporal dev server (temporal CLI) on free
// ports with a throwaway SQLite file, killed on cleanup.
func startTemporal(t *testing.T, namespaces ...string) string {
	t.Helper()
	bin := findBinary(t, "FORTIK_TEST_TEMPORAL", "temporal")
	port := freePort(t)
	args := []string{"server", "start-dev", "--headless", "--ip", "127.0.0.1",
		"--port", strconv.Itoa(port),
		"--ui-port", strconv.Itoa(freePort(t)),
		"--http-port", strconv.Itoa(freePort(t)),
		"--metrics-port", strconv.Itoa(freePort(t)),
		"--db-filename", filepath.Join(t.TempDir(), "temporal.db"),
		"--log-level", "error"}
	for _, ns := range namespaces {
		args = append(args, "--namespace", ns)
	}
	_, out := startProcess(t, bin, args...)
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	waitTCP(t, addr, 90*time.Second, out)
	return addr
}

func dialTemporal(t *testing.T, addr, ns string) client.Client {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := client.DialContext(ctx, client.Options{HostPort: addr, Namespace: ns, Logger: NewTemporal(nil, nil).logger})
		cancel()
		if err == nil {
			t.Cleanup(c.Close)
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("dial temporal: %v", err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

func waitFor(t *testing.T, what string, d time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func gateState(t *testing.T, c client.Client, id string) temporalsdk.State {
	t.Helper()
	v, err := c.QueryWorkflow(context.Background(), id, "", temporalsdk.StateQuery)
	if err != nil {
		t.Fatalf("query %s: %v", id, err)
	}
	var s temporalsdk.State
	if err := v.Get(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func steps(t *testing.T, c client.Client, id string) int {
	t.Helper()
	v, err := c.QueryWorkflow(context.Background(), id, "", stepsQuery)
	if err != nil {
		t.Fatalf("query %s: %v", id, err)
	}
	var n int
	if err := v.Get(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func runningCount(t *testing.T, c client.Client, agent string) int64 {
	t.Helper()
	resp, err := c.CountWorkflow(context.Background(), &workflowservice.CountWorkflowExecutionsRequest{
		Query: fmt.Sprintf("%s = '%s' AND ExecutionStatus = 'Running'", temporalsdk.SearchAttribute, agent),
	})
	if err != nil {
		return -1
	}
	return resp.GetCount()
}

func wfStatus(t *testing.T, c client.Client, id string) enumspb.WorkflowExecutionStatus {
	t.Helper()
	d, err := c.DescribeWorkflowExecution(context.Background(), id, "")
	if err != nil {
		t.Fatalf("describe %s: %v", id, err)
	}
	return d.GetWorkflowExecutionInfo().GetStatus()
}

func schedState(t *testing.T, c client.Client, id string) (exists, paused bool, note string) {
	t.Helper()
	d, err := c.ScheduleClient().GetHandle(context.Background(), id).Describe(context.Background())
	if isNotFound(err) {
		return false, false, ""
	}
	if err != nil {
		t.Fatalf("describe schedule %s: %v", id, err)
	}
	return true, d.Schedule.State.Paused, d.Schedule.State.Note
}

func agentAttrs(agent string) temporal.SearchAttributes {
	return temporal.NewSearchAttributes(temporalsdk.AgentKey.ValueSet(agent))
}

func TestTemporalAdapterRealServer(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a Temporal dev server")
	}
	addr := startTemporal(t, "plain")
	c := dialTemporal(t, addr, "default")
	ctx := context.Background()

	// Register the FortikAgentId search attribute through the operator
	// service, as an operator following the integration help would.
	if _, err := c.OperatorService().AddSearchAttributes(ctx, &operatorservice.AddSearchAttributesRequest{
		Namespace:        "default",
		SearchAttributes: map[string]enumspb.IndexedValueType{temporalsdk.SearchAttribute: enumspb.INDEXED_VALUE_TYPE_KEYWORD},
	}); err != nil {
		t.Fatalf("register search attribute: %v", err)
	}
	waitFor(t, "search attribute", 30*time.Second, func() bool { return runningCount(t, c, "nobody") == 0 })

	w := worker.New(c, testTaskQueue, worker.Options{})
	w.RegisterWorkflowWithOptions(agentWorkflow, workflow.RegisterOptions{Name: "AgentWorkflow"})
	temporalsdk.RegisterMarkerCheck(w, c)
	if err := w.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Stop)

	start := func(id, agent string) {
		t.Helper()
		if _, err := c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
			ID: id, TaskQueue: testTaskQueue, TypedSearchAttributes: agentAttrs(agent),
		}, "AgentWorkflow"); err != nil {
			t.Fatalf("start %s: %v", id, err)
		}
	}
	start("a-1", "agent-a")
	start("a-2", "agent-a")
	start("b-1", "agent-b")
	t.Cleanup(func() { _ = c.TerminateWorkflow(context.Background(), "b-1", "", "test cleanup") })

	// Schedules: one starting agent-a work (attributed by its action's
	// search attribute), one the customer paused for agent-a (attributed by
	// the schedule memo), one for agent-b.
	hourly := client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: time.Hour}}}
	mkSched := func(id, agent string, opts client.ScheduleOptions) {
		t.Helper()
		opts.ID, opts.Spec = id, hourly
		opts.Action = &client.ScheduleWorkflowAction{ID: id + "-wf", Workflow: "AgentWorkflow", TaskQueue: testTaskQueue,
			TypedSearchAttributes: agentAttrs(agent)}
		if _, err := c.ScheduleClient().Create(ctx, opts); err != nil {
			t.Fatalf("create schedule %s: %v", id, err)
		}
	}
	mkSched("sched-a", "agent-a", client.ScheduleOptions{})
	mkSched("sched-a-maint", "agent-x", client.ScheduleOptions{Paused: true, Note: "customer maintenance",
		Memo: map[string]any{temporalsdk.MemoAgentKey: "agent-a"}})
	mkSched("sched-b", "agent-b", client.ScheduleOptions{})
	t.Cleanup(func() { _ = c.ScheduleClient().GetHandle(context.Background(), "sched-b").Delete(context.Background()) })
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
		return n == 3
	})
	waitFor(t, "agent-a workflows visible", 30*time.Second, func() bool { return runningCount(t, c, "agent-a") == 2 })
	waitFor(t, "workflows running", 30*time.Second, func() bool { return steps(t, c, "a-1") > 0 && steps(t, c, "b-1") > 0 })

	src := newSource()
	src.set(t, SystemTemporal, map[string]any{"host_port": addr, "namespace": "default", "tls": false}, nil)
	tp := NewTemporal(src, nil)

	// --- Pause: only agent-a's work stops.
	res, err := tp.Pause(ctx, "agent-a", "suspicious\nrequests")
	if err != nil {
		t.Fatalf("pause: %v (%+v)", err, res)
	}
	if res.System != SystemTemporal || res.Affected != 3 ||
		!strings.Contains(res.Detail, "signalled 2 workflows with fortik-pause") ||
		!strings.Contains(res.Detail, "Temporal cannot freeze arbitrary running workflows") ||
		!strings.Contains(res.Detail, "paused 1 schedule") {
		t.Fatalf("pause result: %+v", res)
	}
	for _, id := range []string{"a-1", "a-2"} {
		waitFor(t, id+" paused", 15*time.Second, func() bool { return gateState(t, c, id).Paused })
		if s := gateState(t, c, id); s.AgentID != "agent-a" || s.Reason != "suspicious requests" {
			t.Errorf("%s state: %+v", id, s)
		}
	}
	if gateState(t, c, "b-1").Paused {
		t.Fatal("agent-b's workflow was paused")
	}
	a1, b1 := steps(t, c, "a-1"), steps(t, c, "b-1")
	time.Sleep(time.Second)
	if got := steps(t, c, "a-1"); got > a1+1 { // at most the step already in flight
		t.Errorf("paused workflow kept working: %d -> %d", a1, got)
	}
	if got := steps(t, c, "b-1"); got <= b1 {
		t.Errorf("agent-b's workflow stopped: %d -> %d", b1, got)
	}
	if ok, paused, note := schedState(t, c, "sched-a"); !ok || !paused || !strings.HasPrefix(note, scheduleNotePrefix) {
		t.Errorf("sched-a after pause: %v %v %q", ok, paused, note)
	}
	if _, paused, _ := schedState(t, c, "sched-b"); paused {
		t.Error("agent-b's schedule was paused")
	}
	if m, err := temporalsdk.CheckMarker(ctx, c, "agent-a"); err != nil || !m.Paused || m.Reason != "suspicious requests" {
		t.Errorf("marker: %+v %v", m, err)
	}
	if m, err := temporalsdk.CheckMarker(ctx, c, "agent-b"); err != nil || m.Paused {
		t.Errorf("agent-b marker: %+v %v", m, err)
	}
	// Work queued while the agent is paused waits (the helper reads the
	// pause marker when the workflow starts).
	start("a-3", "agent-a")
	waitFor(t, "a-3 paused at start", 15*time.Second, func() bool { return gateState(t, c, "a-3").Paused })
	if n := steps(t, c, "a-3"); n != 0 {
		t.Errorf("a-3 ran %d steps while paused", n)
	}
	// Pausing again is harmless (the marker already exists).
	if _, err := tp.Pause(ctx, "agent-a", "again"); err != nil {
		t.Fatalf("second pause: %v", err)
	}

	// --- Resume.
	waitFor(t, "a-3 visible", 30*time.Second, func() bool { return runningCount(t, c, "agent-a") == 3 })
	res, err = tp.Resume(ctx, "agent-a", "cleared")
	if err != nil {
		t.Fatalf("resume: %v (%+v)", err, res)
	}
	if res.Affected != 4 || !strings.Contains(res.Detail, "signalled 3 workflows with fortik-resume") ||
		!strings.Contains(res.Detail, "removed the pause marker") || !strings.Contains(res.Detail, "unpaused 1 schedule") {
		t.Fatalf("resume result: %+v", res)
	}
	for _, id := range []string{"a-1", "a-2", "a-3"} {
		before := steps(t, c, id)
		waitFor(t, id+" working again", 15*time.Second, func() bool {
			return !gateState(t, c, id).Paused && steps(t, c, id) > before
		})
	}
	if _, paused, _ := schedState(t, c, "sched-a"); paused {
		t.Error("sched-a still paused after resume")
	}
	if _, paused, note := schedState(t, c, "sched-a-maint"); !paused || note != "customer maintenance" {
		t.Errorf("resume unpaused the customer's schedule: %v %q", paused, note)
	}
	if m, err := temporalsdk.CheckMarker(ctx, c, "agent-a"); err != nil || m.Paused {
		t.Errorf("marker after resume: %+v %v", m, err)
	}
	if res, err := tp.Resume(ctx, "agent-a", "again"); err != nil || !strings.Contains(res.Detail, "no pause marker was recorded") {
		t.Errorf("second resume: %+v %v", res, err)
	}

	// --- Cancel: agent-a's workflows and schedules only. Not reversible.
	res, err = tp.Cancel(ctx, "agent-a", "kill")
	if err != nil {
		t.Fatalf("cancel: %v (%+v)", err, res)
	}
	if res.Affected != 5 || !strings.Contains(res.Detail, "requested cancellation of 3 workflows") ||
		!strings.Contains(res.Detail, "deleted 2 schedules") || !strings.Contains(res.Detail, "not reversible") {
		t.Fatalf("cancel result: %+v", res)
	}
	for _, id := range []string{"a-1", "a-2", "a-3"} {
		waitFor(t, id+" cancelled", 15*time.Second, func() bool {
			return wfStatus(t, c, id) == enumspb.WORKFLOW_EXECUTION_STATUS_CANCELED
		})
	}
	if st := wfStatus(t, c, "b-1"); st != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		t.Fatalf("agent-b's workflow: %v", st)
	}
	for _, id := range []string{"sched-a", "sched-a-maint"} {
		if ok, _, _ := schedState(t, c, id); ok {
			t.Errorf("%s not deleted", id)
		}
	}
	if ok, paused, _ := schedState(t, c, "sched-b"); !ok || paused {
		t.Error("agent-b's schedule touched")
	}
	waitFor(t, "agent-a closed in visibility", 30*time.Second, func() bool { return runningCount(t, c, "agent-a") == 0 })
	if res, err := tp.Cancel(ctx, "agent-a", "again"); err != nil || res.Affected != 0 {
		t.Errorf("second cancel: %+v %v", res, err)
	}

	// --- Connection tester.
	r, _ := src.Get(ctx, SystemTemporal)
	if err := tp.Test(ctx, r); err != nil {
		t.Fatalf("tester: %v", err)
	}
	src.set(t, SystemTemporal, map[string]any{"host_port": addr, "namespace": "plain"}, nil)
	r, _ = src.Get(ctx, SystemTemporal)
	if err := tp.Test(ctx, r); err == nil || !strings.Contains(err.Error(), "search-attribute create") {
		t.Errorf("tester on a namespace without FortikAgentId: %v", err)
	}
}

func TestTemporalNotConfiguredAndRefusals(t *testing.T) {
	ctx := context.Background()
	src := newSource()
	tp := NewTemporal(src, nil)
	for name, op := range map[string]func(context.Context, string, string) (Result, error){"pause": tp.Pause, "resume": tp.Resume, "cancel": tp.Cancel} {
		if _, err := op(ctx, "agent-1", "r"); !errors.Is(err, ErrNotConfigured) {
			t.Errorf("%s without integration: %v", name, err)
		}
	}
	// An agent id that could break out of the visibility query is refused
	// before anything is dialled.
	src.set(t, SystemTemporal, map[string]any{"host_port": "127.0.0.1:1"}, nil)
	if _, err := tp.Pause(ctx, "a' OR 'x'='x", "r"); err == nil || !strings.Contains(err.Error(), "invalid agent id") {
		t.Errorf("injection id: %v", err)
	}
	// An API key is never sent in plaintext.
	src.set(t, SystemTemporal, map[string]any{"host_port": "127.0.0.1:1", "tls": false}, map[string]string{"api_key": "tmprl-secret-key-123"})
	_, err := tp.Pause(ctx, "agent-1", "r")
	if err == nil || !strings.Contains(err.Error(), "TLS is off") || strings.Contains(err.Error(), "tmprl-secret-key-123") {
		t.Errorf("api key without tls: %v", err)
	}
	// Unreachable server: a failed step, honestly reported, no secrets.
	src.set(t, SystemTemporal, map[string]any{"host_port": "127.0.0.1:1"}, nil)
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if _, err := tp.Cancel(cctx, "agent-1", "r"); err == nil || errors.Is(err, ErrNotConfigured) {
		t.Errorf("unreachable: %v", err)
	}
}
