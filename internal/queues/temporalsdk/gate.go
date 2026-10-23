// Package temporalsdk is the small helper customers use inside Temporal
// workflows to honour Fortik's pause and resume (Fortik containment:
// "pause the agent's queued jobs").
//
// Temporal cannot freeze an arbitrary running workflow from outside, so
// Fortik signals every open workflow tagged with the agent
// (search attribute FortikAgentId) and records a pause marker for workflows
// that start later. A workflow that uses a Gate stops at its next Wait call
// while the agent is paused:
//
//	func MyWorkflow(ctx workflow.Context, in Input) error {
//		gate := temporalsdk.New(ctx, temporalsdk.Options{CheckMarker: true})
//		for _, step := range in.Steps {
//			if err := gate.Wait(ctx); err != nil {
//				return err // cancelled while paused
//			}
//			// ... run the step's activities ...
//		}
//		return nil
//	}
//
// Start agent workflows with the tag:
//
//	client.StartWorkflowOptions{
//		TypedSearchAttributes: temporal.NewSearchAttributes(temporalsdk.AgentKey.ValueSet(agentID)),
//	}
//
// and, for CheckMarker, register the marker check on the worker:
//
//	temporalsdk.RegisterMarkerCheck(w, c)
//
// Cancellation needs no helper: Fortik requests cancellation of the
// workflows and Wait returns the cancellation error.
package temporalsdk

import (
	"context"
	"errors"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/workflow"
)

// Names shared by Fortik and customer workflows.
const (
	// SearchAttribute is the Keyword search attribute that attributes a
	// workflow or schedule to a Fortik agent.
	SearchAttribute = "FortikAgentId"
	// MemoAgentKey is the memo key that attributes a schedule to an agent
	// when the search attribute is not set on it.
	MemoAgentKey = "fortik_agent_id"

	PauseSignal  = "fortik-pause"
	ResumeSignal = "fortik-resume"
	// StateQuery returns the workflow's State (for operators and tests).
	StateQuery = "fortik-pause-state"

	// The pause marker is a workflow Fortik starts (and terminates on
	// resume) with this type on a task queue nobody polls; it never runs.
	// Its memo holds the agent, the reason and the time.
	MarkerWorkflowType = "FortikPauseMarker"
	MarkerTaskQueue    = "fortik-pause-markers"
	markerIDPrefix     = "fortik-pause-marker/"

	// CheckMarkerActivity is the local activity RegisterMarkerCheck adds.
	CheckMarkerActivity = "FortikCheckPauseMarker"

	// markerRecheck is how long a workflow waits before asking again when
	// the marker check fails (it stays paused meanwhile: fail closed).
	markerRecheck = 30 * time.Second
)

// AgentKey is the typed search attribute key.
var AgentKey = temporal.NewSearchAttributeKeyKeyword(SearchAttribute)

// MarkerWorkflowID is the pause marker's workflow id for an agent.
func MarkerWorkflowID(agentID string) string { return markerIDPrefix + agentID }

// Signal is the payload of the fortik-pause and fortik-resume signals.
type Signal struct {
	AgentID string    `json:"agent_id"`
	Reason  string    `json:"reason"`
	At      time.Time `json:"at"`
}

// State is what the StateQuery returns.
type State struct {
	AgentID string `json:"agent_id"`
	Paused  bool   `json:"paused"`
	Reason  string `json:"reason,omitempty"`
}

// MarkerState is the result of the marker check.
type MarkerState struct {
	Paused bool   `json:"paused"`
	Reason string `json:"reason,omitempty"`
}

// Options configure a Gate.
type Options struct {
	// CheckMarker asks, when the workflow starts, whether its agent is
	// paused (Fortik's pause marker), so work queued while the agent is
	// paused waits too. The worker must have called RegisterMarkerCheck.
	// If the check fails the workflow treats itself as paused and asks
	// again every 30 seconds (fail closed).
	CheckMarker bool
}

// Gate tracks the pause state of one workflow execution.
type Gate struct {
	state State
}

// New installs the pause/resume signal handlers and the state query. Call
// it once, at the start of the workflow function.
func New(ctx workflow.Context, opts Options) *Gate {
	g := &Gate{}
	g.state.AgentID, _ = workflow.GetTypedSearchAttributes(ctx).GetKeyword(AgentKey)
	_ = workflow.SetQueryHandler(ctx, StateQuery, func() (State, error) { return g.state, nil })
	pauseCh := workflow.GetSignalChannel(ctx, PauseSignal)
	resumeCh := workflow.GetSignalChannel(ctx, ResumeSignal)
	if opts.CheckMarker && g.state.AgentID != "" {
		// Signals that arrive during the check are buffered and applied
		// after it, in order, so a resume sent after the check wins.
		g.checkMarker(ctx)
	}
	workflow.Go(ctx, func(ctx workflow.Context) {
		for {
			var s Signal
			sel := workflow.NewSelector(ctx)
			sel.AddReceive(pauseCh, func(c workflow.ReceiveChannel, _ bool) {
				c.Receive(ctx, &s)
				g.state.Paused, g.state.Reason = true, s.Reason
				workflow.GetLogger(ctx).Info("Fortik paused this agent's work", "agent", g.state.AgentID, "reason", s.Reason)
			})
			sel.AddReceive(resumeCh, func(c workflow.ReceiveChannel, _ bool) {
				c.Receive(ctx, &s)
				g.state.Paused, g.state.Reason = false, ""
				workflow.GetLogger(ctx).Info("Fortik resumed this agent's work", "agent", g.state.AgentID)
			})
			sel.Select(ctx)
		}
	})
	return g
}

func (g *Gate) checkMarker(ctx workflow.Context) {
	lctx := workflow.WithLocalActivityOptions(ctx, workflow.LocalActivityOptions{
		ScheduleToCloseTimeout: 30 * time.Second,
		RetryPolicy:            &temporal.RetryPolicy{MaximumAttempts: 3},
	})
	for {
		var m MarkerState
		err := workflow.ExecuteLocalActivity(lctx, CheckMarkerActivity, g.state.AgentID).Get(lctx, &m)
		if err == nil {
			g.state.Paused, g.state.Reason = m.Paused, m.Reason
			return
		}
		workflow.GetLogger(ctx).Error("Fortik pause marker check failed; waiting before asking again", "agent", g.state.AgentID, "error", err)
		g.state.Paused, g.state.Reason = true, "pause state unknown (marker check failed)"
		if workflow.Sleep(ctx, markerRecheck) != nil {
			return // cancelled: Wait reports it
		}
	}
}

// Paused reports whether Fortik has paused this workflow's agent.
func (g *Gate) Paused() bool { return g.state.Paused }

// State returns the current pause state.
func (g *Gate) State() State { return g.state }

// Wait returns immediately unless the agent is paused, and otherwise blocks
// until it is resumed or the workflow is cancelled (then it returns the
// cancellation error). Call it before each unit of work.
func (g *Gate) Wait(ctx workflow.Context) error {
	if !g.state.Paused {
		return ctx.Err()
	}
	return workflow.Await(ctx, func() bool { return !g.state.Paused })
}

// RegisterMarkerCheck registers the local activity that Options.CheckMarker
// uses. c must be connected to the namespace the workflows run in.
func RegisterMarkerCheck(r worker.ActivityRegistry, c client.Client) {
	r.RegisterActivityWithOptions(func(ctx context.Context, agentID string) (MarkerState, error) {
		return CheckMarker(ctx, c, agentID)
	}, activity.RegisterOptions{Name: CheckMarkerActivity})
}

// CheckMarker reports whether Fortik's pause marker for the agent is open.
func CheckMarker(ctx context.Context, c client.Client, agentID string) (MarkerState, error) {
	d, err := c.DescribeWorkflowExecution(ctx, MarkerWorkflowID(agentID), "")
	var nf *serviceerror.NotFound
	if errors.As(err, &nf) {
		return MarkerState{}, nil
	}
	if err != nil {
		return MarkerState{}, err
	}
	info := d.GetWorkflowExecutionInfo()
	if info.GetStatus() != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		return MarkerState{}, nil
	}
	m := MarkerState{Paused: true}
	if p := info.GetMemo().GetFields()["reason"]; p != nil {
		_ = converter.GetDefaultDataConverter().FromPayload(p, &m.Reason)
	}
	return m, nil
}
