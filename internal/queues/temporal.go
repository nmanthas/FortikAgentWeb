package queues

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	commonpb "go.temporal.io/api/common/v1"
	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/api/serviceerror"
	"go.temporal.io/api/workflowservice/v1"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	sdklog "go.temporal.io/sdk/log"

	"fortik/internal/integrations"
	"fortik/internal/queues/temporalsdk"
)

const (
	// temporalMaxWorkflows caps the workflows one operation touches (an
	// honest "truncated" note is added beyond it).
	temporalMaxWorkflows = 10000
	// temporalMaxSchedules caps the schedules one operation inspects.
	temporalMaxSchedules = 2000
	temporalParallel     = 16
	// scheduleNotePrefix marks schedules Fortik paused, so Resume unpauses
	// only those (never one the customer paused).
	scheduleNotePrefix = "fortik-pause:"
	temporalHonesty    = "Temporal cannot freeze arbitrary running workflows: workers must honour the fortik-pause signal (Fortik temporalsdk helper)"
)

// Temporal is the queue adapter for Temporal. Work is attributed to an agent
// by the Keyword search attribute FortikAgentId on workflows and schedules
// (or the memo key fortik_agent_id on schedules).
type Temporal struct {
	src    integrations.Source
	logger sdklog.Logger
	now    func() time.Time
	// Safety caps (temporalMaxWorkflows, temporalMaxSchedules; tests lower
	// them). Reaching one is ErrTruncated, never a silent partial success.
	maxWorkflows, maxSchedules int
	// afterList runs after the agent's workflows are listed (tests only:
	// lets a test continue a workflow as new between list and signal).
	afterList func(ctx context.Context)
}

var (
	_ Adapter             = (*Temporal)(nil)
	_ integrations.Tester = (*Temporal)(nil)
)

// NewTemporal builds the adapter. It dials the configured frontend for each
// operation (operations are rare; settings changes apply immediately). log
// may be nil (SDK logs are then discarded).
func NewTemporal(src integrations.Source, log *slog.Logger) *Temporal {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Temporal{
		src:    src,
		logger: sdklog.NewStructuredLogger(log.With("component", "queues.temporal")),
		now:    func() time.Time { return time.Now().UTC() },

		maxWorkflows: temporalMaxWorkflows,
		maxSchedules: temporalMaxSchedules,
	}
}

func (*Temporal) System() string { return SystemTemporal }

type temporalConn struct {
	c                          client.Client
	namespace                  string
	maxWorkflows, maxSchedules int
}

func (t *Temporal) options(r integrations.Resolved) (client.Options, error) {
	hostPort := r.Text("host_port")
	if hostPort == "" {
		return client.Options{}, fmt.Errorf("%w: temporal: host_port not set", ErrNotConfigured)
	}
	ns := r.Text("namespace")
	if ns == "" {
		ns = "default"
	}
	opts := client.Options{
		HostPort:  hostPort,
		Namespace: ns,
		Logger:    t.logger,
		Identity:  "fortik-queues",
	}
	if r.Bool("tls") {
		opts.ConnectionOptions.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if key := r.Secret("api_key"); key != "" {
		if !r.Bool("tls") {
			return client.Options{}, errors.New("temporal: an API key is set but TLS is off; refusing to send the key in plaintext (enable TLS)")
		}
		opts.Credentials = client.NewAPIKeyStaticCredentials(key)
	}
	return opts, nil
}

func (t *Temporal) dial(ctx context.Context, r integrations.Resolved) (temporalConn, error) {
	opts, err := t.options(r)
	if err != nil {
		return temporalConn{}, err
	}
	dctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	c, err := client.DialContext(dctx, opts)
	if err != nil {
		return temporalConn{}, temporalErr("connect to "+opts.HostPort, err)
	}
	return temporalConn{c: c, namespace: opts.Namespace, maxWorkflows: t.maxWorkflows, maxSchedules: t.maxSchedules}, nil
}

func (t *Temporal) open(ctx context.Context) (temporalConn, error) {
	r, err := resolve(ctx, t.src, SystemTemporal)
	if err != nil {
		return temporalConn{}, err
	}
	return t.dial(ctx, r)
}

// temporalErr summarises a Temporal/gRPC error (status message only; never
// credentials).
func temporalErr(op string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("temporal: %s: timed out", op)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("temporal: %s: cancelled", op)
	}
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return fmt.Errorf("temporal: %s: %s", op, msg)
}

func isNotFound(err error) bool {
	var nf *serviceerror.NotFound
	return errors.As(err, &nf)
}

// wfExec is one running workflow found by the visibility query. A workflow
// id can move to a new run (continue-as-new, retries, cron) at any time, so
// operations target the chain (firstRunID), never the listed run.
type wfExec struct{ id, runID, firstRunID string }

// openWorkflows lists the agent's running workflows (visibility query).
func (tc temporalConn) openWorkflows(ctx context.Context, agentID string) ([]wfExec, bool, error) {
	// agentID matches agentIDPattern: no quotes or backslashes.
	query := fmt.Sprintf("%s = '%s' AND ExecutionStatus = 'Running'", temporalsdk.SearchAttribute, agentID)
	var out []wfExec
	var token []byte
	for {
		resp, err := tc.c.ListWorkflow(ctx, &workflowservice.ListWorkflowExecutionsRequest{
			Namespace: tc.namespace, PageSize: 1000, NextPageToken: token, Query: query,
		})
		if err != nil {
			return out, false, temporalErr("list workflows", err)
		}
		for _, e := range resp.GetExecutions() {
			if len(out) >= tc.maxWorkflows {
				return out, true, nil
			}
			out = append(out, wfExec{id: e.GetExecution().GetWorkflowId(), runID: e.GetExecution().GetRunId(), firstRunID: e.GetFirstRunId()})
		}
		token = resp.GetNextPageToken()
		if len(token) == 0 {
			return out, false, nil
		}
	}
}

// errChainClosed: the workflow's chain (every run since its first) has
// closed, or its id now belongs to a different chain started since.
var errChainClosed = errors.New("workflow closed")

// chainAttempts bounds how often an operation chases a chain that keeps
// moving to new runs before it gives up (reported as a failure).
const chainAttempts = 5

// current describes the running execution of w's chain.
func (tc temporalConn) current(ctx context.Context, w wfExec) (runID, firstRunID string, err error) {
	d, err := tc.c.DescribeWorkflowExecution(ctx, w.id, "")
	if isNotFound(err) {
		return "", "", errChainClosed
	}
	if err != nil {
		return "", "", err
	}
	info := d.GetWorkflowExecutionInfo()
	first := info.GetFirstRunId()
	if w.firstRunID != "" && first != "" && first != w.firstRunID {
		return "", "", errChainClosed // the id was reused by another chain: not this agent's listed work
	}
	if info.GetStatus() != enumspb.WORKFLOW_EXECUTION_STATUS_RUNNING {
		return "", "", errChainClosed
	}
	if first == "" {
		first = w.firstRunID
	}
	return info.GetExecution().GetRunId(), first, nil
}

// withChain fills w.firstRunID when the visibility store did not return it
// (some stores leave it empty) by describing the listed run itself.
func (tc temporalConn) withChain(ctx context.Context, w wfExec) (wfExec, error) {
	if w.firstRunID != "" {
		return w, nil
	}
	d, err := tc.c.DescribeWorkflowExecution(ctx, w.id, w.runID)
	if isNotFound(err) {
		return w, errChainClosed
	}
	if err != nil {
		return w, err
	}
	w.firstRunID = d.GetWorkflowExecutionInfo().GetFirstRunId()
	return w, nil
}

// signalChain signals the current run of w's chain. A run that closed
// between describe and signal (continue-as-new) is looked up again; only a
// closed chain counts as gone.
func (tc temporalConn) signalChain(ctx context.Context, w wfExec, name string, arg any) error {
	w, err := tc.withChain(ctx, w)
	if err != nil {
		return err
	}
	for range chainAttempts {
		run, _, err := tc.current(ctx, w)
		if err != nil {
			return err
		}
		err = tc.c.SignalWorkflow(ctx, w.id, run, name, arg)
		if err == nil || !isNotFound(err) {
			return err
		}
	}
	return errors.New("the workflow kept moving to new runs: signal not confirmed")
}

// cancelChain requests cancellation of the current run of w's chain. The
// request names no run id, only the chain's first run, so the server
// applies it to whatever run is current at that moment (a request against
// an old run that already continued as new would be accepted and do
// nothing).
func (tc temporalConn) cancelChain(ctx context.Context, w wfExec, reason string) error {
	w, err := tc.withChain(ctx, w)
	if err != nil {
		return err
	}
	for range chainAttempts {
		_, first, err := tc.current(ctx, w)
		if err != nil {
			return err
		}
		_, err = tc.c.WorkflowService().RequestCancelWorkflowExecution(ctx, &workflowservice.RequestCancelWorkflowExecutionRequest{
			Namespace:           tc.namespace,
			WorkflowExecution:   &commonpb.WorkflowExecution{WorkflowId: w.id},
			FirstExecutionRunId: first,
			Identity:            "fortik-queues",
			RequestId:           newUUID(),
			Reason:              truncateNote("fortik cancel_queue: " + reason),
		})
		if err == nil {
			return nil
		}
		// Closed (NotFound) or no longer this chain (the server refuses a
		// first run id that does not match): look again; anything else
		// while the chain still runs is a failure.
		if _, _, cerr := tc.current(ctx, w); cerr != nil {
			if errors.Is(cerr, errChainClosed) {
				return errChainClosed
			}
			return err
		}
		if !isNotFound(err) {
			return err
		}
	}
	return errors.New("the workflow kept moving to new runs: cancellation not confirmed")
}

type perWorkflow struct {
	done, gone int
	failed     []error
}

// each applies fn to every workflow; a chain that closed meanwhile is
// counted as gone, not as a failure.
func each(ctx context.Context, wfs []wfExec, fn func(context.Context, wfExec) error) perWorkflow {
	var p perWorkflow
	for i, err := range forEach(ctx, temporalParallel, wfs, fn) {
		switch {
		case err == nil:
			p.done++
		case errors.Is(err, errChainClosed):
			p.gone++
		default:
			p.failed = append(p.failed, fmt.Errorf("workflow %s: %w", wfs[i].id, err))
		}
	}
	return p
}

func (p perWorkflow) err(op string) error {
	if len(p.failed) == 0 {
		return nil
	}
	return fmt.Errorf("temporal: %s failed for %s (first: %v)", op, plural(len(p.failed), "workflow", "workflows"), temporalErr(op, p.failed[0]))
}

// scheduleRef is one schedule attributed to the agent, with its
// authoritative state (from Describe; list results lag behind pauses).
type scheduleRef struct {
	id     string
	paused bool
	note   string
}

// agentSchedules returns the schedules attributed to the agent: by the
// schedule's own search attribute or memo, or by the search attribute or
// memo of the workflow it starts.
func (tc temporalConn) agentSchedules(ctx context.Context, agentID string) ([]scheduleRef, bool, error) {
	it, err := tc.c.ScheduleClient().List(ctx, client.ScheduleListOptions{PageSize: 500})
	if err != nil {
		return nil, false, temporalErr("list schedules", err)
	}
	var out []scheduleRef
	seen := 0
	for it.HasNext() {
		e, err := it.Next()
		if err != nil {
			return out, false, temporalErr("list schedules", err)
		}
		if seen++; seen > tc.maxSchedules {
			return out, true, nil
		}
		d, err := tc.c.ScheduleClient().GetHandle(ctx, e.ID).Describe(ctx)
		if isNotFound(err) {
			continue // deleted meanwhile
		}
		if err != nil {
			return out, false, temporalErr("describe schedule "+e.ID, err)
		}
		if !scheduleNamesAgent(e, d, agentID) {
			continue
		}
		ref := scheduleRef{id: e.ID}
		if st := d.Schedule.State; st != nil {
			ref.paused, ref.note = st.Paused, st.Note
		}
		out = append(out, ref)
	}
	return out, false, nil
}

func scheduleNamesAgent(e *client.ScheduleListEntry, d *client.ScheduleDescription, agentID string) bool {
	if v, ok := d.TypedSearchAttributes.GetKeyword(temporalsdk.AgentKey); ok && v == agentID {
		return true
	}
	if payloadsName(d.SearchAttributes.GetIndexedFields(), temporalsdk.SearchAttribute, agentID) ||
		payloadsName(d.Memo.GetFields(), temporalsdk.MemoAgentKey, agentID) ||
		payloadsName(e.SearchAttributes.GetIndexedFields(), temporalsdk.SearchAttribute, agentID) ||
		payloadsName(e.Memo.GetFields(), temporalsdk.MemoAgentKey, agentID) {
		return true
	}
	a, ok := d.Schedule.Action.(*client.ScheduleWorkflowAction)
	return ok && actionNamesAgent(a, agentID)
}

func actionNamesAgent(a *client.ScheduleWorkflowAction, agentID string) bool {
	if v, ok := a.TypedSearchAttributes.GetKeyword(temporalsdk.AgentKey); ok && v == agentID {
		return true
	}
	if payloadsName(a.UntypedSearchAttributes, temporalsdk.SearchAttribute, agentID) {
		return true
	}
	if p, ok := a.Memo[temporalsdk.MemoAgentKey].(*commonpb.Payload); ok {
		return payloadsName(map[string]*commonpb.Payload{"k": p}, "k", agentID)
	}
	return false
}

func payloadsName(fields map[string]*commonpb.Payload, key, agentID string) bool {
	p := fields[key]
	if p == nil {
		return false
	}
	var s string
	if converter.GetDefaultDataConverter().FromPayload(p, &s) == nil {
		return s == agentID
	}
	var l []string
	if converter.GetDefaultDataConverter().FromPayload(p, &l) == nil {
		for _, v := range l {
			if v == agentID {
				return true
			}
		}
	}
	return false
}

func (t *Temporal) signal(agentID, reason string) temporalsdk.Signal {
	return temporalsdk.Signal{AgentID: agentID, Reason: reason, At: t.now()}
}

// Pause records the pause marker, signals fortik-pause to every open
// workflow of the agent and pauses the agent's schedules.
func (t *Temporal) Pause(ctx context.Context, agentID, reason string) (Result, error) {
	res := Result{System: SystemTemporal}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	reason = cleanReason(reason)
	tc, err := t.open(ctx)
	if err != nil {
		return res, err
	}
	defer tc.c.Close()

	// 1. Marker first: a workflow starting from now on sees it.
	_, err = tc.c.ExecuteWorkflow(ctx, client.StartWorkflowOptions{
		ID:                       temporalsdk.MarkerWorkflowID(agentID),
		TaskQueue:                temporalsdk.MarkerTaskQueue,
		WorkflowIDConflictPolicy: enumspb.WORKFLOW_ID_CONFLICT_POLICY_USE_EXISTING,
		WorkflowIDReusePolicy:    enumspb.WORKFLOW_ID_REUSE_POLICY_ALLOW_DUPLICATE,
		Memo: map[string]any{
			temporalsdk.MemoAgentKey: agentID,
			"reason":                 reason,
			"paused_at":              t.now().Format(time.RFC3339),
		},
	}, temporalsdk.MarkerWorkflowType)
	if err != nil {
		res.Detail = "could not record the pause marker; nothing was signalled"
		return res, temporalErr("record pause marker", err)
	}

	// 2. Signal open workflows.
	wfs, truncated, err := tc.openWorkflows(ctx, agentID)
	if err != nil {
		res.Detail = "recorded the pause marker but could not list the agent's workflows"
		return res, err
	}
	if t.afterList != nil {
		t.afterList(ctx)
	}
	sig := t.signal(agentID, reason)
	p := each(ctx, wfs, func(ctx context.Context, w wfExec) error {
		return tc.signalChain(ctx, w, temporalsdk.PauseSignal, sig)
	})

	// 3. Pause the agent's schedules (no new runs start).
	scheds, schedTrunc, schedErr := tc.agentSchedules(ctx, agentID)
	pausedSched, schedFailed := 0, 0
	var firstSchedErr error
	if schedErr == nil {
		for _, s := range scheds {
			if s.paused {
				continue
			}
			err := tc.c.ScheduleClient().GetHandle(ctx, s.id).Pause(ctx, client.SchedulePauseOptions{
				Note: truncateNote(scheduleNotePrefix + " agent " + agentID + " suspended: " + reason),
			})
			switch {
			case err == nil:
				pausedSched++
			case isNotFound(err):
			default:
				schedFailed++
				firstSchedErr = cmpErr(firstSchedErr, err)
			}
		}
	}

	res.Affected = p.done + pausedSched
	var parts []string
	parts = append(parts, fmt.Sprintf("signalled %s with %s; %s", plural(p.done, "workflow", "workflows"), temporalsdk.PauseSignal, temporalHonesty))
	if p.gone > 0 {
		parts = append(parts, plural(p.gone, "workflow", "workflows")+" finished before the signal")
	}
	if truncated {
		parts = append(parts, fmt.Sprintf("only the first %d workflows were signalled", tc.maxWorkflows))
	}
	parts = append(parts, fmt.Sprintf("recorded pause marker %s so new workflows using the helper wait", temporalsdk.MarkerWorkflowID(agentID)))
	parts = append(parts, tc.scheduleDetail("paused", pausedSched, schedFailed, schedTrunc, schedErr))
	res.Detail = strings.Join(parts, "; ")
	return res, errors.Join(tc.truncErr(truncated, schedTrunc, "signalled", "paused"),
		p.err("signal "+temporalsdk.PauseSignal), schedOpErr("pause", schedErr, schedFailed, firstSchedErr))
}

// Resume removes the pause marker, signals fortik-resume and unpauses the
// schedules Fortik paused.
func (t *Temporal) Resume(ctx context.Context, agentID, reason string) (Result, error) {
	res := Result{System: SystemTemporal}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	reason = cleanReason(reason)
	tc, err := t.open(ctx)
	if err != nil {
		return res, err
	}
	defer tc.c.Close()

	// 1. Marker first, so a workflow starting now does not wait for a
	// signal it will never get.
	markerNote := "removed the pause marker"
	err = tc.c.TerminateWorkflow(ctx, temporalsdk.MarkerWorkflowID(agentID), "", "fortik resume: "+reason)
	switch {
	case isNotFound(err):
		markerNote = "no pause marker was recorded"
	case err != nil:
		res.Detail = "could not remove the pause marker; nothing was signalled"
		return res, temporalErr("remove pause marker", err)
	}

	wfs, truncated, err := tc.openWorkflows(ctx, agentID)
	if err != nil {
		res.Detail = markerNote + " but could not list the agent's workflows"
		return res, err
	}
	if t.afterList != nil {
		t.afterList(ctx)
	}
	sig := t.signal(agentID, reason)
	p := each(ctx, wfs, func(ctx context.Context, w wfExec) error {
		return tc.signalChain(ctx, w, temporalsdk.ResumeSignal, sig)
	})

	scheds, schedTrunc, schedErr := tc.agentSchedules(ctx, agentID)
	unpaused, schedFailed := 0, 0
	var firstSchedErr error
	if schedErr == nil {
		for _, s := range scheds {
			if !s.paused || !strings.HasPrefix(s.note, scheduleNotePrefix) {
				continue // never unpause a schedule the customer paused
			}
			err := tc.c.ScheduleClient().GetHandle(ctx, s.id).Unpause(ctx, client.ScheduleUnpauseOptions{
				Note: truncateNote("fortik resume: " + reason),
			})
			switch {
			case err == nil:
				unpaused++
			case isNotFound(err):
			default:
				schedFailed++
				firstSchedErr = cmpErr(firstSchedErr, err)
			}
		}
	}

	res.Affected = p.done + unpaused
	parts := []string{fmt.Sprintf("signalled %s with %s", plural(p.done, "workflow", "workflows"), temporalsdk.ResumeSignal), markerNote}
	if truncated {
		parts = append(parts, fmt.Sprintf("only the first %d workflows were signalled", tc.maxWorkflows))
	}
	parts = append(parts, tc.scheduleDetail("unpaused", unpaused, schedFailed, schedTrunc, schedErr))
	res.Detail = strings.Join(parts, "; ")
	return res, errors.Join(tc.truncErr(truncated, schedTrunc, "signalled", "unpaused"),
		p.err("signal "+temporalsdk.ResumeSignal), schedOpErr("unpause", schedErr, schedFailed, firstSchedErr))
}

// Cancel requests cancellation of every open workflow of the agent and
// deletes its schedules. Not reversible.
func (t *Temporal) Cancel(ctx context.Context, agentID, reason string) (Result, error) {
	res := Result{System: SystemTemporal}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	tc, err := t.open(ctx)
	if err != nil {
		return res, err
	}
	defer tc.c.Close()

	wfs, truncated, err := tc.openWorkflows(ctx, agentID)
	if err != nil {
		return res, err
	}
	if t.afterList != nil {
		t.afterList(ctx)
	}
	reason = cleanReason(reason)
	p := each(ctx, wfs, func(ctx context.Context, w wfExec) error {
		return tc.cancelChain(ctx, w, reason)
	})

	scheds, schedTrunc, schedErr := tc.agentSchedules(ctx, agentID)
	deleted, schedFailed := 0, 0
	var firstSchedErr error
	if schedErr == nil {
		for _, s := range scheds {
			err := tc.c.ScheduleClient().GetHandle(ctx, s.id).Delete(ctx)
			switch {
			case err == nil:
				deleted++
			case isNotFound(err):
			default:
				schedFailed++
				firstSchedErr = cmpErr(firstSchedErr, err)
			}
		}
	}

	res.Affected = p.done + deleted
	parts := []string{fmt.Sprintf("requested cancellation of %s (workflows may run their cancellation handling first; pending activity retries stop with them)",
		plural(p.done, "workflow", "workflows"))}
	if p.gone > 0 {
		parts = append(parts, plural(p.gone, "workflow", "workflows")+" finished before the request")
	}
	if truncated {
		parts = append(parts, fmt.Sprintf("only the first %d workflows were cancelled", tc.maxWorkflows))
	}
	parts = append(parts, tc.scheduleDetail("deleted", deleted, schedFailed, schedTrunc, schedErr))
	parts = append(parts, "not reversible: resubmit workflows to run them")
	res.Detail = strings.Join(parts, "; ")
	return res, errors.Join(tc.truncErr(truncated, schedTrunc, "cancelled", "deleted"),
		p.err("cancel"), schedOpErr("delete", schedErr, schedFailed, firstSchedErr))
}

// Test connects, and checks the FortikAgentId search attribute is usable in
// the namespace (a visibility query on it fails if it is not registered).
func (t *Temporal) Test(ctx context.Context, r integrations.Resolved) error {
	tc, err := t.dial(ctx, r)
	if err != nil {
		return err
	}
	defer tc.c.Close()
	_, err = tc.c.CountWorkflow(ctx, &workflowservice.CountWorkflowExecutionsRequest{
		Namespace: tc.namespace,
		Query:     fmt.Sprintf("%s = 'fortik-connection-test'", temporalsdk.SearchAttribute),
	})
	if err != nil {
		var inv *serviceerror.InvalidArgument
		if errors.As(err, &inv) {
			return fmt.Errorf("temporal: namespace %s cannot be queried by %s (register it: temporal operator search-attribute create --namespace %s --name %s --type Keyword): %s",
				tc.namespace, temporalsdk.SearchAttribute, tc.namespace, temporalsdk.SearchAttribute, inv.Message)
		}
		return temporalErr("query workflows by "+temporalsdk.SearchAttribute, err)
	}
	return nil
}

// truncErr is ErrTruncated when a cap was reached (nil otherwise). It comes
// first in the joined error, so the step's recorded reason (which is
// length-capped) leads with what was NOT done.
func (tc temporalConn) truncErr(wfTrunc, schedTrunc bool, wfVerb, schedVerb string) error {
	var what []string
	if wfTrunc {
		what = append(what, fmt.Sprintf("only the first %d workflows were %s, the rest were NOT", tc.maxWorkflows, wfVerb))
	}
	if schedTrunc {
		what = append(what, fmt.Sprintf("only the first %d schedules of the namespace were inspected, schedules beyond them were NOT %s", tc.maxSchedules, schedVerb))
	}
	if len(what) == 0 {
		return nil
	}
	return fmt.Errorf("temporal: %s (%w)", strings.Join(what, "; "), ErrTruncated)
}

func (tc temporalConn) scheduleDetail(verb string, n, failed int, truncated bool, listErr error) string {
	if listErr != nil {
		return "schedules NOT " + verb + " (could not list them)"
	}
	s := verb + " " + plural(n, "schedule", "schedules")
	if failed > 0 {
		s += fmt.Sprintf(" (%d failed)", failed)
	}
	if truncated {
		s += fmt.Sprintf(" (only the first %d schedules were inspected)", tc.maxSchedules)
	}
	return s
}

func schedOpErr(op string, listErr error, failed int, first error) error {
	if listErr != nil {
		return listErr
	}
	if failed > 0 {
		return fmt.Errorf("temporal: %s failed for %s (first: %v)", op, plural(failed, "schedule", "schedules"), temporalErr(op+" schedule", first))
	}
	return nil
}

func cmpErr(first, err error) error {
	if first != nil {
		return first
	}
	return err
}

func truncateNote(s string) string {
	if len(s) <= 200 {
		return s
	}
	cut := 200
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "..."
}
