package agentgw

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"fortik/internal/action"
)

// The A2A response observer (Envoy ext_proc v3, configured on A2A routes
// next to extAuthz) closes delegation hops when the delegated task visibly
// ends (docs/PHASE3_DESIGN.md §1.1): a task or status update in a terminal
// state, a direct message reply that created no task, or an error reply.
//
// It never decides anything and never changes traffic: agentgateway v1.6.0
// runs ext_proc in FULL_DUPLEX_STREAMED mode, and every body chunk is echoed
// back unchanged as it arrives (streams are not buffered). agentgateway runs
// extAuthz before extProc, so the x-fortik-action-id the observer sees is the
// one the callout injected (a client copy is overwritten); the observer only
// acts on an action the callout allowed on this very route. Any doubt (no
// action, wrong route, unparseable body, lookup error) means the hop stays
// open until it expires: strictly the more restrictive outcome.

const (
	maxObservedBody   = 1 << 20          // non-streaming bodies larger than this are not inspected
	maxObservedEvent  = 1 << 20          // one SSE event
	maxObservedAge    = 10 * time.Minute // the action must be this recent
	observerOpTimeout = 2 * time.Second
)

// terminalStates are A2A TaskState values after which the task does no more work.
var terminalStates = map[string]bool{"completed": true, "canceled": true, "cancelled": true, "failed": true, "rejected": true}

// procService implements Envoy ext_proc v3 (ExternalProcessor/Process).
type procService struct {
	procv3.UnimplementedExternalProcessorServer
	s *Server
}

// Process echoes every message back unchanged and feeds the response body
// to an observer. An unknown message type ends the stream with an error
// (agentgateway's failClosed then fails the request).
func (p *procService) Process(st procv3.ExternalProcessor_ProcessServer) (err error) {
	s := p.s
	ctx := st.Context()
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("ext_proc observer panicked; failing the stream", "panic", r)
			err = status.Error(codes.Internal, "fortik observer error")
		}
	}()
	obs := &a2aObserver{s: s}
	if route, rerr := routeMeta(ctx, MetaRouteAgent); rerr == nil {
		obs.route = route
	}
	for {
		req, rerr := st.Recv()
		if errors.Is(rerr, io.EOF) {
			return nil
		}
		if rerr != nil {
			return rerr
		}
		var resp *procv3.ProcessingResponse
		var chunk []byte
		eos := false
		switch r := req.GetRequest().(type) {
		case *procv3.ProcessingRequest_RequestHeaders:
			obs.actionID = headerValue(r.RequestHeaders.GetHeaders(), HeaderActionID)
			resp = &procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_RequestHeaders{RequestHeaders: &procv3.HeadersResponse{}}}
		case *procv3.ProcessingRequest_RequestBody:
			resp = &procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_RequestBody{RequestBody: echoBody(r.RequestBody)}}
		case *procv3.ProcessingRequest_RequestTrailers:
			resp = &procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_RequestTrailers{RequestTrailers: &procv3.TrailersResponse{}}}
		case *procv3.ProcessingRequest_ResponseHeaders:
			h := r.ResponseHeaders.GetHeaders()
			obs.status, _ = strconv.Atoi(headerValue(h, ":status"))
			obs.contentType = strings.ToLower(headerValue(h, "content-type"))
			obs.encoded = headerValue(h, "content-encoding") != "" && !strings.EqualFold(headerValue(h, "content-encoding"), "identity")
			eos = r.ResponseHeaders.GetEndOfStream()
			resp = &procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ResponseHeaders{ResponseHeaders: &procv3.HeadersResponse{}}}
		case *procv3.ProcessingRequest_ResponseBody:
			chunk, eos = r.ResponseBody.GetBody(), r.ResponseBody.GetEndOfStream()
			resp = &procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ResponseBody{ResponseBody: echoBody(r.ResponseBody)}}
		case *procv3.ProcessingRequest_ResponseTrailers:
			eos = true
			resp = &procv3.ProcessingResponse{Response: &procv3.ProcessingResponse_ResponseTrailers{ResponseTrailers: &procv3.TrailersResponse{}}}
		default:
			s.log.Error("ext_proc observer got an unknown message type; failing the stream", "type", fmt.Sprintf("%T", r))
			return status.Error(codes.Unimplemented, "unsupported ext_proc message")
		}
		if err := st.Send(resp); err != nil {
			return err
		}
		// Observe after the echo so the observer never delays traffic.
		if len(chunk) > 0 || eos {
			obs.feed(ctx, chunk, eos)
		}
	}
}

// echoBody returns a body chunk unchanged (FULL_DUPLEX_STREAMED requires
// the processor to send every chunk back).
func echoBody(b *procv3.HttpBody) *procv3.BodyResponse {
	return &procv3.BodyResponse{Response: &procv3.CommonResponse{BodyMutation: &procv3.BodyMutation{
		Mutation: &procv3.BodyMutation_StreamedResponse{StreamedResponse: &procv3.StreamedBodyResponse{
			Body: b.GetBody(), EndOfStream: b.GetEndOfStream(),
		}},
	}}}
}

// headerValue returns the first value of header k (lowercase) in m.
func headerValue(m *corev3.HeaderMap, k string) string {
	for _, h := range m.GetHeaders() {
		if strings.EqualFold(h.GetKey(), k) {
			if len(h.GetRawValue()) > 0 {
				return string(h.GetRawValue())
			}
			return h.GetValue()
		}
	}
	return ""
}

// a2aObserver watches one A2A response.
type a2aObserver struct {
	s           *Server
	route       string
	actionID    string
	status      int
	contentType string
	encoded     bool

	buf      bytes.Buffer // non-streaming body, or the current SSE event
	disabled bool         // nothing more to learn (closed, overflow, not observable)
	done     bool         // the stream finished

	info   *observedAction
	looked bool
}

func (o *a2aObserver) sse() bool { return strings.HasPrefix(o.contentType, "text/event-stream") }

// feed takes the next response chunk (eos: the response is complete).
func (o *a2aObserver) feed(ctx context.Context, chunk []byte, eos bool) {
	if o.done {
		return
	}
	if eos {
		defer func() { o.done = true }()
	}
	if o.disabled || o.s.pool == nil || o.actionID == "" || o.route == "" || o.encoded {
		return
	}
	if o.status >= 400 {
		if eos {
			o.onFailure(ctx, fmt.Sprintf("delegatee answered HTTP %d", o.status))
		}
		return
	}
	if o.sse() {
		o.feedSSE(ctx, chunk, eos)
		return
	}
	if o.buf.Len()+len(chunk) > maxObservedBody {
		o.disabled = true
		o.buf.Reset()
		return
	}
	o.buf.Write(chunk)
	if eos {
		o.onMessage(ctx, o.buf.Bytes())
		o.buf.Reset()
	}
}

// feedSSE splits a text/event-stream into events and observes each one's data.
func (o *a2aObserver) feedSSE(ctx context.Context, chunk []byte, eos bool) {
	if o.buf.Len()+len(chunk) > maxObservedEvent {
		o.disabled = true
		o.buf.Reset()
		return
	}
	o.buf.Write(chunk)
	for !o.disabled {
		data := o.buf.Bytes()
		i, n := eventBoundary(data)
		if i < 0 {
			break
		}
		event := append([]byte(nil), data[:i]...)
		o.buf.Next(i + n)
		if payload := sseData(event); len(payload) > 0 {
			o.onMessage(ctx, payload)
		}
	}
	if eos && !o.disabled && o.buf.Len() > 0 {
		if payload := sseData(o.buf.Bytes()); len(payload) > 0 {
			o.onMessage(ctx, payload)
		}
		o.buf.Reset()
	}
}

// eventBoundary finds the blank line ending an SSE event: its index and length.
func eventBoundary(b []byte) (int, int) {
	best, size := -1, 0
	for _, sep := range []string{"\n\n", "\r\n\r\n", "\r\r"} {
		if i := bytes.Index(b, []byte(sep)); i >= 0 && (best < 0 || i < best) {
			best, size = i, len(sep)
		}
	}
	return best, size
}

// sseData joins an event's data: lines.
func sseData(event []byte) []byte {
	var out [][]byte
	for _, line := range bytes.FieldsFunc(event, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if v, ok := bytes.CutPrefix(line, []byte("data:")); ok {
			out = append(out, bytes.TrimPrefix(v, []byte(" ")))
		}
	}
	return bytes.Join(out, []byte("\n"))
}

// rpcResponse is a JSON-RPC response from the delegatee.
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result"`
	Error   json.RawMessage `json:"error"`
}

// a2aResult is the part of an A2A Task, Message or status-update event the
// observer needs.
type a2aResult struct {
	Kind   string `json:"kind"`
	ID     string `json:"id"`
	TaskID string `json:"taskId"`
	Role   string `json:"role"`
	Status *struct {
		State string `json:"state"`
	} `json:"status"`
	Final bool `json:"final"`
}

// onMessage observes one JSON-RPC response (a whole body, or one SSE event).
func (o *a2aObserver) onMessage(ctx context.Context, raw []byte) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '{' || checkJSON(raw) != nil {
		return
	}
	var env rpcResponse
	if err := json.Unmarshal(raw, &env); err != nil || env.JSONRPC != "2.0" {
		return
	}
	if len(env.Error) > 0 && string(env.Error) != "null" {
		o.onFailure(ctx, "delegatee answered with a JSON-RPC error")
		return
	}
	var r a2aResult
	if len(env.Result) == 0 || env.Result[0] != '{' || json.Unmarshal(env.Result, &r) != nil {
		return
	}
	switch {
	case r.Kind == "message" || (r.Kind == "" && r.Role != "" && r.Status == nil):
		// A message that is not part of a task ends the interaction.
		if r.TaskID == "" {
			o.onEnded(ctx, "", "delegatee replied with a message (no task)")
		}
	case r.Kind == "task" || (r.Kind == "" && r.ID != "" && r.Status != nil):
		if r.Status != nil && terminalStates[r.Status.State] && boundedID(r.ID) {
			o.onEnded(ctx, r.ID, "task "+r.Status.State)
		}
	case r.Kind == "status-update":
		if r.Status != nil && terminalStates[r.Status.State] && boundedID(r.TaskID) {
			o.onEnded(ctx, r.TaskID, "task "+r.Status.State)
		}
	}
}

func boundedID(id string) bool { return id != "" && len(id) <= 256 && printable(id) }

// observedAction is the allowed callout action a response belongs to.
type observedAction struct {
	Agent        string
	Verb         action.Verb
	ToAgent      string
	TaskID       string // the task the request named (tasks/*, or message.taskId)
	DelegationID string // the open hop the action opened (DELEGATE only)
}

// lookup loads the action the callout allowed for this request, once.
// It must be an allowed a2a action from the callout, recent, and for the
// agent this route targets.
func (o *a2aObserver) lookup(ctx context.Context) *observedAction {
	if o.looked {
		return o.info
	}
	o.looked = true
	toAgent, ok := o.s.cfg.A2ATargets[o.route]
	if !ok || !agentIDPattern.MatchString(o.actionID) {
		return nil
	}
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), observerOpTimeout)
	defer cancel()
	var a observedAction
	var verb, decision string
	var ts time.Time
	err := o.s.pool.QueryRow(lctx, `
		SELECT a.agent_id, a.verb, a.decision, a.ts, COALESCE(a.target->>'to_agent', ''), COALESCE(a.target->>'task_id', ''),
		       COALESCE((SELECT d.delegation_id FROM delegations d
		                 WHERE d.action_id = a.action_id AND d.status = 'open' AND d.from_agent = a.agent_id
		                 LIMIT 1), '')
		FROM actions a
		WHERE a.action_id = $1 AND a.system = 'a2a' AND a.source = $2`,
		o.actionID, action.SourceAgentGateway).Scan(&a.Agent, &verb, &decision, &ts, &a.ToAgent, &a.TaskID, &a.DelegationID)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			o.s.log.Error("A2A response observer: action lookup failed; hop stays open", "action_id", o.actionID, "err", err)
		}
		return nil
	}
	a.Verb = action.Verb(verb)
	switch {
	case decision != "allow", a.ToAgent != toAgent, time.Since(ts) > maxObservedAge:
		return nil
	}
	o.info = &a
	return o.info
}

// onEnded handles a visible end of work: taskID is the task that ended
// ("" for a direct message reply to a DELEGATE).
func (o *a2aObserver) onEnded(ctx context.Context, taskID, reason string) {
	a := o.lookup(ctx)
	if a == nil {
		o.disabled = true
		return
	}
	switch {
	case a.Verb == action.VerbDelegate:
		// The hop this request opened (if the task id is the request's own,
		// or the request did not name one) and every other open hop of the task.
		if a.TaskID != "" && taskID != "" && taskID != a.TaskID {
			return
		}
		if a.DelegationID != "" {
			o.closeHop(ctx, a, a.DelegationID, reason)
		}
		if taskID != "" {
			o.closeTask(ctx, a, taskID, reason)
		}
		o.disabled = true
	case a.TaskID != "" && taskID == a.TaskID:
		// tasks/get, tasks/cancel, tasks/resubscribe on that task.
		o.closeTask(ctx, a, taskID, reason)
		o.disabled = true
	}
}

// onFailure handles an error reply: a DELEGATE that failed opened no work.
func (o *a2aObserver) onFailure(ctx context.Context, reason string) {
	a := o.lookup(ctx)
	o.disabled = true
	if a == nil || a.Verb != action.VerbDelegate || a.DelegationID == "" {
		return
	}
	o.closeHop(ctx, a, a.DelegationID, reason)
}

func (o *a2aObserver) closeHop(ctx context.Context, a *observedAction, id, reason string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), observerOpTimeout)
	defer cancel()
	if err := o.s.deleg.Close(cctx, id, truncate(reason, 200)); err != nil {
		o.s.log.Error("A2A response observer: could not close delegation hop; it stays open until it expires",
			"action_id", o.actionID, "delegation_id", id, "err", err)
		return
	}
	o.s.log.Info("closed delegation hop on A2A response", "action_id", o.actionID, "delegation_id", id,
		"from", a.Agent, "to", a.ToAgent, "reason", reason)
}

func (o *a2aObserver) closeTask(ctx context.Context, a *observedAction, taskID, reason string) {
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), observerOpTimeout)
	defer cancel()
	n, err := o.s.deleg.CloseTask(cctx, a.Agent, a.ToAgent, taskID, truncate(reason, 200))
	if err != nil {
		o.s.log.Error("A2A response observer: could not close task hops; they stay open until they expire",
			"action_id", o.actionID, "task_id", taskID, "err", err)
		return
	}
	if n > 0 {
		o.s.log.Info("closed delegation hops for a finished A2A task", "action_id", o.actionID, "task_id", taskID, "hops", n)
	}
}
