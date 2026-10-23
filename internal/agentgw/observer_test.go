package agentgw

import (
	"context"
	"io"
	"strconv"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	procv3 "github.com/envoyproxy/go-control-plane/envoy/service/ext_proc/v3"

	"fortik/internal/config"
)

func hmap(kv ...string) *corev3.HeaderMap {
	m := &corev3.HeaderMap{}
	for i := 0; i+1 < len(kv); i += 2 {
		m.Headers = append(m.Headers, &corev3.HeaderValue{Key: kv[i], RawValue: []byte(kv[i+1])})
	}
	return m
}

// observe drives one ext_proc stream like agentgateway does (request
// headers and body, response headers, response body chunks) and checks that
// every body chunk comes back unchanged.
func (f *fixture) observe(t *testing.T, ctx context.Context, actionID string, status int, ctype string, chunks ...string) {
	t.Helper()
	st, err := procv3.NewExternalProcessorClient(f.conn).Process(ctx)
	if err != nil {
		t.Fatal(err)
	}
	roundTrip := func(req *procv3.ProcessingRequest) *procv3.ProcessingResponse {
		t.Helper()
		if err := st.Send(req); err != nil {
			t.Fatal(err)
		}
		resp, err := st.Recv()
		if err != nil {
			t.Fatalf("observer stream: %v", err)
		}
		return resp
	}
	echoed := func(resp *procv3.ProcessingResponse, want string, eos bool) {
		t.Helper()
		var br *procv3.BodyResponse
		switch r := resp.GetResponse().(type) {
		case *procv3.ProcessingResponse_RequestBody:
			br = r.RequestBody
		case *procv3.ProcessingResponse_ResponseBody:
			br = r.ResponseBody
		default:
			t.Fatalf("not a body response: %T", r)
		}
		sr := br.GetResponse().GetBodyMutation().GetStreamedResponse()
		if string(sr.GetBody()) != want || sr.GetEndOfStream() != eos {
			t.Fatalf("chunk not echoed unchanged: got %q eos=%v, want %q eos=%v", sr.GetBody(), sr.GetEndOfStream(), want, eos)
		}
	}
	reqBody := a2aBody("message/send", sendParams)
	if r := roundTrip(&procv3.ProcessingRequest{Request: &procv3.ProcessingRequest_RequestHeaders{RequestHeaders: &procv3.HttpHeaders{
		Headers: hmap(":method", "POST", ":path", "/a2a", HeaderActionID, actionID)}}}); r.GetRequestHeaders() == nil {
		t.Fatalf("request headers: %v", r)
	}
	echoed(roundTrip(&procv3.ProcessingRequest{Request: &procv3.ProcessingRequest_RequestBody{RequestBody: &procv3.HttpBody{
		Body: []byte(reqBody), EndOfStream: true}}}), reqBody, true)
	if r := roundTrip(&procv3.ProcessingRequest{Request: &procv3.ProcessingRequest_ResponseHeaders{ResponseHeaders: &procv3.HttpHeaders{
		Headers: hmap(":status", strconv.Itoa(status), "content-type", ctype)}}}); r.GetResponseHeaders() == nil {
		t.Fatalf("response headers: %v", r)
	}
	for i, c := range chunks {
		eos := i == len(chunks)-1
		echoed(roundTrip(&procv3.ProcessingRequest{Request: &procv3.ProcessingRequest_ResponseBody{ResponseBody: &procv3.HttpBody{
			Body: []byte(c), EndOfStream: eos}}}), c, eos)
	}
	if err := st.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recv(); err != io.EOF {
		t.Fatalf("stream end: %v", err)
	}
}

// hopStatus waits briefly for the observer (which acts after echoing).
func (f *fixture) hopStatus(t *testing.T, actionID, want string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var got string
	for {
		if err := f.pool.QueryRow(context.Background(), `SELECT status FROM delegations WHERE action_id=$1`, actionID).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got == want || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got != want {
		t.Fatalf("hop of %s is %s, want %s", actionID, got, want)
	}
}

func (f *fixture) delegation(t *testing.T, agent, route string) string {
	t.Helper()
	set, _ := okHeaders(t, f.delegateFrom(t, agent, route, "", nil))
	return set[HeaderActionID]
}

func TestObserverClosesHopOnTerminalState(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	ctx := a2aCtx("agent-b")
	const js = "application/json"

	// Non-streaming Task, split across chunks.
	id := f.delegation(t, "agent_a", "agent-b")
	f.observe(t, ctx, id, 200, js, `{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-1",`, `"status":{"state":"completed"}}}`)
	f.hopStatus(t, id, "closed")
	var reason string
	if err := f.pool.QueryRow(context.Background(), `SELECT close_reason FROM delegations WHERE action_id=$1`, id).Scan(&reason); err != nil || reason != "task completed" {
		t.Fatalf("close reason %q %v", reason, err)
	}
	if n := f.count(t, `SELECT count(*) FROM diary WHERE event_type='delegation.closed'`); n != 1 {
		t.Fatalf("delegation.closed events: %d", n)
	}

	// A task still working keeps the hop open.
	id = f.delegation(t, "agent_a", "agent-b")
	f.observe(t, ctx, id, 200, js, `{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-2","status":{"state":"working"}}}`)
	time.Sleep(100 * time.Millisecond)
	f.hopStatus(t, id, "open")

	// Streaming: open until the final terminal status-update.
	id = f.delegation(t, "agent_a", "agent-b")
	ev := func(state string, final bool) string {
		return `data: {"jsonrpc":"2.0","id":1,"result":{"kind":"status-update","taskId":"t-3","contextId":"c","status":{"state":"` +
			state + `"},"final":` + strconv.FormatBool(final) + "}}\n\n"
	}
	f.observe(t, ctx, id, 200, "text/event-stream", ev("working", false), ev("working", false)[:40], ev("working", false)[40:])
	time.Sleep(100 * time.Millisecond)
	f.hopStatus(t, id, "open")
	id = f.delegation(t, "agent_a", "agent-b")
	f.observe(t, ctx, id, 200, "text/event-stream", ev("working", false), ev("failed", true), "")
	f.hopStatus(t, id, "closed")

	// A direct message reply (no task) ends the interaction.
	id = f.delegation(t, "agent_a", "agent-b")
	f.observe(t, ctx, id, 200, js, `{"jsonrpc":"2.0","id":1,"result":{"kind":"message","role":"agent","messageId":"m","parts":[]}}`)
	f.hopStatus(t, id, "closed")

	// An error reply: the delegation did not start.
	id = f.delegation(t, "agent_a", "agent-b")
	f.observe(t, ctx, id, 200, js, `{"jsonrpc":"2.0","id":1,"error":{"code":-32600,"message":"no"}}`)
	f.hopStatus(t, id, "closed")
	id = f.delegation(t, "agent_a", "agent-b")
	f.observe(t, ctx, id, 503, "text/plain", "upstream down")
	f.hopStatus(t, id, "closed")
}

func TestObserverIgnoresUntrustedCorrelation(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	done := `{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-1","status":{"state":"completed"}}}`
	id := f.delegation(t, "agent_a", "agent-b")

	// The response came through another agent's route.
	f.observe(t, a2aCtx("agent-c"), id, 200, "application/json", done)
	// No route identity on the observer call.
	f.observe(t, context.Background(), id, 200, "application/json", done)
	// Unknown or missing action ids.
	f.observe(t, a2aCtx("agent-b"), "act_01J0000000000000000000000", 200, "application/json", done)
	f.observe(t, a2aCtx("agent-b"), "", 200, "application/json", done)
	// Duplicate keys (parser differential) and garbage.
	f.observe(t, a2aCtx("agent-b"), id, 200, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-1","status":{"state":"working","state":"completed"}}}`)
	f.observe(t, a2aCtx("agent-b"), id, 200, "application/json", `not json`)
	time.Sleep(100 * time.Millisecond)
	f.hopStatus(t, id, "open")

	// A READ action (tasks/get) does not close a hop of another task.
	set, _ := okHeaders(t, f.check(t, a2aCtx("agent-b"), checkReq("POST", "/a2a", "gw", map[string]string{"authorization": bearer("agent_a")},
		a2aBody("tasks/get", `{"id":"t-other"}`))))
	f.observe(t, a2aCtx("agent-b"), set[HeaderActionID], 200, "application/json", done)
	time.Sleep(100 * time.Millisecond)
	f.hopStatus(t, id, "open")

	// An unknown message type fails the stream (agentgateway then fails closed).
	st, err := procv3.NewExternalProcessorClient(f.conn).Process(a2aCtx("agent-b"))
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&procv3.ProcessingRequest{}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Recv(); err == nil {
		t.Fatal("unknown ext_proc message accepted")
	}
}

// tasks/get or tasks/cancel showing the task ended closes the hops of that
// task (a continuation message names the task, so its hop carries the id).
func TestObserverClosesTaskHopsOnTaskQuery(t *testing.T) {
	f := newFixture(t, config.AgentGWConfig{})
	f.putProfile(t, "agent_a", "a2a", `{"may_delegate_to":["*"],"max_depth":3}`)
	h := map[string]string{"authorization": bearer("agent_a")}
	set, _ := okHeaders(t, f.check(t, a2aCtx("agent-b"), checkReq("POST", "/a2a", "gw", h,
		a2aBody("message/send", `{"message":{"taskId":"t-9","role":"user","parts":[],"messageId":"m"}}`))))
	hop := set[HeaderActionID]
	if n := f.count(t, `SELECT count(*) FROM delegations WHERE action_id=$1 AND task_id='t-9'`, hop); n != 1 {
		t.Fatal("hop without the task id")
	}
	set, _ = okHeaders(t, f.check(t, a2aCtx("agent-b"), checkReq("POST", "/a2a", "gw", h, a2aBody("tasks/cancel", `{"id":"t-9"}`))))
	// The request alone closes nothing: the delegatee must confirm.
	time.Sleep(100 * time.Millisecond)
	f.hopStatus(t, hop, "open")
	f.observe(t, a2aCtx("agent-b"), set[HeaderActionID], 200, "application/json",
		`{"jsonrpc":"2.0","id":1,"result":{"kind":"task","id":"t-9","status":{"state":"canceled"}}}`)
	f.hopStatus(t, hop, "closed")
}
