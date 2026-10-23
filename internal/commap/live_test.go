package commap_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"fortik/internal/authz"
	"fortik/internal/commap"
	"fortik/internal/diary"
	"fortik/internal/events"
)

type sseEvent struct {
	name, id, data string
}

// readSSE parses a stream into events on a channel (closed at EOF).
func readSSE(resp *http.Response) <-chan sseEvent {
	ch := make(chan sseEvent, 64)
	go func() {
		defer close(ch)
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		var ev sseEvent
		for sc.Scan() {
			line := sc.Text()
			switch {
			case line == "":
				if ev.name != "" {
					ch <- ev
				}
				ev = sseEvent{}
			case strings.HasPrefix(line, "event: "):
				ev.name = strings.TrimPrefix(line, "event: ")
			case strings.HasPrefix(line, "id: "):
				ev.id = strings.TrimPrefix(line, "id: ")
			case strings.HasPrefix(line, "data: "):
				ev.data = strings.TrimPrefix(line, "data: ")
			}
		}
	}()
	return ch
}

func next(t *testing.T, ch <-chan sseEvent, name string) sseEvent {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				t.Fatalf("stream ended while waiting for %s", name)
			}
			if ev.name == name {
				return ev
			}
		case <-timeout:
			t.Fatalf("no %s event", name)
		}
	}
}

func TestLiveMapEvents(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus := events.NewMemoryBus(256)
	tailer := events.NewTailer(e.d, bus, discard())
	tailer.Interval = 10 * time.Millisecond
	go func() { _ = tailer.Run(ctx) }()
	<-tailer.Started()
	var revoked atomic.Bool
	live := commap.NewLive(bus, events.SSEOptions{Head: tailer.Head, Backfill: tailer.Backfill, Heartbeat: 50 * time.Millisecond,
		Log: discard(), Revalidate: func(*http.Request) error {
			if revoked.Load() {
				return errors.New("session ended")
			}
			return nil
		}}, e.svc)
	mux := http.NewServeMux()
	commap.NewHandler(e.svc, live, discard()).Register(mux)
	srv := httptest.NewServer(withPrincipal(principal(authz.RoleAuditor), mux))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v1/map/live")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("status %d %s", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	stream := readSSE(resp)

	// An edge row from a rollup arrives as edge.updated: the full row for its window.
	e.register(t, "fin", "finance", "")
	head, _, err := e.d.Head(ctx)
	if err != nil {
		t.Fatal(err)
	}
	out := e.decideAt(t, e.base.Add(time.Minute), pgRead("fin", "finance", "financial"))
	e.rollup(t)
	var row commap.Edge
	for row.To != "store:postgres:finance" {
		ev := next(t, stream, commap.LiveEdgeUpdated)
		if err := json.Unmarshal([]byte(ev.data), &row); err != nil {
			t.Fatal(err)
		}
		if seq, _ := strconv.ParseInt(ev.id, 10, 64); seq <= head {
			t.Fatalf("event id %s not after head %d", ev.id, head)
		}
	}
	if row.From != "agent:fin" || row.Verb != "READ" || row.Count != 1 || row.WindowStart == nil || !row.WindowStart.Equal(e.base) ||
		row.WorstClass != "green" || len(row.SampleActionIDs) != 1 || row.SampleActionIDs[0] != out.Action.ActionID ||
		len(row.Labels) != 1 || row.Labels[0] != "financial" || row.Bytes != 2048 {
		t.Fatalf("edge row %+v", row)
	}

	// A swarm event arrives as swarm.updated carrying the cluster object.
	if _, err := e.pool.Exec(ctx, `INSERT INTO swarms (swarm_id, root_agent_id, detected_by, member_count, state)
		VALUES ('swm_live', 'fin', 'spawn_tree', 1, 'detected');
		INSERT INTO swarm_members (swarm_id, agent_id, role) VALUES ('swm_live', 'fin', 'root')`); err != nil {
		t.Fatal(err)
	}
	if _, err := e.d.Append(ctx, diary.Event{AgentID: "fin", EventType: "swarm.detected", Actor: "system:swarm",
		Data: map[string]any{"swarm_id": "swm_live"}}); err != nil {
		t.Fatal(err)
	}
	ev := next(t, stream, commap.LiveSwarmUpdated)
	var cl struct {
		SwarmID    string   `json:"swarm_id"`
		State      string   `json:"state"`
		Members    []string `json:"members"`
		EventType  string   `json:"event_type"`
		DetectedBy string   `json:"detected_by"`
	}
	if err := json.Unmarshal([]byte(ev.data), &cl); err != nil {
		t.Fatal(err)
	}
	if cl.SwarmID != "swm_live" || cl.State != "detected" || len(cl.Members) != 1 || cl.Members[0] != "agent:fin" ||
		cl.EventType != "swarm.detected" || cl.DetectedBy != "spawn_tree" {
		t.Fatalf("swarm.updated %s", ev.data)
	}

	// Resume from before the rollup: the missed rows are backfilled from the Diary.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/map/live", nil)
	req.Header.Set("Last-Event-ID", strconv.FormatInt(head, 10))
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	resumed := readSSE(resp2)
	var again commap.Edge
	for again.To != "store:postgres:finance" {
		_ = json.Unmarshal([]byte(next(t, resumed, commap.LiveEdgeUpdated).data), &again)
	}
	next(t, resumed, commap.LiveSwarmUpdated)

	// Losing authorization ends the stream at the next heartbeat.
	revoked.Store(true)
	next(t, stream, "unauthorized")
}

func TestLiveRequiresAuditor(t *testing.T) {
	e := newEnv(t)
	live := commap.NewLive(events.NewMemoryBus(8), events.SSEOptions{Log: discard()}, e.svc)
	for _, c := range []struct {
		p    *authz.Principal
		want int
		path string
	}{
		{principal(authz.RoleInterceptor), 403, "/v1/map/live"},
		{nil, 401, "/v1/map/live"},
		{principal(authz.RoleAuditor), 400, "/v1/map/live?after_seq=-1"},
		{principal(authz.RoleAuditor), 400, "/v1/map/live?x=1"},
	} {
		rec := httptest.NewRecorder()
		withPrincipal(c.p, live).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, c.path, nil))
		if rec.Code != c.want {
			t.Errorf("%s: %d, want %d", c.path, rec.Code, c.want)
		}
	}
}
