package commap

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"fortik/internal/authz"
	"fortik/internal/events"
	"fortik/internal/httpx"
)

// Live SSE event names.
const (
	LiveEdgeUpdated  = "edge.updated"
	LiveSwarmUpdated = "swarm.updated"
)

// Live serves GET /v1/map/live: the committed Diary stream (the Phase 2
// event bus, the same authentication and per-heartbeat re-validation as
// /v1/events/stream), filtered and translated into map events:
//
//   - map.edges_updated (a rollup batch) -> one "edge.updated" per edge row,
//     data = the full row for its window (the GET /v1/map edge shape); the
//     console replaces rows by (from, to, verb, window_start).
//   - swarm.* events, and any event whose data names target_type "swarm"
//     -> "swarm.updated", data = the swarm's cluster object as GET /v1/map
//     returns it ({swarm_id, state, members, ...}) read when the event is
//     sent, plus event_type and seq.
//
// Every SSE event has id = the Diary seq (the rows of one rollup event share
// it), so a client resumes with Last-Event-ID.
type Live struct {
	bus  events.Bus
	opts events.SSEOptions
	svc  *Service
}

// NewLive returns the live map stream. Pass the same options as the
// /v1/events/stream handler (Head, Backfill, Revalidate). svc (may be nil)
// supplies swarm cluster objects; without it swarm.updated carries the ids only.
func NewLive(bus events.Bus, opts events.SSEOptions, svc *Service) *Live {
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = events.DefaultHeartbeat
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 30 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &Live{bus: bus, opts: opts, svc: svc}
}

const liveBackfillPage = 1000

func (l *Live) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	if _, err := strictQuery(r, "after_seq"); err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	after, resume, err := liveResumePoint(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if !resume && l.opts.Head != nil {
		if after, err = l.opts.Head(ctx); err != nil {
			l.opts.Log.Error("map live: diary head unavailable", "err", err)
			httpx.WriteError(w, http.StatusServiceUnavailable, "event stream unavailable")
			return
		}
	}
	ch, err := l.bus.Subscribe(ctx, after)
	if err != nil {
		l.opts.Log.Error("map live: subscribe failed", "err", err)
		httpx.WriteError(w, http.StatusServiceUnavailable, "event stream unavailable")
		return
	}
	rc := http.NewResponseController(w)
	hdr := w.Header()
	hdr.Set("Content-Type", "text/event-stream")
	hdr.Set("Cache-Control", "no-store")
	hdr.Set("Connection", "keep-alive")
	hdr.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	cw := &liveWriter{w: w, rc: rc, timeout: l.opts.WriteTimeout, l: l, ctx: ctx}
	if err := cw.write("retry: 3000\n\n"); err != nil {
		return
	}
	hb := time.NewTicker(l.opts.Heartbeat)
	defer hb.Stop()
	last := after
	if resume && l.opts.Head != nil && l.opts.Backfill != nil {
		head, err := l.opts.Head(ctx)
		if err == nil && head > last {
			last, err = l.backfill(ctx, cw, last, head)
		}
		if err != nil {
			l.opts.Log.Warn("map live: resume backfill failed; closing stream", "err", err)
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			if l.opts.Revalidate != nil {
				if err := l.opts.Revalidate(r); err != nil {
					l.opts.Log.Info("map live: caller no longer authorized; closing stream", "err", err)
					_ = cw.write("event: unauthorized\ndata: {}\n\n")
					return
				}
			}
			if err := cw.write(": heartbeat\n\n"); err != nil {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				return // dropped (slow) or closed: the client reconnects with Last-Event-ID
			}
			if ev.Seq <= last {
				continue
			}
			if ev.Seq > last+1 && l.opts.Backfill != nil {
				if last, err = l.backfill(ctx, cw, last, ev.Seq-1); err != nil {
					l.opts.Log.Warn("map live: backfill failed; closing stream", "err", err)
					return
				}
			}
			if err := cw.emit(ev); err != nil {
				return
			}
			last = ev.Seq
		}
	}
}

func (l *Live) backfill(ctx context.Context, cw *liveWriter, after, upto int64) (int64, error) {
	for after < upto {
		evs, err := l.opts.Backfill(ctx, after, upto, liveBackfillPage)
		if err != nil {
			return after, err
		}
		if len(evs) == 0 {
			return upto, nil
		}
		for _, ev := range evs {
			if ev.Seq <= after {
				continue
			}
			if err := cw.emit(ev); err != nil {
				return after, err
			}
			after = ev.Seq
		}
		if len(evs) < liveBackfillPage {
			return upto, nil
		}
	}
	return after, nil
}

func liveResumePoint(r *http.Request) (int64, bool, error) {
	v := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if v == "" {
		v = r.URL.Query().Get("after_seq")
	}
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, fmt.Errorf("invalid Last-Event-ID / after_seq %q", clipName(v))
	}
	return n, true, nil
}

// LiveEvent is one SSE event of the live map.
type LiveEvent struct {
	Name string
	Data []byte
}

// Translate maps a Diary event to the live map events it produces (none for
// events the map does not show).
func (l *Live) Translate(ctx context.Context, ev events.Event) []LiveEvent {
	if ev.EventType == EventEdgesUpdated {
		var d struct {
			Edges []json.RawMessage `json:"edges"`
		}
		if json.Unmarshal(ev.Data, &d) != nil {
			return nil
		}
		out := make([]LiveEvent, 0, len(d.Edges))
		for _, e := range d.Edges {
			out = append(out, LiveEvent{Name: LiveEdgeUpdated, Data: e})
		}
		return out
	}
	var d struct {
		SwarmID    string `json:"swarm_id"`
		TargetType string `json:"target_type"`
		TargetID   string `json:"target_id"`
	}
	_ = json.Unmarshal(ev.Data, &d)
	swarm := ""
	switch {
	case strings.HasPrefix(ev.EventType, "swarm."):
		swarm = d.SwarmID
		if swarm == "" && d.TargetType == "swarm" {
			swarm = d.TargetID
		}
	case d.TargetType == "swarm":
		swarm = d.TargetID
	default:
		return nil
	}
	if !swarmIDPattern.MatchString(swarm) {
		return nil // a swarm event without a usable id cannot be shown as a cluster
	}
	obj := map[string]any{"swarm_id": swarm, "id": "swarm:" + swarm, "kind": "swarm", "label": swarm, "members": []string{}}
	if l.svc != nil {
		c, found, err := l.svc.SwarmCluster(ctx, swarm)
		switch {
		case err != nil:
			l.opts.Log.Warn("map live: swarm lookup failed; sending ids only", "swarm_id", swarm, "err", err)
			obj["stale"] = true
		case found:
			if b, err := json.Marshal(c); err == nil {
				_ = json.Unmarshal(b, &obj)
			}
		}
	}
	obj["event_type"], obj["seq"], obj["ts"] = ev.EventType, ev.Seq, ev.TS
	b, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return []LiveEvent{{Name: LiveSwarmUpdated, Data: b}}
}

type liveWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
	l       *Live
	ctx     context.Context
}

func (c *liveWriter) write(s string) error {
	_ = c.rc.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.w.Write([]byte(s)); err != nil {
		return err
	}
	return c.rc.Flush()
}

func (c *liveWriter) emit(ev events.Event) error {
	for _, le := range c.l.Translate(c.ctx, ev) {
		if err := c.write("event: " + le.Name + "\nid: " + strconv.FormatInt(ev.Seq, 10) + "\ndata: " + string(le.Data) + "\n\n"); err != nil {
			return err
		}
	}
	return nil
}
