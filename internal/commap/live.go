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
//   - map_events rows (a rollup batch, polled every MapPoll; not in the
//     Diary since Phase 6) -> one "edge.updated" per edge row, data = the full
//     row for its window (the GET /v1/map edge shape); the console replaces
//     rows by (from, to, verb, window_start). Older map.edges_updated Diary
//     events still translate the same way.
//   - swarm.* events, and any event whose data names target_type "swarm"
//     -> "swarm.updated", data = the swarm's cluster object as GET /v1/map
//     returns it ({swarm_id, state, members, ...}) read when the event is
//     sent, plus event_type and seq.
//
// Every SSE event has id "<diary seq>.<map_events id>" (both cursors), so a
// client resumes both with Last-Event-ID; a plain "<seq>" resumes the Diary
// and starts the map at its newest event.
type Live struct {
	bus  events.Bus
	opts events.SSEOptions
	svc  *Service
	// MapPoll is how often each stream reads new map_events (default 1s).
	MapPoll time.Duration
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
	after, mapAfter, resume, err := liveResumePoint(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	// Edge updates come from map_events (not the Diary): start from its head
	// unless the client resumes with a map cursor.
	if l.svc != nil && mapAfter < 0 {
		if mapAfter, err = l.svc.MapEventsHead(ctx); err != nil {
			l.opts.Log.Error("map live: map events head unavailable", "err", err)
			httpx.WriteError(w, http.StatusServiceUnavailable, "event stream unavailable")
			return
		}
	}
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
	cw := &liveWriter{w: w, rc: rc, timeout: l.opts.WriteTimeout, l: l, ctx: ctx, mapAfter: max(mapAfter, 0)}
	if err := cw.write("retry: 3000\n\n"); err != nil {
		return
	}
	hb := time.NewTicker(l.opts.Heartbeat)
	defer hb.Stop()
	poll := time.NewTicker(l.mapPoll())
	defer poll.Stop()
	last := after
	cw.diarySeq = after
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
		case <-poll.C:
			if err := cw.pollMap(); err != nil {
				l.opts.Log.Warn("map live: map events unavailable; closing stream", "err", err)
				return
			}
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

// mapPoll is how often a stream checks map_events (default 1s).
func (l *Live) mapPoll() time.Duration {
	if l.MapPoll > 0 {
		return l.MapPoll
	}
	return time.Second
}

// pollMap sends the edge rows of map_events newer than the stream's cursor.
func (c *liveWriter) pollMap() error {
	if c.l.svc == nil {
		return nil
	}
	for {
		evs, err := c.l.svc.MapEventsAfter(c.ctx, c.mapAfter, liveBackfillPage)
		if err != nil {
			return err
		}
		for _, me := range evs {
			var d struct {
				Edges []json.RawMessage `json:"edges"`
			}
			if json.Unmarshal(me.Payload, &d) == nil && me.Type == EventEdgesUpdated {
				for _, e := range d.Edges {
					if err := c.write("event: " + LiveEdgeUpdated + "\nid: " + c.cursor(c.diarySeq, me.ID) + "\ndata: " + string(e) + "\n\n"); err != nil {
						return err
					}
				}
			}
			c.mapAfter = me.ID
		}
		if len(evs) < liveBackfillPage {
			return nil
		}
	}
}

// cursor is the SSE event id: "<diary seq>.<map_events id>" (both resume points).
func (c *liveWriter) cursor(seq, mapID int64) string {
	return strconv.FormatInt(seq, 10) + "." + strconv.FormatInt(mapID, 10)
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

// liveResumePoint parses Last-Event-ID (or after_seq): "<diary seq>" or
// "<diary seq>.<map_events id>". mapAfter is -1 when the client gave no map
// cursor (the stream then starts at the newest map event).
func liveResumePoint(r *http.Request) (after, mapAfter int64, resume bool, err error) {
	v := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if v == "" {
		v = r.URL.Query().Get("after_seq")
	}
	if v == "" {
		return 0, -1, false, nil
	}
	seq, m, hasMap := strings.Cut(v, ".")
	bad := fmt.Errorf("invalid Last-Event-ID / after_seq %q", clipName(v))
	n, err := strconv.ParseInt(seq, 10, 64)
	if err != nil || n < 0 {
		return 0, -1, false, bad
	}
	mapAfter = -1
	if hasMap {
		if mapAfter, err = strconv.ParseInt(m, 10, 64); err != nil || mapAfter < 0 {
			return 0, -1, false, bad
		}
	}
	return n, mapAfter, true, nil
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
	w        http.ResponseWriter
	rc       *http.ResponseController
	timeout  time.Duration
	l        *Live
	ctx      context.Context
	diarySeq int64 // last Diary seq sent
	mapAfter int64 // last map_events id sent
}

func (c *liveWriter) write(s string) error {
	_ = c.rc.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.w.Write([]byte(s)); err != nil {
		return err
	}
	return c.rc.Flush()
}

func (c *liveWriter) emit(ev events.Event) error {
	c.diarySeq = ev.Seq
	for _, le := range c.l.Translate(c.ctx, ev) {
		if err := c.write("event: " + le.Name + "\nid: " + c.cursor(ev.Seq, c.mapAfter) + "\ndata: " + string(le.Data) + "\n\n"); err != nil {
			return err
		}
	}
	return nil
}
