package events

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
	"fortik/internal/httpx"
)

// DefaultHeartbeat is the SSE keep-alive interval (design §11).
const DefaultHeartbeat = 15 * time.Second

// backfillPage bounds one Diary read while closing a gap.
const backfillPage = 1000

// SSEOptions configures the stream handler.
type SSEOptions struct {
	// Heartbeat interval (default DefaultHeartbeat).
	Heartbeat time.Duration
	// WriteTimeout bounds each write to a client; a client that cannot take
	// a write within it is dropped (default 30s). It also lifts the server's
	// global WriteTimeout for this long-lived response.
	WriteTimeout time.Duration
	// Head returns the Diary head seq; a client without Last-Event-ID starts
	// there (live only). Nil = replay whatever the bus still holds.
	Head func(ctx context.Context) (int64, error)
	// Backfill closes gaps (resume older than the bus holds, or events
	// dropped for a slow client) from the Diary. Nil = gaps are not filled.
	Backfill func(ctx context.Context, after, upto int64, limit int) ([]Event, error)
	Log      *slog.Logger
	// Revalidate re-checks the caller's credentials (session still live,
	// role still held) on every heartbeat; a non-nil error ends the stream.
	// Nil = authorization is checked only at connect.
	Revalidate func(r *http.Request) error
}

// SSE serves GET /v1/events/stream: committed Diary entries as Server-Sent
// Events ("event: diary", "id: <seq>", data = Event JSON). Requires the
// auditor role. Resume with the Last-Event-ID header (or ?after_seq=).
type SSE struct {
	bus  Bus
	opts SSEOptions
}

func NewSSE(bus Bus, opts SSEOptions) *SSE {
	if opts.Heartbeat <= 0 {
		opts.Heartbeat = DefaultHeartbeat
	}
	if opts.WriteTimeout <= 0 {
		opts.WriteTimeout = 30 * time.Second
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	return &SSE{bus: bus, opts: opts}
}

// Mount registers the stream route on mux (behind the API's auth middleware).
func (h *SSE) Mount(mux *http.ServeMux) { mux.Handle("GET /v1/events/stream", h) }

func (h *SSE) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor); !ok {
		return
	}
	after, resume, err := resumePoint(r)
	if err != nil {
		httpx.WriteError(w, http.StatusBadRequest, err.Error())
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	if !resume {
		if h.opts.Head != nil {
			if after, err = h.opts.Head(ctx); err != nil {
				h.opts.Log.Error("sse: diary head unavailable", "err", err)
				httpx.WriteError(w, http.StatusServiceUnavailable, "event stream unavailable")
				return
			}
		}
	}
	ch, err := h.bus.Subscribe(ctx, after)
	if err != nil {
		h.opts.Log.Error("sse: subscribe failed", "err", err)
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

	cw := &clientWriter{w: w, rc: rc, timeout: h.opts.WriteTimeout}
	if err := cw.write("retry: 3000\n\n"); err != nil {
		return
	}
	hb := time.NewTicker(h.opts.Heartbeat)
	defer hb.Stop()
	last := after
	if resume && h.opts.Head != nil && h.opts.Backfill != nil {
		// Catch up to the head now rather than waiting for the next live
		// event to reveal the gap (the bus may hold nothing after a restart).
		head, err := h.opts.Head(ctx)
		if err == nil && head > last {
			last, err = h.backfill(ctx, cw, last, head)
		}
		if err != nil {
			h.opts.Log.Warn("sse: resume backfill failed; closing stream", "err", err)
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-hb.C:
			if h.opts.Revalidate != nil {
				if err := h.opts.Revalidate(r); err != nil {
					h.opts.Log.Info("sse: caller no longer authorized; closing stream", "err", err)
					_ = cw.write("event: unauthorized\ndata: {}\n\n")
					return
				}
			}
			if err := cw.write(": heartbeat\n\n"); err != nil {
				return
			}
		case ev, ok := <-ch:
			if !ok {
				// The bus dropped this subscriber (too slow) or closed: end
				// the response; the client reconnects with Last-Event-ID.
				return
			}
			if ev.Seq <= last {
				continue // duplicate (replay overlap or redelivery)
			}
			if ev.Seq > last+1 && h.opts.Backfill != nil {
				if last, err = h.backfill(ctx, cw, last, ev.Seq-1); err != nil {
					h.opts.Log.Warn("sse: backfill failed; closing stream", "err", err)
					return
				}
			}
			if err := cw.event(ev); err != nil {
				return
			}
			last = ev.Seq
		}
	}
}

// backfill writes Diary entries in (after, upto] and returns the new last.
func (h *SSE) backfill(ctx context.Context, cw *clientWriter, after, upto int64) (int64, error) {
	for after < upto {
		evs, err := h.opts.Backfill(ctx, after, upto, backfillPage)
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
			if err := cw.event(ev); err != nil {
				return after, err
			}
			after = ev.Seq
		}
		if len(evs) < backfillPage {
			return upto, nil
		}
	}
	return after, nil
}

// resumePoint reads Last-Event-ID (or ?after_seq=). resume is false when the
// client supplied neither.
func resumePoint(r *http.Request) (int64, bool, error) {
	v := strings.TrimSpace(r.Header.Get("Last-Event-ID"))
	if v == "" {
		v = r.URL.Query().Get("after_seq")
	}
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, fmt.Errorf("invalid Last-Event-ID / after_seq %q", v)
	}
	return n, true, nil
}

type clientWriter struct {
	w       http.ResponseWriter
	rc      *http.ResponseController
	timeout time.Duration
}

func (c *clientWriter) write(s string) error {
	// Per-write deadline: a stuck client is dropped instead of pinning the
	// handler; it also replaces the server-wide WriteTimeout for this stream.
	_ = c.rc.SetWriteDeadline(time.Now().Add(c.timeout))
	if _, err := c.w.Write([]byte(s)); err != nil {
		return err
	}
	return c.rc.Flush()
}

func (c *clientWriter) event(ev Event) error {
	b, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	// json.Marshal output has no raw newlines, so one data: line suffices.
	return c.write("event: diary\nid: " + strconv.FormatInt(ev.Seq, 10) + "\ndata: " + string(b) + "\n\n")
}
