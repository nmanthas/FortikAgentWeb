package events

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"fortik/internal/diary"
)

// DefaultTailInterval is how often the tailer polls the Diary (design §11).
const DefaultTailInterval = 250 * time.Millisecond

// tailBatch bounds one poll so a large backlog is published in slices.
const tailBatch = 500

// FromEntry converts a stored Diary entry to a bus Event. Data is the
// entry's "data" object exactly as committed (summaries only by Diary rule).
func FromEntry(en diary.Entry) (Event, error) {
	var body struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal([]byte(en.BodyJSON), &body); err != nil {
		return Event{}, fmt.Errorf("diary seq %d: unparseable body: %w", en.Seq, err)
	}
	if len(body.Data) == 0 {
		body.Data = json.RawMessage(`{}`)
	}
	return Event{Seq: en.Seq, TS: en.TS, AgentID: en.AgentID, EventType: en.EventType, Data: body.Data}, nil
}

// Tailer publishes committed Diary entries to a Bus in seq order (the outbox
// pattern: only committed state changes are ever published). Run exactly one
// tailer per process; consumers dedupe by seq.
type Tailer struct {
	diary    *diary.Diary
	bus      Bus
	log      *slog.Logger
	Interval time.Duration // default DefaultTailInterval

	last      atomic.Int64
	startOnce sync.Once
	started   chan struct{}
}

func NewTailer(d *diary.Diary, bus Bus, log *slog.Logger) *Tailer {
	return &Tailer{diary: d, bus: bus, log: log, Interval: DefaultTailInterval, started: make(chan struct{})}
}

// Started is closed once the tailer has read the Diary head it starts from.
func (t *Tailer) Started() <-chan struct{} { return t.started }

// Last is the seq of the last entry published (or the starting head).
func (t *Tailer) Last() int64 { return t.last.Load() }

// Run starts at the current Diary head (history is served by Backfill, not
// re-published) and polls until ctx ends. Errors are logged and retried on
// the next tick; an entry is never skipped because publishing failed.
func (t *Tailer) Run(ctx context.Context) error {
	interval := t.Interval
	if interval <= 0 {
		interval = DefaultTailInterval
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		seq, _, err := t.diary.Head(ctx)
		if err == nil {
			t.last.Store(seq)
			t.startOnce.Do(func() { close(t.started) })
			break
		}
		t.log.Warn("events tailer: cannot read diary head; retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-tick.C:
		}
		t.poll(ctx)
	}
}

// poll publishes every entry after Last, in slices, until caught up.
func (t *Tailer) poll(ctx context.Context) {
	for ctx.Err() == nil {
		last := t.last.Load()
		entries, err := t.diary.Query(ctx, diary.Filter{AfterSeq: last, Limit: tailBatch})
		if err != nil {
			if ctx.Err() == nil {
				t.log.Warn("events tailer: diary query failed", "after_seq", last, "err", err)
			}
			return
		}
		for _, en := range entries {
			ev, err := FromEntry(en)
			if err != nil {
				// A corrupt body is the Diary verifier's concern; it cannot
				// be published meaningfully, so it is logged and passed over.
				t.log.Error("events tailer: skipping entry", "seq", en.Seq, "err", err)
				t.last.Store(en.Seq)
				continue
			}
			if err := t.bus.Publish(ctx, ev); err != nil {
				if ctx.Err() == nil {
					t.log.Warn("events tailer: publish failed; will retry", "seq", en.Seq, "err", err)
				}
				return
			}
			t.last.Store(en.Seq)
		}
		if len(entries) < tailBatch {
			return
		}
	}
}

// Backfill reads committed entries with after < seq <= upto (upto <= 0 means
// no upper bound) straight from the Diary, at most limit (<= 10000).
func (t *Tailer) Backfill(ctx context.Context, after, upto int64, limit int) ([]Event, error) {
	return BackfillFromDiary(ctx, t.diary, after, upto, limit)
}

// Head returns the current Diary head seq.
func (t *Tailer) Head(ctx context.Context) (int64, error) {
	seq, _, err := t.diary.Head(ctx)
	return seq, err
}

// BackfillFromDiary is Backfill without a Tailer.
func BackfillFromDiary(ctx context.Context, d *diary.Diary, after, upto int64, limit int) ([]Event, error) {
	if limit <= 0 || limit > 10000 {
		limit = 1000
	}
	entries, err := d.Query(ctx, diary.Filter{AfterSeq: after, MaxSeq: upto, Limit: limit})
	if err != nil {
		return nil, err
	}
	out := make([]Event, 0, len(entries))
	for _, en := range entries {
		ev, err := FromEntry(en)
		if err != nil {
			continue // see Tailer.poll
		}
		out = append(out, ev)
	}
	return out, nil
}
