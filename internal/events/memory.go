package events

import (
	"context"
	"errors"
	"sync"
)

// ErrClosed is returned by Publish/Subscribe after Close.
var ErrClosed = errors.New("events: bus closed")

// DefaultRingSize is how many recent events the memory bus keeps for replay.
const DefaultRingSize = 1000

// subscriberBuffer is the per-subscriber channel slack on top of the replay.
// A subscriber that falls this far behind is dropped (its channel is closed)
// so a slow consumer can never block Publish or other consumers; it is
// expected to reconnect and resume from its last seq.
const subscriberBuffer = 256

// MemoryBus is an in-process Bus with a ring buffer for replay. It is the
// default for single-process deployments.
type MemoryBus struct {
	mu      sync.Mutex
	ring    []Event // circular, oldest at head when full
	head    int
	full    bool
	lastSeq int64
	subs    map[*memSub]struct{}
	closed  bool
}

type memSub struct {
	ch   chan Event
	done bool // channel closed; guarded by MemoryBus.mu
}

// NewMemoryBus returns a bus that keeps the last size events (size <= 0
// means DefaultRingSize).
func NewMemoryBus(size int) *MemoryBus {
	if size <= 0 {
		size = DefaultRingSize
	}
	return &MemoryBus{ring: make([]Event, 0, size), subs: map[*memSub]struct{}{}}
}

// Publish stores e for replay and fans it out without blocking. Events with
// seq <= the last published seq are duplicates (the Diary seq is the dedupe
// key) and are ignored.
func (b *MemoryBus) Publish(_ context.Context, e Event) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return ErrClosed
	}
	if e.Seq <= b.lastSeq {
		return nil
	}
	b.lastSeq = e.Seq
	if !b.full {
		b.ring = append(b.ring, e)
		if len(b.ring) == cap(b.ring) {
			b.full = true
		}
	} else {
		b.ring[b.head] = e
		b.head = (b.head + 1) % len(b.ring)
	}
	for s := range b.subs {
		select {
		case s.ch <- e:
		default:
			// Slow consumer: drop it rather than block everyone.
			b.dropLocked(s)
		}
	}
	return nil
}

// Subscribe replays buffered events with seq > afterSeq, then delivers live
// events until ctx ends or the subscriber falls behind (channel closed).
func (b *MemoryBus) Subscribe(ctx context.Context, afterSeq int64) (<-chan Event, error) {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil, ErrClosed
	}
	replay := b.snapshotLocked(afterSeq)
	s := &memSub{ch: make(chan Event, len(replay)+subscriberBuffer)}
	for _, e := range replay {
		s.ch <- e
	}
	b.subs[s] = struct{}{}
	b.mu.Unlock()

	go func() {
		<-ctx.Done()
		b.mu.Lock()
		b.dropLocked(s)
		b.mu.Unlock()
	}()
	return s.ch, nil
}

// snapshotLocked returns ring events with seq > afterSeq in seq order.
func (b *MemoryBus) snapshotLocked(afterSeq int64) []Event {
	n := len(b.ring)
	out := make([]Event, 0, n)
	for i := 0; i < n; i++ {
		e := b.ring[(b.head+i)%n]
		if e.Seq > afterSeq {
			out = append(out, e)
		}
	}
	return out
}

func (b *MemoryBus) dropLocked(s *memSub) {
	if s.done {
		return
	}
	s.done = true
	delete(b.subs, s)
	close(s.ch)
}

// Close closes every subscription; later calls fail with ErrClosed.
func (b *MemoryBus) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return nil
	}
	b.closed = true
	for s := range b.subs {
		b.dropLocked(s)
	}
	return nil
}
