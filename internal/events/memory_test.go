package events

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func ev(seq int64) Event {
	return Event{Seq: seq, TS: time.Now().UTC(), EventType: "action.decided", Data: json.RawMessage(`{}`)}
}

func recv(t *testing.T, ch <-chan Event) Event {
	t.Helper()
	select {
	case e, ok := <-ch:
		if !ok {
			t.Fatal("channel closed")
		}
		return e
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for event")
	}
	return Event{}
}

func TestMemoryBusReplayLiveAndDedupe(t *testing.T) {
	b := NewMemoryBus(5)
	ctx := context.Background()
	for i := int64(1); i <= 8; i++ {
		if err := b.Publish(ctx, ev(i)); err != nil {
			t.Fatal(err)
		}
	}
	_ = b.Publish(ctx, ev(7)) // duplicate: ignored
	sctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ch, err := b.Subscribe(sctx, 5)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []int64{6, 7, 8} {
		if got := recv(t, ch).Seq; got != want {
			t.Fatalf("replay: got %d want %d", got, want)
		}
	}
	// Ring holds only the last 5 (4..8): asking for everything replays those.
	all, _ := b.Subscribe(sctx, 0)
	if got := recv(t, all).Seq; got != 4 {
		t.Fatalf("ring oldest: got %d want 4", got)
	}
	_ = b.Publish(ctx, ev(9))
	if got := recv(t, ch).Seq; got != 9 {
		t.Fatalf("live: got %d", got)
	}
	cancel()
	deadline := time.After(2 * time.Second)
	for {
		select {
		case _, ok := <-ch:
			if !ok {
				return // closed after ctx cancel
			}
		case <-deadline:
			t.Fatal("subscription not closed after cancel")
		}
	}
}

func TestMemoryBusDropsSlowSubscriberWithoutBlocking(t *testing.T) {
	b := NewMemoryBus(10)
	ctx := context.Background()
	slow, _ := b.Subscribe(ctx, 0)
	fast, _ := b.Subscribe(ctx, 0)
	done := make(chan struct{})
	go func() {
		for range fast {
		}
		close(done)
	}()
	start := time.Now()
	for i := int64(1); i <= subscriberBuffer*3; i++ {
		_ = b.Publish(ctx, ev(i))
	}
	if time.Since(start) > time.Second {
		t.Fatal("publish blocked on a slow subscriber")
	}
	n := 0
	for range slow {
		n++
	}
	if n != subscriberBuffer {
		t.Fatalf("slow subscriber should get its buffer then be closed; got %d", n)
	}
	_ = b.Close()
	<-done
	if err := b.Publish(ctx, ev(10000)); err != ErrClosed {
		t.Fatalf("publish after close: %v", err)
	}
}
