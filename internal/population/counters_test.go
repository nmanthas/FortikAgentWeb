package population_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"fortik/internal/config"
	"fortik/internal/population"
)

type fakeClock struct{ t atomic.Int64 }

func newClock(t time.Time) *fakeClock {
	c := &fakeClock{}
	c.t.Store(t.UnixNano())
	return c
}

func (c *fakeClock) Now() time.Time      { return time.Unix(0, c.t.Load()) }
func (c *fakeClock) Add(d time.Duration) { c.t.Add(int64(d)) }

func TestMemoryCountersSlidingWindow(t *testing.T) {
	ctx := context.Background()
	clk := newClock(time.Unix(1_700_000_000, 0))
	m := population.NewMemoryCounters()
	m.Now = clk.Now
	for i := 1; i <= 5; i++ {
		n, err := m.Incr(ctx, "k", time.Minute)
		if err != nil || n != int64(i) {
			t.Fatalf("incr %d: %d %v", i, n, err)
		}
	}
	clk.Add(30 * time.Second)
	if n, _ := m.Incr(ctx, "k", time.Minute); n != 6 {
		t.Fatalf("after 30s: %d", n)
	}
	// 59s after the first burst it is still inside the minute.
	clk.Add(29 * time.Second)
	if n, _ := m.Count(ctx, "k", time.Minute); n != 6 {
		t.Fatalf("at 59s: %d", n)
	}
	// 60s after the first burst it slides out; the later event remains.
	clk.Add(time.Second)
	if n, _ := m.Count(ctx, "k", time.Minute); n != 1 {
		t.Fatalf("at 60s: %d", n)
	}
	clk.Add(31 * time.Second)
	if n, _ := m.Count(ctx, "k", time.Minute); n != 0 {
		t.Fatalf("at 91s: %d", n)
	}
	// Keys are independent; an unknown key counts 0 and is not created.
	if n, _ := m.Count(ctx, "other", time.Minute); n != 0 {
		t.Fatal(n)
	}
}

func TestMemoryCountersConcurrentIncrIsExact(t *testing.T) {
	m := population.NewMemoryCounters()
	var wg sync.WaitGroup
	seen := make([]atomic.Bool, 1001)
	for i := 0; i < 1000; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n, err := m.Incr(context.Background(), "burst", time.Minute)
			if err != nil || n < 1 || n > 1000 || seen[n].Swap(true) {
				t.Errorf("incr returned %d (%v) twice or out of range", n, err)
			}
		}()
	}
	wg.Wait()
	if n, _ := m.Count(context.Background(), "burst", time.Minute); n != 1000 {
		t.Fatalf("count %d", n)
	}
}

func TestCountersRejectBadInput(t *testing.T) {
	m := population.NewMemoryCounters()
	ctx := context.Background()
	for _, tc := range []struct {
		key string
		w   time.Duration
	}{{"", time.Minute}, {"k", 0}, {"k", -time.Second}, {"k", 48 * time.Hour}} {
		if _, err := m.Incr(ctx, tc.key, tc.w); !errors.Is(err, population.ErrCountersUnavailable) {
			t.Fatalf("%q %s: %v", tc.key, tc.w, err)
		}
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.Incr(cctx, "k", time.Minute); !errors.Is(err, population.ErrCountersUnavailable) {
		t.Fatalf("cancelled: %v", err)
	}
}

// Real redis-server: same semantics, atomic under concurrency, shared by
// two clients (two Fortik processes), and an unreachable Redis is an error.
func TestRedisCounters(t *testing.T) {
	url := startRedis(t)
	ctx := context.Background()
	c1, err := population.NewRedisCounters(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c1.Close()
	c2, err := population.NewRedisCounters(url)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()

	var wg sync.WaitGroup
	seen := make([]atomic.Bool, 201)
	for i := 0; i < 200; i++ {
		wg.Add(1)
		c := c1
		if i%2 == 1 {
			c = c2
		}
		go func() {
			defer wg.Done()
			n, err := c.Incr(ctx, "spawn:type:worker", time.Minute)
			if err != nil || n < 1 || n > 200 || seen[n].Swap(true) {
				t.Errorf("incr returned %d (%v)", n, err)
			}
		}()
	}
	wg.Wait()
	if n, err := c2.Count(ctx, "spawn:type:worker", time.Minute); err != nil || n != 200 {
		t.Fatalf("count %d %v", n, err)
	}
	if n, err := c1.Count(ctx, "absent", time.Minute); err != nil || n != 0 {
		t.Fatalf("absent %d %v", n, err)
	}
	// Sliding: a 2-second window forgets events older than 2 seconds.
	if _, err := c1.Incr(ctx, "short", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if n, _ := c1.Count(ctx, "short", 2*time.Second); n != 1 {
		t.Fatalf("short now: %d", n)
	}
	time.Sleep(2100 * time.Millisecond)
	if n, _ := c1.Incr(ctx, "short", 2*time.Second); n != 1 {
		t.Fatalf("short after window: %d", n)
	}

	// NewCounters with the redis provider pings and works.
	ctr, closeFn, err := population.NewCounters(ctx, config.CountersConfig{Provider: "redis", RedisURL: url})
	if err != nil {
		t.Fatal(err)
	}
	if n, err := ctr.Count(ctx, "spawn:type:worker", time.Minute); err != nil || n != 200 {
		t.Fatalf("via NewCounters: %d %v", n, err)
	}
	_ = closeFn()
}

func TestRedisCountersUnavailableFailsClosed(t *testing.T) {
	ctx := context.Background()
	c, err := population.NewRedisCounters("redis://127.0.0.1:1/0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Incr(ctx, "k", time.Minute); !errors.Is(err, population.ErrCountersUnavailable) {
		t.Fatalf("incr: %v", err)
	}
	if _, _, err := population.NewCounters(ctx, config.CountersConfig{Provider: "redis", RedisURL: "redis://127.0.0.1:1/0"}); err == nil {
		t.Fatal("NewCounters must refuse an unreachable redis")
	}
	if _, err := population.NewRedisCounters("://user:hunter2@nowhere"); err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Fatalf("bad url error must not echo the url: %v", err)
	}
	if _, _, err := population.NewCounters(ctx, config.CountersConfig{Provider: "bogus"}); err == nil {
		t.Fatal("unknown provider accepted")
	}
}
