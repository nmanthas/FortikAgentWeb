package decide_test

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"fortik/internal/action"
)

func pct(d []time.Duration, p float64) time.Duration {
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*p)]
}

// TestDecideLatencyGreen measures full Decide overhead for green actions
// (control state read + OPA + transactional persistence + Diary append),
// i.e. the "Fortik decision overhead" the plan budgets at < 50 ms p95.
func TestDecideLatencyGreen(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement skipped in -short mode")
	}
	if raceEnabled {
		t.Skip("latency budget not measured under -race (the race detector slows code ~10x); run without -race")
	}
	f := setup(t)
	ctx := context.Background()
	a := pgAction("claude_code_01", "SELECT", action.VerbRead, "prod", nil)
	for i := 0; i < 50; i++ { // warm up
		_, _ = f.svc.Decide(ctx, a)
	}

	const n = 2000
	seq := make([]time.Duration, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if _, err := f.svc.Decide(ctx, a); err != nil {
			t.Fatal(err)
		}
		seq = append(seq, time.Since(start))
	}
	t.Logf("sequential  n=%d p50=%v p95=%v p99=%v", n, pct(seq, .50), pct(seq, .95), pct(seq, .99))

	// Concurrent: 8 workers, mirroring several agents/copies at once.
	var mu sync.Mutex
	conc := make([]time.Duration, 0, n)
	var wg sync.WaitGroup
	start := time.Now()
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < n/8; i++ {
				s := time.Now()
				if _, err := f.svc.Decide(ctx, a); err != nil {
					t.Error(err)
				}
				mu.Lock()
				conc = append(conc, time.Since(s))
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	rate := float64(n) / time.Since(start).Seconds()
	t.Logf("concurrent  n=%d workers=8 throughput=%.0f/s p50=%v p95=%v p99=%v", n, rate, pct(conc, .50), pct(conc, .95), pct(conc, .99))

	if p := pct(seq, .95); p > 50*time.Millisecond {
		t.Errorf("sequential p95 %v exceeds the 50ms budget", p)
	}
	if p := pct(conc, .95); p > 50*time.Millisecond {
		t.Errorf("concurrent p95 %v exceeds the 50ms budget", p)
	}
}
