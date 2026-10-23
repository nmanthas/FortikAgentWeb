package population_test

import (
	"context"
	"math"
	"testing"
	"time"

	"fortik/internal/action"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/population"
)

func repeat(v, n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = v
	}
	return out
}

func TestSpawnBaselineMath(t *testing.T) {
	// 14 days alternating 60 / 120 spawns per hour: mean 90, sigma 30 ->
	// mean + 3 sigma = 180 per hour = 3 per minute.
	alt := make([]int, 14*24)
	for i := range alt {
		alt[i] = 60
		if i%2 == 1 {
			alt[i] = 120
		}
	}
	for _, tc := range []struct {
		name   string
		hourly []int
		static int
		want   float64
	}{
		{"no history", nil, 0, 0},
		{"no history keeps 0 even with a static limit", nil, 10, 0},
		{"mean+3sigma over 14 days", alt, 0, 3},
		{"constant series: sigma 0", repeat(600, 4*24), 0, 10},
		{"exactly 3 days uses mean+3sigma", repeat(120, 72), 0, 2},
		// < 3 days: 5 x median. Median of [0,0,60,60,600] = 60 -> 300/h = 5/min.
		{"under 3 days: 5x median", []int{0, 60, 600, 0, 60}, 0, 5},
		{"under 3 days, even length median", []int{30, 90}, 0, 5}, // median 60
		{"static floor wins when higher", alt, 7, 7},
		{"static floor ignored when lower", alt, 2, 3},
		// A slow type (12/h -> 0.2/min) still allows one spawn a minute.
		{"one per minute floor", repeat(12, 5*24), 0, 1},
		// A zero statistic carries no scale: static, or no baseline.
		{"zero median, no static", []int{0, 0, 0, 40}, 0, 0},
		{"zero median, static", []int{0, 0, 0, 40}, 4, 4},
	} {
		got := population.SpawnBaseline(tc.hourly, tc.static)
		if math.Abs(got-tc.want) > 1e-9 {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

// The enricher derives spawn_baseline_limit from spawn_stats in Postgres
// (14 days back, zero-filled, current hour excluded) and the observer feeds
// spawn_stats only with allowed spawns.
func TestBaselineFromSpawnStats(t *testing.T) {
	f := newFixture(t, nil, config.PopulationConfig{})
	ctx := context.Background()
	now := time.Now().UTC()
	hour := now.Truncate(time.Hour)
	f.agent(t, "w1", "worker", "", 100, false)
	f.agentType(t, population.AgentType{Type: "worker"})

	enrich := func(a action.Action) population.EnrichedContext {
		t.Helper()
		v, err := f.svc.Enrich(ctx, a, control.State{AgentID: a.AgentID, Registered: true, Type: "worker"})
		if err != nil {
			t.Fatal(err)
		}
		return *v.(*population.EnrichedContext)
	}
	read := action.Action{ActionID: action.NewID("act"), AgentID: "w1", System: "memory", Verb: action.VerbRead}
	if pc := enrich(read); pc.SpawnBaselineLimit != 0 {
		t.Fatalf("no history: %v", pc.SpawnBaselineLimit)
	}

	// 4 days of history: hours alternate 60/120 (mean 90, sigma 30 -> 3/min).
	// Rows outside the window (15 days ago) and in the current hour are ignored.
	b := &pgxBatch{}
	for i := 1; i <= 4*24; i++ {
		c := 60
		if i%2 == 0 {
			c = 120
		}
		b.add(hour.Add(-time.Duration(i)*time.Hour), c)
	}
	b.add(hour.Add(-15*24*time.Hour), 100000)
	b.add(hour, 100000)
	for _, r := range b.rows {
		if _, err := f.pool.Exec(ctx, `INSERT INTO spawn_stats (hour, agent_type, count) VALUES ($1, 'worker', $2)`, r.h, r.c); err != nil {
			t.Fatal(err)
		}
	}
	// A fresh service (the baseline is cached for a minute).
	svc, err := population.New(f.pool, f.d, f.alerts, population.NewMemoryCounters(), config.PopulationConfig{}, discard())
	if err != nil {
		t.Fatal(err)
	}
	v, err := svc.Enrich(ctx, read, control.State{AgentID: "w1", Registered: true, Type: "worker"})
	if err != nil {
		t.Fatal(err)
	}
	if got := v.(*population.EnrichedContext).SpawnBaselineLimit; math.Abs(got-3) > 1e-9 {
		t.Fatalf("baseline from spawn_stats: %v", got)
	}
	// Changing the type's static limit invalidates the cached baseline.
	if _, err := svc.PutAgentType(ctx, population.AgentType{Type: "worker", SpawnRatePerMin: 8}, "user:sec@acme.com", ""); err != nil {
		t.Fatal(err)
	}
	v, _ = svc.Enrich(ctx, read, control.State{AgentID: "w1", Registered: true, Type: "worker"})
	if pc := v.(*population.EnrichedContext); pc.SpawnBaselineLimit != 8 || pc.SpawnRateLimit != 8 {
		t.Fatalf("static floor: %+v", pc)
	}
}

type pgxBatch struct {
	rows []struct {
		h time.Time
		c int
	}
}

func (b *pgxBatch) add(h time.Time, c int) {
	b.rows = append(b.rows, struct {
		h time.Time
		c int
	}{h, c})
}
