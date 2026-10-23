package baseline_test

import (
	"math"
	"testing"
	"time"

	"fortik/internal/baseline"
	"fortik/internal/config"
)

var plan = baseline.ParamsFrom(config.BaselineConfig{}) // 14 days, 3 sigma, 5x median, 3 days, min 20

const hr = int64(3600)

var nowHour = baseline.HourStart(time.Date(2026, 10, 20, 15, 30, 0, 0, time.UTC)).Unix()

// series builds `hours` hours of history ending just before nowHour, with
// f(i) for hour i (0 = oldest).
func series(hours int, f func(i int) int64) map[int64]int64 {
	m := map[int64]int64{}
	for i := 0; i < hours; i++ {
		m[nowHour-int64(hours-i)*hr] = f(i)
	}
	return m
}

func TestParamsDefaults(t *testing.T) {
	if plan.Days != 14 || plan.Sigma != 3 || plan.MedianFactor != 5 || plan.MinHistoryDays != 3 || plan.MinCount != 20 {
		t.Fatalf("%+v", plan)
	}
	if plan.Retention() != 15*24*time.Hour {
		t.Fatal(plan.Retention())
	}
}

// 14 days alternating 10 and 30 per hour: mean 20, stddev 10, threshold 50.
func TestMeanPlusThreeSigma(t *testing.T) {
	s := series(14*24, func(i int) int64 {
		if i%2 == 0 {
			return 10
		}
		return 30
	})
	h := baseline.ComputeHistory(s, nowHour, plan)
	if h.Method != baseline.MethodSigma || h.Mean != 20 || h.Stddev != 10 || h.Threshold != 50 || h.HistoryDays != 14 {
		t.Fatalf("%+v", h)
	}
	if c := baseline.Evaluate(h, 50, plan); c.AboveNormal {
		t.Fatalf("50 is not above 50: %+v", c)
	}
	if c := baseline.Evaluate(h, 51, plan); !c.AboveNormal || c.Current != 51 || c.Threshold != 50 {
		t.Fatalf("51: %+v", c)
	}
}

// Zero-filled: hours without activity count as 0 in mean and stddev.
func TestSigmaZeroFillsIdleHours(t *testing.T) {
	s := map[int64]int64{nowHour - 4*24*hr: 96} // one active hour 4 days ago, idle since
	p := plan
	p.MinActiveHours = 1 // the sigma statistic itself (not the sparse-history rule)
	h := baseline.ComputeHistory(s, nowHour, p)
	if h.Method != baseline.MethodSigma || h.HistoryDays != 4 {
		t.Fatalf("%+v", h)
	}
	if math.Abs(h.Mean-1) > 1e-9 {
		t.Fatalf("mean %v", h.Mean)
	}
	want := 1 + 3*math.Sqrt((95.0*95.0+95.0*1.0)/96.0) // population stddev
	if math.Abs(h.Threshold-want) > 1e-9 {
		t.Fatalf("threshold %v want %v", h.Threshold, want)
	}
}

// Less than 3 days of history: 5 x the median of the active hours.
func TestFiveTimesMedianWithShortHistory(t *testing.T) {
	// 2 days: active hours 4, 6, 8 (median 6), the rest idle.
	s := series(48, func(i int) int64 {
		switch i {
		case 0:
			return 4
		case 10:
			return 8
		case 20:
			return 6
		}
		return 0
	})
	p := plan
	p.MinActiveHours = 1
	h := baseline.ComputeHistory(s, nowHour, p)
	if h.Method != baseline.MethodMedian || h.Median != 6 || h.Threshold != 30 || h.HistoryDays != 2 {
		t.Fatalf("%+v", h)
	}
	if c := baseline.Evaluate(h, 30, plan); c.AboveNormal {
		t.Fatalf("30 is not above 5x6: %+v", c)
	}
	if c := baseline.Evaluate(h, 31, plan); !c.AboveNormal || c.Method != baseline.MethodMedian {
		t.Fatalf("31: %+v", c)
	}
}

// The switch to mean + 3 sigma happens at exactly min_history_days.
func TestHistoryDaysBoundary(t *testing.T) {
	short := baseline.ComputeHistory(series(3*24-1, func(int) int64 { return 2 }), nowHour, plan)
	full := baseline.ComputeHistory(series(3*24, func(int) int64 { return 2 }), nowHour, plan)
	if short.Method != baseline.MethodMedian || full.Method != baseline.MethodSigma || full.HistoryDays != 3 {
		t.Fatalf("short %+v full %+v", short, full)
	}
}

// Never above normal below min_count, however far above the statistic.
func TestMinCount(t *testing.T) {
	h := baseline.ComputeHistory(series(14*24, func(int) int64 { return 1 }), nowHour, plan)
	if h.Threshold != 1 {
		t.Fatalf("%+v", h)
	}
	if c := baseline.Evaluate(h, 19, plan); c.AboveNormal || c.MinCount != 20 {
		t.Fatalf("19 < min_count: %+v", c)
	}
	if c := baseline.Evaluate(h, 20, plan); !c.AboveNormal {
		t.Fatalf("20 >= min_count: %+v", c)
	}
}

// Phase 5 review M4: no history for the verb (its first use, or nothing in the
// window) is bounded by the first-use ceiling, never unbounded.
func TestFirstUseCeiling(t *testing.T) {
	for name, s := range map[string]map[int64]int64{
		"empty":        {},
		"current only": {nowHour: 5000},
		"outside window": {
			nowHour - 15*24*hr: 10,
		},
		"zeros only": {nowHour - 5*hr: 0},
	} {
		if c := baseline.Compute(s, nowHour, 200, plan); c.AboveNormal || c.Method != baseline.MethodFirstUse || c.HistoryDays != 0 {
			t.Fatalf("%s at the ceiling: %+v", name, c)
		}
		if c := baseline.Compute(s, nowHour, 100_000, plan); !c.AboveNormal || c.Threshold != 200 {
			t.Fatalf("%s far above the ceiling: %+v", name, c)
		}
	}
	if (baseline.History{}).Method != "" || baseline.Evaluate(baseline.History{}, 1_000_000, plan).AboveNormal {
		t.Fatal("a zero History is never above normal")
	}
}

// Phase 5 review M4: one burst in the first hours cannot pre-train a huge
// threshold (sparse history: at most median_factor x the ceiling).
func TestBurstCannotPretrainThreshold(t *testing.T) {
	s := map[int64]int64{nowHour - hr: 10_000}
	c := baseline.Compute(s, nowHour, 40_000, plan)
	if c.Method != baseline.MethodSparse || c.Threshold != 1000 || !c.AboveNormal {
		t.Fatalf("%+v", c)
	}
	// Six active hours later the agent's own median applies.
	s = series(6, func(int) int64 { return 300 })
	if h := baseline.ComputeHistory(s, nowHour, plan); h.Method != baseline.MethodMedian || h.Threshold != 1500 {
		t.Fatalf("%+v", h)
	}
}

// Phase 5 review L1: an agent that runs 100 calls once a day is not above
// normal at its usual run (the busiest hour already seen), although the
// zero-filled sigma threshold is ~64; more than it ever did still is.
func TestPeriodicAgentNotHeldAtItsUsualRun(t *testing.T) {
	s := series(14*24, func(i int) int64 {
		if i%24 == 0 {
			return 100
		}
		return 0
	})
	h := baseline.ComputeHistory(s, nowHour, plan)
	if h.Method != baseline.MethodSigma || h.Threshold > 100 || h.Max != 100 {
		t.Fatalf("%+v", h)
	}
	if c := baseline.Evaluate(h, 100, plan); c.AboveNormal {
		t.Fatalf("usual run: %+v", c)
	}
	if c := baseline.Evaluate(h, 101, plan); !c.AboveNormal {
		t.Fatalf("above its busiest hour: %+v", c)
	}
}

// The current hour is never part of its own history, and history older than
// the window is ignored (history_days capped at days).
func TestWindowBounds(t *testing.T) {
	s := series(20*24, func(int) int64 { return 3 })
	s[nowHour] = 999
	s[nowHour+hr] = 999
	h := baseline.ComputeHistory(s, nowHour, plan)
	if h.HistoryDays != 14 || h.Mean != 3 || h.Stddev != 0 {
		t.Fatalf("%+v", h)
	}
}
