// Package baseline keeps 14-day hourly action counts per (agent, verb) and
// tells policy when the current hour is above the agent's own normal
// (docs/PHASE5_DESIGN.md §4). Plain statistics, no ML:
//
//   - history: the hourly counts of the last `days` days before the current
//     hour, from the first hour the agent used the verb (zero-filled);
//   - no history for the verb (first use): above normal when current >
//     first_use_ceiling, so switching to a verb never used before is not a
//     free, unbounded hour;
//   - fewer than min_active_hours active hours: above normal when current >
//     max(first_use_ceiling, min(median_factor x median, median_factor x
//     first_use_ceiling)), so one burst cannot pre-train a huge threshold;
//   - with at least min_history_days of history: above normal when
//     current > mean + sigma x stddev (population stddev);
//   - with less: above normal when current > median_factor x median, the
//     median taken over the hours in which the agent was active (a median
//     over zero-filled hours is 0 for any agent idle half of the time and
//     would carry no scale);
//   - never when current < min_count, and (with history) never when current
//     is at most the busiest hour already in the history: an agent that
//     runs once a day is not "above normal" at its usual run, however many
//     idle hours pull the mean and stddev down.
//
// Only executed calls are counted (allow, allow_reduced): held and denied
// calls do not raise the agent's own baseline.
//
// `current` is the count of the current hour INCLUDING the call being
// decided.
package baseline

import (
	"math"
	"sort"
	"time"

	"fortik/internal/config"
)

// Methods reported in Context.Method.
const (
	MethodNone     = "none"      // no statistics (zero History): never above normal
	MethodFirstUse = "first_use" // no history for the verb: first_use_ceiling
	MethodSparse   = "sparse"    // fewer than min_active_hours active hours
	MethodMedian   = "median"    // less than min_history_days of history
	MethodSigma    = "sigma"     // mean + sigma x stddev
)

// Params are the statistics settings (config.BaselineConfig with defaults).
type Params struct {
	Days            int     `json:"days"`
	Sigma           float64 `json:"sigma"`
	MedianFactor    float64 `json:"median_factor"`
	MinHistoryDays  int     `json:"min_history_days"`
	MinCount        int64   `json:"min_count"`
	FirstUseCeiling int64   `json:"first_use_ceiling"`
	MinActiveHours  int     `json:"min_active_hours"`
}

// ParamsFrom applies the plan's defaults to zero fields.
func ParamsFrom(c config.BaselineConfig) Params {
	p := Params{Days: c.Days, Sigma: c.Sigma, MedianFactor: c.MedianFactor, MinHistoryDays: c.MinHistoryDays, MinCount: c.MinCount,
		FirstUseCeiling: c.FirstUseCeiling, MinActiveHours: c.MinActiveHours}
	if p.Days <= 0 {
		p.Days = 14
	}
	if p.Sigma <= 0 {
		p.Sigma = 3
	}
	if p.MedianFactor <= 0 {
		p.MedianFactor = 5
	}
	if p.MinHistoryDays <= 0 {
		p.MinHistoryDays = 3
	}
	if p.MinCount <= 0 {
		p.MinCount = 20
	}
	if p.FirstUseCeiling <= 0 {
		p.FirstUseCeiling = 200
	}
	if p.MinActiveHours <= 0 {
		p.MinActiveHours = 6
	}
	return p
}

// ceiling is FirstUseCeiling, defaulted (Params built by hand may leave it 0).
func (p Params) ceiling() int64 {
	if p.FirstUseCeiling <= 0 {
		return 200
	}
	return p.FirstUseCeiling
}

// minActive is MinActiveHours, defaulted.
func (p Params) minActive() int {
	if p.MinActiveHours <= 0 {
		return 6
	}
	return p.MinActiveHours
}

// Window is the history length.
func (p Params) Window() time.Duration { return time.Duration(p.Days) * 24 * time.Hour }

// Retention is how long hourly counts are kept: the window plus one day.
func (p Params) Retention() time.Duration { return p.Window() + 24*time.Hour }

// History is the part of the statistics that depends only on past hours
// (stable within the current hour, so it can be cached).
type History struct {
	Mean        float64
	Stddev      float64
	Median      float64
	HistoryDays float64
	Threshold   float64
	Max         int64 // the busiest hour in the history
	Method      string
}

// Context is input.context.baseline.
type Context struct {
	Current     int64   `json:"current"`
	Mean        float64 `json:"mean"`
	Stddev      float64 `json:"stddev"`
	Median      float64 `json:"median"`
	HistoryDays float64 `json:"history_days"`
	Threshold   float64 `json:"threshold"`
	AboveNormal bool    `json:"above_normal"`
	Method      string  `json:"method"`
	MinCount    int64   `json:"min_count"`
}

// HourStart truncates t to its UTC hour.
func HourStart(t time.Time) time.Time { return t.UTC().Truncate(time.Hour) }

// ComputeHistory derives the statistics from stored hourly counts (unix hour
// start -> count) for the hours before current (a unix hour start). Hours
// outside [current - days, current) are ignored.
func ComputeHistory(series map[int64]int64, current int64, p Params) History {
	from := current - int64(p.Days)*24*3600
	first := int64(math.MaxInt64)
	for h, c := range series {
		if h >= from && h < current && c > 0 && h < first {
			first = h
		}
	}
	firstUse := History{Method: MethodFirstUse, Threshold: float64(p.ceiling())}
	if first == math.MaxInt64 {
		return firstUse
	}
	n := int((current - first) / 3600)
	if n <= 0 {
		return firstUse
	}
	vals := make([]int64, n)
	var active []int64
	var h0max int64
	for i := range vals {
		v := series[first+int64(i)*3600]
		if v < 0 {
			v = 0
		}
		vals[i] = v
		if v > 0 {
			active = append(active, v)
		}
		if v > h0max {
			h0max = v
		}
	}
	h := History{HistoryDays: float64(n) / 24, Max: h0max}
	h.Mean, h.Stddev = meanStd(vals)
	h.Median = median(active)
	switch {
	case len(active) < p.minActive():
		// Too few active hours to trust the agent's own scale: at least the
		// first-use ceiling, at most median_factor x that ceiling, so a burst
		// in the first hours cannot pre-train an unbounded threshold.
		h.Method = MethodSparse
		c := float64(p.ceiling())
		h.Threshold = math.Max(c, math.Min(p.MedianFactor*h.Median, p.MedianFactor*c))
	case h.HistoryDays < float64(p.MinHistoryDays):
		h.Method = MethodMedian
		h.Threshold = p.MedianFactor * h.Median
	default:
		h.Method = MethodSigma
		h.Threshold = h.Mean + p.Sigma*h.Stddev
	}
	return h
}

// Evaluate combines the history with the current hour's count (including the
// call being decided).
func Evaluate(h History, current int64, p Params) Context {
	c := Context{
		Current: current, Mean: round2(h.Mean), Stddev: round2(h.Stddev), Median: round2(h.Median),
		HistoryDays: round2(h.HistoryDays), Threshold: round2(h.Threshold), Method: h.Method, MinCount: p.MinCount,
	}
	if h.Method == "" {
		c.Method = MethodNone
	}
	c.AboveNormal = c.Method != MethodNone && current >= p.MinCount && float64(current) > h.Threshold &&
		(c.Method == MethodFirstUse || current > h.Max)
	return c
}

// Compute is ComputeHistory + Evaluate.
func Compute(series map[int64]int64, currentHour int64, current int64, p Params) Context {
	return Evaluate(ComputeHistory(series, currentHour, p), current, p)
}

func meanStd(xs []int64) (float64, float64) {
	if len(xs) == 0 {
		return 0, 0
	}
	var sum float64
	for _, x := range xs {
		sum += float64(x)
	}
	mean := sum / float64(len(xs))
	var ss float64
	for _, x := range xs {
		d := float64(x) - mean
		ss += d * d
	}
	return mean, math.Sqrt(ss / float64(len(xs)))
}

func median(xs []int64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]int64(nil), xs...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	n := len(s)
	if n%2 == 1 {
		return float64(s[n/2])
	}
	return float64(s[n/2-1]+s[n/2]) / 2
}

func round2(f float64) float64 { return math.Round(f*100) / 100 }
