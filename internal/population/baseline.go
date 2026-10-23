package population

import (
	"context"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Spawn baseline (docs/PHASE3_DESIGN.md §2.3): plain statistics over the
// hourly spawn counts of the last 14 days, no ML.
const (
	BaselineHistory    = 14 * 24 * time.Hour
	minBaselineHours   = 3 * 24 // below this, 5 x median instead of mean + 3 sigma
	baselineCacheTTL   = time.Minute
	medianMultiplier   = 5
	sigmaMultiplier    = 3
	minBaselinePerMin  = 1.0
	baselineCacheLimit = 4096
)

// SpawnBaseline derives the per-minute spawn limit from hourly spawn counts
// (oldest first, every hour of the history present, zeros included; the
// current partial hour excluded).
//
//   - No history: 0 (no baseline yet; only the static limits apply).
//   - Fewer than 3 days: 5 x median, else mean + 3 sigma (population sigma).
//   - Per minute = hourly / 60, never below staticPerMin when it is set and
//     never below one spawn per minute: an hourly limit spread evenly over
//     60 minutes would otherwise refuse every spawn of a type that spawns
//     less than once a minute.
//   - A history whose statistic is 0 (e.g. the median of a type that spawns
//     in fewer than half of its hours) carries no scale: the result is the
//     static limit, or 0 (no baseline) without one.
func SpawnBaseline(hourly []int, staticPerMin int) float64 {
	if len(hourly) == 0 {
		return 0
	}
	var limit float64
	if len(hourly) < minBaselineHours {
		limit = medianMultiplier * median(hourly)
	} else {
		mean, sd := meanStd(hourly)
		limit = mean + sigmaMultiplier*sd
	}
	if limit <= 0 {
		if staticPerMin > 0 {
			return float64(staticPerMin)
		}
		return 0
	}
	perMin := limit / 60
	if perMin < minBaselinePerMin {
		perMin = minBaselinePerMin
	}
	if s := float64(staticPerMin); staticPerMin > 0 && perMin < s {
		perMin = s
	}
	return math.Round(perMin*1000) / 1000
}

func median(xs []int) float64 {
	s := append([]int(nil), xs...)
	sort.Ints(s)
	n := len(s)
	if n%2 == 1 {
		return float64(s[n/2])
	}
	return float64(s[n/2-1]+s[n/2]) / 2
}

func meanStd(xs []int) (float64, float64) {
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

// hourlySeries loads spawn_stats for agentType over the history window
// ending at the start of now's hour, zero-filling missing hours from the
// first recorded hour on.
func hourlySeries(ctx context.Context, pool *pgxpool.Pool, agentType string, now time.Time) ([]int, error) {
	end := now.UTC().Truncate(time.Hour)
	start := end.Add(-BaselineHistory)
	rows, err := pool.Query(ctx, `SELECT hour, count FROM spawn_stats WHERE agent_type = $1 AND hour >= $2 AND hour < $3 ORDER BY hour`,
		agentType, start, end)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	counts := map[int64]int{}
	var first time.Time
	for rows.Next() {
		var h time.Time
		var c int
		if err := rows.Scan(&h, &c); err != nil {
			return nil, err
		}
		h = h.UTC().Truncate(time.Hour)
		if first.IsZero() || h.Before(first) {
			first = h
		}
		counts[h.Unix()] += c
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if first.IsZero() {
		return nil, nil
	}
	n := int(end.Sub(first) / time.Hour)
	out := make([]int, n)
	for i := range out {
		out[i] = counts[first.Add(time.Duration(i)*time.Hour).Unix()]
	}
	return out, nil
}

// baselineCache memoises per-type baselines for baselineCacheTTL so the
// enricher does not query spawn_stats on every decision.
type baselineCache struct {
	mu sync.Mutex
	m  map[string]baselineEntry
}

type baselineEntry struct {
	limit  float64
	static int
	at     time.Time
}

func (c *baselineCache) get(ctx context.Context, pool *pgxpool.Pool, agentType string, static int, now time.Time) (float64, error) {
	c.mu.Lock()
	e, ok := c.m[agentType]
	c.mu.Unlock()
	if ok && e.static == static && now.Sub(e.at) < baselineCacheTTL && !now.Before(e.at) {
		return e.limit, nil
	}
	series, err := hourlySeries(ctx, pool, agentType, now)
	if err != nil {
		return 0, err
	}
	limit := SpawnBaseline(series, static)
	c.mu.Lock()
	if c.m == nil || len(c.m) >= baselineCacheLimit {
		c.m = map[string]baselineEntry{}
	}
	c.m[agentType] = baselineEntry{limit: limit, static: static, at: now}
	c.mu.Unlock()
	return limit, nil
}

func (c *baselineCache) invalidate(agentType string) {
	c.mu.Lock()
	delete(c.m, agentType)
	c.mu.Unlock()
}
