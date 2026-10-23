package api

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/control"
)

// statsSummary: GET /v1/stats/summary, the console KPI row. "Today" is the
// current UTC day.
func (s *Server) statsSummary(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	today := dayStart(time.Now())
	var agentsTotal, actionsToday, heldPending, agentsNotFull int64
	byClass := map[string]int64{"green": 0, "yellow": 0, "red": 0}
	var green, yellow, red int64
	err := s.Pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM agents),
		       (SELECT count(*) FROM actions WHERE ts >= $1),
		       (SELECT count(*) FROM actions WHERE ts >= $1 AND class = 'green'),
		       (SELECT count(*) FROM actions WHERE ts >= $1 AND class = 'yellow'),
		       (SELECT count(*) FROM actions WHERE ts >= $1 AND class = 'red'),
		       (SELECT count(*) FROM held_actions WHERE outcome = 'pending'),
		       (SELECT count(*) FROM agents WHERE level > 0)`, today).
		Scan(&agentsTotal, &actionsToday, &green, &yellow, &red, &heldPending, &agentsNotFull)
	if err != nil {
		s.internal(w, err)
		return
	}
	byClass["green"], byClass["yellow"], byClass["red"] = green, yellow, red

	byLevel := map[string]int64{}
	for l := control.Full; l <= control.Killed; l++ {
		byLevel[l.String()] = 0
	}
	rows, err := s.Pool.Query(ctx, `SELECT level, count(*) FROM agents GROUP BY level`)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var lvl int16
		var n int64
		if err := rows.Scan(&lvl, &n); err != nil {
			s.internal(w, err)
			return
		}
		byLevel[control.Level(lvl).String()] = n
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{
		"agents_total": agentsTotal, "actions_today": actionsToday, "by_class_today": byClass,
		"held_pending": heldPending, "red_today": red, "agents_not_full": agentsNotFull, "agents_by_level": byLevel,
		"day_start": today.Format(time.RFC3339),
	})
}

type hourBucket struct {
	Hour       time.Time `json:"hour"`
	Count      int64     `json:"count"`
	WorstClass string    `json:"worst_class"` // "" when the hour had no actions
}

// agentStats: GET /v1/agents/{id}/stats?hours=24 (1..168). Hourly buckets
// are UTC hours, oldest first, including empty ones (for charting).
func (s *Server) agentStats(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ctx := r.Context()
	hours := 24
	if v := r.URL.Query().Get("hours"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 168 {
			writeError(w, http.StatusBadRequest, "hours must be an integer between 1 and 168")
			return
		}
		hours = n
	}
	var one int
	err := s.Pool.QueryRow(ctx, `SELECT 1 FROM agents WHERE agent_id = $1`, id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "agent not found")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	last := time.Now().UTC().Truncate(time.Hour)
	first := last.Add(-time.Duration(hours-1) * time.Hour)

	byClass := map[string]int64{"green": 0, "yellow": 0, "red": 0}
	byVerb := map[string]int64{}
	bySystem := map[string]int64{}
	for _, q := range []struct {
		m   map[string]int64
		col string
	}{{byClass, "class"}, {byVerb, "verb"}, {bySystem, "system"}} {
		// col is one of three fixed identifiers above, never user input.
		if err := s.groupCounts(ctx, q.m, `SELECT `+q.col+`, count(*) FROM actions WHERE agent_id = $1 AND ts >= $2 GROUP BY 1`, id, first); err != nil {
			s.internal(w, err)
			return
		}
	}

	rows, err := s.Pool.Query(ctx, `
		SELECT h.hour, count(a.action_id),
		       CASE WHEN bool_or(a.class = 'red') THEN 'red' WHEN bool_or(a.class = 'yellow') THEN 'yellow'
		            WHEN count(a.action_id) > 0 THEN 'green' ELSE '' END
		FROM generate_series($2::timestamptz, $3::timestamptz, interval '1 hour') AS h(hour)
		LEFT JOIN actions a ON a.agent_id = $1 AND a.ts >= h.hour AND a.ts < h.hour + interval '1 hour'
		GROUP BY h.hour ORDER BY h.hour`, id, first, last)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	hourly := make([]hourBucket, 0, hours)
	for rows.Next() {
		var b hourBucket
		if err := rows.Scan(&b.Hour, &b.Count, &b.WorstClass); err != nil {
			s.internal(w, err)
			return
		}
		b.Hour = b.Hour.UTC()
		hourly = append(hourly, b)
	}
	if err := rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"agent_id": id, "hours": hours, "since": first.Format(time.RFC3339),
		"by_class": byClass, "by_verb": byVerb, "by_system": bySystem, "hourly": hourly})
}
