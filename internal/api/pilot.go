package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/authz"
)

// Pilot success metrics (plan, "Success metrics for design partners"):
//
//	risky actions handled without a kill      >= 95%
//	false-alarm rate on red (overturned)       < 2%
//	time from red action to step-down (p50)    < 1 s
//	actions undone successfully when requested 100% of supported types
//	Fortik overhead on green actions (p95)     < 50 ms
//
// Observe-mode decisions count with their would-be result.

type metric struct {
	Value  *float64 `json:"value"` // nil: no data in the window
	Unit   string   `json:"unit"`
	Target string   `json:"target"`
	Met    *bool    `json:"met"`
	Basis  string   `json:"basis"`
	N      int64    `json:"n"`
}

// PilotMetrics is GET /v1/metrics/pilot.
type PilotMetrics struct {
	From              time.Time           `json:"from"`
	To                time.Time           `json:"to"`
	RiskyWithoutKill  metric              `json:"risky_handled_without_kill"`
	RedOverturned     metric              `json:"red_false_alarm_rate"`
	RedToStepDownP50  metric              `json:"red_to_step_down_p50"`
	UndoSuccess       metric              `json:"undo_success"`
	UndoByKind        map[string][2]int64 `json:"undo_by_kind"` // kind -> [succeeded, failed]
	GreenOverheadP95  metric              `json:"green_overhead_p95"`
	Decisions         int64               `json:"decisions"`
	ObservedDecisions int64               `json:"observed_decisions"`
}

func ptr[T any](v T) *T { return &v }

func (s *Server) pilotMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
		return
	}
	to := time.Now().UTC()
	from := to.Add(-30 * 24 * time.Hour)
	if v := r.URL.Query().Get("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "from must be RFC 3339")
			return
		}
		from = t.UTC()
	}
	if v := r.URL.Query().Get("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			writeError(w, http.StatusBadRequest, "to must be RFC 3339")
			return
		}
		to = t.UTC()
	}
	if !from.Before(to) || to.Sub(from) > 366*24*time.Hour {
		writeError(w, http.StatusBadRequest, "from must be before to, at most one year apart")
		return
	}
	m, err := ComputePilotMetrics(r.Context(), s.Pool, from, to)
	if err != nil {
		s.internal(w, err)
		return
	}
	writeJSON(w, http.StatusOK, m)
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// ComputePilotMetrics computes the success metrics over [from, to).
func ComputePilotMetrics(ctx context.Context, q querier, from, to time.Time) (PilotMetrics, error) {
	m := PilotMetrics{From: from, To: to, UndoByKind: map[string][2]int64{}}
	decided := `a.ts >= $1 AND a.ts < $2 AND a.source <> 'vendor_audit'`
	if err := q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE a.observed) FROM actions a WHERE `+decided, from, to).
		Scan(&m.Decisions, &m.ObservedDecisions); err != nil {
		return m, err
	}

	// 1. Risky (yellow/red) actions whose agent was not killed in the window.
	var risky, notKilled int64
	if err := q.QueryRow(ctx, `
		WITH killed AS (SELECT DISTINCT agent_id FROM diary WHERE event_type = 'agent.level_changed' AND ts >= $1 AND ts < $2
		                  AND body_json::jsonb -> 'data' ->> 'to' = 'KILLED')
		SELECT count(*), count(*) FILTER (WHERE a.agent_id NOT IN (SELECT agent_id FROM killed WHERE agent_id IS NOT NULL))
		FROM actions a WHERE `+decided+` AND a.class IN ('yellow', 'red') AND NOT a.fail_closed`, from, to).Scan(&risky, &notKilled); err != nil {
		return m, err
	}
	m.RiskyWithoutKill = ratio(notKilled, risky, ">= 95%", 0.95, true,
		"yellow and red decisions whose agent was not KILLED in the window, out of all yellow and red decisions")

	// 2. Red decisions a human overturned: the hold approved, or the automatic
	// step-down reversed by a person within 24 hours.
	var red, overturned int64
	if err := q.QueryRow(ctx, `
		SELECT count(*),
		       count(*) FILTER (WHERE EXISTS (SELECT 1 FROM held_actions h WHERE h.action_id = a.action_id AND h.outcome = 'approved')
		                         OR (a.decision_json ? 'ladder_change' AND a.decision_json -> 'ladder_change' <> 'null'::jsonb AND EXISTS (
		                             SELECT 1 FROM diary d WHERE d.event_type = 'agent.level_changed' AND d.agent_id = a.agent_id
		                               AND d.ts > a.ts AND d.ts < a.ts + interval '24 hours'
		                               AND d.body_json::jsonb -> 'data' ->> 'direction' = 'up'
		                               AND d.body_json::jsonb -> 'data' ->> 'automatic' = 'false')))
		FROM actions a WHERE `+decided+` AND a.class = 'red' AND NOT a.fail_closed AND a.rule_id NOT IN ('POL-002', 'POL-010', 'POL-011', 'POL-015')`,
		from, to).Scan(&red, &overturned); err != nil {
		return m, err
	}
	m.RedOverturned = ratio(overturned, red, "< 2%", 0.02, false,
		"red decisions whose hold a person approved, or whose automatic step-down a person reversed within 24 h, out of all red decisions (gates excluded)")

	// 3. Red action -> step-down event (automatic, same action).
	var p50 *float64
	var nStep int64
	if err := q.QueryRow(ctx, `
		SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM d.ts - a.ts) * 1000), count(*)
		FROM actions a JOIN diary d ON d.event_type = 'agent.level_changed' AND d.agent_id = a.agent_id
		     AND d.body_json::jsonb -> 'data' ->> 'action_id' = a.action_id AND d.body_json::jsonb -> 'data' ->> 'automatic' = 'true'
		WHERE `+decided+` AND a.class = 'red'`, from, to).Scan(&p50, &nStep); err != nil {
		return m, err
	}
	m.RedToStepDownP50 = metric{Value: p50, Unit: "ms", Target: "< 1000 ms", N: nStep,
		Basis: "median time from a red action's timestamp to its automatic step-down Diary event"}
	if p50 != nil {
		m.RedToStepDownP50.Met = ptr(*p50 < 1000)
	}

	// 4. Undo runs: executed vs failed, per kind.
	rows, err := q.Query(ctx, `
		SELECT COALESCE(u.kind, 'unknown'), count(*) FILTER (WHERE d.event_type = 'undo.executed'), count(*) FILTER (WHERE d.event_type = 'undo.failed')
		FROM diary d LEFT JOIN undo_handles u ON u.action_id = d.body_json::jsonb -> 'data' ->> 'action_id'
		WHERE d.event_type IN ('undo.executed', 'undo.failed') AND d.ts >= $1 AND d.ts < $2 GROUP BY 1`, from, to)
	if err != nil {
		return m, err
	}
	var ok, failed int64
	for rows.Next() {
		var kind string
		var s, f int64
		if err := rows.Scan(&kind, &s, &f); err != nil {
			rows.Close()
			return m, err
		}
		m.UndoByKind[kind] = [2]int64{s, f}
		ok, failed = ok+s, failed+f
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return m, err
	}
	m.UndoSuccess = ratio(ok, ok+failed, "100%", 1, true, "undo runs that succeeded, out of all undo runs requested (by kind in undo_by_kind)")

	// 5. Fortik overhead on green decisions (server-side decision latency).
	var p95 *float64
	var nGreen int64
	if err := q.QueryRow(ctx, `SELECT percentile_cont(0.95) WITHIN GROUP (ORDER BY a.latency_us) / 1000.0, count(*)
		FROM actions a WHERE `+decided+` AND a.class = 'green' AND NOT a.fail_closed AND a.latency_us > 0`, from, to).Scan(&p95, &nGreen); err != nil {
		return m, err
	}
	m.GreenOverheadP95 = metric{Value: p95, Unit: "ms", Target: "< 50 ms", N: nGreen,
		Basis: "95th percentile of the recorded decision latency of green decisions (excludes the downstream API's own time)"}
	if p95 != nil {
		m.GreenOverheadP95.Met = ptr(*p95 < 50)
	}
	return m, nil
}

// ratio is num/den as a percentage with its target check (atLeast: >= goal).
func ratio(num, den int64, target string, goal float64, atLeast bool, basis string) metric {
	m := metric{Unit: "%", Target: target, Basis: basis, N: den}
	if den == 0 {
		return m
	}
	v := float64(num) / float64(den)
	m.Value = ptr(v * 100)
	if atLeast {
		m.Met = ptr(v >= goal)
	} else {
		m.Met = ptr(v < goal)
	}
	return m
}
