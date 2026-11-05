package netsuite

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/authz"
	"fortik/internal/diary"
	"fortik/internal/httpx"
	"fortik/internal/integrations"
	"fortik/internal/policy"
	"fortik/internal/saas"
)

// Diary events and alert kinds.
const (
	EventActivityObserved = "saas.activity_observed"
	EventSync             = "saas.sync"
	KindPolicyViolation   = "saas_policy_violation"
)

// Evaluator is decide.Service.Evaluate: what policy WOULD decide, no effects.
type Evaluator interface {
	Evaluate(ctx context.Context, a action.Action) (policy.Result, error)
}

// TxRaiser is alerts.PGStore.
type TxRaiser interface {
	RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error)
}

// Syncer ingests NetSuite activity into Fortik as observed actions.
type Syncer struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	conn   *Connector
	eval   Evaluator
	alerts TxRaiser
	log    *slog.Logger
}

// NewSyncer wires ingestion.
func NewSyncer(pool *pgxpool.Pool, d *diary.Diary, conn *Connector, eval Evaluator, raiser TxRaiser, log *slog.Logger) *Syncer {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Syncer{pool: pool, diary: d, conn: conn, eval: eval, alerts: raiser, log: log}
}

// SyncResult reports one ingestion pass.
type SyncResult struct {
	Events     int    `json:"events"`     // new events recorded
	Violations int    `json:"violations"` // events policy would have held or denied
	Duplicates int    `json:"duplicates"` // already recorded
	Unknown    int    `json:"unknown_agents"`
	Cursor     string `json:"cursor"`
	Error      string `json:"error,omitempty"`
}

// Sync reads activity after the stored cursor and records it. A failure is
// stored as the last error; the last successful sync time is kept, so the
// console shows stale data as stale.
func (s *Syncer) Sync(ctx context.Context, actor string) (SyncResult, error) {
	ts, err := s.conn.tenants(ctx)
	if err != nil {
		return SyncResult{}, err
	}
	if len(ts) == 0 {
		return SyncResult{}, fmt.Errorf("%w: no NetSuite REST connection", integrations.ErrNotConfigured)
	}
	var total SyncResult
	var firstErr error
	for _, t := range ts {
		if t.Err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", t.Settings.IntegrationID, t.Err)
			}
			continue
		}
		res, err := s.syncTenant(ctx, t.Settings, actor)
		total.Events += res.Events
		total.Violations += res.Violations
		total.Duplicates += res.Duplicates
		total.Unknown += res.Unknown
		total.Cursor = res.Cursor
		if res.Error != "" && total.Error == "" {
			total.Error = t.Settings.IntegrationID + ": " + res.Error
		}
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", t.Settings.IntegrationID, err)
		}
	}
	return total, firstErr
}

// syncTenant ingests one tenant's activity after its stored cursor.
func (s *Syncer) syncTenant(ctx context.Context, st Settings, actor string) (SyncResult, error) {
	var cursor string
	err := s.pool.QueryRow(ctx, `SELECT cursor FROM saas_sync_state WHERE system = $1 AND tenant = $2`, System, st.AccountID).Scan(&cursor)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return SyncResult{}, err
	}
	evs, next, aerr := s.conn.activity(ctx, st, cursor)
	res := SyncResult{Cursor: next}
	for _, ev := range evs {
		if ev.Action.AgentID == "" {
			res.Unknown++
			continue
		}
		added, violated, err := s.record(ctx, st.AccountID, ev)
		if err != nil {
			return res, err
		}
		if !added {
			res.Duplicates++
			continue
		}
		res.Events++
		if violated {
			res.Violations++
		}
	}
	errText := ""
	if aerr != nil {
		errText = clip(aerr.Error(), 500)
		res.Error = errText
	}
	_, err = s.pool.Exec(ctx, `INSERT INTO saas_sync_state (system, tenant, cursor, last_attempt_at, last_success_at, last_error)
		VALUES ($1, $2, $3, now(), CASE WHEN $4 = '' THEN now() END, NULLIF($4, ''))
		ON CONFLICT (system, tenant) DO UPDATE SET cursor = EXCLUDED.cursor, last_attempt_at = now(),
			last_success_at = CASE WHEN $4 = '' THEN now() ELSE saas_sync_state.last_success_at END, last_error = NULLIF($4, '')`,
		System, st.AccountID, next, errText)
	if err != nil {
		return res, err
	}
	if res.Events > 0 || aerr != nil {
		if _, err := s.diary.Append(ctx, diary.Event{EventType: EventSync, Actor: actor, Data: map[string]any{
			"system": System, "integration_id": st.IntegrationID, "tenant": st.AccountID, "events": res.Events, "violations": res.Violations, "cursor": next, "error": errText}}); err != nil {
			return res, err
		}
	}
	return res, aerr
}

func (s *Syncer) record(ctx context.Context, tenant string, ev saas.Activity) (bool, bool, error) {
	a := ev.Action
	a.ActionID = action.NewID("act")
	// Evaluated without a source (vendor_audit actions are recorded, never
	// decided: Decide refuses that source); recorded as vendor_audit below.
	res, evalErr := s.eval.Evaluate(ctx, a)
	a.Source = action.SourceVendorAudit
	evaluated := evalErr == nil
	if evalErr != nil {
		s.log.Warn("netsuite: could not evaluate observed activity", "event", ev.NativeEventID, "err", evalErr)
	}
	added, violated := false, false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO saas_events_seen (system, tenant, event_id) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, System, tenant, ev.NativeEventID)
		if err != nil || tag.RowsAffected() == 0 {
			return err
		}
		added = true
		ts, tsNote := ev.At, "event time from NetSuite"
		if ts.IsZero() {
			ts, tsNote = time.Now(), "event time not parseable; ingestion time used"
		}
		class, rule, would, why := "green", "NETSUITE-OBSERVED", "unknown", "not evaluated: "+fmt.Sprint(evalErr)
		if evaluated {
			class, rule, would, why = string(res.Class), res.RuleID, string(res.Decision), res.Reason
			violated = res.Decision != policy.Allow
		}
		reason := fmt.Sprintf("observed after execution in NetSuite system notes (not decided by Fortik); policy would have: %s (%s)", would, rule)
		target, _ := json.Marshal(a.Target)
		dj, _ := json.Marshal(map[string]any{"after_execution": map[string]any{"would_be_decision": would, "rule_id": rule, "reason": why,
			"class": class, "evaluated": evaluated}, "evidence": map[string]any{"source": ev.Source, "system_note_id": ev.NativeEventID,
			"entity": ev.AgentNativeID, "tenant": tenant, "ts_note": tsNote}})
		if _, err := tx.Exec(ctx, `INSERT INTO actions (action_id, agent_id, system, verb, action_hash, class, decision, rule_id, reason,
			reversible, source, target, payload_summary, decision_json, fail_closed, latency_us, ts, observed)
			VALUES ($1,$2,$3,$4,$5,$6,'allow',$7,$8,false,$9,$10,'{}',$11,false,0,$12,true)`,
			a.ActionID, a.AgentID, a.System, string(a.Verb), a.Hash(), class, rule, reason, a.Source, target, dj, ts); err != nil {
			return err
		}
		if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: EventActivityObserved, Actor: "system:netsuite-sync",
			Data: map[string]any{"action_id": a.ActionID, "system": System, "tenant": tenant, "system_note_id": ev.NativeEventID,
				"entity": ev.AgentNativeID, "would_be_decision": would, "rule_id": rule}}); err != nil {
			return err
		}
		if violated {
			sev := alerts.SevWarning
			if class == "red" {
				sev = alerts.SevHigh
			}
			details, _ := json.Marshal(map[string]any{"system_note_id": ev.NativeEventID, "rule_id": rule, "reason": why, "tenant": tenant})
			if _, err := s.alerts.RaiseTx(ctx, tx, alerts.Alert{Kind: KindPolicyViolation, Severity: sev, AgentID: a.AgentID, ActionID: a.ActionID,
				Summary:  fmt.Sprintf("NetSuite activity by %s that policy would have refused (%s), seen after it happened: %s", a.AgentID, rule, clip(why, 160)),
				Details:  details,
				DedupKey: KindPolicyViolation + ":" + System + ":" + a.AgentID + ":" + rule}); err != nil {
				return err
			}
		}
		return nil
	})
	return added, violated, err
}

// Worker syncs every interval while the integration is configured.
func (s *Syncer) Worker(ctx context.Context, every time.Duration) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if _, err := s.Sync(ctx, "system:netsuite-sync"); err != nil && !errors.Is(err, integrations.ErrNotConfigured) && ctx.Err() == nil {
			s.log.Warn("netsuite: activity sync failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Register mounts the NetSuite status and sync API:
//
//	GET  /v1/saas/netsuite        auditor or security: probes, inventory, sync state, coverage
//	POST /v1/saas/netsuite/sync   security: ingest activity now
func (s *Syncer) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/saas/netsuite", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := authz.Require(w, r, authz.RoleAuditor, authz.RoleSecurity); !ok {
			return
		}
		out := map[string]any{"system": System, "declaration": Declaration()}
		ts, err := s.conn.tenants(r.Context())
		if err != nil || len(ts) == 0 {
			out["configured"] = false
			out["detail"] = "no NetSuite REST connection"
			out["tenants"] = []any{}
			httpx.WriteJSON(w, http.StatusOK, out)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		tenants := make([]map[string]any, 0, len(ts))
		for _, t := range ts {
			st := t.Settings
			tv := map[string]any{"integration_id": st.IntegrationID, "connection": st.Key, "account_id": st.AccountID}
			if t.Err != nil {
				tv["detail"] = t.Err.Error()
				tenants = append(tenants, tv)
				continue
			}
			tv["probes"] = s.conn.probes(ctx, st)
			if inv, err := s.conn.inventory(ctx, st); err == nil {
				tv["inventory"] = inv
			} else {
				tv["inventory_error"] = err.Error()
			}
			var cursor string
			var attempt, success *time.Time
			var lastErr *string
			if err := s.pool.QueryRow(r.Context(), `SELECT cursor, last_attempt_at, last_success_at, last_error FROM saas_sync_state WHERE system = $1 AND tenant = $2`,
				System, st.AccountID).Scan(&cursor, &attempt, &success, &lastErr); err == nil {
				tv["sync"] = map[string]any{"cursor": cursor, "last_attempt_at": attempt, "last_success_at": success, "last_error": lastErr}
			} else {
				tv["sync"] = map[string]any{"status": "never synchronized"}
			}
			tenants = append(tenants, tv)
		}
		out["configured"] = true
		out["tenants"] = tenants
		// The single-tenant fields earlier clients read.
		for k, v := range tenants[0] {
			if k != "integration_id" && k != "connection" {
				out[k] = v
			}
		}
		httpx.WriteJSON(w, http.StatusOK, out)
	})
	mux.HandleFunc("POST /v1/saas/netsuite/sync", func(w http.ResponseWriter, r *http.Request) {
		p, ok := authz.Require(w, r, authz.RoleSecurity)
		if !ok {
			return
		}
		res, err := s.Sync(r.Context(), p.Actor())
		switch {
		case errors.Is(err, integrations.ErrNotConfigured):
			httpx.WriteError(w, http.StatusServiceUnavailable, "netsuite integration not configured")
		case err != nil:
			res.Error = err.Error()
			httpx.WriteJSON(w, http.StatusBadGateway, res)
		default:
			httpx.WriteJSON(w, http.StatusOK, res)
		}
	})
}
