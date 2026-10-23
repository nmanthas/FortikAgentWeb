package overrides

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/access"
	"fortik/internal/alerts"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
)

// KindRestored is the info alert telling an agent's owner that a suspended
// system came back automatically.
const KindRestored = "override_restored"

// AlertRaiser records an alert inside the caller's transaction so it commits
// with the state change it reports (D4's alerts store implements RaiseTx).
type AlertRaiser interface {
	RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error)
}

// Worker restores timed overrides at their expiry after the safety checks of
// docs/PHASE3_DESIGN.md §5. Several workers (processes) may run at once:
// rows are claimed with FOR UPDATE SKIP LOCKED.
type Worker struct {
	store    *PGStore
	profiles ProfileReverter
	alerts   AlertRaiser
	interval time.Duration
	log      *slog.Logger
	// maxPerSweep bounds one sweep so a backlog cannot starve shutdown.
	maxPerSweep int
}

// NewWorker returns the restore worker. interval is
// config.OverridesConfig.SweepInterval; profiles is the access store (used to
// put back the access-profile version saved at suspension when it changed).
func NewWorker(store *PGStore, profiles ProfileReverter, raiser AlertRaiser, interval time.Duration, log *slog.Logger) (*Worker, error) {
	if store == nil || profiles == nil || raiser == nil {
		return nil, errors.New("overrides worker: store, profile reverter and alert raiser are required")
	}
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Worker{store: store, profiles: profiles, alerts: raiser, interval: interval, log: log, maxPerSweep: 500}, nil
}

// Run sweeps every interval until ctx ends.
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		if _, err := w.Sweep(ctx); err != nil && ctx.Err() == nil {
			w.log.Error("override restore sweep failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// SweepResult counts what one sweep settled.
type SweepResult struct {
	Restored   int
	Blocked    int
	Superseded int
}

// Sweep processes every due override once (each in its own transaction).
// A row that fails with an internal error stays active (still enforced) and
// is retried on the next sweep.
func (w *Worker) Sweep(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	var failed []string
	var errs []error
	for i := 0; i < w.maxPerSweep; i++ {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		id, status, err := w.processNext(ctx, failed)
		if err != nil {
			if id == "" {
				return res, errors.Join(append(errs, err)...)
			}
			failed = append(failed, id)
			errs = append(errs, fmt.Errorf("override %s: %w", id, err))
			continue
		}
		switch status {
		case "":
			return res, errors.Join(errs...)
		case StatusRestored:
			res.Restored++
		case StatusBlocked:
			res.Blocked++
		case StatusSuperseded:
			res.Superseded++
		}
	}
	return res, errors.Join(errs...)
}

// processNext claims one due override and settles it. It returns the
// override id ("" when nothing is due) and its new status.
func (w *Worker) processNext(ctx context.Context, skip []string) (string, string, error) {
	var id, status string
	if skip == nil {
		skip = []string{}
	}
	err := pgx.BeginFunc(ctx, w.store.pool, func(tx pgx.Tx) error {
		o, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM access_overrides
			WHERE status = 'active' AND expires_at IS NOT NULL AND expires_at <= now() AND NOT (override_id = ANY($1))
			ORDER BY expires_at, override_id LIMIT 1 FOR UPDATE SKIP LOCKED`, skip))
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		id = o.OverrideID
		status, err = w.settle(ctx, tx, o)
		return err
	})
	if err != nil {
		status = ""
	}
	return id, status, err
}

// settle runs the restore checks for one locked, due override and records
// the result in tx.
func (w *Worker) settle(ctx context.Context, tx pgx.Tx, o Override) (string, error) {
	// 1. The agent must not be frozen (agent scope; a team member's own level
	//    already refuses that member's actions through the control gate).
	if o.Scope == ScopeAgent {
		lvl, ok, err := agentLevel(ctx, tx, o.ScopeID, false)
		if err != nil {
			return "", err
		}
		if !ok {
			return w.block(ctx, tx, o, fmt.Sprintf("agent %s is no longer registered", o.ScopeID), nil)
		}
		if lvl >= control.Quarantined {
			return w.block(ctx, tx, o, fmt.Sprintf("agent %s is %s", o.ScopeID, lvl), map[string]any{"agent_level": lvl.String()})
		}
	}
	// 2. No red action by the agent (or a team member) on this system since
	//    the override started, refused or not.
	red, err := redSince(ctx, tx, o)
	if err != nil {
		return "", err
	}
	if red != nil {
		return w.block(ctx, tx, o, fmt.Sprintf("red action %s (%s) by %s on %s during the suspension", red.ActionID, red.RuleID, red.AgentID, o.System),
			map[string]any{"red_action_id": red.ActionID, "red_rule_id": red.RuleID, "red_agent_id": red.AgentID})
	}
	// 3. A newer override in force for the same scope and system takes over.
	var newer string
	err = tx.QueryRow(ctx, `SELECT override_id FROM access_overrides
		WHERE scope = $1 AND scope_id = $2 AND system = $3 AND status IN ('active', 'blocked') AND override_id <> $4
		  AND (starts_at > $5 OR (starts_at = $5 AND override_id > $4))
		ORDER BY starts_at DESC, override_id DESC LIMIT 1`, o.Scope, o.ScopeID, o.System, o.OverrideID, o.StartsAt).Scan(&newer)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
	case err != nil:
		return "", err
	default:
		next, err := scan(tx.QueryRow(ctx, `UPDATE access_overrides SET status = 'superseded' WHERE override_id = $1 RETURNING `+cols, o.OverrideID))
		if err != nil {
			return "", err
		}
		data := eventData(next)
		data["superseded_by"] = newer
		if _, err := w.store.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentOf(o), EventType: EventSuperseded, Actor: Actor, Data: data}); err != nil {
			return "", err
		}
		return StatusSuperseded, nil
	}
	// 4. Put back the access-profile version saved at suspension if it changed.
	//    Revert runs in its own transaction (it locks the agent row and the
	//    Diary head); this transaction holds neither yet, only the override row.
	profile, err := w.restoreProfile(ctx, tx, o)
	if err != nil {
		var permanent *profileError
		if errors.As(err, &permanent) {
			return w.block(ctx, tx, o, permanent.Error(), nil)
		}
		return "", err
	}
	// Re-check the level under a share lock (agents row -> diary head) so a
	// kill that landed during the revert is honoured.
	var sponsor string
	if o.Scope == ScopeAgent {
		lvl, ok, err := agentLevel(ctx, tx, o.ScopeID, true)
		if err != nil {
			return "", err
		}
		if !ok {
			return w.block(ctx, tx, o, fmt.Sprintf("agent %s is no longer registered", o.ScopeID), nil)
		}
		if lvl >= control.Quarantined {
			return w.block(ctx, tx, o, fmt.Sprintf("agent %s is %s", o.ScopeID, lvl), map[string]any{"agent_level": lvl.String()})
		}
		if err := tx.QueryRow(ctx, `SELECT sponsor FROM agents WHERE agent_id = $1`, o.ScopeID).Scan(&sponsor); err != nil {
			return "", err
		}
	}
	next, err := scan(tx.QueryRow(ctx, `UPDATE access_overrides SET status = 'restored', restored_at = now()
		WHERE override_id = $1 RETURNING `+cols, o.OverrideID))
	if err != nil {
		return "", err
	}
	data := eventData(next)
	data["checks"] = map[string]any{"agent_not_frozen": true, "no_red_action": true, "no_newer_override": true}
	if profile != nil {
		data["profile_restored"] = profile
	}
	if _, err := w.store.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentOf(o), EventType: EventRestored, Actor: Actor, Data: data}); err != nil {
		return "", err
	}
	details := map[string]any{"override_id": o.OverrideID, "scope": o.Scope, "scope_id": o.ScopeID, "system": o.System,
		"mode": o.Mode, "created_by": o.CreatedBy}
	if sponsor != "" {
		details["notify"] = sponsor
	}
	if _, err := w.alerts.RaiseTx(ctx, tx, alerts.Alert{
		Kind:     KindRestored,
		Severity: alerts.SevInfo,
		AgentID:  agentOf(o),
		Summary:  fmt.Sprintf("%s access restored for %s %s after the %s override ended", o.System, o.Scope, o.ScopeID, o.Mode),
		Details:  mustJSON(details),
		DedupKey: KindRestored + ":" + o.OverrideID,
	}); err != nil {
		return "", fmt.Errorf("raise restore alert: %w", err)
	}
	return StatusRestored, nil
}

// block marks the override blocked (it stays enforced until a human releases
// it), writes override.restore_blocked and raises override_restore_blocked.
func (w *Worker) block(ctx context.Context, tx pgx.Tx, o Override, why string, extra map[string]any) (string, error) {
	next, err := scan(tx.QueryRow(ctx, `UPDATE access_overrides SET status = 'blocked', blocked_reason = $2
		WHERE override_id = $1 RETURNING `+cols, o.OverrideID, why))
	if err != nil {
		return "", err
	}
	data := eventData(next)
	data["blocked_reason"] = why
	for k, v := range extra {
		data[k] = v
	}
	if _, err := w.store.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentOf(o), EventType: EventRestoreBlocked, Actor: Actor, Data: data}); err != nil {
		return "", err
	}
	details := map[string]any{"override_id": o.OverrideID, "scope": o.Scope, "scope_id": o.ScopeID, "system": o.System,
		"mode": o.Mode, "blocked_reason": why}
	for k, v := range extra {
		details[k] = v
	}
	if _, err := w.alerts.RaiseTx(ctx, tx, alerts.Alert{
		Kind:     alerts.KindRestoreBlocked,
		Severity: alerts.SevWarning,
		AgentID:  agentOf(o),
		Summary:  fmt.Sprintf("automatic restore of %s for %s %s blocked: %s (still %s until released)", o.System, o.Scope, o.ScopeID, why, o.Mode),
		Details:  mustJSON(details),
		DedupKey: alerts.KindRestoreBlocked + ":" + o.OverrideID,
	}); err != nil {
		return "", fmt.Errorf("raise restore-blocked alert: %w", err)
	}
	return StatusBlocked, nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}

func agentLevel(ctx context.Context, tx pgx.Tx, agentID string, lock bool) (control.Level, bool, error) {
	q := `SELECT level FROM agents WHERE agent_id = $1`
	if lock {
		q += ` FOR SHARE`
	}
	var lvl int16
	err := tx.QueryRow(ctx, q, agentID).Scan(&lvl)
	if errors.Is(err, pgx.ErrNoRows) {
		return control.Killed, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return control.Level(lvl), true, nil
}

type redAction struct {
	ActionID, RuleID, AgentID string
}

// redSince finds the first red action by the agent (or a team member) on the
// system since the override started, whatever its decision: a red attempt
// refused by the suspension still blocks the restore. The red rule reported
// is the red finding (e.g. POL-301), not the gate that refused it. Records
// synthesised because Fortik itself could not decide (FAIL-CLOSED) say
// nothing about the agent and are ignored.
func redSince(ctx context.Context, tx pgx.Tx, o Override) (*redAction, error) {
	who := `agent_id = $1`
	if o.Scope == ScopeTeam {
		who = `agent_id IN (SELECT agent_id FROM agents WHERE business_unit = $1)`
	}
	q := `SELECT action_id, agent_id,
			coalesce((SELECT m->>'rule_id' FROM jsonb_array_elements(
				CASE WHEN jsonb_typeof(decision_json->'matched') = 'array' THEN decision_json->'matched' ELSE '[]'::jsonb END) m
				WHERE m->>'class' = 'red' ORDER BY m->>'rule_id' LIMIT 1), rule_id)
		FROM actions
		WHERE ` + who + ` AND system = $2 AND class = 'red' AND ts >= $3 AND rule_id <> $4
		ORDER BY ts LIMIT 1`
	var r redAction
	err := tx.QueryRow(ctx, q, o.ScopeID, o.System, o.StartsAt, decide.RuleFailClosed).Scan(&r.ActionID, &r.AgentID, &r.RuleID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// profileError is a restore failure that retrying cannot fix (the saved
// version no longer validates, or is gone): the override is blocked.
type profileError struct{ msg string }

func (e *profileError) Error() string { return e.msg }

// restoreProfile reverts the agent's access profile for the system to the
// version saved at suspension when the current one differs in content. It
// returns a description for the Diary (nil when nothing was needed).
func (w *Worker) restoreProfile(ctx context.Context, tx pgx.Tx, o Override) (map[string]any, error) {
	if o.Scope != ScopeAgent || !access.KnownSystem(o.System) {
		return nil, nil
	}
	var curVersion int
	var cur []byte
	err := tx.QueryRow(ctx, `SELECT version, profile_json FROM access_profiles WHERE agent_id = $1 AND system = $2
		ORDER BY version DESC LIMIT 1`, o.ScopeID, o.System).Scan(&curVersion, &cur)
	if errors.Is(err, pgx.ErrNoRows) {
		curVersion = 0
	} else if err != nil {
		return nil, err
	}
	saved := o.RestoreProfileVersion
	if curVersion == saved {
		return nil, nil
	}
	if saved == 0 {
		// There was no profile at suspension and one was created during it
		// (by a person with access rights). There is no "no profile" version
		// to put back; the new profile is kept and the restore says so.
		return map[string]any{"from_version": curVersion, "to_version": curVersion,
			"note": "no profile existed at suspension; the profile created during it is kept"}, nil
	}
	var savedJSON []byte
	err = tx.QueryRow(ctx, `SELECT profile_json FROM access_profiles WHERE agent_id = $1 AND system = $2 AND version = $3`,
		o.ScopeID, o.System, saved).Scan(&savedJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, &profileError{fmt.Sprintf("saved access profile v%d for %s no longer exists", saved, o.System)}
	}
	if err != nil {
		return nil, err
	}
	if jsonEqual(cur, savedJSON) {
		return nil, nil
	}
	p, err := w.profiles.Revert(ctx, o.ScopeID, o.System, saved, Actor,
		fmt.Sprintf("automatic restore after override %s: access profile v%d put back", o.OverrideID, saved))
	if err != nil {
		if errors.Is(err, access.ErrInvalidProfile) || errors.Is(err, access.ErrNotFound) || errors.Is(err, access.ErrAgentNotFound) {
			return nil, &profileError{fmt.Sprintf("could not put back access profile v%d for %s: %s", saved, o.System, sanitize(err.Error()))}
		}
		return nil, fmt.Errorf("revert access profile: %w", err)
	}
	return map[string]any{"from_version": curVersion, "to_version": p.Version, "reverted_to": saved}, nil
}

func jsonEqual(a, b []byte) bool {
	ca, err1 := diary.Canonical(json.RawMessage(a))
	cb, err2 := diary.Canonical(json.RawMessage(b))
	if err1 != nil || err2 != nil {
		return bytes.Equal(a, b)
	}
	return ca == cb
}
