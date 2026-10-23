// Package decide is the Decide service: Action in, enforced decision out.
package decide

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/metrics"
	"fortik/internal/policy"
)

// Evaluator is the policy engine (an interface so tests can inject failures).
type Evaluator interface {
	Eval(ctx context.Context, in policy.Input) (policy.Result, error)
}

// Service implements Decider against Postgres + the embedded OPA bundle.
type Service struct {
	Pool    *pgxpool.Pool
	Policy  Evaluator
	Control *control.Store
	Diary   *diary.Diary
	Fail    config.FailConfig
	Log     *slog.Logger
	HeldTTL time.Duration // how long a held action waits for a human (default 24h)
	// Access supplies input.access (Phase 2 access profiles). Errors fail closed.
	Access AccessSource
	// LADDER-3Y: this many held yellow actions within YellowWindow step the
	// agent down to SUPERVISED (plan: 3 within 10 minutes). 0 disables.
	YellowHoldsThreshold int
	YellowWindow         time.Duration
	// Phase 3 extension points.
	Enrichers []Enricher
	Observers []Observer
	Actor     string // diary actor for decisions (default "system:decide")
	Now       func() time.Time
}

var _ Decider = (*Service)(nil)

// AccessSource returns input.access for an agent and system.
type AccessSource interface {
	PolicyInput(ctx context.Context, agentID, system string) (access.PolicyInput, error)
}

// Enricher adds one key under input.context before policy evaluation
// (delegation chain, population, overrides, grant...). An error fails the
// decision closed. Enrichers must be fast: they run on every decision.
type Enricher interface {
	Key() string
	Enrich(ctx context.Context, a action.Action, st control.State) (any, error)
}

// Observer runs inside the decision transaction after the action, hold,
// step-down and Diary events are written (e.g. record a delegation hop,
// consume an approval grant, step down a delegation's origin agent). An
// error rolls the whole decision back and fails it closed.
type Observer interface {
	AfterDecide(ctx context.Context, tx pgx.Tx, out *Outcome, in policy.Input) error
}

// PreLocker is optionally implemented by an Observer that will lock other
// agents' rows during AfterDecide (e.g. stepping down a delegation's origin).
// PreLock runs right after the acting agent's row lock and before anything
// else in the transaction, preserving the lock order agents rows -> diary_head.
type PreLocker interface {
	PreLock(ctx context.Context, tx pgx.Tx, res policy.Result, in policy.Input) error
}

// RuleLadder3Y names the automatic yellow-holds step-down in the Diary.
const RuleLadder3Y = "LADDER-3Y"

var errLevelChanged = errors.New("control level changed during decision")

const (
	RuleFailClosed = "FAIL-CLOSED"
	RuleFailOpen   = "FAIL-OPEN-ALLOWLIST"
)

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

type actorKey struct{}

// WithActor attaches the authenticated caller (e.g. "token:pgproxy") so the
// Diary records who asked, not what the request body claims.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, actorKey{}, actor)
}

func (s *Service) actor(ctx context.Context, a action.Action) string {
	if v, ok := ctx.Value(actorKey{}).(string); ok && v != "" {
		return v
	}
	if s.Actor != "" {
		return s.Actor
	}
	if a.Source != "" {
		return "interceptor:" + a.Source
	}
	return "system:decide"
}

// Decide classifies, decides and records one action. See Decider for the
// fail-closed contract.
func (s *Service) Decide(ctx context.Context, a action.Action) (Outcome, error) {
	start := time.Now()
	if err := a.Validate(); err != nil {
		return Outcome{}, err
	}
	a.Normalize(s.now())

	// A reused action_id is a caller bug, reported before evaluation so it can
	// never mask a decision (the PK check in persist remains the backstop).
	var used bool
	if err := s.Pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM actions WHERE action_id = $1)`, a.ActionID).Scan(&used); err == nil && used {
		return Outcome{}, fmt.Errorf("%w: action_id %s was already used", action.ErrInvalid, a.ActionID)
	}
	st, err := s.Control.Get(ctx, a.AgentID)
	if err != nil {
		return s.failClosed(ctx, a, start, "control_state", err), nil
	}
	var acc *access.PolicyInput
	if s.Access != nil {
		pi, err := s.Access.PolicyInput(ctx, a.AgentID, a.System)
		if err != nil {
			return s.failClosed(ctx, a, start, "access_profile", err), nil
		}
		acc = &pi
	}
	var pctx map[string]any
	for _, e := range s.Enrichers {
		v, err := e.Enrich(ctx, a, st)
		if err != nil {
			return s.failClosed(ctx, a, start, "enrich:"+e.Key(), err), nil
		}
		if v != nil {
			if pctx == nil {
				pctx = map[string]any{}
			}
			pctx[e.Key()] = v
		}
	}
	for attempt := 0; attempt < 3; attempt++ {
		evalStart := time.Now()
		in := policy.Input{Action: a, Agent: st, Access: acc, Context: pctx}
		res, err := s.Policy.Eval(ctx, in)
		metrics.PolicyEval.Observe(time.Since(evalStart).Seconds())
		if err != nil {
			return s.failClosed(ctx, a, start, "policy", err), nil
		}
		out, fresh, err := s.persist(ctx, a, st, res, start, in)
		if errors.Is(err, errLevelChanged) {
			st = fresh
			continue
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "actions_pkey" {
			return Outcome{}, fmt.Errorf("%w: action_id %s was already used", action.ErrInvalid, a.ActionID)
		}
		if err != nil {
			return s.failAfterEval(ctx, a, st, res, start, err), nil
		}
		s.observe(out)
		return out, nil
	}
	return s.failClosed(ctx, a, start, "control_state", errors.New("agent level kept changing during decision")), nil
}

// persist records the decision atomically: action row, held action, step-down
// and Diary events commit together or not at all. The agent's level is
// re-read inside the transaction; if it moved since evaluation the caller
// re-evaluates against the fresh state.
func (s *Service) persist(ctx context.Context, a action.Action, st control.State, res policy.Result, start time.Time, in policy.Input) (Outcome, control.State, error) {
	out := Outcome{Action: a, Result: res, LevelBefore: st.Level, LevelAfter: st.Level}
	var fresh control.State
	err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
		// Lock order is always agents row -> diary_head (same as SetLevel and
		// StepDownTx). A decision that may step the agent down takes the agent
		// row lock up front so it can never deadlock with a concurrent level change.
		// Otherwise a share lock: a concurrent level change (e.g. a kill) waits
		// for this decision to commit instead of landing between the re-check
		// below and the commit, so decisions and level changes linearise.
		lock := `SELECT 1 FROM agents WHERE agent_id = $1 FOR SHARE`
		if res.LadderChange != nil {
			lock = `SELECT 1 FROM agents WHERE agent_id = $1 FOR UPDATE`
		}
		if _, err := tx.Exec(ctx, lock, a.AgentID); err != nil {
			return err
		}
		for _, o := range s.Observers {
			if pl, ok := o.(PreLocker); ok {
				if err := pl.PreLock(ctx, tx, res, in); err != nil {
					return fmt.Errorf("observer prelock: %w", err)
				}
			}
		}
		cur, err := control.Get(ctx, tx, a.AgentID)
		if err != nil {
			return err
		}
		if cur.Level != st.Level || cur.Registered != st.Registered {
			fresh = cur
			return errLevelChanged
		}

		out.Held = res.Decision == policy.Hold
		out.LatencyUS = time.Since(start).Microseconds()
		decisionJSON := map[string]any{
			"matched":          res.Matched,
			"reduced_form":     res.ReducedForm,
			"ladder_change":    res.LadderChange,
			"policy_version":   res.PolicyVersion,
			"grant_id":         res.GrantID,
			"context":          in.Context,
			"level_before":     st.Level.String(),
			"agent_registered": st.Registered,
		}
		ts, err := s.insertAction(ctx, tx, a, res, decisionJSON, false, out.LatencyUS)
		if err != nil {
			return err
		}
		a.TS, out.Action.TS = ts, ts
		events := []diary.Event{{AgentID: a.AgentID, EventType: diary.EventActionDecided, Actor: s.actor(ctx, a), Data: decidedEvent(a, res, st.Level)}}
		if out.Held {
			if err := s.insertHeld(ctx, tx, a, res); err != nil {
				return err
			}
			events = append(events, diary.Event{AgentID: a.AgentID, EventType: diary.EventActionHeld, Actor: s.actor(ctx, a), Data: map[string]any{
				"action_id": a.ActionID, "rule_id": res.RuleID, "class": string(res.Class), "reason": res.Reason,
				"approver_role": "security", "safe_form": a.Target["safe_form"],
				// Recorded in the hash chain, not only in the mutable
				// held_actions row: how many distinct approvers this hold needs.
				"approvals_required": max(1, res.ApprovalsRequired),
			}})
		}
		if _, err := s.Diary.AppendTx(ctx, tx, events...); err != nil {
			return err
		}
		if out.Held && res.Class == policy.Yellow && st.Registered && s.YellowHoldsThreshold > 0 && st.Level < control.Supervised {
			window := s.YellowWindow
			if window <= 0 {
				window = 10 * time.Minute
			}
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM held_actions h JOIN actions a USING (action_id)
				WHERE h.agent_id = $1 AND a.class = 'yellow' AND h.created_at > now() - make_interval(secs => $2)`,
				a.AgentID, window.Seconds()).Scan(&n); err != nil {
				return err
			}
			if n >= s.YellowHoldsThreshold && (res.LadderChange == nil) {
				// Agent row: share-locked above; StepDownTx upgrades to FOR UPDATE.
				_, changed, err := s.Control.StepDownTx(ctx, tx, a.AgentID, control.Supervised,
					fmt.Sprintf("%d yellow actions held within %s", n, window), s.actor(ctx, a),
					map[string]any{"action_id": a.ActionID, "rule_id": RuleLadder3Y})
				if err != nil {
					return err
				}
				if changed {
					out.LevelAfter = control.Supervised
					metrics.StepDowns.WithLabelValues(control.Supervised.String(), RuleLadder3Y).Inc()
				}
			}
		}
		if res.LadderChange != nil && st.Registered {
			to, err := control.ParseLevel(res.LadderChange.To)
			if err != nil {
				return fmt.Errorf("policy named unknown ladder level: %w", err)
			}
			_, changed, err := s.Control.StepDownTx(ctx, tx, a.AgentID, to, res.LadderChange.Reason, s.actor(ctx, a),
				map[string]any{"action_id": a.ActionID, "rule_id": res.RuleID})
			if err != nil {
				return err
			}
			if changed {
				out.LevelAfter = to
				metrics.StepDowns.WithLabelValues(to.String(), res.RuleID).Inc()
				if _, err := tx.Exec(ctx, `UPDATE actions SET decision_json = decision_json || jsonb_build_object('level_after', $2::text, 'ladder_applied', true) WHERE action_id = $1`,
					a.ActionID, to.String()); err != nil {
					return err
				}
			}
		}
		for _, o := range s.Observers {
			if err := o.AfterDecide(ctx, tx, &out, in); err != nil {
				return fmt.Errorf("observer: %w", err)
			}
		}
		return nil
	})
	return out, fresh, err
}

func decidedEvent(a action.Action, res policy.Result, lvl control.Level) map[string]any {
	ev := map[string]any{
		"action_id":       a.ActionID,
		"instance_id":     a.InstanceID,
		"system":          a.System,
		"verb":            string(a.Verb),
		"source":          a.Source,
		"class":           string(res.Class),
		"decision":        string(res.Decision),
		"rule_id":         res.RuleID,
		"reason":          res.Reason,
		"matched":         res.Matched,
		"level":           lvl.String(),
		"target":          a.Target,
		"payload_summary": a.PayloadSummary,
		"action_hash":     a.Hash(),
		"policy_version":  res.PolicyVersion,
	}
	if len(res.ReducedForm) > 0 {
		ev["reduced_form"] = res.ReducedForm
	}
	if res.LadderChange != nil {
		ev["ladder_change"] = res.LadderChange
	}
	if res.Decision == policy.Hold {
		ev["approvals_required"] = max(1, res.ApprovalsRequired)
	}
	if res.GrantID != "" {
		ev["grant_id"] = res.GrantID
	}
	return ev
}

// insertAction writes the action row and returns its recorded ts. The ts is
// never earlier than the start of the writing transaction (GREATEST with the
// database's now()): the map rollup folds actions by ts behind a horizon of
// the oldest open writing transaction, and a ts taken when Decide began
// (before enrichers, policy, retries and the wait for a connection) could
// otherwise fall behind the horizon before the row commits and never be
// folded.
func (s *Service) insertAction(ctx context.Context, tx pgx.Tx, a action.Action, res policy.Result, decisionJSON map[string]any, failClosed bool, latencyUS int64) (time.Time, error) {
	target, err := json.Marshal(a.Target)
	if err != nil {
		return time.Time{}, err
	}
	summary, err := json.Marshal(a.PayloadSummary)
	if err != nil {
		return time.Time{}, err
	}
	dj, err := json.Marshal(decisionJSON)
	if err != nil {
		return time.Time{}, err
	}
	var ts time.Time
	err = tx.QueryRow(ctx, `
		INSERT INTO actions (action_id, agent_id, instance_id, system, verb, action_hash, class, decision, rule_id, reason,
			reversible, source, target, payload_summary, decision_json, fail_closed, latency_us, ts)
		VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,
			CASE WHEN $19 THEN GREATEST($18::timestamptz, now()) ELSE $18::timestamptz END)
		RETURNING ts`,
		a.ActionID, a.AgentID, a.InstanceID, a.System, string(a.Verb), a.Hash(), string(res.Class), string(res.Decision),
		res.RuleID, res.Reason, a.Reversible, a.Source, target, summary, dj, failClosed, latencyUS, a.TS,
		s.Now == nil).Scan(&ts) // an injected clock (tests) is authoritative
	if err != nil {
		return time.Time{}, fmt.Errorf("insert action: %w", err)
	}
	return ts.UTC(), nil
}

func (s *Service) insertHeld(ctx context.Context, tx pgx.Tx, a action.Action, res policy.Result) error {
	ttl := s.HeldTTL
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	var safeForm []byte
	if sf, ok := a.Target["safe_form"]; ok && sf != nil {
		b, err := json.Marshal(sf)
		if err != nil {
			return err
		}
		safeForm = b
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO held_actions (action_id, agent_id, rule_id, reason, approvals_required, approver_role, safe_form, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'security', $6, $7)`,
		a.ActionID, a.AgentID, res.RuleID, res.Reason, max(1, res.ApprovalsRequired), safeForm, s.now().Add(ttl))
	if err != nil {
		return fmt.Errorf("insert held action: %w", err)
	}
	return nil
}

// failAfterEval handles a persistence failure AFTER policy produced a result.
// A decision that already refuses the action (deny/hold) is kept: an outage
// can never loosen it, and a red step-down is still attempted on its own.
// Only an executing decision falls back to the generic fail-closed path.
func (s *Service) failAfterEval(ctx context.Context, a action.Action, st control.State, res policy.Result, start time.Time, cause error) Outcome {
	if res.Decision.Executes() {
		return s.failClosed(ctx, a, start, "persist", cause)
	}
	out := Outcome{Action: a, Result: res, LevelBefore: st.Level, LevelAfter: st.Level, FailClosed: true,
		LatencyUS: time.Since(start).Microseconds()}
	out.Result.Reason = res.Reason + " (decision could not be recorded; refused)"
	if s.Log != nil {
		s.Log.Error("decision could not be recorded; keeping the refusal", "err", cause, "agent_id", a.AgentID,
			"action_id", a.ActionID, "decision", res.Decision, "rule_id", res.RuleID)
	}
	metrics.FailClosed.WithLabelValues("persist", string(res.Decision)).Inc()
	s.recordBestEffort(ctx, a, out.Result, map[string]any{"fail_stage": "persist", "error": cause.Error(),
		"matched": res.Matched, "level_before": st.Level.String()}, out.LatencyUS)
	if res.LadderChange != nil && st.Registered {
		if to, err := control.ParseLevel(res.LadderChange.To); err == nil {
			rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			defer cancel()
			err := pgx.BeginFunc(rctx, s.Pool, func(tx pgx.Tx) error {
				_, changed, err := s.Control.StepDownTx(rctx, tx, a.AgentID, to, res.LadderChange.Reason+" (decision record failed)",
					s.actor(ctx, a), map[string]any{"action_id": a.ActionID, "rule_id": res.RuleID})
				if changed {
					out.LevelAfter = to
				}
				return err
			})
			if err != nil {
				out.LevelAfter = st.Level
				if s.Log != nil {
					s.Log.Error("step-down after failed record also failed", "err", err, "agent_id", a.AgentID)
				}
			}
		}
	}
	s.observe(out)
	return out
}

// failClosed builds the decision used when Fortik cannot decide normally:
// READs on the configured allowlist may proceed; everything else is refused.
// The attempt is recorded best-effort (the store may be what failed).
func (s *Service) failClosed(ctx context.Context, a action.Action, start time.Time, stage string, cause error) Outcome {
	res := policy.Result{
		Class:    policy.Red,
		Decision: policy.Deny,
		RuleID:   RuleFailClosed,
		Reason:   fmt.Sprintf("Fortik could not decide (%s unavailable): fail closed", stage),
	}
	if a.Verb == action.VerbRead && s.failOpenAllowed(a) {
		res = policy.Result{Class: policy.Green, Decision: policy.Allow, RuleID: RuleFailOpen,
			Reason: fmt.Sprintf("Fortik could not decide (%s unavailable): READ allowed by fail-open allowlist", stage)}
	}
	if s.Log != nil {
		s.Log.Error("decide failed; applying fail behaviour", "stage", stage, "err", cause,
			"agent_id", a.AgentID, "system", a.System, "verb", a.Verb, "decision", res.Decision)
	}
	metrics.FailClosed.WithLabelValues(stage, string(res.Decision)).Inc()
	out := Outcome{Action: a, Result: res, FailClosed: true, LatencyUS: time.Since(start).Microseconds()}

	s.recordBestEffort(ctx, a, res, map[string]any{"fail_stage": stage, "error": cause.Error()}, out.LatencyUS)
	s.observe(out)
	return out
}

// recordBestEffort records a fail-path decision in its own short transaction
// (the action row + an action.decided event). If the full row cannot be
// stored (e.g. the target is what broke the insert), it retries without the
// target and payload so the refusal is still in the Diary.
func (s *Service) recordBestEffort(ctx context.Context, a action.Action, res policy.Result, extra map[string]any, latencyUS int64) {
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
	defer cancel()
	try := func(a action.Action, note string) error {
		return pgx.BeginFunc(rctx, s.Pool, func(tx pgx.Tx) error {
			if _, err := s.insertAction(rctx, tx, a, res, extra, true, latencyUS); err != nil {
				return err
			}
			data := map[string]any{"action_id": a.ActionID, "system": a.System, "verb": string(a.Verb), "class": string(res.Class),
				"decision": string(res.Decision), "rule_id": res.RuleID, "reason": res.Reason, "fail_closed": true}
			for k, v := range extra {
				data[k] = v
			}
			if note != "" {
				data["note"] = note
			}
			_, err := s.Diary.AppendTx(rctx, tx, diary.Event{AgentID: a.AgentID, EventType: diary.EventActionDecided, Actor: s.actor(ctx, a), Data: data})
			return err
		})
	}
	err := try(a, "")
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return // the action row already exists (recorded earlier)
		}
		min := a
		min.Target, min.PayloadSummary, min.Chain = map[string]any{}, action.PayloadSummary{}, nil
		err = try(min, "target and payload omitted: the full record could not be stored")
	}
	if err != nil && s.Log != nil {
		s.Log.Error("could not record fail-path decision", "err", err, "action_id", a.ActionID)
	}
}

func (s *Service) failOpenAllowed(a action.Action) bool {
	for _, e := range s.Fail.GreenReadAllowlist {
		if e.System == a.System && (e.Agent == "*" || e.Agent == a.AgentID) {
			return true
		}
	}
	return false
}

func (s *Service) observe(out Outcome) {
	r := out.Result
	metrics.Decisions.WithLabelValues(string(r.Class), string(r.Decision), out.Action.System, out.Action.Source).Inc()
	metrics.DecideLatency.WithLabelValues(string(r.Class)).Observe(float64(out.LatencyUS) / 1e6)
	if out.Held {
		metrics.Held.WithLabelValues(string(r.Class), r.RuleID).Inc()
	}
}
