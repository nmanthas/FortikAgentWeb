package swarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
)

const systemActor = "system:swarm"

// Key implements decide.Enricher.
func (s *Service) Key() string { return ContextKey }

// counted reports whether an action counts toward the Max-5 breaker: any
// verb except READ (identical reads by many agents are normal), while the
// breaker is enabled. Postgres row writes (INSERT, UPDATE, DELETE, MERGE,
// COPY FROM) are not counted: their identity is the statement shape without
// its values, so six agents running the same routine parameterised write
// would look "identical"; destructive and schema statements still count, and
// many agents converging on one table is the converging-targets signal.
func (s *Service) counted(a action.Action) bool {
	if s.cfg.BreakerN <= 0 || a.Verb == action.VerbRead {
		return false
	}
	if a.System == action.SystemPostgres {
		st, _ := a.Target["statement_type"].(string)
		switch st {
		case "INSERT", "UPDATE", "DELETE", "MERGE", "COPY_FROM_STDIN", "SELECT":
			return false
		}
	}
	return true
}

// actorsSQL selects the distinct agents/copies of counted calls with one hash
// in the window. An instance id counts as a separate copy only when it is a
// copy registered for that agent: the X-Fortik-Instance-Id header is the
// caller's own claim, and made-up labels must not let one agent look like
// several (or trip the breaker on others' identical calls).
const actorsSQL = `SELECT a.agent_id, CASE WHEN i.instance_id IS NULL THEN '' ELSE a.instance_id END AS inst, min(a.ts) AS first
	FROM actions a
	LEFT JOIN instances i ON i.instance_id = a.instance_id AND i.agent_id = a.agent_id
	WHERE a.action_hash = $1 AND a.ts > $2 AND a.verb <> 'READ' AND a.decision <> 'deny' AND NOT a.fail_closed
	GROUP BY 1, 2`

// Enrich implements decide.Enricher: input.context.swarm for the action
// (see PolicyContext). While no breaker is tripped for the action's hash it
// counts the distinct OTHER agents/copies that made the same call in the
// breaker window; when they are already breaker_n, this call is the one that
// trips it (breaker.pending) and POL-651 holds it. The observer re-counts
// inside the decision transaction (decisions are serialised by the Diary
// head lock) and trips the breaker. Errors fail the decision closed.
func (s *Service) Enrich(ctx context.Context, a action.Action, _ control.State) (any, error) {
	pc := &PolicyContext{MemberOf: []string{}}
	ids, frozen, err := activeOf(ctx, s.pool, a.AgentID)
	if err != nil {
		return nil, fmt.Errorf("swarm: membership: %w", err)
	}
	pc.MemberOf, pc.Frozen, pc.FrozenSwarmID = ids, frozen != "", frozen
	if a.Verb == action.VerbDelegate {
		if to, _ := a.Target["to_agent"].(string); to != "" && to != a.AgentID {
			_, f, err := activeOf(ctx, s.pool, to)
			if err != nil {
				return nil, fmt.Errorf("swarm: delegatee membership: %w", err)
			}
			pc.DelegateeFrozen = f != ""
		}
	}
	hash := a.Hash()
	state, swarmID, releasedAt, err := breakerRow(ctx, s.pool, hash)
	if err != nil {
		return nil, fmt.Errorf("swarm: breaker: %w", err)
	}
	if state == "tripped" {
		pc.Breaker = BreakerContext{Tripped: true, SwarmID: swarmID}
		return pc, nil
	}
	if !s.counted(a) {
		return pc, nil
	}
	since := s.windowStart(a.TS, releasedAt)
	var n int
	self, err := s.registeredInstance(ctx, s.pool, a)
	if err != nil {
		return nil, fmt.Errorf("swarm: instance: %w", err)
	}
	err = s.pool.QueryRow(ctx, `SELECT count(*) FROM (SELECT agent_id, inst FROM (`+actorsSQL+`) x
			WHERE NOT (agent_id = $3 AND inst = $4) LIMIT $5) y`, hash, since, a.AgentID, self, s.cfg.BreakerN).Scan(&n)
	if err != nil {
		return nil, fmt.Errorf("swarm: breaker count: %w", err)
	}
	pc.Breaker = BreakerContext{DistinctOthers: n, Threshold: s.cfg.BreakerN}
	if n >= s.cfg.BreakerN {
		pc.Breaker.Tripped, pc.Breaker.Pending = true, true
	}
	return pc, nil
}

// registeredInstance is the action's instance id when it is a copy
// registered for the agent, else "" (the agent itself).
func (s *Service) registeredInstance(ctx context.Context, q querier, a action.Action) (string, error) {
	if a.InstanceID == "" {
		return "", nil
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM instances WHERE instance_id = $1 AND agent_id = $2)`, a.InstanceID, a.AgentID).Scan(&ok)
	if err != nil || !ok {
		return "", err
	}
	return a.InstanceID, nil
}

// windowStart: the breaker window before ts, but never before the hash's
// breaker was last released (a released breaker starts counting afresh).
func (s *Service) windowStart(ts time.Time, releasedAt *time.Time) time.Time {
	since := ts.Add(-s.cfg.BreakerWindow)
	if releasedAt != nil && releasedAt.After(since) {
		since = *releasedAt
	}
	return since
}

func breakerRow(ctx context.Context, q querier, hash string) (state, swarmID string, releasedAt *time.Time, err error) {
	err = q.QueryRow(ctx, `SELECT state, swarm_id, released_at FROM swarm_breakers WHERE action_hash = $1`, hash).
		Scan(&state, &swarmID, &releasedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil, nil
	}
	return state, swarmID, releasedAt, err
}

// contextOf extracts the enricher's context from a policy input.
func contextOf(in policy.Input) *PolicyContext {
	switch v := in.Context[ContextKey].(type) {
	case *PolicyContext:
		return v
	case PolicyContext:
		return &v
	}
	return nil
}

// AfterDecide implements decide.Observer. Inside the decision transaction
// (after the action row and the Diary events are written, holding the Diary
// head lock, so decisions are serialised here) it:
//
//   - counts the distinct agents/copies that made this call (action hash) in
//     the breaker window, this one included; when they exceed breaker_n and
//     no breaker is tripped for the hash, it trips one: the swarm is created
//     (or the agents' existing swarm is used) with the actors (and, when they
//     share a delegation root, the root and its delegation tree) as members,
//     swarm_breakers is written and swarm.breaker_tripped recorded;
//   - for a call matching a tripped breaker: adds the actor to the swarm and,
//     if the decision would run the call (no approval grant), turns it into
//     the POL-651 hold for two approvers (the enricher normally made policy
//     hold it already; this covers a breaker tripped by a concurrent decision
//     after this one was enriched);
//   - tags the action (and its hold) with the actor's swarm.
//
// It must run FIRST among the observers, so the others see the final
// decision. Any error rolls the decision back and fails it closed.
func (s *Service) AfterDecide(ctx context.Context, tx pgx.Tx, out *decide.Outcome, in policy.Input) error {
	a := out.Action
	hash := a.Hash()
	state, breakerSwarm, releasedAt, err := breakerRow(ctx, tx, hash)
	if err != nil {
		return fmt.Errorf("swarm: breaker: %w", err)
	}
	if state != "tripped" {
		breakerSwarm = ""
	}
	if breakerSwarm == "" && s.counted(a) && !out.FailClosed && out.Result.Decision != policy.Deny {
		since := s.windowStart(a.TS, releasedAt)
		actors, err := s.actors(ctx, tx, hash, since)
		if err != nil {
			return err
		}
		pc := contextOf(in)
		heldForPending := pc != nil && pc.Breaker.Pending && out.Held && out.Result.RuleID == RuleBreaker
		if len(actors) > s.cfg.BreakerN || heldForPending {
			if breakerSwarm, err = s.trip(ctx, tx, out, hash, actors, since); err != nil {
				return fmt.Errorf("swarm: trip breaker: %w", err)
			}
		}
	}
	if breakerSwarm != "" {
		// A call matching a tripped breaker is held, but making it does not
		// make the caller a swarm member (membership freezes an agent, and
		// the breaker may have been tripped by others): its hold is tagged
		// with the swarm so the queue groups it.
		// A grant releases a breaker-matching call only when it carries the
		// breaker's two approvals (policy checks the same on the normal path;
		// this covers a breaker tripped after this call was enriched).
		if out.Result.Decision.Executes() && (out.Result.GrantID == "" || grantApprovals(in) < BreakerApprovals) {
			if err := s.convert(ctx, tx, out, breakerSwarm); err != nil {
				return fmt.Errorf("swarm: hold for breaker: %w", err)
			}
		}
	}
	ids, _, err := activeOf(ctx, tx, a.AgentID)
	if err != nil {
		return fmt.Errorf("swarm: membership: %w", err)
	}
	if len(ids) == 0 {
		if breakerSwarm != "" {
			if _, err := tx.Exec(ctx, `UPDATE actions SET swarm_id = COALESCE(swarm_id, $2) WHERE action_id = $1`, a.ActionID, breakerSwarm); err != nil {
				return fmt.Errorf("swarm: tag action: %w", err)
			}
			if out.Held {
				if _, err := tx.Exec(ctx, `UPDATE held_actions SET swarm_id = COALESCE(swarm_id, $2) WHERE action_id = $1`, a.ActionID, breakerSwarm); err != nil {
					return fmt.Errorf("swarm: tag hold: %w", err)
				}
			}
		}
		return nil
	}
	sid := ids[0]
	if breakerSwarm != "" && slices.Contains(ids, breakerSwarm) {
		sid = breakerSwarm
	}
	if _, err := tx.Exec(ctx, `UPDATE actions SET swarm_id = $2 WHERE action_id = $1`, a.ActionID, sid); err != nil {
		return fmt.Errorf("swarm: tag action: %w", err)
	}
	if out.Held {
		if _, err := tx.Exec(ctx, `UPDATE held_actions SET swarm_id = $2 WHERE action_id = $1`, a.ActionID, sid); err != nil {
			return fmt.Errorf("swarm: tag hold: %w", err)
		}
	}
	return nil
}

// actors lists the distinct agents/copies that made a counted call with
// this hash since `since` (the current decision included), first seen first.
func (s *Service) actors(ctx context.Context, tx pgx.Tx, hash string, since time.Time) ([]actor, error) {
	rows, err := tx.Query(ctx, `SELECT agent_id, inst FROM (`+actorsSQL+`) x ORDER BY first, 1, 2 LIMIT 10000`, hash, since)
	if err != nil {
		return nil, fmt.Errorf("swarm: breaker actors: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (actor, error) {
		var x actor
		err := r.Scan(&x.AgentID, &x.InstanceID)
		return x, err
	})
}

// trip creates (or reuses) the swarm and writes the breaker.
func (s *Service) trip(ctx context.Context, tx pgx.Tx, out *decide.Outcome, hash string, actors []actor, since time.Time) (string, error) {
	a := out.Action
	agents := slices.Compact(slices.Sorted(func(yield func(string) bool) {
		for _, x := range actors {
			if !yield(x.AgentID) {
				return
			}
		}
	}))
	var existing string
	err := tx.QueryRow(ctx, `SELECT s.swarm_id FROM swarms s
		WHERE s.state <> 'released'
		  AND NOT EXISTS (SELECT 1 FROM unnest($1::text[]) x(agent)
		                  WHERE NOT EXISTS (SELECT 1 FROM swarm_members m WHERE m.swarm_id = s.swarm_id AND m.agent_id = x.agent))
		ORDER BY s.created_at DESC, s.swarm_id LIMIT 1`, agents).Scan(&existing)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	root, err := s.rootOf(ctx, tx, agents)
	if err != nil {
		return "", err
	}
	ms := membersOf(actors, func(agent string) string {
		if agent == root {
			return RoleRoot
		}
		return RoleMember
	})
	if root != "" {
		ms = append(ms, Member{AgentID: root, Role: RoleRoot})
		tree, err := s.treeOf(ctx, tx, root)
		if err != nil {
			return "", err
		}
		for _, t := range tree {
			ms = append(ms, Member{AgentID: t, Role: RoleMember})
		}
	}
	shown := actors
	if len(shown) > 50 {
		shown = shown[:50]
	}
	signal := map[string]any{
		"action_hash": hash, "system": a.System, "verb": string(a.Verb), "distinct_actors": len(actors),
		"breaker_n": s.cfg.BreakerN, "window_seconds": int(s.cfg.BreakerWindow / time.Second),
		"tripping_action_id": a.ActionID, "actors": shown, "delegation_root": root,
	}
	swarmID := existing
	if existing != "" {
		if _, err := s.grow(ctx, tx, existing, ms, since, "Max-5 breaker tripped on this swarm's members", systemActor, a.AgentID); err != nil {
			return "", err
		}
		if _, err := tx.Exec(ctx, `UPDATE swarms SET action_hash = COALESCE(action_hash, $2), updated_at = $3 WHERE swarm_id = $1`,
			existing, hash, s.now()); err != nil {
			return "", err
		}
		if _, err := raise(ctx, tx, existing, StateBreakerTripped, s.now()); err != nil {
			return "", err
		}
		// Votes to release the swarm as it was do not cover a breaker that
		// tripped after them.
		if err := s.clearVotes(ctx, tx, existing, systemActor, "breaker tripped"); err != nil {
			return "", err
		}
	} else {
		id, err := s.pickID(ctx, tx, agents, root)
		if err != nil {
			return "", err
		}
		sw, err := s.create(ctx, tx, newSwarm{ID: id, Root: root, DetectedBy: DetectedActionHash, Signal: signal, ActionHash: hash,
			State: StateBreakerTripped, Members: ms, Since: since, EventAgent: a.AgentID}, systemActor)
		if err != nil {
			return "", err
		}
		swarmID = sw.SwarmID
	}
	if err := s.writeBreaker(ctx, tx, hash, swarmID); err != nil {
		return "", err
	}
	// Identical calls already waiting for approval (held by another rule
	// before the trip) now need the breaker's two approvers too.
	// Rows locked by an approval in progress are skipped (this transaction
	// holds the Diary head; waiting could deadlock): a grant from such an
	// approval carries one approval and policy still requires two.
	tag, err := tx.Exec(ctx, `UPDATE held_actions SET approvals_required = GREATEST(approvals_required, $3), swarm_id = COALESCE(swarm_id, $1)
		WHERE action_id IN (SELECT h.action_id FROM held_actions h JOIN actions a ON a.action_id = h.action_id
			WHERE a.action_hash = $2 AND a.ts > $4 AND h.outcome = 'pending' FOR UPDATE OF h SKIP LOCKED)`,
		swarmID, hash, BreakerApprovals, since.Add(-s.opt.HeldTTL))
	if err != nil {
		return "", err
	}
	raised := tag.RowsAffected()
	if _, err := tx.Exec(ctx, `UPDATE actions SET swarm_id = $1 WHERE action_id IN (
			SELECT action_id FROM actions WHERE action_hash = $2 AND ts > $3 AND swarm_id IS NULL FOR UPDATE SKIP LOCKED)`,
		swarmID, hash, since); err != nil {
		return "", err
	}
	_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: EventBreakerTripped, Actor: systemActor, Data: map[string]any{
		"swarm_id": swarmID, "action_hash": hash, "by": "max_n", "distinct_actors": len(actors), "breaker_n": s.cfg.BreakerN,
		"window_seconds": int(s.cfg.BreakerWindow / time.Second), "tripping_action_id": a.ActionID, "system": a.System,
		"verb": string(a.Verb), "existing_swarm": existing != "", "holds_raised_to_two_approvers": raised,
	}})
	return swarmID, err
}

// writeBreaker trips the hash's breaker for the swarm (re-using a released
// row). A breaker already tripped for another swarm is a conflict.
func (s *Service) writeBreaker(ctx context.Context, tx pgx.Tx, hash, swarmID string) error {
	var got string
	err := tx.QueryRow(ctx, `INSERT INTO swarm_breakers (action_hash, swarm_id, tripped_at, state) VALUES ($1, $2, $3, 'tripped')
		ON CONFLICT (action_hash) DO UPDATE SET swarm_id = EXCLUDED.swarm_id, tripped_at = EXCLUDED.tripped_at, state = 'tripped', released_at = NULL
		WHERE swarm_breakers.state = 'released'
		RETURNING swarm_id`, hash, swarmID, s.now()).Scan(&got)
	if errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: the breaker for this action hash is already tripped for another swarm", ErrConflict)
	}
	return err
}

// convert turns an executing decision into the POL-651 hold for two
// approvers, inside the decision transaction: the action row, the hold and
// an action.held Diary event (naming the decision it replaces).
func (s *Service) convert(ctx context.Context, tx pgx.Tx, out *decide.Outcome, swarmID string) error {
	a := out.Action
	res := &out.Result
	from, fromRule := res.Decision, res.RuleID
	class := res.Class
	if class == policy.Green {
		class = policy.Yellow
	}
	reason := fmt.Sprintf("swarm breaker tripped (swarm %s): this identical call was already made by more agents or copies than the breaker allows; held for %d distinct approvers",
		swarmID, BreakerApprovals)
	if _, err := tx.Exec(ctx, `UPDATE actions SET class = $2, decision = 'hold', rule_id = $3, reason = $4, swarm_id = $5,
			decision_json = decision_json || jsonb_build_object('swarm_breaker',
				jsonb_build_object('converted_from', decision, 'converted_rule_id', rule_id, 'swarm_id', $5::text, 'approvals_required', $6::int))
		WHERE action_id = $1`, a.ActionID, string(class), RuleBreaker, reason, swarmID, BreakerApprovals); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO held_actions (action_id, agent_id, rule_id, reason, approvals_required, approver_role, expires_at, swarm_id)
		VALUES ($1, $2, $3, $4, $5, 'security', $6, $7)`,
		a.ActionID, a.AgentID, RuleBreaker, reason, BreakerApprovals, s.now().Add(s.opt.HeldTTL), swarmID); err != nil {
		return fmt.Errorf("insert held action: %w", err)
	}
	if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: diary.EventActionHeld, Actor: systemActor, Data: map[string]any{
		"action_id": a.ActionID, "rule_id": RuleBreaker, "class": string(class), "reason": reason, "approver_role": "security",
		"approvals_required": BreakerApprovals, "swarm_id": swarmID, "converted_from": string(from), "converted_rule_id": fromRule,
	}}); err != nil {
		return err
	}
	res.Matched = append(res.Matched, policy.Match{RuleID: RuleBreaker, Class: policy.Yellow, Reason: reason})
	res.Class, res.Decision, res.RuleID, res.Reason = class, policy.Hold, RuleBreaker, reason
	res.ReducedForm, res.ApprovalsRequired = nil, BreakerApprovals
	res.GrantID = "" // the grant is not consumed: it stays usable only for a hold it satisfies
	out.Held = true
	return nil
}

// grantApprovals is the number of distinct approvers behind the approval
// grant in the policy input (input.context.grant.approvals; 0 without one).
func grantApprovals(in policy.Input) int {
	g, ok := in.Context["grant"]
	if !ok || g == nil {
		return 0
	}
	b, err := json.Marshal(g)
	if err != nil {
		return 0
	}
	var v struct {
		GrantID   string `json:"grant_id"`
		Approvals int    `json:"approvals"`
	}
	if json.Unmarshal(b, &v) != nil || v.GrantID == "" {
		return 0
	}
	return v.Approvals
}
