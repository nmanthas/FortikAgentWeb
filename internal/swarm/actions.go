package swarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/gateway/google"
)

// EventCallsHeld records, per member, the pending held calls a kill keeps
// held (tagged with the swarm, two approvers).
const EventCallsHeld = "swarm.calls_held"

// Kill-swarm step numbers (Step.Phase).
const (
	PhaseFreeze = iota + 1
	PhaseHold
	PhaseRevoke
	PhaseCancelQueue
	PhaseMemory
	PhaseStop
	PhaseSeal
)

const (
	swarmLockWait = 5 * time.Minute
	lockPollMin   = 10 * time.Millisecond
	lockPollMax   = 200 * time.Millisecond
)

// lockSwarm serialises operations on one swarm across processes (a session
// advisory lock on a dedicated connection, polled so it never blocks in a
// lock wait). The returned function releases it.
func (s *Service) lockSwarm(ctx context.Context, id string) (func(), error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	key := "fortik.swarm:" + id
	deadline := time.Now().Add(swarmLockWait)
	poll := lockPollMin
	for {
		var ok bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, key).Scan(&ok); err != nil {
			conn.Release()
			return nil, err
		}
		if ok {
			break
		}
		if time.Now().After(deadline) {
			conn.Release()
			return nil, fmt.Errorf("%w: another operation on swarm %s did not finish within %s", ErrBusy, id, swarmLockWait)
		}
		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			conn.Release()
			return nil, ctx.Err()
		case <-t.C:
		}
		poll = min(2*poll, lockPollMax)
	}
	return func() {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		var ok bool
		if err := conn.QueryRow(uctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, key).Scan(&ok); err != nil || !ok {
			// Closing the session releases its advisory locks.
			c := conn.Hijack()
			_ = c.Close(uctx)
			return
		}
		conn.Release()
	}, nil
}

// prepare validates an action request, takes the swarm's lock and reads it
// (refusing a released swarm).
func (s *Service) prepare(ctx context.Context, id, reason, actor string) (Swarm, func(), error) {
	if err := checkID(id); err != nil {
		return Swarm{}, nil, err
	}
	if _, err := checkReason(reason); err != nil {
		return Swarm{}, nil, err
	}
	if strings.TrimSpace(actor) == "" {
		return Swarm{}, nil, fmt.Errorf("%w: actor is required", ErrInvalid)
	}
	if _, err := getSwarm(ctx, s.pool, id, false); err != nil {
		return Swarm{}, nil, err
	}
	unlock, err := s.lockSwarm(ctx, id)
	if err != nil {
		return Swarm{}, nil, err
	}
	sw, err := getSwarm(ctx, s.pool, id, false)
	if err != nil {
		unlock()
		return Swarm{}, nil, err
	}
	if sw.State == StateReleased {
		unlock()
		return Swarm{}, nil, fmt.Errorf("%w: swarm %s was released", ErrConflict, id)
	}
	return sw, unlock, nil
}

// startOp records a running containment op with target swarm.
func (s *Service) startOp(ctx context.Context, op, id, actor, reason string) (Op, error) {
	o := Op{OpID: action.NewID("cop"), Op: op, TargetType: containment.TargetSwarm, TargetID: id, Actor: actor, Reason: reason,
		Status: containment.StatusRunning, Steps: []Step{}}
	err := s.pool.QueryRow(ctx, `INSERT INTO containment_ops (op_id, op, target_type, target_id, actor, reason, status)
		VALUES ($1, $2, 'swarm', $3, $4, $5, 'running') RETURNING created_at`, o.OpID, op, id, actor, reason).Scan(&o.CreatedAt)
	if err != nil {
		return Op{}, fmt.Errorf("swarm: record op: %w", err)
	}
	o.CreatedAt = o.CreatedAt.UTC()
	return o, nil
}

// finishOp stores the steps and status, runs extra (state changes) and
// writes the containment.<op> Diary event plus events, in one transaction.
func (s *Service) finishOp(ctx context.Context, op Op, steps []Step, agents []string, extra func(tx pgx.Tx) ([]diary.Event, error)) (Op, error) {
	op.Steps = steps
	op.Status = containment.StatusOf(steps)
	raw, err := json.Marshal(steps)
	if err != nil {
		return Op{}, err
	}
	fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	err = pgx.BeginFunc(fctx, s.pool, func(tx pgx.Tx) error {
		if err := lockDiaryHead(fctx, tx); err != nil {
			return err
		}
		var fin time.Time
		if err := tx.QueryRow(fctx, `UPDATE containment_ops SET status = $2, steps = $3::jsonb, finished_at = now()
			WHERE op_id = $1 RETURNING finished_at`, op.OpID, op.Status, string(raw)).Scan(&fin); err != nil {
			return err
		}
		fin = fin.UTC()
		op.FinishedAt = &fin
		events := []diary.Event{{EventType: containment.EventPrefix + op.Op, Actor: op.Actor, Data: map[string]any{
			"op_id": op.OpID, "op": op.Op, "target_type": op.TargetType, "target_id": op.TargetID, "swarm_id": op.TargetID,
			"reason": op.Reason, "status": op.Status, "agents": agents, "steps": steps,
		}}}
		if extra != nil {
			more, err := extra(tx)
			if err != nil {
				return err
			}
			events = append(events, more...)
		}
		_, err := s.diary.AppendTx(fctx, tx, events...)
		return err
	})
	if err != nil {
		s.log.Error("swarm op could not be recorded as finished", "op_id", op.OpID, "op", op.Op, "err", err)
		return Op{}, fmt.Errorf("swarm: record result of %s: %w", op.OpID, err)
	}
	return op, nil
}

// failedPhase records a phase that could not run at all.
func failedPhase(name string, phase int, err error) Step {
	return Step{Name: name, Status: containment.StepFailed, Phase: phase,
		Detail: "could not run for the members: " + oneLine(err.Error())}
}

func phased(steps []Step, phase int) []Step {
	for i := range steps {
		steps[i].Phase = phase
	}
	return steps
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

// --- trip_breaker -----------------------------------------------------------------

// TripRequest is POST /v1/swarms/{id}/trip.
type TripRequest struct {
	Reason string `json:"reason"`
	// ActionHash: the hash whose calls are held (default: the swarm's own
	// breaker hash, for swarms the breaker detected).
	ActionHash string `json:"action_hash,omitempty"`
}

// Trip trips a breaker by hand for the swarm's action hash: matching calls
// are held (POL-651, two approvers). Nothing else changes.
func (s *Service) Trip(ctx context.Context, id string, req TripRequest, actor string) (Op, error) {
	sw, unlock, err := s.prepare(ctx, id, req.Reason, actor)
	if err != nil {
		return Op{}, err
	}
	defer unlock()
	hash := strings.TrimSpace(req.ActionHash)
	if hash == "" {
		hash = sw.ActionHash
	}
	if hash == "" {
		return Op{}, fmt.Errorf("%w: swarm %s has no breaker hash (detected by %s): give action_hash", ErrInvalid, id, sw.DetectedBy)
	}
	if !hashPattern.MatchString(hash) {
		return Op{}, fmt.Errorf("%w: action_hash must be 64 lowercase hex characters", ErrInvalid)
	}
	op := Op{OpID: action.NewID("cop"), Op: containment.OpTripBreaker, TargetType: containment.TargetSwarm, TargetID: id,
		Actor: actor, Reason: req.Reason}
	ctx = context.WithoutCancel(ctx)
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockDiaryHead(ctx, tx); err != nil {
			return err
		}
		state, owner, _, err := breakerRow(ctx, tx, hash)
		if err != nil {
			return err
		}
		step := Step{Name: "trip_breaker", Status: containment.StepDone,
			Detail: fmt.Sprintf("breaker tripped for action hash %s: every matching call is held for %d approvers (POL-651)", hash, BreakerApprovals)}
		var events []diary.Event
		switch {
		case state == "tripped" && owner != id:
			return fmt.Errorf("%w: the breaker for this action hash is tripped for swarm %s", ErrConflict, owner)
		case state == "tripped":
			step.Status, step.Detail = containment.StepSkipped, "breaker already tripped for this swarm: matching calls are already held"
		default:
			if err := s.writeBreaker(ctx, tx, hash, id); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE swarms SET action_hash = COALESCE(action_hash, $2), updated_at = $3 WHERE swarm_id = $1`,
				id, hash, s.now()); err != nil {
				return err
			}
			if _, err := raise(ctx, tx, id, StateBreakerTripped, s.now()); err != nil {
				return err
			}
			if err := s.clearVotes(ctx, tx, id, actor, "breaker tripped by hand"); err != nil {
				return err
			}
			events = append(events, diary.Event{EventType: EventBreakerTripped, Actor: actor, Data: map[string]any{
				"swarm_id": id, "action_hash": hash, "by": "manual", "op_id": op.OpID, "reason": req.Reason}})
		}
		op.Steps = []Step{step}
		op.Status = containment.StatusOf(op.Steps)
		raw, err := json.Marshal(op.Steps)
		if err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `INSERT INTO containment_ops (op_id, op, target_type, target_id, actor, reason, status, steps, finished_at)
			VALUES ($1, $2, 'swarm', $3, $4, $5, $6, $7::jsonb, now()) RETURNING created_at, finished_at`,
			op.OpID, op.Op, id, actor, req.Reason, op.Status, string(raw)).Scan(&op.CreatedAt, &op.FinishedAt); err != nil {
			return err
		}
		events = append(events, diary.Event{EventType: containment.EventPrefix + op.Op, Actor: actor, Data: map[string]any{
			"op_id": op.OpID, "op": op.Op, "target_type": op.TargetType, "target_id": id, "swarm_id": id, "reason": req.Reason,
			"status": op.Status, "steps": op.Steps, "action_hash": hash}})
		_, err = s.diary.AppendTx(ctx, tx, events...)
		return err
	})
	if err != nil {
		return Op{}, err
	}
	op.CreatedAt = op.CreatedAt.UTC()
	if op.FinishedAt != nil {
		t := op.FinishedAt.UTC()
		op.FinishedAt = &t
	}
	return op, nil
}

// --- suspend / isolate --------------------------------------------------------------

// Suspend runs the Phase 4 suspend on every member (marked as suspended by
// the swarm, so its release resumes only those).
func (s *Service) Suspend(ctx context.Context, id, reason, actor string) (Op, error) {
	return s.containAll(ctx, id, reason, actor, containment.OpSuspend, containment.SwarmStepSuspend, StateSuspended, EventSuspended)
}

// Isolate runs the Phase 4 isolate on every member (level ISOLATED, never
// loosening; lifted per agent by step-up through the level API).
func (s *Service) Isolate(ctx context.Context, id, reason, actor string) (Op, error) {
	return s.containAll(ctx, id, reason, actor, containment.OpIsolate, containment.SwarmStepIsolate, StateIsolated, EventIsolated)
}

func (s *Service) containAll(ctx context.Context, id, reason, actor, opName, step, state, event string) (Op, error) {
	sw, unlock, err := s.prepare(ctx, id, reason, actor)
	if err != nil {
		return Op{}, err
	}
	defer unlock()
	ctx = context.WithoutCancel(ctx)
	agents, err := memberAgents(ctx, s.pool, id)
	if err != nil {
		return Op{}, err
	}
	op, err := s.startOp(ctx, opName, id, actor, reason)
	if err != nil {
		return Op{}, err
	}
	run := containment.SwarmRun{OpID: op.OpID, Op: opName, SwarmID: id, Actor: actor, Reason: reason, AgentIDs: agents}
	steps, err := s.contain.RunSwarmStep(ctx, run, step)
	if err != nil {
		steps = []Step{failedPhase(step, 0, err)}
	}
	return s.finishOp(ctx, op, steps, agents, func(tx pgx.Tx) ([]diary.Event, error) {
		changed, err := raise(ctx, tx, id, state, s.now())
		if err != nil {
			return nil, err
		}
		if err := s.clearVotes(ctx, tx, id, actor, opName+" of the swarm"); err != nil {
			return nil, err
		}
		return []diary.Event{{EventType: event, Actor: actor, Data: map[string]any{
			"swarm_id": id, "op_id": op.OpID, "reason": reason, "previous_state": sw.State, "state_changed": changed,
			"members": len(agents)}}}, nil
	})
}

// --- kill -------------------------------------------------------------------------------

// KillRequest is POST /v1/swarms/{id}/kill.
type KillRequest struct {
	Reason string `json:"reason"`
	// KeepRootReadOnly keeps the root agent at READ_ONLY instead of KILLED
	// (default true, as in the plan's demo).
	KeepRootReadOnly *bool `json:"keep_root_read_only,omitempty"`
}

// Kill runs the 7 kill-swarm steps in order, each in parallel across the
// members, recording every member's honest step result:
//
//  1. freeze spawning (swarm frozen: POL-652/653);
//  2. hold every pending call: members' pending delayed Gmail sends are
//     cancelled (never sent), their held calls stay held for two approvers;
//  3. revoke every member's live credentials (and terminate DB sessions);
//  4. cancel queued jobs and retries;
//  5. memory access none (frozen, not deleted);
//  6. stop all copies: level KILLED (the root READ_ONLY when
//     keep_root_read_only) and every copy stopped;
//  7. seal the Diary bundle (swarm.sealed), exportable signed.
//
// Re-running a kill is idempotent: steps already achieved are skipped.
func (s *Service) Kill(ctx context.Context, id string, req KillRequest, actor string) (Op, error) {
	sw, unlock, err := s.prepare(ctx, id, req.Reason, actor)
	if err != nil {
		return Op{}, err
	}
	defer unlock()
	ctx = context.WithoutCancel(ctx)
	// Keeping the root at READ_ONLY suits an orchestrator above its workers.
	// For a copy surge the "root" is the copied agent itself, so by default
	// it is killed with its copies (an explicit keep_root_read_only: true
	// still keeps it).
	keepRoot := req.KeepRootReadOnly == nil || *req.KeepRootReadOnly
	if req.KeepRootReadOnly == nil && sw.DetectedBy == DetectedCopySurge {
		keepRoot = false
	}
	agents, err := memberAgents(ctx, s.pool, id)
	if err != nil {
		return Op{}, err
	}
	op, err := s.startOp(ctx, containment.OpKillSwarm, id, actor, req.Reason)
	if err != nil {
		return Op{}, err
	}
	run := containment.SwarmRun{OpID: op.OpID, Op: containment.OpKillSwarm, SwarmID: id, Actor: actor, Reason: req.Reason, AgentIDs: agents}
	if keepRoot && sw.RootAgentID != "" {
		run.ReadOnly = map[string]bool{sw.RootAgentID: true}
	}
	var steps []Step
	steps = append(steps, s.freeze(ctx, sw, op.OpID, actor, req.Reason))

	held, err := s.contain.RunSwarmEach(ctx, run, "hold_pending_calls", func(ctx context.Context, agent string, _ control.Level) (string, string) {
		return s.holdPending(ctx, sw, op.OpID, agent, actor, req.Reason)
	})
	if err != nil {
		held = []Step{failedPhase("hold_pending_calls", PhaseHold, err)}
	}
	steps = append(steps, phased(held, PhaseHold)...)

	for _, ph := range []struct {
		kind  string
		phase int
	}{
		{containment.SwarmStepRevoke, PhaseRevoke},
		{containment.SwarmStepCancelQueue, PhaseCancelQueue},
		{containment.SwarmStepMemoryNone, PhaseMemory},
		{containment.SwarmStepStop, PhaseStop},
	} {
		st, err := s.contain.RunSwarmStep(ctx, run, ph.kind)
		if err != nil {
			st = []Step{failedPhase(ph.kind, ph.phase, err)}
		}
		steps = append(steps, phased(st, ph.phase)...)
	}
	return s.seal(ctx, sw, op, steps, agents, keepRoot)
}

// freeze is kill step 1: the swarm is frozen (state killed) and release
// votes cast before the kill are dropped.
func (s *Service) freeze(ctx context.Context, sw Swarm, opID, actor, reason string) Step {
	step := Step{Name: "freeze_spawning", Phase: PhaseFreeze}
	start := time.Now()
	var prev string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockDiaryHead(ctx, tx); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT state FROM swarms WHERE swarm_id = $1 FOR UPDATE`, sw.SwarmID).Scan(&prev); err != nil {
			return err
		}
		if prev == StateKilled {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE swarms SET state = 'killed', updated_at = $2 WHERE swarm_id = $1`, sw.SwarmID, s.now()); err != nil {
			return err
		}
		if err := s.clearVotes(ctx, tx, sw.SwarmID, actor, "swarm killed"); err != nil {
			return err
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventFrozen, Actor: actor, Data: map[string]any{
			"swarm_id": sw.SwarmID, "op_id": opID, "reason": reason, "previous_state": prev}})
		return err
	})
	step.Duration = time.Since(start).Milliseconds()
	switch {
	case err != nil:
		step.Status, step.Detail = containment.StepFailed, "could not freeze the swarm: "+oneLine(err.Error())+"; members may still delegate and register copies"
	case prev == StateKilled:
		step.Status, step.Detail = containment.StepSkipped, "already frozen: DELEGATE, new copies and non-READ actions of members are refused (POL-652/653)"
	default:
		step.Status, step.Detail = containment.StepDone, "frozen: members may not DELEGATE or register copies (POL-652) and may only READ, with no new credentials (POL-653), until the swarm is released"
	}
	return step
}

// holdPending is kill step 2 for one member: cancel its pending delayed
// Gmail sends and keep its held calls held (tagged with the swarm, at
// least two approvers), recording the latter in the Diary.
func (s *Service) holdPending(ctx context.Context, sw Swarm, opID, agent, actor, reason string) (string, string) {
	res, err := google.CancelPendingSends(ctx, s.pool, s.diary, []string{agent}, sw.CreatedAt, actor, reason)
	if err != nil {
		return containment.StepFailed, "delayed Gmail sends NOT cancelled: " + oneLine(err.Error()) + "; held calls NOT re-checked"
	}
	c := res[agent]
	var held []string
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE held_actions SET swarm_id = COALESCE(swarm_id, $2), approvals_required = GREATEST(approvals_required, $3)
			WHERE agent_id = $1 AND outcome = 'pending' RETURNING action_id`, agent, sw.SwarmID, BreakerApprovals)
		if err != nil {
			return err
		}
		if held, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil || len(held) == 0 {
			return err
		}
		if err := lockDiaryHead(ctx, tx); err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agent, EventType: EventCallsHeld, Actor: actor, Data: map[string]any{
			"swarm_id": sw.SwarmID, "op_id": opID, "action_ids": held, "approvals_required_at_least": BreakerApprovals}})
		return err
	})
	parts := []string{fmt.Sprintf("%d pending delayed Gmail sends cancelled (never sent)", len(c.Cancelled))}
	if len(c.Cancelled) > 0 {
		parts[0] += ": " + strings.Join(clipIDs(c.Cancelled), ", ")
	}
	if err != nil {
		parts = append(parts, "held calls NOT re-checked: "+oneLine(err.Error()))
	} else {
		parts = append(parts, fmt.Sprintf("%d held calls stay held, now needing at least %d approvers", len(held), BreakerApprovals))
	}
	if c.SentSince > 0 {
		parts = append(parts, fmt.Sprintf("%d delayed sends were already delivered after the swarm was detected and before this step", c.SentSince))
	}
	if len(c.InFlight) > 0 {
		parts = append(parts, fmt.Sprintf("%d sends were already being sent when the kill reached them and could NOT be stopped (they may have been delivered): %s",
			len(c.InFlight), strings.Join(clipIDs(c.InFlight), ", ")))
		return containment.StepFailed, strings.Join(parts, "; ")
	}
	switch {
	case err != nil:
		return containment.StepFailed, strings.Join(parts, "; ")
	case len(c.Cancelled) == 0 && len(held) == 0:
		return containment.StepSkipped, "nothing pending: no delayed Gmail sends to cancel and no held calls" + suffix(c.SentSince)
	}
	return containment.StepDone, strings.Join(parts, "; ")
}

func suffix(sent int) string {
	if sent == 0 {
		return ""
	}
	return fmt.Sprintf("; %d delayed sends were already delivered after the swarm was detected", sent)
}

func clipIDs(ids []string) []string {
	if len(ids) <= 20 {
		return ids
	}
	return append(append([]string{}, ids[:20]...), fmt.Sprintf("and %d more", len(ids)-20))
}

// Brief is the root's first delegation (the task the swarm was given).
type Brief struct {
	DelegationID   string          `json:"delegation_id"`
	From           string          `json:"from_agent"`
	To             string          `json:"to_agent"`
	Channel        string          `json:"channel"`
	TaskID         string          `json:"task_id,omitempty"`
	ActionID       string          `json:"action_id,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	Target         json.RawMessage `json:"target,omitempty"`
	PayloadSummary json.RawMessage `json:"payload_summary,omitempty"`
}

func brief(ctx context.Context, q querier, root string) (*Brief, error) {
	if root == "" {
		return nil, nil
	}
	var b Brief
	err := q.QueryRow(ctx, `SELECT d.delegation_id, d.from_agent, d.to_agent, d.channel, COALESCE(d.task_id, ''), COALESCE(d.action_id, ''),
			d.created_at, a.target, a.payload_summary
		FROM delegations d LEFT JOIN actions a ON a.action_id = d.action_id
		WHERE d.from_agent = $1 AND d.from_agent <> d.to_agent ORDER BY d.created_at, d.delegation_id LIMIT 1`, root).
		Scan(&b.DelegationID, &b.From, &b.To, &b.Channel, &b.TaskID, &b.ActionID, &b.CreatedAt, &b.Target, &b.PayloadSummary)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	b.CreatedAt = b.CreatedAt.UTC()
	return &b, err
}

// seal is kill step 7: the swarm.sealed Diary event (swarm, members, spawn
// tree, brief, held calls, every step) commits with the op's result.
func (s *Service) seal(ctx context.Context, sw Swarm, op Op, steps []Step, agents []string, keepRoot bool) (Op, error) {
	seal := Step{Name: "seal_bundle", Phase: PhaseSeal, Status: containment.StepDone,
		Detail: "sealed in Diary event " + EventSealed + "; export it signed: GET /v1/swarms/" + sw.SwarmID + "/bundle"}
	steps = append(steps, seal)
	return s.finishOp(ctx, op, steps, agents, func(tx pgx.Tx) ([]diary.Event, error) {
		cur, err := getSwarm(ctx, tx, sw.SwarmID, false)
		if err != nil {
			return nil, err
		}
		ms, err := members(ctx, tx, sw.SwarmID)
		if err != nil {
			return nil, err
		}
		tree, err := spawnTree(ctx, tx, cur.RootAgentID)
		if err != nil {
			return nil, err
		}
		br, err := brief(ctx, tx, cur.RootAgentID)
		if err != nil {
			return nil, err
		}
		held, err := heldCalls(ctx, tx, sw.SwarmID, maxHeldCalls+1)
		if err != nil {
			return nil, err
		}
		truncated := len(held) > maxHeldCalls
		if truncated {
			held = held[:maxHeldCalls]
		}
		return []diary.Event{{AgentID: cur.RootAgentID, EventType: EventSealed, Actor: op.Actor, Data: map[string]any{
			"swarm_id": sw.SwarmID, "op_id": op.OpID, "reason": op.Reason, "swarm": cur, "members": ms, "spawn_tree": tree,
			"brief": br, "held_calls": held, "held_calls_truncated": truncated, "steps": steps,
			"status": containment.StatusOf(steps), "keep_root_read_only": keepRoot,
		}}}, nil
	})
}

// --- release ------------------------------------------------------------------------------

// Release records approver's vote to release the swarm. The first vote is
// recorded; the vote of a second, different approver releases it in the
// same transaction: breakers released, freeze lifted (state released).
// Then the members the swarm suspended are resumed (recorded as a
// release_swarm op). It never un-kills: KILLED members stay KILLED until
// security re-enables each through the level API, and other levels
// (ISOLATED, READ_ONLY) are not raised.
func (s *Service) Release(ctx context.Context, id, reason, approver, actor string) (ReleaseResult, error) {
	approver = strings.TrimSpace(approver)
	if approver == "" {
		return ReleaseResult{}, fmt.Errorf("%w: approver is required", ErrInvalid)
	}
	sw, unlock, err := s.prepare(ctx, id, reason, actor)
	if err != nil {
		return ReleaseResult{}, err
	}
	defer unlock()
	ctx = context.WithoutCancel(ctx)
	out := ReleaseResult{Required: ReleaseApprovals}
	var approvers, breakers []string
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockDiaryHead(ctx, tx); err != nil {
			return err
		}
		cur, err := getSwarm(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.State == StateReleased {
			return fmt.Errorf("%w: swarm %s was released", ErrConflict, id)
		}
		// Two-person rule: an API token's key is "token:<name>", a person's
		// "user:<email>". One operator may hold several tokens, so two token
		// votes do not make two people.
		if !strings.HasPrefix(approver, "user:") && !s.opt.AllowTokenPairs {
			var tokenVoted bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM swarm_release_votes WHERE swarm_id = $1 AND approver <> $2 AND approver NOT LIKE 'user:%')`,
				id, approver).Scan(&tokenVoted); err != nil {
				return err
			}
			if tokenVoted {
				return ErrTwoPerson
			}
		}
		tag, err := tx.Exec(ctx, `INSERT INTO swarm_release_votes (swarm_id, approver, reason, created_at) VALUES ($1, $2, $3, $4)
			ON CONFLICT (swarm_id, approver) DO NOTHING`, id, approver, reason, s.now())
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrAlreadyVoted
		}
		rows, err := tx.Query(ctx, `SELECT approver FROM swarm_release_votes WHERE swarm_id = $1 ORDER BY created_at, approver`, id)
		if err != nil {
			return err
		}
		if approvers, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		out.Votes = len(approvers)
		events := []diary.Event{{EventType: EventReleaseVote, Actor: actor, Data: map[string]any{
			"swarm_id": id, "approver": approver, "reason": reason, "votes": out.Votes, "required": ReleaseApprovals}}}
		if out.Votes >= ReleaseApprovals {
			out.Released = true
			now := s.now()
			if _, err := tx.Exec(ctx, `UPDATE swarms SET state = 'released', released_at = $2, updated_at = $2 WHERE swarm_id = $1`, id, now); err != nil {
				return err
			}
			rows, err := tx.Query(ctx, `UPDATE swarm_breakers SET state = 'released', released_at = $2
				WHERE swarm_id = $1 AND state = 'tripped' RETURNING action_hash`, id, now)
			if err != nil {
				return err
			}
			if breakers, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
				return err
			}
			events = append(events, diary.Event{EventType: EventReleased, Actor: actor, Data: map[string]any{
				"swarm_id": id, "approvers": approvers, "previous_state": cur.State, "breakers_released": breakers,
				"freeze_lifted": cur.State == StateKilled, "reason": reason}})
		}
		_, err = s.diary.AppendTx(ctx, tx, events...)
		return err
	})
	if err != nil || !out.Released {
		return out, err
	}
	op, err := s.afterRelease(ctx, sw, approvers, breakers, actor, reason)
	if err != nil {
		return out, fmt.Errorf("swarm released, but resuming its members could not be recorded: %w", err)
	}
	out.Op = &op
	return out, nil
}

// afterRelease records the release op: what the release lifted, then the
// members' resume steps and what stays in force.
func (s *Service) afterRelease(ctx context.Context, sw Swarm, approvers, breakers []string, actor, reason string) (Op, error) {
	agents, err := memberAgents(ctx, s.pool, sw.SwarmID)
	if err != nil {
		return Op{}, err
	}
	op, err := s.startOp(ctx, containment.OpReleaseSwarm, sw.SwarmID, actor, reason)
	if err != nil {
		return Op{}, err
	}
	steps := []Step{{Name: "release_breakers", Status: containment.StepDone,
		Detail: fmt.Sprintf("approved by %s: %d breakers released; matching calls are decided normally again", strings.Join(approvers, " and "), len(breakers))}}
	if len(breakers) == 0 {
		steps[0].Status, steps[0].Detail = containment.StepSkipped, "approved by "+strings.Join(approvers, " and ")+": no breaker was tripped"
	}
	if sw.State == StateKilled {
		steps = append(steps, Step{Name: "lift_freeze", Status: containment.StepDone, Detail: "freeze lifted: POL-652/653 no longer apply to the members"})
	} else {
		steps = append(steps, Step{Name: "lift_freeze", Status: containment.StepSkipped, Detail: "the swarm was not frozen"})
	}
	run := containment.SwarmRun{OpID: op.OpID, Op: containment.OpReleaseSwarm, SwarmID: sw.SwarmID, Actor: actor, Reason: reason, AgentIDs: agents}
	st, err := s.contain.RunSwarmStep(ctx, run, containment.SwarmStepResume)
	if err != nil {
		st = []Step{failedPhase("resume", 0, err)}
	}
	steps = append(steps, st...)
	kept, err := s.contain.RunSwarmEach(ctx, run, "keep_level", func(_ context.Context, _ string, lvl control.Level) (string, string) {
		switch {
		case lvl >= control.Killed:
			return containment.StepSkipped, "KILLED: stays KILLED; a release never un-kills (security re-enables it through the level API)"
		case lvl > control.Full:
			return containment.StepSkipped, fmt.Sprintf("level %s kept: step it up through the level API (owner or security)", lvl)
		}
		return containment.StepSkipped, "level FULL: nothing to restore"
	})
	if err != nil {
		kept = []Step{failedPhase("keep_level", 0, err)}
	}
	steps = append(steps, kept...)
	return s.finishOp(ctx, op, steps, agents, nil)
}
