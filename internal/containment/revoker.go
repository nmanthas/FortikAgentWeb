package containment

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"time"

	"fortik/internal/control"
)

// Keys the level-API result map carries besides the broker's per-system
// revocation descriptions.
const (
	ResultKeyOp    = "containment_op"
	ResultKeySteps = "containment"
)

// RevokeAll implements api.Revoker. PUT /v1/agents/{id}/level calls it after
// committing a change to QUARANTINED or KILLED (and on a repeat of either,
// which is how failed steps are retried), so the console's level buttons
// and the containment buttons behave the same:
//
//   - KILLED: the kill steps after the level change (revoke everything,
//     cancel queued jobs, terminate DB sessions, stop every copy, memory
//     access none), recorded as a containment "kill" operation and sealed in
//     the containment.kill Diary event. The level is not set again here (no
//     recursion into the level API).
//   - QUARANTINED: revoke, pause queued jobs, tell copies to pause and set
//     memory access staging_only (never loosening), recorded in a
//     containment.quarantine Diary event. The agent is not marked suspended:
//     the level already refuses everything (POL-011).
//   - any other level: credential revocation only.
//
// The result is the broker's system -> description map plus ResultKeyOp and
// ResultKeySteps; the error lists the steps that failed.
//
// The steps run detached from the caller's cancellation but keep its
// deadline (the level API bounds the whole containment, not each step): an
// external step (revocation, queue systems) still running at the deadline
// fails and says so, and later external steps fail at once, so the level
// request is not held for 30s per step. Steps that only change Fortik's own
// database (stop or suspend copies, memory access) still run, each bounded
// by its step timeout.
// The operation's record is written on a fresh, short context so it is kept
// even after the deadline. The agent's containment lock is taken as for
// every operation; if another operation on the agent does not finish in
// time, credentials are still revoked (it only tightens) and the error says
// the other steps did NOT run.
func (m *Manager) RevokeAll(ctx context.Context, agentID, actor, reason string) (map[string]string, error) {
	base := context.WithoutCancel(ctx)
	wait := lockWait
	if dl, ok := ctx.Deadline(); ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithDeadline(base, dl)
		defer cancel()
		wait = time.Until(dl)
	} else {
		ctx = base
	}
	reason = strings.TrimSpace(reason)
	revokeOnly := func(cause error) (map[string]string, error) {
		// Fail toward containment: still revoke credentials.
		rctx, cancel := context.WithTimeout(base, stepTimeout)
		defer cancel()
		res, rerr := m.revoker.RevokeAll(rctx, agentID, actor, reason)
		return res, errors.Join(cause, rerr)
	}
	locks, err := m.newLocks(ctx)
	if err != nil {
		return revokeOnly(err)
	}
	defer locks.close()
	if err := locks.lock(ctx, agentID, wait); err != nil {
		return revokeOnly(fmt.Errorf("containment steps NOT run (credentials revoked only): %w", err))
	}
	a, err := m.agent(ctx, agentID)
	if err != nil {
		return revokeOnly(err)
	}
	lp := func(op string) *plan {
		return &plan{req: Request{Op: op, TargetType: TargetAgent, TargetID: a.ID, Reason: reason}, actor: actor, security: true,
			agents: []agentRow{a}, locks: locks, locked: a.ID, lockWait: wait, local: base}
	}
	switch {
	case a.Level >= control.Killed:
		if reason == "" {
			reason = "level set to KILLED"
		}
		return m.levelKill(ctx, base, lp(OpKill), actor, reason)
	case a.Level == control.Quarantined:
		if reason == "" {
			reason = "level set to QUARANTINED"
		}
		return m.levelQuarantine(ctx, base, lp(OpQuarantine), actor, reason)
	}
	return m.revoker.RevokeAll(ctx, agentID, actor, reason)
}

// recordTimeout bounds writing an operation's record on the level API path
// (on a context of its own, so the record survives the request deadline).
const recordTimeout = 10 * time.Second

func (m *Manager) record(base context.Context, f func(ctx context.Context) error) error {
	ctx, cancel := context.WithTimeout(base, recordTimeout)
	defer cancel()
	return f(ctx)
}

func (m *Manager) agent(ctx context.Context, agentID string) (agentRow, error) {
	rows, err := m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id = $1`, agentID)
	if err != nil {
		return agentRow{}, err
	}
	as, err := scanAgents(rows)
	if err != nil {
		return agentRow{}, err
	}
	if len(as) == 0 {
		return agentRow{}, fmt.Errorf("%w: agent %s", ErrNotFound, agentID)
	}
	return as[0], nil
}

func (m *Manager) levelKill(ctx, base context.Context, p *plan, actor, reason string) (map[string]string, error) {
	a := p.agents[0]
	p.req.Reason = reason
	var op Op
	err := m.record(base, func(rctx context.Context) (err error) { op, err = m.start(rctx, p); return err })
	if err != nil {
		res, rerr := m.revoker.RevokeAll(ctx, a.ID, actor, reason)
		return res, errors.Join(err, rerr)
	}
	var revoked map[string]string
	steps := m.forEach(ctx, p, func(a agentRow, r *recorder) {
		r.skip("set_level", "agent is KILLED through the level API: level not set again")
		revoked = m.killFollowUp(ctx, p, a, r, false)
	})
	err = m.record(base, func(rctx context.Context) (err error) { op, err = m.finish(rctx, op, steps, p.agentIDs()); return err })
	if err != nil {
		return levelResult(revoked, p.opID, steps), err
	}
	return levelResult(revoked, op.OpID, op.Steps), stepsError(op.Op, op.Steps)
}

func (m *Manager) levelQuarantine(ctx, base context.Context, p *plan, actor, reason string) (map[string]string, error) {
	a := p.agents[0]
	p.req.Reason = reason
	var op Op
	err := m.record(base, func(rctx context.Context) (err error) { op, err = m.start(rctx, p); return err })
	if err != nil {
		res, rerr := m.revoker.RevokeAll(ctx, a.ID, actor, reason)
		return res, errors.Join(err, rerr)
	}
	var revoked map[string]string
	steps := m.forEach(ctx, p, func(a agentRow, r *recorder) {
		revoked, _ = m.revokeStep(ctx, p, a, r)
		m.queueSteps(ctx, p, a, r, queuePause)
		m.instanceStep(p.localCtx(ctx), r, "suspend_instances", func(ctx context.Context) ([]string, string, error) {
			return m.instances.SuspendInstances(ctx, a.ID, "", actor, reason)
		})
		m.memoryStep(p.localCtx(ctx), p, a, r, memoryStagingOnly, false)
	})
	// finish records the containment_ops row and the containment.quarantine
	// Diary event in one transaction.
	err = m.record(base, func(rctx context.Context) (err error) { op, err = m.finish(rctx, op, steps, p.agentIDs()); return err })
	if err != nil {
		return levelResult(revoked, p.opID, steps), err
	}
	return levelResult(revoked, op.OpID, op.Steps), stepsError(op.Op, op.Steps)
}

func levelResult(revoked map[string]string, opID string, steps []Step) map[string]string {
	out := make(map[string]string, len(revoked)+2)
	maps.Copy(out, revoked)
	parts := make([]string, 0, len(steps))
	for _, s := range steps {
		parts = append(parts, s.Name+"="+s.Status)
	}
	out[ResultKeyOp] = opID
	out[ResultKeySteps] = statusOf(steps) + ": " + strings.Join(parts, ", ")
	return out
}

// stepsError summarises the failed steps (nil when none failed).
func stepsError(op string, steps []Step) error {
	var failed []string
	for _, s := range steps {
		if s.Status == StepFailed {
			failed = append(failed, s.Name+": "+s.Detail)
		}
	}
	if len(failed) == 0 {
		return nil
	}
	return fmt.Errorf("containment %s: %d step(s) failed: %s", op, len(failed), strings.Join(failed, "; "))
}
