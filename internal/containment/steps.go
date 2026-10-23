package containment

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"

	"fortik/internal/control"
	"fortik/internal/memory"
	"fortik/internal/queues"
)

// Memory access modes (memory_access.mode; same values as memory.Access*).
const (
	memoryFull        = "full"
	memoryStagingOnly = "staging_only"
	memoryNone        = "none"
)

var memoryRank = map[string]int{memoryFull: 0, memoryStagingOnly: 1, memoryNone: 2}

// Queue actions.
const (
	queuePause  = "pause"
	queueResume = "resume"
	queueCancel = "cancel"
)

// systemPostgres is the broker system whose revocation terminates the
// agent's database sessions (pgroles: NOLOGIN + pg_terminate_backend).
const systemPostgres = "postgres"

// execute runs the operation's steps over the plan's targets.
func (m *Manager) execute(ctx context.Context, p *plan) []Step {
	switch p.req.Op {
	case OpSuspend:
		if p.instance != "" {
			return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.suspendInstance(ctx, p, a, r) })
		}
		return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.suspendAgent(ctx, p, a, r, false) })
	case OpEStop:
		return m.forEach(ctx, p, func(a agentRow, r *recorder) {
			if a.Level >= control.Killed {
				r.skip("mark_suspended", "agent is KILLED: it is already refused everything; not suspended by this e-stop")
				return
			}
			m.suspendAgent(ctx, p, a, r, true)
		})
	case OpResume:
		if p.instance != "" {
			return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.resumeInstance(ctx, p, a, r) })
		}
		return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.resumeAgent(ctx, p, a, r, "") })
	case OpEStopRelease:
		return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.resumeAgent(ctx, p, a, r, a.ResolvedBy) })
	case OpIsolate:
		return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.isolateAgent(ctx, p, a, r) })
	case OpMemoryRemove:
		return m.forEach(ctx, p, func(a agentRow, r *recorder) {
			m.memoryStep(ctx, p, a, r, p.req.MemoryMode, false)
			r.skip("revoke_memory_credentials", "agents hold no vector-store credentials: memory is reached only through "+
				"Fortik's memory gateway and memory MCP tools, which refuse by memory access")
		})
	case OpMemoryRestore:
		return m.memoryRestore(ctx, p)
	case OpCancelQueue:
		return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.queueSteps(ctx, p, a, r, queueCancel) })
	case OpKill:
		return m.forEach(ctx, p, func(a agentRow, r *recorder) { m.killAgent(ctx, p, a, r) })
	}
	return []Step{{Name: "dispatch", Status: StepFailed, Detail: "unknown op " + p.req.Op}}
}

func (p *plan) eventData(extra map[string]any) map[string]any {
	d := map[string]any{"op_id": p.opID, "op": p.req.Op, "via": "containment", "reason": p.req.Reason}
	if p.swarmID != "" {
		d["swarm_id"] = p.swarmID
	}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

// --- suspend / resume ---------------------------------------------------------

// suspendAgent: mark suspended -> revoke live credentials -> pause queued
// jobs -> tell running copies to pause. When the agent was already
// suspended and a completed operation already ran the external steps for
// this suspension, those are not repeated (idempotent); after a failed
// step they are retried.
func (m *Manager) suspendAgent(ctx context.Context, p *plan, a agentRow, r *recorder, estop bool) {
	changed := false
	r.do(ctx, "mark_suspended", func(ctx context.Context) (string, string) {
		var by string
		err := pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
			var err error
			changed, err = m.control.SetSuspendedTx(ctx, tx, a.ID, true, p.req.Reason, p.actor, p.eventData(nil))
			if err != nil {
				return err
			}
			if changed && (estop || p.suspendMarker != "") {
				by = p.suspendMarker
				if estop {
					by = estopMarker + p.opID
				}
				_, err = tx.Exec(ctx, `UPDATE agents SET suspended_by = $2 WHERE agent_id = $1`, a.ID, by)
				return err
			}
			if !changed {
				return tx.QueryRow(ctx, `SELECT COALESCE(suspended_by, '') FROM agents WHERE agent_id = $1`, a.ID).Scan(&by)
			}
			return nil
		})
		switch {
		case err != nil:
			changed = false
			return StepFailed, "could not mark the agent suspended: " + sanitize(err)
		case !changed && estop:
			return StepSkipped, fmt.Sprintf("already suspended (by %s): left as is; releasing this e-stop will not resume it", by)
		case !changed:
			return StepSkipped, fmt.Sprintf("already suspended (by %s): unchanged", by)
		}
		return StepDone, "suspended: every action refused (POL-016) until resumed; memory and state kept"
	})
	prior := ""
	if !changed {
		prior = m.priorComplete(ctx, a.ID, "suspended_at", OpSuspend, OpEStop)
	}
	if prior != "" {
		why := fmt.Sprintf("already suspended: operation %s completed this step for the current suspension; not repeated", prior)
		r.skip("revoke_credentials", why)
		r.skip(queueStepName(queuePause), why)
	} else {
		m.revokeStep(ctx, p, a, r)
		m.queueSteps(ctx, p, a, r, queuePause)
	}
	m.instanceStep(ctx, r, "suspend_instances", func(ctx context.Context) ([]string, string, error) {
		return m.instances.SuspendInstances(ctx, a.ID, "", p.actor, p.req.Reason)
	})
}

// resumeAgent: clear the suspension -> resume queues -> suspended copies
// live again. Credentials are issued again on request. expectedBy, for an
// e-stop release, is the suspended_by marker the agent must still carry: an
// agent suspended again separately in the meantime is left alone. A caller
// without the security role lifts only a suspension it imposed (checked
// under the agents row lock) and resumes only the copies it suspended.
//
// Queued work and copies of an agent at QUARANTINED or beyond stay paused:
// the quarantine paused them, and a resume or e-stop release does not lift
// a quarantine (step the level up through the level API, then resume).
// Copies suspended on their own (an instance suspend) stay suspended too.
func (m *Manager) resumeAgent(ctx context.Context, p *plan, a agentRow, r *recorder, expectedBy string) {
	if a.Level >= control.Killed {
		r.skip("clear_suspension", "agent is KILLED: not resumed (re-enable is manual through the level API, security only)")
		return
	}
	left, refused := false, false
	var level control.Level
	r.do(ctx, "clear_suspension", func(ctx context.Context) (string, string) {
		var changed, suspended bool
		var current string
		err := pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
			var lvl int16
			err := tx.QueryRow(ctx, `SELECT suspended_at IS NOT NULL, COALESCE(suspended_by, ''), level FROM agents WHERE agent_id = $1 FOR UPDATE`,
				a.ID).Scan(&suspended, &current, &lvl)
			if err != nil {
				return err
			}
			level = control.Level(lvl)
			switch {
			case expectedBy != "" && current != expectedBy:
				left = true
				return nil
			case p.restricted() && suspended && current != p.actor:
				refused = true
				return nil
			}
			changed, err = m.control.SetSuspendedTx(ctx, tx, a.ID, false, "", p.actor, p.eventData(nil))
			return err
		})
		switch {
		case err != nil:
			left = true
			return StepFailed, "could not clear the suspension: " + sanitize(err) + "; still suspended, queues and copies NOT resumed"
		case refused:
			return StepFailed, "refused: " + imposedBy(current).Error() + "; still suspended, queues and copies NOT resumed"
		case left && !suspended:
			return StepSkipped, "no longer suspended: nothing to release"
		case left:
			return StepSkipped, fmt.Sprintf("now suspended separately (by %s): left suspended", current)
		case !changed:
			return StepSkipped, "not suspended: nothing to clear"
		}
		return StepDone, "suspension cleared: actions are decided normally again; credentials are issued again on request"
	})
	if left || refused {
		return
	}
	if level >= control.Quarantined {
		why := fmt.Sprintf("agent is %s: its queued work and copies stay paused (the quarantine paused them); "+
			"step the level up through the level API, then resume", level)
		if level >= control.Killed {
			why = "agent is KILLED: queued work and copies are not resumed"
		}
		r.skip(queueStepName(queueResume), why)
		r.skip("resume_instances", why)
		return
	}
	only := ""
	if p.restricted() {
		only = p.actor
	}
	m.queueSteps(ctx, p, a, r, queueResume)
	m.instanceStep(ctx, r, "resume_instances", func(ctx context.Context) ([]string, string, error) {
		return m.instances.ResumeInstances(ctx, a.ID, "", p.actor, p.req.Reason, only)
	})
}

// suspendInstance suspends one copy. Credentials and queued work are per
// agent, so they are left alone (and the steps say so). Containment of one
// copy is only as strong as the copy's identity: unless the agent requires
// instances, a copy that stops sending its instance id acts as the agent.
func (m *Manager) suspendInstance(ctx context.Context, p *plan, a agentRow, r *recorder) {
	m.instanceStep(ctx, r, "suspend_instances", func(ctx context.Context) ([]string, string, error) {
		ids, detail, err := m.instances.SuspendInstances(ctx, a.ID, p.instance, p.actor, p.req.Reason)
		if err == nil && len(ids) > 0 {
			detail += "; the copy keeps its copy_cap slot until resumed or stopped"
		}
		return ids, detail, err
	})
	var require bool
	if err := m.pool.QueryRow(ctx, `SELECT require_instances FROM agents WHERE agent_id = $1`, a.ID).Scan(&require); err != nil {
		m.log.Warn("containment: require_instances lookup failed", "agent_id", a.ID, "err", err)
	}
	why := "credentials are issued per agent and shared by its copies: not revoked for one copy; "
	if require {
		why += "the agent requires instances, so every action and credential request must carry a live instance id: " +
			"the suspended copy's are refused (POL-705)"
	} else {
		why += "actions and credential requests carrying the suspended copy's instance id are refused (POL-705), but the agent " +
			"does not require instances: a copy that omits its instance id is not told apart from its siblings, so this " +
			"suspension relies on the copy's cooperation; suspend the agent to stop it for certain"
	}
	r.skip("revoke_credentials", why)
	r.skip(queueStepName(queuePause), "queued work is attributed per agent, not per copy: not paused for one copy")
}

func (m *Manager) resumeInstance(ctx context.Context, p *plan, a agentRow, r *recorder) {
	only := ""
	if p.restricted() {
		only = p.actor
	}
	m.instanceStep(ctx, r, "resume_instances", func(ctx context.Context) ([]string, string, error) {
		return m.instances.ResumeInstances(ctx, a.ID, p.instance, p.actor, p.req.Reason, only)
	})
}

// --- isolate / kill ---------------------------------------------------------------

// stepDown records a set_level step moving the agent down to `to` (never
// loosening) and reports whether the level changed.
func (m *Manager) stepDown(ctx context.Context, p *plan, a agentRow, r *recorder, to control.Level, effect string) bool {
	changed := false
	r.do(ctx, "set_level", func(ctx context.Context) (string, string) {
		var from control.Level
		err := pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
			var err error
			from, changed, err = m.control.StepDownTx(ctx, tx, a.ID, to, p.req.Reason, p.actor, p.eventData(map[string]any{"automatic": false}))
			return err
		})
		switch {
		case err != nil:
			changed = false
			return StepFailed, fmt.Sprintf("could not set level %s: %s", to, sanitize(err))
		case !changed:
			return StepSkipped, fmt.Sprintf("already %s (at or past %s): level unchanged, never loosened", from, to)
		}
		return StepDone, fmt.Sprintf("%s -> %s: %s", from, to, effect)
	})
	return changed
}

// isolateAgent: level ISOLATED -> revoke live credentials -> pause copies
// over the cap. Lifted by step-up through the level API.
func (m *Manager) isolateAgent(ctx context.Context, p *plan, a agentRow, r *recorder) {
	changed := m.stepDown(ctx, p, a, r, control.Isolated, "internal reads only; no SEND, EXPORT or external egress (POL-012)")
	prior := ""
	if !changed {
		prior = m.priorComplete(ctx, a.ID, "level_changed_at", OpIsolate, OpKill)
	}
	if prior != "" {
		r.skip("revoke_credentials", fmt.Sprintf("operation %s already revoked credentials at this level; not repeated", prior))
	} else {
		m.revokeStep(ctx, p, a, r)
	}
	m.instanceStep(ctx, r, "pause_extra_copies", func(ctx context.Context) ([]string, string, error) {
		return m.instances.PauseExtra(ctx, a.ID, p.actor, p.req.Reason)
	})
}

// killAgent: level KILLED -> revoke everything -> cancel queued jobs ->
// terminate DB sessions -> stop all copies -> memory access none. The seal
// (containment.kill Diary event with every step) is written by finish.
func (m *Manager) killAgent(ctx context.Context, p *plan, a agentRow, r *recorder) {
	changed := m.stepDown(ctx, p, a, r, control.Killed, "no actions permitted (POL-010); re-enable is manual, security only")
	m.killFollowUp(ctx, p, a, r, changed)
}

// killFollowUp runs the kill steps after the level is KILLED (also used by
// the level API path, where the level was set before RevokeAll is called).
func (m *Manager) killFollowUp(ctx context.Context, p *plan, a agentRow, r *recorder, levelChanged bool) map[string]string {
	prior := ""
	if !levelChanged {
		prior = m.priorComplete(ctx, a.ID, "level_changed_at", OpKill)
	}
	var revoked map[string]string
	if prior != "" {
		why := fmt.Sprintf("operation %s already completed this step for the current kill; not repeated", prior)
		r.skip("revoke_credentials", why)
		r.skip(queueStepName(queueCancel), why)
		r.skip("terminate_db_sessions", why)
	} else {
		var revokeStatus string
		revoked, revokeStatus = m.revokeStep(ctx, p, a, r)
		m.queueSteps(ctx, p, a, r, queueCancel)
		m.terminateStep(r, revoked, revokeStatus)
	}
	m.instanceStep(p.localCtx(ctx), r, "stop_instances", func(ctx context.Context) ([]string, string, error) {
		return m.instances.StopInstances(ctx, a.ID, "", p.actor, p.req.Reason)
	})
	m.memoryStep(p.localCtx(ctx), p, a, r, memoryNone, false)
	return revoked
}

// terminateStep reports the database-session termination that the
// postgres revocation (pgroles) performed.
func (m *Manager) terminateStep(r *recorder, revoked map[string]string, revokeStatus string) {
	desc, ok := revoked[systemPostgres]
	switch {
	case !ok && revokeStatus == StepFailed && len(revoked) == 0:
		r.steps = append(r.steps, Step{Name: "terminate_db_sessions", AgentID: r.agent, Status: StepFailed,
			Detail: "credential revocation failed before any system reported: database sessions NOT terminated"})
	case !ok:
		r.skip("terminate_db_sessions", "no postgres credential adapter (pgroles) registered: Fortik holds no per-agent database roles whose sessions could be terminated")
	case strings.HasPrefix(desc, "revocation FAILED") || strings.HasPrefix(desc, "no revocation adapter"):
		r.steps = append(r.steps, Step{Name: "terminate_db_sessions", AgentID: r.agent, Status: StepFailed, Detail: "postgres: " + desc})
	default:
		r.steps = append(r.steps, Step{Name: "terminate_db_sessions", AgentID: r.agent, Status: StepDone, Detail: "postgres: " + desc})
	}
}

// --- memory -------------------------------------------------------------------

// memoryStep sets the agent's memory access to mode. Without loosen it
// never relaxes access (none stays none when staging_only is asked). The
// check and the change run in one transaction holding the agent's
// memory_access row lock, so a concurrent change cannot slip between them.
func (m *Manager) memoryStep(ctx context.Context, p *plan, a agentRow, r *recorder, mode string, loosen bool) {
	r.do(ctx, "set_memory_access", func(ctx context.Context) (string, string) {
		if m.memory == nil {
			return StepFailed, "memory protection not configured: memory access NOT changed"
		}
		var cur, by string
		skip, refused := false, false
		err := pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
			err := tx.QueryRow(ctx, `SELECT mode, changed_by FROM memory_access WHERE agent_id = $1 FOR UPDATE`, a.ID).Scan(&cur, &by)
			if errors.Is(err, pgx.ErrNoRows) {
				cur, err = memoryFull, nil
			}
			if err != nil {
				return err
			}
			if cur == mode || !loosen && memoryRank[cur] > memoryRank[mode] {
				skip = true
				return nil
			}
			if loosen && p.restricted() && memoryRank[mode] < memoryRank[cur] && by != p.actor {
				refused = true
				return nil
			}
			return m.memory.SetAccess(ctx, tx, a.ID, mode, p.actor, p.req.Reason)
		})
		switch {
		case err != nil:
			return StepFailed, fmt.Sprintf("could not set memory access %s: %s; access unchanged", mode, sanitize(err))
		case refused:
			return StepFailed, fmt.Sprintf("refused: %s; memory access left %s", imposedBy(by).Error(), cur)
		case skip && cur == mode:
			return StepSkipped, "memory access already " + mode
		case skip:
			return StepSkipped, fmt.Sprintf("memory access already %s (stricter than %s): never loosened", cur, mode)
		}
		switch mode {
		case memoryNone:
			return StepDone, fmt.Sprintf("memory access %s -> none: no memory reads or writes; staged writes not promoted; existing memory frozen, not deleted", cur)
		case memoryStagingOnly:
			return StepDone, fmt.Sprintf("memory access %s -> staging_only: reads allowed, writes staged and never promoted while in this mode", cur)
		}
		return StepDone, fmt.Sprintf("memory access %s -> %s", cur, mode)
	})
}

// memoryRestore optionally rolls the namespace back to a clean snapshot
// (once, for the whole operation), then restores full access. If the
// rollback fails, access is not restored (fail closed).
func (m *Manager) memoryRestore(ctx context.Context, p *plan) []Step {
	var steps []Step
	rolledBack := true
	if id := p.req.RollbackSnapshotID; id != "" {
		op := &recorder{}
		st := op.do(ctx, "rollback_snapshot", func(ctx context.Context) (string, string) {
			if m.memory == nil {
				return StepFailed, "memory protection not configured: NOT rolled back"
			}
			if err := m.memory.RollbackToSnapshot(ctx, id, p.actor, p.req.Reason); err != nil {
				if errors.Is(err, memory.ErrSnapshotNotClean) {
					return StepFailed, fmt.Sprintf("snapshot %s is not clean (it holds flagged or unreviewed staged items, or is a pre-restore copy): "+
						"NOT rolled back: %s", id, sanitize(err))
				}
				return StepFailed, fmt.Sprintf("rollback to snapshot %s FAILED: %s", id, sanitize(err))
			}
			return StepDone, fmt.Sprintf("namespace rolled back to clean snapshot %s (a pre-restore snapshot was taken first)", id)
		})
		rolledBack = st == StepDone
		steps = append(steps, op.steps...)
	}
	steps = append(steps, m.forEach(ctx, p, func(a agentRow, r *recorder) {
		switch {
		case !rolledBack:
			r.skip("set_memory_access", fmt.Sprintf("not restored: the rollback to snapshot %s failed; memory access left unchanged", p.req.RollbackSnapshotID))
		case a.Level >= control.Killed:
			r.skip("set_memory_access", "agent is KILLED: memory access not restored")
		default:
			m.memoryStep(ctx, p, a, r, memoryFull, true)
			if last := &r.steps[len(r.steps)-1]; last.Status != StepFailed {
				last.Detail += m.heldForReview(ctx, a.ID)
			}
		}
	})...)
	return steps
}

// pendingReviewer is implemented by memory.Service: the agent's staged
// writes held for review (made while its access was not full, or restored
// from a snapshot), which are not promoted until a review window passes.
type pendingReviewer interface {
	PendingReview(ctx context.Context, agentID string) ([]memory.StagedItem, error)
}

const maxHeldIDs = 20

// heldForReview describes, for the restore step, the agent's writes that
// are held for review, so restoring full access does not silently lead to
// their promotion.
func (m *Manager) heldForReview(ctx context.Context, agentID string) string {
	pr, ok := m.memory.(pendingReviewer)
	if !ok {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	items, err := pr.PendingReview(ctx, agentID)
	var b strings.Builder
	if len(items) > 0 {
		ids := make([]string, 0, min(len(items), maxHeldIDs))
		for _, it := range items[:min(len(items), maxHeldIDs)] {
			ids = append(ids, it.Store+"/"+it.Namespace+"/"+it.ID)
		}
		fmt.Fprintf(&b, "; %d writes made during the memory cut (or restored from a snapshot) are held for review, "+
			"not promoted until a review window passes (flag or drop them in the Memory tab): %s", len(items), strings.Join(ids, ", "))
		if len(items) > maxHeldIDs {
			fmt.Fprintf(&b, " and %d more", len(items)-maxHeldIDs)
		}
	}
	if err != nil {
		b.WriteString("; could not list every write held for review: " + sanitize(err))
	}
	return b.String()
}

// --- external systems -------------------------------------------------------------

// revokeStep revokes every live credential of the agent and records the
// broker's per-system description of what was actually achieved.
func (m *Manager) revokeStep(ctx context.Context, p *plan, a agentRow, r *recorder) (map[string]string, string) {
	var res map[string]string
	st := r.do(ctx, "revoke_credentials", func(ctx context.Context) (string, string) {
		var err error
		res, err = m.revoker.RevokeAll(ctx, a.ID, p.actor, p.req.Reason)
		detail := describeRevocation(res)
		switch {
		case err != nil && detail == "":
			return StepFailed, "revocation FAILED: " + sanitize(err)
		case err != nil:
			return StepFailed, "revocation incomplete: " + detail
		case detail == "":
			return StepSkipped, "no revocation adapters configured and no live credentials recorded: nothing to revoke"
		}
		return StepDone, detail
	})
	return res, st
}

func describeRevocation(res map[string]string) string {
	parts := make([]string, 0, len(res))
	for _, sys := range slices.Sorted(maps.Keys(res)) {
		parts = append(parts, sys+": "+res[sys])
	}
	return strings.Join(parts, "; ")
}

func queueStepName(act string) string { return act + "_queue" }

// queueSteps runs act on every configured queue system (one step each).
func (m *Manager) queueSteps(ctx context.Context, p *plan, a agentRow, r *recorder, act string) {
	name := queueStepName(act)
	if len(m.queues) == 0 {
		r.skip(name, "no queue system configured (temporal, celery, queue_webhook): no queued work to "+act)
		return
	}
	for _, q := range m.queues {
		r.do(ctx, name, func(ctx context.Context) (string, string) {
			var (
				res queues.Result
				err error
			)
			switch act {
			case queuePause:
				res, err = q.Pause(ctx, a.ID, p.req.Reason)
			case queueResume:
				res, err = q.Resume(ctx, a.ID, p.req.Reason)
			default:
				res, err = q.Cancel(ctx, a.ID, p.req.Reason)
			}
			sys := q.System()
			switch {
			case errors.Is(err, queues.ErrNotConfigured):
				return StepSkipped, sys + ": not configured: nothing to " + act
			case errors.Is(err, queues.ErrUnsupported):
				return StepSkipped, sys + ": " + act + " is not supported by this queue system"
			case err != nil:
				// Any other error (a missing secret, a truncated run, ...)
				// fails the step; what the adapter did achieve is kept.
				detail := fmt.Sprintf("%s: %s FAILED: %s", sys, act, sanitize(err))
				if d := strings.TrimSpace(res.Detail); d != "" {
					detail += "; " + clipDetail(d)
				}
				return StepFailed, detail
			}
			return StepDone, fmt.Sprintf("%s: %d affected: %s", sys, res.Affected, res.Detail)
		})
	}
}

// instanceStep records a population change of copies.
func (m *Manager) instanceStep(ctx context.Context, r *recorder, name string, f func(context.Context) ([]string, string, error)) {
	r.do(ctx, name, func(ctx context.Context) (string, string) {
		ids, detail, err := f(ctx)
		switch {
		case err != nil:
			return StepFailed, "copies NOT changed: " + sanitize(err)
		case len(ids) == 0:
			return StepSkipped, detail
		}
		return StepDone, detail
	})
}

// priorComplete returns the id of the latest finished operation among ops
// that actually revoked the agent's credentials (a revoke_credentials step
// for agentID with status done: not an instance-target op, which never
// revokes, and not an op that skipped the step by pointing at an earlier
// one) after the agent entered its current state (stateCol:
// agents.suspended_at or agents.level_changed_at), provided it recorded no
// failed step for the agent; or "" when the external steps must (re)run.
// Errors return "" (fail toward doing the containment again).
func (m *Manager) priorComplete(ctx context.Context, agentID, stateCol string, ops ...string) string {
	if stateCol != "suspended_at" && stateCol != "level_changed_at" {
		return ""
	}
	var opID string
	var clean bool
	err := m.pool.QueryRow(ctx, `SELECT o.op_id,
			NOT jsonb_path_exists(o.steps, '$[*] ? (@.agent_id == $a && @.status == "failed")', jsonb_build_object('a', $1::text))
		FROM containment_ops o JOIN agents a ON a.agent_id = $1
		WHERE o.op = ANY($2) AND o.status <> 'running' AND o.finished_at >= a.`+stateCol+`
			AND o.target_type <> 'instance'
			AND o.steps @> jsonb_build_array(jsonb_build_object('agent_id', $1::text, 'name', 'revoke_credentials', 'status', 'done'))
		ORDER BY o.finished_at DESC, o.op_id DESC LIMIT 1`, agentID, ops).Scan(&opID, &clean)
	if err != nil {
		if !errors.Is(err, pgx.ErrNoRows) {
			m.log.Warn("containment: prior-op lookup failed; repeating the steps", "agent_id", agentID, "err", err)
		}
		return ""
	}
	if !clean {
		return ""
	}
	return opID
}

// clipDetail keeps an adapter's description single-line and bounded.
func clipDetail(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxDetail {
		s = s[:maxDetail] + "..."
	}
	return s
}

const maxDetail = 1000

// sanitize keeps an error short and single-line for steps and the Diary.
func sanitize(err error) string {
	s := strings.Join(strings.Fields(err.Error()), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}
