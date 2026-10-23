package containment

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"fortik/internal/control"
)

// Swarm operations (docs/PHASE5_DESIGN.md §1). The swarm package records
// these as containment ops with target type "swarm" and runs each step of
// a swarm operation across the members through RunSwarmStep / RunSwarmEach,
// so every member's step reuses the honest Phase 4 implementations and runs
// under that member's containment lock.
const (
	TargetSwarm    = "swarm"
	OpTripBreaker  = "trip_breaker"
	OpKillSwarm    = "kill_swarm"
	OpReleaseSwarm = "release_swarm"
)

// SwarmMarker is agents.suspended_by for agents a swarm suspend suspended,
// so the swarm's release resumes only those (like an e-stop release).
func SwarmMarker(swarmID string) string { return "swarm:" + swarmID }

// Swarm step kinds for RunSwarmStep.
const (
	// SwarmStepRevoke: revoke every live credential (and report the
	// database-session termination the postgres revocation performed).
	SwarmStepRevoke = "revoke"
	// SwarmStepCancelQueue: cancel queued jobs, retries and schedules.
	SwarmStepCancelQueue = "cancel_queue"
	// SwarmStepMemoryNone: memory access none (frozen, not deleted).
	SwarmStepMemoryNone = "memory_none"
	// SwarmStepStop: level KILLED (READ_ONLY for SwarmRun.ReadOnly agents),
	// then stop every copy.
	SwarmStepStop = "stop"
	// SwarmStepSuspend / SwarmStepIsolate: the Phase 4 suspend / isolate.
	SwarmStepSuspend = "suspend"
	SwarmStepIsolate = "isolate"
	// SwarmStepResume: lift only suspensions this swarm imposed
	// (SwarmMarker); KILLED agents are never resumed.
	SwarmStepResume = "resume"
)

// SwarmRun is one step of a swarm operation over its member agents.
type SwarmRun struct {
	OpID     string // the swarm operation's containment_ops id (recorded by the caller)
	Op       string // kill_swarm | suspend | isolate | release_swarm (Diary events of the steps carry it)
	SwarmID  string
	Actor    string
	Reason   string
	AgentIDs []string
	// ReadOnly lists agents SwarmStepStop sets to READ_ONLY instead of
	// KILLED (the root kept read-only); never loosening a stricter level.
	ReadOnly map[string]bool
}

// StatusOf is the operation status of a set of steps: done when no step
// failed, failed when steps failed and none achieved anything, partial
// otherwise.
func StatusOf(steps []Step) string { return statusOf(steps) }

// RunSwarmStep runs one step kind on every member agent, in parallel (at
// most Workers at a time), each under that agent's containment lock, and
// returns the steps in member order. A member that is not a registered
// agent gets a failed step (nothing can be done to it).
func (m *Manager) RunSwarmStep(ctx context.Context, run SwarmRun, step string) ([]Step, error) {
	var fn func(context.Context, *plan, agentRow, *recorder)
	switch step {
	case SwarmStepRevoke:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) {
			if prior := m.swarmPrior(ctx, a); prior != "" {
				why := fmt.Sprintf("operation %s already completed this step for the current kill; not repeated", prior)
				r.skip("revoke_credentials", why)
				r.skip("terminate_db_sessions", why)
				return
			}
			revoked, st := m.revokeStep(ctx, p, a, r)
			m.terminateStep(r, revoked, st)
		}
	case SwarmStepCancelQueue:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) {
			if prior := m.swarmPrior(ctx, a); prior != "" {
				r.skip(queueStepName(queueCancel), fmt.Sprintf("operation %s already completed this step for the current kill; not repeated", prior))
				return
			}
			m.queueSteps(ctx, p, a, r, queueCancel)
		}
	case SwarmStepMemoryNone:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) {
			m.memoryStep(ctx, p, a, r, memoryNone, false)
		}
	case SwarmStepStop:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) {
			to, effect := control.Killed, "no actions permitted (POL-010); re-enable is manual, security only"
			if run.ReadOnly[a.ID] {
				to, effect = control.ReadOnly, "kept as the swarm's root at READ_ONLY: reads only (keep_root_read_only)"
			}
			m.stepDown(ctx, p, a, r, to, effect)
			m.instanceStep(ctx, r, "stop_instances", func(ctx context.Context) ([]string, string, error) {
				return m.instances.StopInstances(ctx, a.ID, "", p.actor, p.req.Reason)
			})
		}
	case SwarmStepSuspend:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) {
			if a.Level >= control.Killed {
				r.skip("mark_suspended", "agent is KILLED: it is already refused everything; not suspended by this swarm")
				return
			}
			m.suspendAgent(ctx, p, a, r, false)
		}
	case SwarmStepIsolate:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) { m.isolateAgent(ctx, p, a, r) }
	case SwarmStepResume:
		fn = func(ctx context.Context, p *plan, a agentRow, r *recorder) {
			m.resumeAgent(ctx, p, a, r, SwarmMarker(run.SwarmID))
		}
	default:
		return nil, fmt.Errorf("%w: unknown swarm step %q", ErrInvalid, step)
	}
	return m.runSwarm(ctx, run, step == SwarmStepSuspend, fn)
}

// RunSwarmEach runs fn as the step `name` on every member agent, in
// parallel and under each agent's containment lock (the agent's level is
// read under the lock). fn returns the step's honest status and detail.
func (m *Manager) RunSwarmEach(ctx context.Context, run SwarmRun, name string, fn func(ctx context.Context, agentID string, level control.Level) (status, detail string)) ([]Step, error) {
	if fn == nil || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: step name and function are required", ErrInvalid)
	}
	return m.runSwarm(ctx, run, false, func(ctx context.Context, _ *plan, a agentRow, r *recorder) {
		r.do(ctx, name, func(ctx context.Context) (string, string) { return fn(ctx, a.ID, a.Level) })
	})
}

func (m *Manager) runSwarm(ctx context.Context, run SwarmRun, suspend bool, fn func(context.Context, *plan, agentRow, *recorder)) ([]Step, error) {
	if strings.TrimSpace(run.Actor) == "" || strings.TrimSpace(run.SwarmID) == "" || strings.TrimSpace(run.OpID) == "" {
		return nil, fmt.Errorf("%w: swarm step needs op id, swarm id and actor", ErrInvalid)
	}
	ctx = context.WithoutCancel(ctx)
	ids := slices.Compact(slices.Sorted(slices.Values(run.AgentIDs)))
	rows, err := m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id = ANY($1) ORDER BY agent_id`, ids)
	if err != nil {
		return nil, err
	}
	agents, err := scanAgents(rows)
	if err != nil {
		return nil, err
	}
	known := map[string]bool{}
	for _, a := range agents {
		known[a.ID] = true
	}
	p := &plan{req: Request{Op: run.Op, TargetType: TargetSwarm, TargetID: run.SwarmID, Reason: run.Reason},
		actor: run.Actor, security: true, opID: run.OpID, agents: agents, lockWait: lockWait, swarmID: run.SwarmID}
	if suspend {
		p.suspendMarker = SwarmMarker(run.SwarmID)
	}
	if p.locks, err = m.newLocks(ctx); err != nil {
		return nil, err
	}
	defer p.locks.close()
	steps := m.forEach(ctx, p, func(a agentRow, r *recorder) { fn(ctx, p, a, r) })
	for _, id := range ids {
		if !known[id] {
			steps = append(steps, Step{Name: "lock_agent", AgentID: id, Status: StepFailed,
				Detail: "not a registered agent: no containment step could run for it"})
		}
	}
	return steps, nil
}

// swarmPrior returns, for a KILLED agent, the latest finished kill or
// kill_swarm operation that already revoked its credentials for the
// current kill (so a repeated swarm kill does not repeat the external
// steps); "" otherwise.
func (m *Manager) swarmPrior(ctx context.Context, a agentRow) string {
	if a.Level < control.Killed {
		return ""
	}
	return m.priorComplete(ctx, a.ID, "level_changed_at", OpKill, OpKillSwarm)
}
