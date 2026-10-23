package containment

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/diary"
	"fortik/internal/queues"
)

// CredentialRevoker revokes every live credential of an agent on every
// system and returns system -> what was actually achieved. broker.Broker
// (broker.Service) satisfies it.
type CredentialRevoker interface {
	RevokeAll(ctx context.Context, agentID, actor, reason string) (map[string]string, error)
}

// MemoryAccess sets an agent's memory access (internal/memory implements
// it). SetAccess must make the change and its Diary event inside tx when tx
// is non-nil (the caller holds the agent's memory_access row lock in it and
// commits), or in its own transaction when tx is nil; setting the current
// mode is a no-op. RollbackToSnapshot replaces a namespace with a clean
// snapshot's contents (refusing a snapshot that is not clean).
type MemoryAccess interface {
	SetAccess(ctx context.Context, tx pgx.Tx, agentID, mode, actor, reason string) error
	RollbackToSnapshot(ctx context.Context, snapshotID, actor, reason string) error
}

// Instances controls an agent's running copies (population.InstanceControl
// implements it). instanceID "" means every copy of the agent. Each method
// is idempotent and returns the instance ids it changed and an honest
// human summary.
//
// ResumeInstances with instanceID "" leaves copies suspended on their own
// (an instance suspend) suspended; with onlyImposedBy non-empty it lifts
// only suspensions that actor imposed (for one instance anything else is
// refused with an error and nothing changes). SuspendedBy reports who
// imposed a suspended copy's suspension (false when it is not suspended).
type Instances interface {
	SuspendInstances(ctx context.Context, agentID, instanceID, actor, reason string) ([]string, string, error)
	ResumeInstances(ctx context.Context, agentID, instanceID, actor, reason, onlyImposedBy string) ([]string, string, error)
	StopInstances(ctx context.Context, agentID, instanceID, actor, reason string) ([]string, string, error)
	PauseExtra(ctx context.Context, agentID, actor, reason string) ([]string, string, error)
	SuspendedBy(ctx context.Context, agentID, instanceID string) (string, bool, error)
}

// Step and operation statuses.
const (
	StepDone    = "done"
	StepSkipped = "skipped"
	StepFailed  = "failed"

	StatusRunning = "running"
	StatusDone    = "done"
	StatusPartial = "partial"
	StatusFailed  = "failed"
)

// EStopConfirmation is the typed confirmation a fleet e-stop needs.
const EStopConfirmation = "STOP ALL AGENTS"

// FleetTargetID is the target id of fleet operations.
const FleetTargetID = "fleet"

// EventPrefix + op is the Diary event of an operation ("containment.kill").
// EventQuarantine records the steps run when the level API sets QUARANTINED.
const (
	EventPrefix     = "containment."
	EventQuarantine = "containment.quarantine"
)

// estopMarker prefixes agents.suspended_by for agents an e-stop suspended.
const estopMarker = "estop:"

var (
	ErrInvalid  = errors.New("invalid containment request")
	ErrNotFound = errors.New("containment target not found")
	// ErrConflict: the operation cannot run on the target's current state
	// (resume a KILLED agent, resume a copy of a suspended agent).
	ErrConflict = errors.New("containment conflict")
	// ErrConfirmRequired: a fleet e-stop without the typed confirmation.
	ErrConfirmRequired = fmt.Errorf("%w: fleet e-stop needs \"confirm\": %q", ErrInvalid, EStopConfirmation)
	// ErrForbidden: the caller's role does not allow the operation on the
	// target's current state (see ForbiddenError).
	ErrForbidden = errors.New("containment forbidden")
)

// ForbiddenError says why a caller without the security role was refused.
type ForbiddenError struct{ Msg string }

func (e *ForbiddenError) Error() string        { return e.Msg }
func (e *ForbiddenError) Is(target error) bool { return target == ErrForbidden }

func forbidden(format string, args ...any) error {
	return &ForbiddenError{Msg: fmt.Sprintf(format, args...)}
}

// imposedBy is the refusal of D2: lifting someone else's containment.
func imposedBy(actor string) error {
	if actor == "" {
		actor = "an unrecorded actor"
	}
	return forbidden("lifting a containment imposed by %s requires the security role", actor)
}

var (
	idPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	opIDPattern = regexp.MustCompile(`^cop_[0-9A-HJKMNP-TV-Z]{26}$`)
)

const (
	// maxReason matches internal/api's reason limit; reasons may span lines
	// (\n, \t) but carry no other control characters.
	maxReason   = 1000
	maxTeam     = 128
	stepTimeout = 30 * time.Second
	// DefaultWorkers bounds how many target agents run their steps in parallel.
	DefaultWorkers = 8
)

// targets per op (docs/PHASE4_DESIGN.md §1).
var opTargets = map[string]map[string]bool{
	OpSuspend:       {TargetInstance: true, TargetAgent: true, TargetTeam: true},
	OpResume:        {TargetInstance: true, TargetAgent: true, TargetTeam: true},
	OpIsolate:       {TargetAgent: true, TargetTeam: true},
	OpMemoryRemove:  {TargetAgent: true, TargetTeam: true},
	OpMemoryRestore: {TargetAgent: true, TargetTeam: true},
	OpCancelQueue:   {TargetAgent: true},
	OpKill:          {TargetAgent: true, TargetTeam: true},
	OpEStop:         {TargetFleet: true},
	OpEStopRelease:  {TargetFleet: true},
}

// Manager runs containment operations (it implements Service, and
// api.Revoker for the level API's QUARANTINED/KILLED transitions).
type Manager struct {
	pool      *pgxpool.Pool
	diary     *diary.Diary
	control   *control.Store
	revoker   CredentialRevoker
	queues    []queues.Adapter
	memory    MemoryAccess
	instances Instances
	log       *slog.Logger

	// Workers bounds parallelism across target agents (default DefaultWorkers).
	Workers int
}

var _ Service = (*Manager)(nil)

// New builds the manager. pool, diary, control store, revoker and instances
// are required; queue adapters may be empty (queue steps then say no queue
// system is configured) and memory may be nil (memory steps then fail
// honestly: access is not changed).
func New(pool *pgxpool.Pool, d *diary.Diary, ctl *control.Store, revoker CredentialRevoker, qs []queues.Adapter,
	mem MemoryAccess, inst Instances, log *slog.Logger) (*Manager, error) {
	if pool == nil || d == nil || ctl == nil || revoker == nil || inst == nil {
		return nil, errors.New("containment: pool, diary, control store, credential revoker and instances are required")
	}
	for _, q := range qs {
		if q == nil {
			return nil, errors.New("containment: nil queue adapter")
		}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Manager{pool: pool, diary: d, control: ctl, revoker: revoker, queues: append([]queues.Adapter(nil), qs...),
		memory: mem, instances: inst, log: log}, nil
}

func (m *Manager) workers() int {
	if m.Workers > 0 {
		return m.Workers
	}
	return DefaultWorkers
}

// Caller is who runs an operation: the Diary actor (the authenticated
// principal) and whether they hold the security role. Ownership of the
// target is checked by the caller of RunAs (the HTTP handler); what the
// manager enforces for a caller without the security role is:
//
//   - operations that need the security role (kill, cancel_queue, team and
//     fleet ops, a memory_restore with rollback_snapshot_id) are refused;
//   - resume and memory_restore lift only containment the same actor
//     imposed (agents.suspended_by, memory_access.changed_by, the copy's
//     instance.suspended event), checked under the agent's containment lock
//     and again under the row locks inside the steps.
type Caller struct {
	Actor    string
	Security bool
}

// Run executes one operation for actor with the security role (role checks
// are the caller's). A fleet e-stop needs RunConfirmed.
func (m *Manager) Run(ctx context.Context, req Request, actor string) (Op, error) {
	return m.RunAs(ctx, req, "", Caller{Actor: actor, Security: true})
}

// RunConfirmed is Run with the typed confirmation an e-stop needs
// (EStopConfirmation); other operations ignore confirm.
func (m *Manager) RunConfirmed(ctx context.Context, req Request, confirm, actor string) (Op, error) {
	return m.RunAs(ctx, req, confirm, Caller{Actor: actor, Security: true})
}

// RunAs runs an operation for c (see Caller). Refusals return ErrForbidden
// (a *ForbiddenError) before anything is changed or recorded.
func (m *Manager) RunAs(ctx context.Context, req Request, confirm string, c Caller) (Op, error) {
	return m.run(ctx, req, confirm, c)
}

// SecurityOnly reports whether the operation needs the security role
// whoever owns the target.
func SecurityOnly(req Request) bool {
	switch req.Op {
	case OpKill, OpEStop, OpEStopRelease, OpCancelQueue:
		return true
	}
	if strings.TrimSpace(req.RollbackSnapshotID) != "" {
		// A rollback replaces a whole memory namespace, which other agents
		// may share: security only, like POST /v1/memory/snapshots/{id}/restore.
		return true
	}
	tt := strings.TrimSpace(req.TargetType)
	return tt != TargetAgent && tt != TargetInstance
}

// agentRow is a target agent as read under its containment lock (team and
// fleet targets are first read before it and read again under it).
type agentRow struct {
	ID          string
	Level       control.Level
	Suspended   bool
	SuspendedBy string
	Sponsor     string
	// ResolvedBy is suspended_by as the operation resolved its targets
	// (an e-stop release's marker); it is not refreshed.
	ResolvedBy string
}

// plan is a validated request with its resolved targets.
type plan struct {
	req      Request
	actor    string
	security bool // the caller holds the security role
	opID     string
	agents   []agentRow
	instance string // instance target: the copy (agents holds its agent)
	release  string // estop_release: the e-stop op id ("" = every e-stop)
	locks    *agentLocks
	locked   string // the agent whose lock the whole operation holds
	lockWait time.Duration
	// swarmID is set for the steps of a swarm operation (Diary events carry
	// it); suspendMarker, when set, is written to agents.suspended_by by a
	// suspend that changed the agent (a swarm suspend's SwarmMarker).
	swarmID       string
	suspendMarker string
	// local, when set, is the context of the steps that only change
	// Fortik's own database (copies, memory access): the level API path
	// bounds the external steps by the request deadline, but these still
	// run (each bounded by stepTimeout) after a slow external system used
	// the deadline up.
	local context.Context
}

func (p *plan) localCtx(ctx context.Context) context.Context {
	if p.local != nil {
		return p.local
	}
	return ctx
}

// restricted: the caller lifts only containment they imposed (D2).
func (p *plan) restricted() bool { return !p.security }

func (m *Manager) run(ctx context.Context, req Request, confirm string, c Caller) (Op, error) {
	actor := c.Actor
	req, err := normalize(req, actor)
	if err != nil {
		return Op{}, err
	}
	if !c.Security && SecurityOnly(req) {
		return Op{}, forbidden("the security role is required for %s", opLabel(req))
	}
	if req.Op == OpEStop && confirm != EStopConfirmation {
		return Op{}, ErrConfirmRequired
	}
	p := &plan{req: req, actor: actor, security: c.Security, lockWait: lockWait}
	if err := m.resolve(ctx, p); err != nil {
		return Op{}, err
	}
	// Containment must finish even if the caller goes away: the steps run
	// detached from the request (each external call is bounded).
	ctx = context.WithoutCancel(ctx)
	if p.locks, err = m.newLocks(ctx); err != nil {
		return Op{}, err
	}
	defer p.locks.close()
	if req.TargetType == TargetAgent || req.TargetType == TargetInstance {
		// Serialise with every other operation on this agent, then read the
		// target again and apply the state checks under the lock.
		id := p.agents[0].ID
		if err := p.locks.lock(ctx, id, p.lockWait); err != nil {
			return Op{}, err
		}
		p.locked = id
		if err := m.resolve(ctx, p); err != nil {
			return Op{}, err
		}
		if p.agents[0].ID != id {
			return Op{}, fmt.Errorf("%w: instance %s moved to another agent", ErrConflict, req.TargetID)
		}
		if p.restricted() {
			if err := m.checkImposer(ctx, p); err != nil {
				return Op{}, err
			}
		}
	}
	op, err := m.start(ctx, p)
	if err != nil {
		return Op{}, err
	}
	steps := m.execute(ctx, p)
	return m.finish(ctx, op, steps, p.agentIDs())
}

// checkImposer refuses, for a caller without the security role, a resume or
// memory_restore that would lift containment someone else imposed (D2). It
// runs under the agent's containment lock; the steps check again under the
// row locks.
func (m *Manager) checkImposer(ctx context.Context, p *plan) error {
	a := p.agents[0]
	switch p.req.Op {
	case OpResume:
		if p.instance != "" {
			by, suspended, err := m.instances.SuspendedBy(ctx, a.ID, p.instance)
			if err != nil {
				return err
			}
			if suspended && by != p.actor {
				return imposedBy(by)
			}
			return nil
		}
		if a.Suspended && a.SuspendedBy != p.actor {
			return imposedBy(a.SuspendedBy)
		}
	case OpMemoryRestore:
		var mode, by string
		err := m.pool.QueryRow(ctx, `SELECT mode, changed_by FROM memory_access WHERE agent_id = $1`, a.ID).Scan(&mode, &by)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if mode != memoryFull && by != p.actor {
			return imposedBy(by)
		}
	}
	return nil
}

func opLabel(req Request) string {
	if req.TargetType == TargetTeam || req.TargetType == TargetFleet {
		return req.TargetType + " " + req.Op
	}
	if req.Op == OpMemoryRestore && req.RollbackSnapshotID != "" {
		return "memory_restore with rollback_snapshot_id (a snapshot rollback replaces a whole memory namespace)"
	}
	return req.Op
}

func (p *plan) agentIDs() []string {
	ids := make([]string, len(p.agents))
	for i, a := range p.agents {
		ids[i] = a.ID
	}
	return ids
}

// normalize validates and canonicalises a request.
func normalize(req Request, actor string) (Request, error) {
	req.Op = strings.TrimSpace(req.Op)
	req.TargetType = strings.TrimSpace(req.TargetType)
	req.TargetID = strings.TrimSpace(req.TargetID)
	req.Reason = strings.TrimSpace(req.Reason)
	req.MemoryMode = strings.TrimSpace(req.MemoryMode)
	req.RollbackSnapshotID = strings.TrimSpace(req.RollbackSnapshotID)
	if strings.TrimSpace(actor) == "" {
		return req, fmt.Errorf("%w: actor is required", ErrInvalid)
	}
	targets, ok := opTargets[req.Op]
	if !ok {
		return req, fmt.Errorf("%w: unknown op %q", ErrInvalid, req.Op)
	}
	if req.TargetType == "" && req.Op == OpEStop || req.TargetType == "" && req.Op == OpEStopRelease {
		req.TargetType = TargetFleet
	}
	if !targets[req.TargetType] {
		return req, fmt.Errorf("%w: op %s does not apply to target_type %q", ErrInvalid, req.Op, req.TargetType)
	}
	if err := plainText("reason", req.Reason, maxReason, true); err != nil {
		return req, err
	}
	if req.Reason == "" {
		return req, fmt.Errorf("%w: reason is required", ErrInvalid)
	}
	switch req.TargetType {
	case TargetInstance, TargetAgent:
		if !idPattern.MatchString(req.TargetID) {
			return req, fmt.Errorf("%w: target_id must match %s", ErrInvalid, idPattern)
		}
	case TargetTeam:
		if req.TargetID == "" {
			return req, fmt.Errorf("%w: target_id (the team / business unit) is required", ErrInvalid)
		}
		if err := plainText("target_id", req.TargetID, maxTeam, false); err != nil {
			return req, err
		}
	case TargetFleet:
		if req.TargetID == "" {
			req.TargetID = FleetTargetID
		}
		if req.TargetID != FleetTargetID && !(req.Op == OpEStopRelease && opIDPattern.MatchString(req.TargetID)) {
			return req, fmt.Errorf("%w: target_id must be %q (or, to release one e-stop, its op id)", ErrInvalid, FleetTargetID)
		}
	}
	if req.Op == OpMemoryRemove {
		if req.MemoryMode == "" {
			req.MemoryMode = memoryNone
		}
		if req.MemoryMode != memoryNone && req.MemoryMode != memoryStagingOnly {
			return req, fmt.Errorf("%w: memory_mode must be %q or %q", ErrInvalid, memoryNone, memoryStagingOnly)
		}
	} else if req.MemoryMode != "" {
		return req, fmt.Errorf("%w: memory_mode applies only to %s", ErrInvalid, OpMemoryRemove)
	}
	if req.RollbackSnapshotID != "" {
		if req.Op != OpMemoryRestore {
			return req, fmt.Errorf("%w: rollback_snapshot_id applies only to %s", ErrInvalid, OpMemoryRestore)
		}
		if !idPattern.MatchString(req.RollbackSnapshotID) {
			return req, fmt.Errorf("%w: rollback_snapshot_id must match %s", ErrInvalid, idPattern)
		}
	}
	return req, nil
}

// plainText checks length and characters: no control characters, except
// newline and tab when multiline.
func plainText(field, v string, max int, multiline bool) error {
	if len(v) > max {
		return fmt.Errorf("%w: %s is longer than %d bytes", ErrInvalid, field, max)
	}
	for _, r := range v {
		if multiline && (r == '\n' || r == '\t') {
			continue
		}
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s contains control characters", ErrInvalid, field)
		}
	}
	return nil
}

const agentCols = `agent_id, level, suspended_at IS NOT NULL, COALESCE(suspended_by, ''), sponsor`

func scanAgents(rows pgx.Rows) ([]agentRow, error) {
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (agentRow, error) {
		var a agentRow
		var lvl int16
		err := r.Scan(&a.ID, &lvl, &a.Suspended, &a.SuspendedBy, &a.Sponsor)
		a.Level = control.Level(lvl)
		a.ResolvedBy = a.SuspendedBy
		return a, err
	})
}

// resolve reads the target agents and refuses operations the targets'
// state does not allow.
func (m *Manager) resolve(ctx context.Context, p *plan) error {
	req := p.req
	var (
		rows pgx.Rows
		err  error
	)
	switch req.TargetType {
	case TargetInstance:
		var agentID string
		qerr := m.pool.QueryRow(ctx, `SELECT agent_id FROM instances WHERE instance_id = $1`, req.TargetID).Scan(&agentID)
		if errors.Is(qerr, pgx.ErrNoRows) {
			return fmt.Errorf("%w: instance %s", ErrNotFound, req.TargetID)
		}
		if qerr != nil {
			return qerr
		}
		p.instance = req.TargetID
		rows, err = m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id = $1`, agentID)
	case TargetAgent:
		rows, err = m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE agent_id = $1`, req.TargetID)
	case TargetTeam:
		rows, err = m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE business_unit = $1 ORDER BY agent_id`, req.TargetID)
	case TargetFleet:
		if req.Op == OpEStop {
			rows, err = m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents ORDER BY agent_id`)
			break
		}
		if req.TargetID != FleetTargetID {
			var op string
			qerr := m.pool.QueryRow(ctx, `SELECT op FROM containment_ops WHERE op_id = $1`, req.TargetID).Scan(&op)
			if errors.Is(qerr, pgx.ErrNoRows) || qerr == nil && op != OpEStop {
				return fmt.Errorf("%w: no e-stop operation %s", ErrNotFound, req.TargetID)
			}
			if qerr != nil {
				return qerr
			}
			p.release = req.TargetID
			rows, err = m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE suspended_by = $1 ORDER BY agent_id`, estopMarker+req.TargetID)
			break
		}
		rows, err = m.pool.Query(ctx, `SELECT `+agentCols+` FROM agents WHERE suspended_by LIKE 'estop:%' ORDER BY agent_id`)
	}
	if err != nil {
		return err
	}
	if p.agents, err = scanAgents(rows); err != nil {
		return err
	}
	if len(p.agents) == 0 {
		switch req.TargetType {
		case TargetAgent, TargetInstance:
			return fmt.Errorf("%w: agent %s", ErrNotFound, req.TargetID)
		case TargetTeam:
			return fmt.Errorf("%w: no agents in team %q", ErrNotFound, req.TargetID)
		}
		// Fleet operations over zero agents are recorded (an e-stop of an
		// empty fleet, a release with nothing left to release).
	}
	if req.TargetType == TargetAgent || req.TargetType == TargetInstance {
		a := p.agents[0]
		killed := a.Level >= control.Killed
		switch {
		case killed && (req.Op == OpResume || req.Op == OpMemoryRestore):
			return fmt.Errorf("%w: agent %s is KILLED: re-enable is manual through the level API (security only)", ErrConflict, a.ID)
		case req.TargetType == TargetInstance && req.Op == OpResume && a.Suspended:
			return fmt.Errorf("%w: agent %s is suspended: resume the agent, not one copy", ErrConflict, a.ID)
		}
	}
	return nil
}

// start records the operation as running.
func (m *Manager) start(ctx context.Context, p *plan) (Op, error) {
	p.opID = action.NewID("cop")
	op := Op{OpID: p.opID, Op: p.req.Op, TargetType: p.req.TargetType, TargetID: p.req.TargetID, Actor: p.actor,
		Reason: p.req.Reason, Status: StatusRunning, Steps: []Step{}}
	err := m.pool.QueryRow(ctx, `INSERT INTO containment_ops (op_id, op, target_type, target_id, actor, reason, status)
		VALUES ($1, $2, $3, $4, $5, $6, 'running') RETURNING created_at`,
		op.OpID, op.Op, op.TargetType, op.TargetID, op.Actor, op.Reason).Scan(&op.CreatedAt)
	if err != nil {
		return Op{}, fmt.Errorf("containment: record op: %w", err)
	}
	op.CreatedAt = op.CreatedAt.UTC()
	return op, nil
}

// statusOf: done when no step failed; failed when steps failed and none
// achieved anything (skipped steps needed no change); partial otherwise.
func statusOf(steps []Step) string {
	failed, done := 0, 0
	for _, s := range steps {
		switch s.Status {
		case StepFailed:
			failed++
		case StepDone:
			done++
		}
	}
	switch {
	case failed == 0:
		return StatusDone
	case done == 0:
		return StatusFailed
	default:
		return StatusPartial
	}
}

// finish stores the steps and final status and writes the containment.<op>
// Diary event in the same transaction.
func (m *Manager) finish(ctx context.Context, op Op, steps []Step, agents []string) (Op, error) {
	op.Status = statusOf(steps)
	if op.Op == OpKill {
		steps = append(steps, Step{Name: "seal", Status: StepDone, Detail: "every step sealed in Diary event " + EventPrefix + OpKill})
	}
	op.Steps = steps
	raw, err := json.Marshal(steps)
	if err != nil {
		return Op{}, err
	}
	agentID := ""
	if op.TargetType == TargetAgent || op.TargetType == TargetInstance {
		if len(agents) == 1 {
			agentID = agents[0]
		}
	}
	err = pgx.BeginFunc(ctx, m.pool, func(tx pgx.Tx) error {
		var fin time.Time
		if err := tx.QueryRow(ctx, `UPDATE containment_ops SET status = $2, steps = $3::jsonb, finished_at = now()
			WHERE op_id = $1 RETURNING finished_at`, op.OpID, op.Status, string(raw)).Scan(&fin); err != nil {
			return err
		}
		fin = fin.UTC()
		op.FinishedAt = &fin
		_, err := m.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventPrefix + op.Op, Actor: op.Actor, Data: map[string]any{
			"op_id": op.OpID, "op": op.Op, "target_type": op.TargetType, "target_id": op.TargetID, "reason": op.Reason,
			"status": op.Status, "agents": agents, "steps": steps,
		}})
		return err
	})
	if err != nil {
		m.log.Error("containment op could not be recorded as finished", "op_id", op.OpID, "op", op.Op, "err", err)
		return Op{}, fmt.Errorf("containment: record result of %s: %w", op.OpID, err)
	}
	m.log.Info("containment op finished", "op_id", op.OpID, "op", op.Op, "target_type", op.TargetType,
		"target_id", op.TargetID, "status", op.Status, "actor", op.Actor)
	return op, nil
}

// recorder collects one agent's steps in order (shared with the panic
// guard, so steps that already ran are kept).
type recorder struct {
	agent string
	steps []Step
}

// do runs one step with a bounded context and records its outcome.
func (r *recorder) do(ctx context.Context, name string, f func(ctx context.Context) (status, detail string)) string {
	start := time.Now()
	sctx, cancel := context.WithTimeout(ctx, stepTimeout)
	defer cancel()
	status, detail := f(sctx)
	r.steps = append(r.steps, Step{Name: name, AgentID: r.agent, Status: status, Detail: detail, Duration: time.Since(start).Milliseconds()})
	return status
}

// skip records a step that did not need to run.
func (r *recorder) skip(name, detail string) {
	r.steps = append(r.steps, Step{Name: name, AgentID: r.agent, Status: StepSkipped, Detail: detail})
}

// forEach runs fn for every agent of the plan, at most Workers at a time,
// and returns the steps in agent order. Unless the operation already holds
// the agent's containment lock (single-agent targets), each agent's steps
// run under that agent's lock, with the agent read again under it. A
// panicking pipeline is recorded as a failed step for that agent (keeping
// the steps that already ran) rather than taking the operation down.
func (m *Manager) forEach(ctx context.Context, p *plan, fn func(a agentRow, r *recorder)) []Step {
	agents := p.agents
	recs := make([]*recorder, len(agents))
	sem := make(chan struct{}, m.workers())
	var wg sync.WaitGroup
	for i, a := range agents {
		recs[i] = &recorder{agent: a.ID}
		wg.Add(1)
		sem <- struct{}{}
		go func(rec *recorder) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if v := recover(); v != nil {
					m.log.Error("containment step panicked", "agent_id", a.ID, "panic", fmt.Sprint(v))
					rec.steps = append(rec.steps, Step{Name: "internal", AgentID: a.ID, Status: StepFailed,
						Detail: "internal error: the remaining steps for this agent did not run"})
				}
			}()
			if p.locks != nil && a.ID != p.locked {
				if err := p.locks.lock(ctx, a.ID, p.lockWait); err != nil {
					rec.steps = append(rec.steps, Step{Name: "lock_agent", AgentID: a.ID, Status: StepFailed,
						Detail: sanitize(err) + ": no step ran for this agent; run the operation again"})
					return
				}
				defer p.locks.unlock(a.ID)
				fresh, err := m.agent(ctx, a.ID)
				if err != nil {
					rec.steps = append(rec.steps, Step{Name: "lock_agent", AgentID: a.ID, Status: StepFailed,
						Detail: "could not read the agent under its lock: " + sanitize(err) + "; no step ran for this agent"})
					return
				}
				fresh.ResolvedBy = a.ResolvedBy
				a = fresh
			}
			fn(a, rec)
		}(recs[i])
	}
	wg.Wait()
	out := []Step{}
	for _, r := range recs {
		out = append(out, r.steps...)
	}
	return out
}
