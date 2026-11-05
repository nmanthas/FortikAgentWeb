package containment

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Receipt outcomes: what a containment operation is PROVEN to have achieved,
// re-read from authoritative state when the receipt is generated. A step that
// reported "done" is not, by itself, proof that an agent stopped.
const (
	OutcomeConfirmed = "confirmed"           // every verifiable check holds, no failed step, no known residual access
	OutcomePartial   = "partially_confirmed" // the main state holds, but a step failed, a check failed or access remains
	OutcomeFailed    = "failed"              // the operation's main state does not hold
	OutcomeUnknown   = "unknown"             // nothing Fortik can re-read proves or disproves the effect

	CheckConfirmed = "confirmed"
	CheckFailed    = "failed"
	CheckUnknown   = "unknown"
)

// ReceiptCheck is one authoritative re-read of the state an operation should
// have produced.
type ReceiptCheck struct {
	Name     string `json:"name"`
	AgentID  string `json:"agent_id,omitempty"`
	Expected string `json:"expected"`
	Observed string `json:"observed"`
	Outcome  string `json:"outcome"`
	Primary  bool   `json:"primary,omitempty"` // the state the operation exists to produce
	Source   string `json:"source"`            // where it was read
}

// ReceiptStep is a step as the operation reported it, with what that report
// alone can and cannot prove.
type ReceiptStep struct {
	Step
	Outcome string `json:"outcome"` // reported | skipped | failed
}

// Receipt is the evidence for one containment operation.
type Receipt struct {
	OpID        string         `json:"op_id"`
	Op          string         `json:"op"`
	TargetType  string         `json:"target_type"`
	TargetID    string         `json:"target_id"`
	Actor       string         `json:"actor"`
	Reason      string         `json:"reason"`
	OpStatus    string         `json:"op_status"`
	CreatedAt   time.Time      `json:"created_at"`
	FinishedAt  *time.Time     `json:"finished_at,omitempty"`
	GeneratedAt time.Time      `json:"generated_at"`
	Agents      []string       `json:"agents"`
	Steps       []ReceiptStep  `json:"steps"`
	Checks      []ReceiptCheck `json:"checks"`
	Residual    []string       `json:"residual_access"`
	DiarySeqs   []int64        `json:"diary_seqs"`
	Outcome     string         `json:"outcome"`
	Summary     string         `json:"summary"`
}

// residualMarkers are phrases containment steps use when access was not, or
// cannot be, fully withdrawn. They are surfaced verbatim as residual access.
var residualMarkers = []string{"not recallable", "expire within", "up to the receiver", "not tracked", "NOT revoked",
	"manual_required", "review manually", "cannot be held", "prefetched", "until it expires", "remains valid", "only if its worker"}

// Receipt builds the evidence for op opID by re-reading current state.
func (m *Manager) Receipt(ctx context.Context, opID string) (Receipt, error) {
	op, err := m.Get(ctx, opID)
	if err != nil {
		return Receipt{}, err
	}
	r := Receipt{OpID: op.OpID, Op: op.Op, TargetType: op.TargetType, TargetID: op.TargetID, Actor: op.Actor, Reason: op.Reason,
		OpStatus: op.Status, CreatedAt: op.CreatedAt, FinishedAt: op.FinishedAt, GeneratedAt: time.Now().UTC(),
		Checks: []ReceiptCheck{}, Residual: []string{}, DiarySeqs: []int64{}}
	failedSteps := 0
	for _, s := range op.Steps {
		out := "reported"
		switch s.Status {
		case "failed":
			out = "failed"
			failedSteps++
		case "skipped":
			out = "skipped"
		}
		r.Steps = append(r.Steps, ReceiptStep{Step: s, Outcome: out})
		if s.AgentID != "" && !slices.Contains(r.Agents, s.AgentID) {
			r.Agents = append(r.Agents, s.AgentID)
		}
		for _, mk := range residualMarkers {
			if strings.Contains(s.Detail, mk) {
				r.Residual = append(r.Residual, fmt.Sprintf("%s (%s): %s", s.Name, s.AgentID, s.Detail))
				break
			}
		}
	}
	if len(r.Agents) == 0 && op.TargetType == TargetAgent {
		r.Agents = []string{op.TargetID}
	}
	if len(r.Agents) > 200 {
		r.Residual = append(r.Residual, fmt.Sprintf("receipt re-checks the first 200 of %d agents only", len(r.Agents)))
		r.Agents = r.Agents[:200]
	}
	for _, ag := range r.Agents {
		cs, err := m.agentChecks(ctx, op, ag)
		if err != nil {
			return Receipt{}, err
		}
		r.Checks = append(r.Checks, cs...)
	}
	rows, err := m.pool.Query(ctx, `SELECT seq FROM diary WHERE (body_json::jsonb -> 'data' ->> 'op_id') = $1 ORDER BY seq LIMIT 50`, opID)
	if err != nil {
		return Receipt{}, err
	}
	seqs, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return Receipt{}, err
	}
	r.DiarySeqs = append(r.DiarySeqs, seqs...)
	r.Outcome, r.Summary = classify(r, failedSteps)
	return r, nil
}

func classify(r Receipt, failedSteps int) (string, string) {
	primary, primaryOK, failed, unknown := 0, 0, 0, 0
	for _, c := range r.Checks {
		switch c.Outcome {
		case CheckFailed:
			failed++
		case CheckUnknown:
			unknown++
		}
		if c.Primary {
			primary++
			if c.Outcome == CheckConfirmed {
				primaryOK++
			}
		}
	}
	switch {
	case primary == 0 && len(r.Checks)-unknown == 0:
		return OutcomeUnknown, "no state Fortik can re-read proves or disproves this operation's effect (e.g. an external queue); see the steps"
	case primary > 0 && primaryOK == 0:
		return OutcomeFailed, fmt.Sprintf("the operation's main state does not hold for any of %d agents", primary)
	case primaryOK < primary:
		return OutcomePartial, fmt.Sprintf("main state holds for %d of %d agents", primaryOK, primary)
	case failed > 0 || failedSteps > 0 || len(r.Residual) > 0 || unknown > 0:
		return OutcomePartial, fmt.Sprintf("main state confirmed; %d failed step(s), %d failed check(s), %d unverifiable check(s), %d residual access note(s)",
			failedSteps, failed, unknown, len(r.Residual))
	default:
		return OutcomeConfirmed, "every verifiable check holds; no failed step and no known residual access"
	}
}

var levelNames = []string{"FULL", "SUPERVISED", "READ_ONLY", "ISOLATED", "QUARANTINED", "KILLED"}

func levelName(l int) string {
	if l >= 0 && l < len(levelNames) {
		return levelNames[l]
	}
	return fmt.Sprintf("level %d", l)
}

// agentChecks re-reads what op should have left true for agent ag.
func (m *Manager) agentChecks(ctx context.Context, op Op, ag string) ([]ReceiptCheck, error) {
	var level int
	var suspended bool
	err := m.pool.QueryRow(ctx, `SELECT level, suspended_at IS NOT NULL FROM agents WHERE agent_id = $1`, ag).Scan(&level, &suspended)
	if errors.Is(err, pgx.ErrNoRows) {
		return []ReceiptCheck{{Name: "agent_registered", AgentID: ag, Expected: "registered", Observed: "not found", Outcome: CheckFailed, Source: "agents"}}, nil
	}
	if err != nil {
		return nil, err
	}
	var live, liveRecent int
	if err := m.pool.QueryRow(ctx, `SELECT count(*) FILTER (WHERE status = 'live'),
		count(*) FILTER (WHERE status = 'live' AND last_heartbeat > now() - interval '1 minute')
		FROM instances WHERE agent_id = $1`, ag).Scan(&live, &liveRecent); err != nil {
		return nil, err
	}
	memMode := "full"
	if err := m.pool.QueryRow(ctx, `SELECT mode FROM memory_access WHERE agent_id = $1`, ag).Scan(&memMode); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	var grants int
	if err := m.pool.QueryRow(ctx, `SELECT count(*) FROM connector_grants WHERE agent_id = $1 AND status = 'active'`, ag).Scan(&grants); err != nil {
		return nil, err
	}
	var openDeleg int
	if err := m.pool.QueryRow(ctx, `SELECT count(*) FROM delegations WHERE (from_agent = $1 OR to_agent = $1) AND status = 'open' AND expires_at > now()`, ag).Scan(&openDeleg); err != nil {
		return nil, err
	}
	chk := func(name, expected, observed string, ok, primary bool, source string) ReceiptCheck {
		out := CheckFailed
		if ok {
			out = CheckConfirmed
		}
		return ReceiptCheck{Name: name, AgentID: ag, Expected: expected, Observed: observed, Outcome: out, Primary: primary, Source: source}
	}
	var cs []ReceiptCheck
	switch op.Op {
	case OpKill, "kill_swarm":
		cs = append(cs,
			chk("level", "KILLED", levelName(level), level == 5, true, "agents.level"),
			chk("running_copies", "0 live", fmt.Sprintf("%d live", live), live == 0, false, "instances"),
			chk("memory_access", "none", memMode, memMode == "none", false, "memory_access"),
			chk("copilot_grants", "0 active", fmt.Sprintf("%d active", grants), grants == 0, false, "connector_grants"))
		if liveRecent > 0 {
			cs = append(cs, ReceiptCheck{Name: "copy_heartbeats", AgentID: ag, Expected: "no heartbeat after the kill",
				Observed: fmt.Sprintf("%d copies heartbeated in the last minute", liveRecent), Outcome: CheckFailed, Source: "instances"})
		}
		if openDeleg > 0 {
			cs = append(cs, ReceiptCheck{Name: "open_delegations", AgentID: ag, Expected: "0 open",
				Observed: fmt.Sprintf("%d open (refused by the KILLED level, but still open)", openDeleg), Outcome: CheckUnknown, Source: "delegations"})
		}
	case OpSuspend, OpEStop:
		cs = append(cs,
			chk("suspended", "suspended", map[bool]string{true: "suspended", false: "not suspended"}[suspended], suspended, true, "agents.suspended_at"),
			chk("running_copies", "0 live (told to pause)", fmt.Sprintf("%d live", live), live == 0, false, "instances"))
	case OpResume, OpEStopRelease:
		cs = append(cs, chk("suspended", "not suspended", map[bool]string{true: "suspended", false: "not suspended"}[suspended], !suspended, true, "agents.suspended_at"))
	case OpIsolate:
		cs = append(cs, chk("level", "ISOLATED or stricter", levelName(level), level >= 3, true, "agents.level"))
	case OpQuarantine:
		cs = append(cs, chk("level", "QUARANTINED or stricter", levelName(level), level >= 4, true, "agents.level"))
	case OpMemoryRemove:
		cs = append(cs, chk("memory_access", "none or staging_only", memMode, memMode != "full", true, "memory_access"))
	case OpMemoryRestore:
		cs = append(cs, chk("memory_access", "full", memMode, memMode == "full", true, "memory_access"))
	default:
		cs = append(cs, ReceiptCheck{Name: "external_state", AgentID: ag, Expected: "per the steps",
			Observed: "not re-readable by Fortik (external system)", Outcome: CheckUnknown, Source: "steps only"})
	}
	return cs, nil
}
