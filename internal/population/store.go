package population

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/alerts"
	"fortik/internal/diary"
)

var (
	ErrInstanceNotFound = errors.New("instance not found")
	ErrInstanceExists   = errors.New("instance_id already registered")
	ErrAgentNotFound    = errors.New("agent not found")
	ErrInvalid          = errors.New("invalid request")
	// ErrAgentSurge: registering another agent of the type would exceed
	// agent_types.max_agents (POST /v1/agents answers 409).
	ErrAgentSurge = errors.New("agent registration surge")
)

// GoneError is returned by Heartbeat for an instance that must stop
// (paused, refused, stopped, or stale). The handler answers 410.
type GoneError struct{ Instance Instance }

func (e *GoneError) Error() string {
	return fmt.Sprintf("instance %s is %s", e.Instance.InstanceID, e.Instance.Status)
}

// SurgeError details ErrAgentSurge.
type SurgeError struct {
	Type      string
	Count     int
	MaxAgents int
}

func (e *SurgeError) Error() string {
	return fmt.Sprintf("agent type %s already has %d registered agents (max_agents %d)", e.Type, e.Count, e.MaxAgents)
}

func (e *SurgeError) Is(target error) bool { return target == ErrAgentSurge }

var typePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,63}$`)

const instanceColumns = `instance_id, agent_id, host, COALESCE(parent_instance_id, ''), started_at, last_heartbeat,
	CASE WHEN status = 'live' AND last_heartbeat <= $1 THEN 'stale' ELSE status END AS status, COALESCE(reason, '') AS reason, new_host`

func scanInstance(row pgx.Row) (Instance, error) {
	var in Instance
	err := row.Scan(&in.InstanceID, &in.AgentID, &in.Host, &in.ParentInstanceID, &in.StartedAt, &in.LastHeartbeat, &in.Status, &in.Reason, &in.NewHost)
	in.StartedAt, in.LastHeartbeat = in.StartedAt.UTC(), in.LastHeartbeat.UTC()
	return in, err
}

func (s *Service) staleBefore() time.Time { return s.now().Add(-s.cfg.StaleAfter) }

// Instance returns one instance (any agent) with its effective status.
func (s *Service) Instance(ctx context.Context, id string) (Instance, error) {
	in, err := scanInstance(s.pool.QueryRow(ctx, `SELECT `+instanceColumns+` FROM instances WHERE instance_id = $2`, s.staleBefore(), id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Instance{}, ErrInstanceNotFound
	}
	return in, err
}

// InstanceList is GET /v1/agents/{id}/instances.
type InstanceList struct {
	AgentID   string     `json:"agent_id"`
	CopyCap   int        `json:"copy_cap"`
	Live      int        `json:"live"`
	Instances []Instance `json:"instances"`
}

// ListInstances returns the agent's instances, newest first (status filters
// on the effective status, so "stale" and "live" are distinct).
func (s *Service) ListInstances(ctx context.Context, agentID, status string, limit int) (InstanceList, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}
	out := InstanceList{AgentID: agentID, Instances: []Instance{}}
	cutoff := s.staleBefore()
	err := s.pool.QueryRow(ctx, `SELECT a.copy_cap,
		(SELECT count(*) FROM instances i WHERE i.agent_id = a.agent_id AND i.status = 'live' AND i.last_heartbeat > $2)
		FROM agents a WHERE a.agent_id = $1`, agentID, cutoff).Scan(&out.CopyCap, &out.Live)
	if errors.Is(err, pgx.ErrNoRows) {
		return out, ErrAgentNotFound
	}
	if err != nil {
		return out, err
	}
	rows, err := s.pool.Query(ctx, `SELECT * FROM (SELECT `+instanceColumns+` FROM instances WHERE agent_id = $2) x
		WHERE ($3 = '' OR x.status = $3) ORDER BY x.started_at DESC, x.instance_id DESC LIMIT $4`, cutoff, agentID, status, limit)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		in, err := scanInstance(rows)
		if err != nil {
			return out, err
		}
		out.Instances = append(out.Instances, in)
	}
	return out, rows.Err()
}

// Heartbeat refreshes a live instance of agentID. A suspended instance is
// refreshed too but returns *SuspendedError (it must pause until resumed);
// any other instance that is not live returns *GoneError; a live instance that missed its heartbeats (stale)
// is stopped first, so it must register again (and pass the caps again).
func (s *Service) Heartbeat(ctx context.Context, agentID, instanceID string) (Instance, error) {
	var out Instance
	gone, suspended := false, false
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cutoff := s.staleBefore()
		in, err := scanInstance(tx.QueryRow(ctx, `SELECT `+instanceColumns+` FROM instances WHERE instance_id = $2 AND agent_id = $3 FOR UPDATE`,
			cutoff, instanceID, agentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInstanceNotFound
		}
		if err != nil {
			return err
		}
		switch in.Status {
		case StatusLive:
			now := s.now()
			if _, err := tx.Exec(ctx, `UPDATE instances SET last_heartbeat = $2 WHERE instance_id = $1`, instanceID, now); err != nil {
				return err
			}
			in.LastHeartbeat = now
			out = in
			return nil
		case StatusStale:
			reason := fmt.Sprintf("stale: no heartbeat within %s; register again", s.cfg.StaleAfter)
			if _, err := tx.Exec(ctx, `UPDATE instances SET status = 'stopped', reason = $2 WHERE instance_id = $1`, instanceID, reason); err != nil {
				return err
			}
			if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventInstanceStopped, Actor: systemActor,
				Data: map[string]any{"instance_id": instanceID, "reason": reason, "last_heartbeat": in.LastHeartbeat}}); err != nil {
				return err
			}
			in.Status, in.Reason = StatusStale, reason
			out, gone = in, true
			return nil
		case StatusSuspended:
			// A suspended copy is alive but must pause: keep its heartbeat
			// fresh so Resume finds it live, and answer 423 "pause".
			now := s.now()
			if _, err := tx.Exec(ctx, `UPDATE instances SET last_heartbeat = $2 WHERE instance_id = $1`, instanceID, now); err != nil {
				return err
			}
			in.LastHeartbeat = now
			out, suspended = in, true
			return nil
		default:
			out, gone = in, true
			return nil
		}
	})
	if err == nil && gone {
		return out, &GoneError{Instance: out}
	}
	if err == nil && suspended {
		return out, &SuspendedError{Instance: out}
	}
	return out, err
}

// Stop marks an instance of agentID stopped (idempotent; a refused
// instance stays refused).
func (s *Service) Stop(ctx context.Context, agentID, instanceID, actor string) (Instance, error) {
	var out Instance
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		in, err := scanInstance(tx.QueryRow(ctx, `SELECT `+instanceColumns+` FROM instances WHERE instance_id = $2 AND agent_id = $3 FOR UPDATE`,
			s.staleBefore(), instanceID, agentID))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrInstanceNotFound
		}
		if err != nil {
			return err
		}
		out = in
		if in.Status == StatusStopped || in.Status == StatusRefused {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE instances SET status = 'stopped', reason = 'stopped by the agent' WHERE instance_id = $1`, instanceID); err != nil {
			return err
		}
		out.Status, out.Reason = StatusStopped, "stopped by the agent"
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventInstanceStopped, Actor: actor,
			Data: map[string]any{"instance_id": instanceID, "previous_status": in.Status, "reason": out.Reason}})
		return err
	})
	return out, err
}

// PauseResult is the answer of POST /v1/agents/{id}/instances/pause-extra.
type PauseResult struct {
	AgentID    string   `json:"agent_id"`
	CopyCap    int      `json:"copy_cap"`
	LiveBefore int      `json:"live_before"`
	LiveAfter  int      `json:"live_after"`
	Paused     []string `json:"paused"` // newest first
}

// PauseExtra pauses the newest live instances above the agent's copy_cap.
// They get 410 on their next heartbeat and POL-705 on every action of an
// agent that requires instances. One instance.paused event per instance.
func (s *Service) PauseExtra(ctx context.Context, agentID, actor, reason string) (PauseResult, error) {
	res := PauseResult{AgentID: agentID, Paused: []string{}}
	reason = clip(strings.TrimSpace(reason), maxReasonLen)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		// Lock order agents -> instances -> diary_head, as in decisions.
		if err := tx.QueryRow(ctx, `SELECT copy_cap FROM agents WHERE agent_id = $1 FOR UPDATE`, agentID).Scan(&res.CopyCap); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrAgentNotFound
			}
			return err
		}
		rows, err := tx.Query(ctx, `SELECT instance_id FROM instances WHERE agent_id = $1 AND status = 'live' AND last_heartbeat > $2
			ORDER BY started_at ASC, instance_id ASC FOR UPDATE`, agentID, s.staleBefore())
		if err != nil {
			return err
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			return err
		}
		res.LiveBefore = len(ids)
		if len(ids) <= res.CopyCap {
			res.LiveAfter = len(ids)
			return nil
		}
		extra := ids[res.CopyCap:]
		for i := len(extra) - 1; i >= 0; i-- {
			res.Paused = append(res.Paused, extra[i])
		}
		why := fmt.Sprintf("paused: above copy_cap %d", res.CopyCap)
		if reason != "" {
			why += ": " + reason
		}
		if _, err := tx.Exec(ctx, `UPDATE instances SET status = 'paused', reason = $2 WHERE instance_id = ANY($1)`, res.Paused, why); err != nil {
			return err
		}
		res.LiveAfter = res.CopyCap
		events := make([]diary.Event, 0, len(res.Paused))
		for _, id := range res.Paused {
			events = append(events, diary.Event{AgentID: agentID, EventType: EventInstancePaused, Actor: actor, Data: map[string]any{
				"instance_id": id, "copy_cap": res.CopyCap, "live_before": res.LiveBefore, "reason": why,
			}})
		}
		_, err = s.diary.AppendTx(ctx, tx, events...)
		return err
	})
	return res, err
}

// --- agent types ---------------------------------------------------------------

// AgentTypeView is an agent type with its audit fields and current numbers.
type AgentTypeView struct {
	AgentType
	Agents    int       `json:"agents"`
	Live      int       `json:"live"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// AgentTypes lists every configured type with its registered agents and
// live instances.
func (s *Service) AgentTypes(ctx context.Context) ([]AgentTypeView, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT t.type, t.expected_max_instances, t.max_agents, t.spawn_rate_per_min, t.action_rate_per_min, t.updated_by, t.updated_at,
			(SELECT count(*) FROM agents a WHERE a.type = t.type),
			(SELECT count(*) FROM instances i JOIN agents a ON a.agent_id = i.agent_id
			 WHERE a.type = t.type AND i.status = 'live' AND i.last_heartbeat > $1)
		FROM agent_types t ORDER BY t.type`, s.staleBefore())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AgentTypeView{}
	for rows.Next() {
		var v AgentTypeView
		if err := rows.Scan(&v.Type, &v.ExpectedMaxInstances, &v.MaxAgents, &v.SpawnRatePerMin, &v.ActionRatePerMin, &v.UpdatedBy, &v.UpdatedAt,
			&v.Agents, &v.Live); err != nil {
			return nil, err
		}
		v.UpdatedAt = v.UpdatedAt.UTC()
		out = append(out, v)
	}
	return out, rows.Err()
}

const maxLimit = 1_000_000

// PutAgentType creates or replaces an agent type (Diary agent_type.changed
// with the old and new values).
func (s *Service) PutAgentType(ctx context.Context, t AgentType, actor, reason string) (AgentType, error) {
	if !typePattern.MatchString(t.Type) {
		return AgentType{}, fmt.Errorf("%w: type must match %s", ErrInvalid, typePattern)
	}
	for name, v := range map[string]int{"expected_max_instances": t.ExpectedMaxInstances, "max_agents": t.MaxAgents,
		"spawn_rate_per_min": t.SpawnRatePerMin, "action_rate_per_min": t.ActionRatePerMin} {
		if v < 0 || v > maxLimit {
			return AgentType{}, fmt.Errorf("%w: %s must be between 0 and %d", ErrInvalid, name, maxLimit)
		}
	}
	reason = clip(strings.TrimSpace(reason), maxReasonLen)
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var old AgentType
		err := tx.QueryRow(ctx, `SELECT type, expected_max_instances, max_agents, spawn_rate_per_min, action_rate_per_min
			FROM agent_types WHERE type = $1 FOR UPDATE`, t.Type).
			Scan(&old.Type, &old.ExpectedMaxInstances, &old.MaxAgents, &old.SpawnRatePerMin, &old.ActionRatePerMin)
		created := errors.Is(err, pgx.ErrNoRows)
		if err != nil && !created {
			return err
		}
		if !created && old == t {
			return nil // unchanged: no Diary noise
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO agent_types (type, expected_max_instances, max_agents, spawn_rate_per_min, action_rate_per_min, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7)
			ON CONFLICT (type) DO UPDATE SET expected_max_instances = EXCLUDED.expected_max_instances, max_agents = EXCLUDED.max_agents,
				spawn_rate_per_min = EXCLUDED.spawn_rate_per_min, action_rate_per_min = EXCLUDED.action_rate_per_min,
				updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			t.Type, t.ExpectedMaxInstances, t.MaxAgents, t.SpawnRatePerMin, t.ActionRatePerMin, actor, s.now()); err != nil {
			return err
		}
		data := map[string]any{"type": t.Type, "new": t, "created": created}
		if !created {
			data["old"] = old
		}
		if reason != "" {
			data["reason"] = reason
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventAgentTypeChanged, Actor: actor, Data: data})
		return err
	})
	if err != nil {
		return AgentType{}, err
	}
	s.baselines.invalidate(t.Type)
	return t, nil
}

// --- registration surge guard ----------------------------------------------------

// CheckAgentRegistration is the guard POST /v1/agents calls before creating
// an agent of agentType: it refuses (ErrAgentSurge, as *SurgeError) when the
// type already has max_agents registered agents, and raises a deduplicated
// agent_registration_surge alert. Any other error must also refuse the
// creation (fail closed). An empty type, or a type without max_agents, is
// not limited.
//
// The count and the API's insert are separate statements: two concurrent
// creations can both pass at max_agents-1. Use CheckAgentRegistrationTx
// inside the creation transaction for an exact limit.
func (s *Service) CheckAgentRegistration(ctx context.Context, agentType string) error {
	var surge *SurgeError
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		surge, err = s.checkSurge(ctx, tx, agentType)
		return err
	})
	if err != nil {
		return err
	}
	if surge == nil {
		return nil
	}
	if _, aerr := s.alerts.Raise(ctx, surgeAlert(surge)); aerr != nil {
		s.log.Error("could not raise agent_registration_surge", "type", agentType, "err", aerr)
		return errors.Join(surge, aerr)
	}
	return surge
}

// CheckAgentRegistrationTx is CheckAgentRegistration inside the caller's
// agent-creation transaction: it serialises creations of the same type with
// a transaction-scoped advisory lock, so the limit is exact. On a surge the
// caller rolls back, so the alert is raised in its own transaction.
func (s *Service) CheckAgentRegistrationTx(ctx context.Context, tx pgx.Tx, agentType string) error {
	surge, err := s.checkSurge(ctx, tx, agentType)
	if err != nil || surge == nil {
		return err
	}
	if _, aerr := s.alerts.Raise(context.WithoutCancel(ctx), surgeAlert(surge)); aerr != nil {
		s.log.Error("could not raise agent_registration_surge", "type", agentType, "err", aerr)
		return errors.Join(surge, aerr)
	}
	return surge
}

func (s *Service) checkSurge(ctx context.Context, tx pgx.Tx, agentType string) (*SurgeError, error) {
	if agentType == "" {
		return nil, nil
	}
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "fortik.population.agents:"+agentType); err != nil {
		return nil, err
	}
	var maxAgents, n int
	err := tx.QueryRow(ctx, `SELECT t.max_agents, (SELECT count(*) FROM agents a WHERE a.type = t.type) FROM agent_types t WHERE t.type = $1`, agentType).
		Scan(&maxAgents, &n)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("population: registration guard: %w", err)
	}
	if maxAgents > 0 && n >= maxAgents {
		return &SurgeError{Type: agentType, Count: n, MaxAgents: maxAgents}, nil
	}
	return nil, nil
}

func surgeAlert(e *SurgeError) alerts.Alert {
	b, _ := json.Marshal(map[string]any{"agent_type": e.Type, "registered": e.Count, "max_agents": e.MaxAgents})
	return alerts.Alert{
		Kind: alerts.KindAgentSurge, Severity: alerts.SevHigh, AgentType: e.Type,
		Summary:  fmt.Sprintf("registration of another %s agent refused: %d registered, max_agents %d", e.Type, e.Count, e.MaxAgents),
		Details:  b,
		DedupKey: "agent_registration_surge:type:" + e.Type,
	}
}
