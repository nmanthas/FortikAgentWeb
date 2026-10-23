package control

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
)

// Store is the Postgres-backed control state. Phase 1 reads levels straight
// from the system of record (sub-millisecond by primary key); a Redis hot
// cache arrives with copy counts and baselines, behind this same type.
type Store struct {
	pool  *pgxpool.Pool
	diary *diary.Diary
}

func NewStore(pool *pgxpool.Pool, d *diary.Diary) *Store { return &Store{pool: pool, diary: d} }

// Querier is satisfied by a pool, a conn or a tx.
type Querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Get returns the agent's control state. An unknown agent is returned as
// unregistered (policy refuses it); that is not an error.
func (s *Store) Get(ctx context.Context, agentID string) (State, error) {
	return Get(ctx, s.pool, agentID)
}

func Get(ctx context.Context, q Querier, agentID string) (State, error) {
	st := State{AgentID: agentID}
	var lvl int16
	var suspendedReason *string
	err := q.QueryRow(ctx, `SELECT level, sponsor, type, business_unit, discovered, suspended_at IS NOT NULL, suspended_reason
		FROM agents WHERE agent_id = $1`, agentID).
		Scan(&lvl, &st.Sponsor, &st.Type, &st.Team, &st.Discovered, &st.Suspended, &suspendedReason)
	if suspendedReason != nil {
		st.SuspendedReason = *suspendedReason
	}
	if errors.Is(err, pgx.ErrNoRows) {
		st.Level = Isolated
		st.LevelName = st.Level.String()
		return st, nil
	}
	if err != nil {
		return State{}, fmt.Errorf("control state for %s: %w", agentID, err)
	}
	st.Registered = true
	st.Level = Level(lvl)
	st.LevelName = st.Level.String()
	return st, nil
}

// StepDownTx moves the agent to `to` only if that is MORE restricted than its
// current level (automatic step-down never loosens control). It records the
// change in the Diary inside tx. Returns the previous level and whether it changed.
func (s *Store) StepDownTx(ctx context.Context, tx pgx.Tx, agentID string, to Level, reason, actor string, data map[string]any) (Level, bool, error) {
	if !to.Valid() {
		return 0, false, fmt.Errorf("invalid level %d", to)
	}
	var from int16
	err := tx.QueryRow(ctx, `SELECT level FROM agents WHERE agent_id = $1 FOR UPDATE`, agentID).Scan(&from)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil // unregistered agents are refused by policy; nothing to step down
	}
	if err != nil {
		return 0, false, err
	}
	if Level(from) >= to {
		return Level(from), false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE agents SET level = $2, level_changed_at = now(), updated_at = now() WHERE agent_id = $1`, agentID, int16(to)); err != nil {
		return Level(from), false, err
	}
	ev := map[string]any{"from": Level(from).String(), "to": to.String(), "direction": "down", "automatic": true, "reason": reason}
	for k, v := range data {
		ev[k] = v
	}
	if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: diary.EventLevelChanged, Actor: actor, Data: ev}); err != nil {
		return Level(from), false, err
	}
	return Level(from), true, nil
}

// SetLevel is the operator path (any direction). Phase 1 exposes it only via
// the fortik CLI; the authorised PUT /v1/agents/{id}/level API with
// one-level-at-a-time step-up and role checks arrives with the control ladder phase.
func (s *Store) SetLevel(ctx context.Context, agentID string, to Level, reason, actor string) (Level, error) {
	if !to.Valid() {
		return 0, fmt.Errorf("invalid level %d", to)
	}
	if reason == "" {
		return 0, errors.New("a reason is required to change an agent's level")
	}
	var from int16
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT level FROM agents WHERE agent_id = $1 FOR UPDATE`, agentID).Scan(&from); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("agent %s is not registered", agentID)
			}
			return err
		}
		if Level(from) == to {
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE agents SET level = $2, level_changed_at = now(), updated_at = now() WHERE agent_id = $1`, agentID, int16(to)); err != nil {
			return err
		}
		dir := "down"
		if to < Level(from) {
			dir = "up"
		}
		_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: diary.EventLevelChanged, Actor: actor,
			Data: map[string]any{"from": Level(from).String(), "to": to.String(), "direction": dir, "automatic": false, "reason": reason}})
		return err
	})
	return Level(from), err
}

// Agent is a registry row used by seeding/registration.
type Agent struct {
	AgentID      string
	Name         string
	Type         string
	Platform     string
	Sponsor      string
	BusinessUnit string
	CopyCap      int
	Level        Level
}

// Register inserts or updates an agent's descriptive fields. It never
// changes the level of an existing agent (levels change only through the
// ladder paths, each audited).
func (s *Store) Register(ctx context.Context, a Agent, actor string) (bool, error) {
	if a.CopyCap <= 0 {
		a.CopyCap = 1
	}
	var inserted bool
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			INSERT INTO agents (agent_id, name, type, platform, sponsor, business_unit, copy_cap, level)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
			ON CONFLICT (agent_id) DO UPDATE SET name = EXCLUDED.name, type = EXCLUDED.type, platform = EXCLUDED.platform,
				sponsor = EXCLUDED.sponsor, business_unit = EXCLUDED.business_unit, copy_cap = EXCLUDED.copy_cap, updated_at = now()
			RETURNING (xmax = 0)`,
			a.AgentID, a.Name, a.Type, a.Platform, a.Sponsor, a.BusinessUnit, a.CopyCap, int16(a.Level)).Scan(&inserted)
		if err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: diary.EventAgentRegistered, Actor: actor,
			Data: map[string]any{"name": a.Name, "type": a.Type, "platform": a.Platform, "sponsor": a.Sponsor,
				"business_unit": a.BusinessUnit, "copy_cap": a.CopyCap, "new": inserted}})
		return err
	})
	return inserted, err
}

// SetSuspendedTx marks an agent suspended (reason != "") or resumed (reason
// == "") inside tx and records the change in the Diary. It returns whether
// the state changed (idempotent: suspending a suspended agent is a no-op).
func (s *Store) SetSuspendedTx(ctx context.Context, tx pgx.Tx, agentID string, suspend bool, reason, actor string, data map[string]any) (bool, error) {
	var was bool
	err := tx.QueryRow(ctx, `SELECT suspended_at IS NOT NULL FROM agents WHERE agent_id = $1 FOR UPDATE`, agentID).Scan(&was)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, fmt.Errorf("agent %s is not registered", agentID)
	}
	if err != nil {
		return false, err
	}
	if was == suspend {
		return false, nil
	}
	if suspend {
		if reason == "" {
			return false, errors.New("a reason is required to suspend an agent")
		}
		_, err = tx.Exec(ctx, `UPDATE agents SET suspended_at = now(), suspended_by = $2, suspended_reason = $3, updated_at = now() WHERE agent_id = $1`, agentID, actor, reason)
	} else {
		_, err = tx.Exec(ctx, `UPDATE agents SET suspended_at = NULL, suspended_by = NULL, suspended_reason = NULL, updated_at = now() WHERE agent_id = $1`, agentID)
	}
	if err != nil {
		return false, err
	}
	ev := map[string]any{"suspended": suspend, "reason": reason}
	for k, v := range data {
		ev[k] = v
	}
	evType := diary.EventAgentSuspended
	if !suspend {
		evType = diary.EventAgentResumed
	}
	if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: evType, Actor: actor, Data: ev}); err != nil {
		return false, err
	}
	return true, nil
}
