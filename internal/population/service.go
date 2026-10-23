package population

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
)

// DefaultUnregisteredSurgePerMin: more POL-015 (unregistered agent) denials
// than this within a minute raise unregistered_agent_surge.
const DefaultUnregisteredSurgePerMin = 20

// Service is the population subsystem (docs/PHASE3_DESIGN.md §2). It is the
// decide.Enricher (key "population") and the decide.Observer for copies,
// spawns and action rates, and it backs the instance, agent-type and
// registration-surge APIs.
type Service struct {
	pool     *pgxpool.Pool
	diary    *diary.Diary
	alerts   *alerts.PGStore
	counters Counters
	cfg      config.PopulationConfig
	log      *slog.Logger

	// UnregisteredSurgePerMin overrides DefaultUnregisteredSurgePerMin
	// (negative disables the alert).
	UnregisteredSurgePerMin int
	// Now is the clock (tests); default time.Now.
	Now func() time.Time

	baselines baselineCache
}

var (
	_ decide.Enricher = (*Service)(nil)
	_ decide.Observer = (*Service)(nil)
)

// New builds the service. Zero durations in cfg get the documented defaults.
func New(pool *pgxpool.Pool, d *diary.Diary, al *alerts.PGStore, counters Counters, cfg config.PopulationConfig, log *slog.Logger) (*Service, error) {
	if pool == nil || d == nil || al == nil || counters == nil {
		return nil, errors.New("population: pool, diary, alerts and counters are required")
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 15 * time.Second
	}
	if cfg.StaleAfter <= 0 {
		cfg.StaleAfter = 45 * time.Second
	}
	if cfg.SpikeCooldown <= 0 {
		cfg.SpikeCooldown = 5 * time.Minute
	}
	if cfg.DefaultActionRatePerMin < 0 {
		return nil, errors.New("population: default_action_rate_per_min must be >= 0")
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: pool, diary: d, alerts: al, counters: counters, cfg: cfg, log: log}, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

// Config returns the effective configuration (defaults applied).
func (s *Service) Config() config.PopulationConfig { return s.cfg }

func (s *Service) surgeThreshold() int {
	if s.UnregisteredSurgePerMin == 0 {
		return DefaultUnregisteredSurgePerMin
	}
	return s.UnregisteredSurgePerMin
}

// Key implements decide.Enricher.
func (s *Service) Key() string { return ContextKey }

// Enrich implements decide.Enricher: input.context.population for every
// action. One query reads the agent, its type, live counts and the action's
// instance. agent_live and type_live count fresh live copies plus every
// suspended copy (whatever its heartbeat): a suspended copy keeps its
// copy_cap slot, so the agent's shared token cannot register a fresh copy in
// its place; the counters supply the action and spawn rates. Any error fails
// the decision closed (counters unavailable included).
//
// The action counter is incremented here, at decision time, so the rate
// limit is an atomic check-and-count even under concurrent requests
// (ActionsLastMinute excludes the current action). For a spawn, the spawn
// counter is incremented here too (SpawnsLastMinute includes the current
// attempt); spawn_stats, which feeds the baseline, only records spawns that
// were allowed (observer), so an attack cannot poison its own baseline.
func (s *Service) Enrich(ctx context.Context, a action.Action, st control.State) (any, error) {
	now := s.now()
	pc := EnrichedContext{PolicyContext: PolicyContext{InstanceID: a.InstanceID}}
	if a.InstanceID != "" {
		pc.InstanceStatus = StatusUnregistered
	}
	var (
		agentType                          string
		copyCap, agentLive, typeLive       int
		expectedMax, spawnRate, actionRate int
		instStatus                         *string
	)
	err := s.pool.QueryRow(ctx, `
		SELECT a.type, a.copy_cap, a.require_instances,
			(SELECT count(*) FROM instances i WHERE i.agent_id = a.agent_id AND (i.status = 'live' AND i.last_heartbeat > $2 OR i.status = 'suspended')),
			CASE WHEN a.type = '' THEN 0 ELSE
				(SELECT count(*) FROM instances i JOIN agents b ON b.agent_id = i.agent_id
				 WHERE b.type = a.type AND (i.status = 'live' AND i.last_heartbeat > $2 OR i.status = 'suspended')) END,
			COALESCE(t.expected_max_instances, 0), COALESCE(t.spawn_rate_per_min, 0), COALESCE(t.action_rate_per_min, 0),
			(SELECT CASE WHEN i.status = 'live' AND i.last_heartbeat <= $2 THEN 'stale' ELSE i.status END
			 FROM instances i WHERE i.instance_id = $3 AND i.agent_id = a.agent_id)
		FROM agents a LEFT JOIN agent_types t ON t.type = a.type
		WHERE a.agent_id = $1`, a.AgentID, now.Add(-s.cfg.StaleAfter), a.InstanceID).
		Scan(&agentType, &copyCap, &pc.RequireInstances, &agentLive, &typeLive, &expectedMax, &spawnRate, &actionRate, &instStatus)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Unregistered agent: the control gate (POL-015) refuses it. No
		// counters are touched, so unknown agent ids cannot grow them.
		return &pc, nil
	case err != nil:
		return nil, fmt.Errorf("population: %w", err)
	}
	pc.AgentType, pc.CopyCap, pc.AgentLive, pc.TypeLive = agentType, copyCap, agentLive, typeLive
	pc.TypeExpectedMax, pc.SpawnRateLimit = expectedMax, spawnRate
	pc.ActionRateLimit = actionRate
	if pc.ActionRateLimit == 0 {
		pc.ActionRateLimit = s.cfg.DefaultActionRatePerMin
	}
	if instStatus != nil {
		pc.InstanceStatus = *instStatus
	}

	n, err := s.counters.Incr(ctx, actionCounterKey(a.AgentID), time.Minute)
	if err != nil {
		return nil, err
	}
	pc.ActionsLastMinute = int(n - 1)

	scope := spawnScope(a.AgentID, agentType)
	if IsSpawn(a) {
		n, err = s.counters.Incr(ctx, spawnCounterKey(scope), time.Minute)
	} else {
		n, err = s.counters.Count(ctx, spawnCounterKey(scope), time.Minute)
	}
	if err != nil {
		return nil, err
	}
	pc.SpawnsLastMinute = int(n)
	spikes, err := s.counters.Count(ctx, spikeCounterKey(scope), s.cfg.SpikeCooldown)
	if err != nil {
		return nil, err
	}
	pc.SpawnThrottled = spikes > 0
	if agentType != "" {
		b, err := s.baselines.get(ctx, s.pool, agentType, spawnRate, now)
		if err != nil {
			return nil, fmt.Errorf("population: spawn baseline: %w", err)
		}
		pc.SpawnBaselineLimit = b
	}
	return &pc, nil
}
