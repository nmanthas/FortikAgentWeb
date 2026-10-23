package swarm

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/containment"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/diary"
)

// AlertRaiser raises an alert inside the caller's transaction
// (alerts.PGStore implements it).
type AlertRaiser interface {
	RaiseTx(ctx context.Context, tx pgx.Tx, a alerts.Alert) (alerts.Alert, error)
}

// Containment runs one step of a swarm operation across the members
// (containment.Manager implements it).
type Containment interface {
	RunSwarmStep(ctx context.Context, run containment.SwarmRun, step string) ([]containment.Step, error)
	RunSwarmEach(ctx context.Context, run containment.SwarmRun, name string,
		fn func(ctx context.Context, agentID string, level control.Level) (status, detail string)) ([]containment.Step, error)
}

// Options are the optional settings of the service.
type Options struct {
	// HeldTTL is how long a call the observer turns into a breaker hold
	// waits for approvers (use decide.Service.HeldTTL; default 24h).
	HeldTTL time.Duration
	// StaleAfter: a live copy whose last heartbeat is older is not counted
	// for copy surges (config.PopulationConfig.StaleAfter; default 45s).
	StaleAfter time.Duration
	// Signer signs bundle exports (the Diary signing key). Nil: bundle
	// export is refused (ErrNoSigner).
	Signer *diary.Signer
	// ConvergeScanLimit bounds the actions one converging-target pass reads
	// (default 50000; the pass says when it was truncated).
	ConvergeScanLimit int
	// AllowTokenPairs: two API tokens may supply both release votes
	// (config.ApprovalsConfig.AllowTokenPairs; dev only).
	AllowTokenPairs bool
	Log             *slog.Logger
	// Now is the clock (default time.Now); decisions use decide's own clock.
	Now func() time.Time
}

// Service is the swarm subsystem: decide enricher (Key "swarm") and observer,
// background sweep, containment actions and the bundle export.
type Service struct {
	pool    *pgxpool.Pool
	diary   *diary.Diary
	alerts  AlertRaiser
	contain Containment
	cfg     config.SwarmConfig
	opt     Options
	log     *slog.Logger
}

var (
	_ decide.Enricher = (*Service)(nil)
	_ decide.Observer = (*Service)(nil)
)

// New builds the service. pool, diary, alert raiser and containment are
// required. Zero config fields take the plan's defaults (breaker_n 5,
// breaker_window 10m, fanout_limit 10, depth_limit 5, converge_n 8,
// converge_window 10m, sweep_interval 15s); a negative breaker_n disables
// the Max-5 breaker.
func New(pool *pgxpool.Pool, d *diary.Diary, raiser AlertRaiser, cm Containment, cfg config.SwarmConfig, opt Options) (*Service, error) {
	if pool == nil || d == nil || raiser == nil || cm == nil {
		return nil, errors.New("swarm: pool, diary, alert raiser and containment are required")
	}
	if cfg.BreakerN == 0 {
		cfg.BreakerN = 5
	}
	if cfg.BreakerWindow <= 0 {
		cfg.BreakerWindow = 10 * time.Minute
	}
	if cfg.FanoutLimit <= 0 {
		cfg.FanoutLimit = 10
	}
	if cfg.DepthLimit <= 0 {
		cfg.DepthLimit = 5
	}
	if cfg.ConvergeN <= 0 {
		cfg.ConvergeN = 8
	}
	if cfg.ConvergeWindow <= 0 {
		cfg.ConvergeWindow = 10 * time.Minute
	}
	if cfg.SweepInterval <= 0 {
		cfg.SweepInterval = 15 * time.Second
	}
	if opt.HeldTTL <= 0 {
		opt.HeldTTL = 24 * time.Hour
	}
	if opt.StaleAfter <= 0 {
		opt.StaleAfter = 45 * time.Second
	}
	if opt.ConvergeScanLimit <= 0 {
		opt.ConvergeScanLimit = 50000
	}
	log := opt.Log
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: pool, diary: d, alerts: raiser, contain: cm, cfg: cfg, opt: opt, log: log}, nil
}

// Config returns the effective configuration.
func (s *Service) Config() config.SwarmConfig { return s.cfg }

func (s *Service) now() time.Time {
	if s.opt.Now != nil {
		return s.opt.Now().UTC()
	}
	return time.Now().UTC()
}

// lockDiaryHead serialises a swarm write with every decision: decisions
// append to the Diary (locking diary_head) before their observers run, so
// any transaction that changes swarms first takes diary_head too. The lock
// order everywhere is then agents rows -> diary_head -> swarm rows.
func lockDiaryHead(ctx context.Context, tx pgx.Tx) error {
	_, err := tx.Exec(ctx, `SELECT 1 FROM diary_head WHERE id FOR UPDATE`)
	return err
}

var idPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

const maxReason = 1000

// checkReason: required, at most 1000 bytes, newlines and tabs allowed but
// no other control characters.
func checkReason(r string) (string, error) {
	if r == "" || len(r) > maxReason {
		return "", fmt.Errorf("%w: reason is required (at most %d bytes)", ErrInvalid, maxReason)
	}
	blank := true
	for _, c := range r {
		if c == '\n' || c == '\t' {
			continue
		}
		if unicode.IsControl(c) {
			return "", fmt.Errorf("%w: reason contains control characters", ErrInvalid)
		}
		if !unicode.IsSpace(c) {
			blank = false
		}
	}
	if blank {
		return "", fmt.Errorf("%w: reason is required", ErrInvalid)
	}
	return r, nil
}

func checkID(id string) error {
	if !idPattern.MatchString(id) {
		return fmt.Errorf("%w: swarm id must match %s", ErrInvalid, idPattern)
	}
	return nil
}
