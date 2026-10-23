package baseline

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/decide"
	"fortik/internal/policy"
)

// ContextKey is the enricher's key (input.context.baseline).
const ContextKey = "baseline"

// Rule ids of the baseline policy (policies/fortik/baseline).
const (
	RuleAboveNormal = "POL-660"
	RuleMalformed   = "POL-661"
)

// Options tune the service around the statistics.
type Options struct {
	// FlushInterval: how often counts are written to baseline_hourly
	// (default 5s). Writes are batched off the decision path.
	FlushInterval time.Duration
	// MaintainInterval: retention prune of baseline_hourly and re-sync of the
	// hot store from it (default 1h).
	MaintainInterval time.Duration
	// MaxPending: pending (agent, verb, hour) keys that trigger an early
	// flush (default 5000).
	MaxPending int
	// HistoryCacheTTL bounds how long the statistics of past hours are cached
	// per (agent, verb) (default 1m; they only change at the hour boundary or
	// on a re-sync).
	HistoryCacheTTL time.Duration
	// LoadCheckInterval: how often a decision checks that a hot store that
	// can lose its data (Redis) still holds the loaded counts (default 5s).
	LoadCheckInterval time.Duration
}

// Service is the baseline enricher (decide.Enricher, key "baseline") and
// observer (decide.Observer), the durable writer and the backfill.
type Service struct {
	pool  *pgxpool.Pool
	store Store
	p     Params
	opt   Options
	log   *slog.Logger
	// Now is the clock for maintenance and the API (decisions use the
	// action's server-assigned ts). Tests may replace it.
	Now func() time.Time

	mu      sync.Mutex
	pending map[pendKey]int64
	kick    chan struct{}

	cacheMu sync.Mutex
	cache   map[pendKey]cachedHistory

	loadMu        sync.Mutex
	loadCheckedAt time.Time
}

type pendKey struct {
	agent, verb string
	hour        int64
}

type cachedHistory struct {
	h  History
	at time.Time
}

const historyCacheLimit = 50000

var (
	_ decide.Enricher = (*Service)(nil)
	_ decide.Observer = (*Service)(nil)
)

// New builds the service. store is the hot store (NewStore); pool holds
// baseline_hourly.
func New(pool *pgxpool.Pool, store Store, p Params, opt Options, log *slog.Logger) *Service {
	if opt.FlushInterval <= 0 {
		opt.FlushInterval = 5 * time.Second
	}
	if opt.MaintainInterval <= 0 {
		opt.MaintainInterval = time.Hour
	}
	if opt.MaxPending <= 0 {
		opt.MaxPending = 5000
	}
	if opt.HistoryCacheTTL <= 0 {
		opt.HistoryCacheTTL = time.Minute
	}
	if opt.LoadCheckInterval <= 0 {
		opt.LoadCheckInterval = 5 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Service{pool: pool, store: store, p: p, opt: opt, log: log, Now: time.Now,
		pending: map[pendKey]int64{}, kick: make(chan struct{}, 1), cache: map[pendKey]cachedHistory{}}
}

// Params returns the statistics settings.
func (s *Service) Params() Params { return s.p }

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// counted reports whether an action is counted: registered agents and known
// verbs only (unregistered agents are refused by the control gate; unknown
// verbs fail closed by POL-002), so arbitrary ids cannot grow the store.
func counted(a action.Action, st control.State) bool {
	return st.Registered && a.AgentID != "" && action.KnownVerb(a.Verb)
}

func (s *Service) Key() string { return ContextKey }

// Enrich returns the Context for the action's (agent, verb) in the hour of
// its server timestamp; `current` counts this call. A store failure fails
// the decision closed.
func (s *Service) Enrich(ctx context.Context, a action.Action, st control.State) (any, error) {
	if !counted(a, st) {
		return nil, nil
	}
	if err := s.ensureLoaded(ctx); err != nil {
		return nil, err
	}
	hour := HourStart(a.TS).Unix()
	verb := string(a.Verb)
	hist, err := s.history(ctx, a.AgentID, verb, hour)
	if err != nil {
		return nil, err
	}
	cur, err := s.store.Get(ctx, a.AgentID, verb, hour)
	if err != nil {
		return nil, fmt.Errorf("baseline: %w", err)
	}
	return Evaluate(hist, cur+1, s.p), nil
}

// ensureLoaded reloads the hot store from baseline_hourly when it lost its
// counts since the last load (see LoadMarker). Decisions wait for the reload;
// a failure fails the decision closed.
func (s *Service) ensureLoaded(ctx context.Context) error {
	lm, ok := s.store.(LoadMarker)
	if !ok {
		return nil
	}
	s.loadMu.Lock()
	defer s.loadMu.Unlock()
	now := time.Now()
	if !s.loadCheckedAt.IsZero() && !now.Before(s.loadCheckedAt) && now.Sub(s.loadCheckedAt) < s.opt.LoadCheckInterval {
		return nil
	}
	loaded, err := lm.Loaded(ctx)
	if err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	if !loaded {
		s.log.Warn("baseline hot store lost its counts (redis restart, flush or eviction): reloading from baseline_hourly before deciding")
		if err := s.Flush(ctx); err != nil {
			s.log.Warn("baseline: flush before reload failed; unflushed counts stay pending", "err", err)
		}
		if _, err := s.resync(ctx, HourStart(s.now()).Add(-s.p.Window())); err != nil {
			return err
		}
		s.invalidateCache()
		if err := lm.MarkLoaded(ctx); err != nil {
			return fmt.Errorf("baseline: %w", err)
		}
	}
	s.loadCheckedAt = now
	return nil
}

func (s *Service) history(ctx context.Context, agentID, verb string, hour int64) (History, error) {
	k := pendKey{agentID, verb, hour}
	now := time.Now()
	s.cacheMu.Lock()
	c, ok := s.cache[k]
	s.cacheMu.Unlock()
	if ok && now.Sub(c.at) < s.opt.HistoryCacheTTL && !now.Before(c.at) {
		return c.h, nil
	}
	from := hour - int64(s.p.Days)*24*3600
	series, err := s.store.Series(ctx, agentID, verb, from)
	if err != nil {
		return History{}, fmt.Errorf("baseline: %w", err)
	}
	h := ComputeHistory(series, hour, s.p)
	s.cacheMu.Lock()
	if len(s.cache) >= historyCacheLimit {
		s.cache = map[pendKey]cachedHistory{}
	}
	s.cache[k] = cachedHistory{h: h, at: now}
	s.cacheMu.Unlock()
	return h, nil
}

func (s *Service) invalidateCache() {
	s.cacheMu.Lock()
	s.cache = map[pendKey]cachedHistory{}
	s.cacheMu.Unlock()
}

// AfterDecide counts the decided action in the hot store and queues it for
// baseline_hourly. Wire it LAST among the observers: a failure of an earlier
// observer then rolls the decision back before anything is counted. A hot
// store failure fails the decision closed (like the enricher).
func (s *Service) AfterDecide(ctx context.Context, _ pgx.Tx, out *decide.Outcome, in policy.Input) error {
	if out == nil || !counted(out.Action, in.Agent) || !out.Result.Decision.Executes() {
		// Only executed calls count: held and denied calls must not raise the
		// agent's own baseline (a burst a human denies would otherwise train it).
		return nil
	}
	a := out.Action
	hour := HourStart(a.TS).Unix()
	if err := s.store.Add(ctx, a.AgentID, string(a.Verb), hour, 1); err != nil {
		return fmt.Errorf("baseline: %w", err)
	}
	s.mu.Lock()
	s.pending[pendKey{a.AgentID, string(a.Verb), hour}]++
	n := len(s.pending)
	s.mu.Unlock()
	if n >= s.opt.MaxPending {
		select {
		case s.kick <- struct{}{}:
		default:
		}
	}
	return nil
}

// Flush writes the pending counts to baseline_hourly in one statement
// (additive upsert, rows in key order so concurrent flushers from several
// processes cannot deadlock). On failure the counts stay pending.
func (s *Service) Flush(ctx context.Context) error {
	s.mu.Lock()
	batch := s.pending
	s.pending = map[pendKey]int64{}
	s.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	keys := make([]pendKey, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.agent != b.agent {
			return a.agent < b.agent
		}
		if a.verb != b.verb {
			return a.verb < b.verb
		}
		return a.hour < b.hour
	})
	agents := make([]string, len(keys))
	verbs := make([]string, len(keys))
	hours := make([]time.Time, len(keys))
	counts := make([]int64, len(keys))
	for i, k := range keys {
		agents[i], verbs[i], hours[i], counts[i] = k.agent, k.verb, time.Unix(k.hour, 0).UTC(), batch[k]
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO baseline_hourly (agent_id, verb, hour, count)
		SELECT * FROM unnest($1::text[], $2::text[], $3::timestamptz[], $4::bigint[])
		ON CONFLICT (agent_id, verb, hour) DO UPDATE SET count = baseline_hourly.count + EXCLUDED.count`,
		agents, verbs, hours, counts)
	if err != nil {
		s.mu.Lock()
		for k, n := range batch {
			s.pending[k] += n
		}
		s.mu.Unlock()
		return fmt.Errorf("baseline: flush: %w", err)
	}
	return nil
}

// Pending returns how many (agent, verb, hour) counts await a flush.
func (s *Service) Pending() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.pending)
}

// Backfill loads the window from baseline_hourly into the hot store (max-
// merge: never lowers a hot count). When baseline_hourly has nothing in the
// window, it is first seeded from the actions table (every recorded,
// non-fail-closed action of a known verb). Call it before serving decisions.
func (s *Service) Backfill(ctx context.Context) (int, error) {
	from := HourStart(s.now()).Add(-s.p.Window())
	var found bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM baseline_hourly WHERE hour >= $1)`, from).Scan(&found); err != nil {
		return 0, fmt.Errorf("baseline: backfill: %w", err)
	}
	if !found {
		verbs := make([]string, 0, len(action.Verbs()))
		for _, v := range action.Verbs() {
			verbs = append(verbs, string(v))
		}
		tag, err := s.pool.Exec(ctx, `
			INSERT INTO baseline_hourly (agent_id, verb, hour, count)
			SELECT agent_id, verb, date_trunc('hour', ts AT TIME ZONE 'UTC') AT TIME ZONE 'UTC', count(*)
			FROM actions
			WHERE ts >= $1 AND NOT fail_closed AND verb = ANY($2) AND decision IN ('allow', 'allow_reduced')
			GROUP BY 1, 2, 3
			ON CONFLICT (agent_id, verb, hour) DO NOTHING`, from, verbs)
		if err != nil {
			return 0, fmt.Errorf("baseline: seed from actions: %w", err)
		}
		if tag.RowsAffected() > 0 {
			s.log.Info("baseline seeded from the actions table", "rows", tag.RowsAffected())
		}
	}
	n, err := s.resync(ctx, from)
	if err != nil {
		return n, err
	}
	s.invalidateCache()
	if lm, ok := s.store.(LoadMarker); ok {
		if err := lm.MarkLoaded(ctx); err != nil {
			return n, fmt.Errorf("baseline: %w", err)
		}
	}
	return n, nil
}

// resync streams baseline_hourly rows from `from` into the hot store.
func (s *Service) resync(ctx context.Context, from time.Time) (int, error) {
	rows, err := s.pool.Query(ctx, `SELECT agent_id, verb, hour, count FROM baseline_hourly WHERE hour >= $1 ORDER BY agent_id, verb, hour`, from)
	if err != nil {
		return 0, fmt.Errorf("baseline: load: %w", err)
	}
	defer rows.Close()
	const chunk = 2000
	batch := make([]Row, 0, chunk)
	total := 0
	for rows.Next() {
		var r Row
		var h time.Time
		if err := rows.Scan(&r.AgentID, &r.Verb, &h, &r.Count); err != nil {
			return total, fmt.Errorf("baseline: load: %w", err)
		}
		if !action.KnownVerb(action.Verb(r.Verb)) {
			continue
		}
		r.Hour = HourStart(h).Unix()
		batch = append(batch, r)
		if len(batch) == chunk {
			if err := s.store.Merge(ctx, batch); err != nil {
				return total, fmt.Errorf("baseline: %w", err)
			}
			total += len(batch)
			batch = batch[:0]
		}
	}
	if err := rows.Err(); err != nil {
		return total, fmt.Errorf("baseline: load: %w", err)
	}
	if len(batch) > 0 {
		if err := s.store.Merge(ctx, batch); err != nil {
			return total, fmt.Errorf("baseline: %w", err)
		}
		total += len(batch)
	}
	return total, nil
}

// Prune deletes baseline_hourly rows older than days+1 and drops the same
// hours from the hot store. It returns the number of rows deleted.
func (s *Service) Prune(ctx context.Context) (int64, error) {
	before := HourStart(s.now()).Add(-s.p.Retention())
	tag, err := s.pool.Exec(ctx, `DELETE FROM baseline_hourly WHERE hour < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("baseline: prune: %w", err)
	}
	if err := s.store.Prune(ctx, before.Unix()); err != nil {
		return tag.RowsAffected(), fmt.Errorf("baseline: prune: %w", err)
	}
	return tag.RowsAffected(), nil
}

// Run prunes once, then flushes every FlushInterval (or early when
// MaxPending is reached) and prunes + re-syncs every MaintainInterval, until
// ctx is cancelled; then it flushes one last time. Errors are logged and
// retried on the next tick. Call Backfill before Run (and before serving).
func (s *Service) Run(ctx context.Context) {
	flush := time.NewTicker(s.opt.FlushInterval)
	defer flush.Stop()
	maint := time.NewTicker(s.opt.MaintainInterval)
	defer maint.Stop()
	if _, err := s.Prune(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("baseline prune failed", "err", err)
	}
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			if err := s.Flush(fctx); err != nil {
				s.log.Error("baseline: final flush failed; counts since the last flush are lost from baseline_hourly", "err", err, "pending", s.Pending())
			}
			cancel()
			return
		case <-flush.C:
		case <-s.kick:
		case <-maint.C:
			s.maintain(ctx)
			continue
		}
		if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
			s.log.Error("baseline flush failed; will retry", "err", err, "pending", s.Pending())
		}
	}
}

func (s *Service) maintain(ctx context.Context) {
	if n, err := s.Prune(ctx); err != nil {
		if ctx.Err() == nil {
			s.log.Error("baseline prune failed", "err", err)
		}
	} else if n > 0 {
		s.log.Info("baseline hours pruned", "rows", n)
	}
	if err := s.Flush(ctx); err != nil && ctx.Err() == nil {
		s.log.Error("baseline flush failed; will retry", "err", err)
	}
	if _, err := s.resync(ctx, HourStart(s.now()).Add(-s.p.Window())); err != nil {
		if ctx.Err() == nil {
			s.log.Error("baseline re-sync failed", "err", err)
		}
	} else {
		s.invalidateCache()
	}
}

// Point is one hour of an API series.
type Point struct {
	Hour  time.Time `json:"hour"`
	Count int64     `json:"count"`
}

// View is the body of GET /v1/agents/{id}/baseline (the console's shape):
// one verb's hourly series over the window (zero-filled, the current hour
// last) and its statistics evaluated against the current hour's count so
// far, plus every verb with counts. Without ?verb= the verb with the most
// calls in the window is shown (ties: alphabetical); with no counts at all,
// verb is null, series empty and method "none".
type View struct {
	AgentID string    `json:"agent_id"`
	From    time.Time `json:"from"` // first hour of the window
	To      time.Time `json:"to"`   // the current (partial) hour
	Params  Params    `json:"params"`
	Verb    *string   `json:"verb"`
	Verbs   []string  `json:"verbs"`
	Context
	Series []Point `json:"series"`
}

// ErrNoAgent: the agent is not registered.
var ErrNoAgent = errors.New("agent not found")

// AgentBaseline builds the View for agentID and verb ("" = busiest verb).
func (s *Service) AgentBaseline(ctx context.Context, agentID, verb string) (View, error) {
	var exists bool
	if err := s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1)`, agentID).Scan(&exists); err != nil {
		return View{}, err
	}
	if !exists {
		return View{}, ErrNoAgent
	}
	cur := HourStart(s.now())
	from := cur.Add(-s.p.Window())
	v := View{AgentID: agentID, From: from, To: cur, Params: s.p, Series: []Point{}}
	verbs, err := s.store.Verbs(ctx, agentID)
	if err != nil {
		return View{}, err
	}
	v.Verbs = append([]string{}, verbs...)
	var series map[int64]int64
	if verb != "" {
		if series, err = s.store.Series(ctx, agentID, verb, from.Unix()); err != nil {
			return View{}, err
		}
	} else {
		var best int64 = -1
		for _, vb := range verbs {
			ser, err := s.store.Series(ctx, agentID, vb, from.Unix())
			if err != nil {
				return View{}, err
			}
			var total int64
			for _, c := range ser {
				total += c
			}
			if total > best {
				best, verb, series = total, vb, ser
			}
		}
	}
	if verb == "" {
		v.Context = Evaluate(History{Method: MethodNone}, 0, s.p)
		return v, nil
	}
	v.Verb = &verb
	v.Context = Compute(series, cur.Unix(), series[cur.Unix()], s.p)
	for h := from; !h.After(cur); h = h.Add(time.Hour) {
		v.Series = append(v.Series, Point{Hour: h, Count: series[h.Unix()]})
	}
	return v, nil
}
