package commap

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/config"
	"fortik/internal/diary"
)

// Diary event written by every rollup batch that changed edges. The event
// stream turns it into "edge.updated" on /v1/map/live.
const EventEdgesUpdated = "map.edges_updated"

// AlertKind is the alert raised for a hidden signal.
const AlertKind = "hidden_signal"

// Cursor sources in edge_rollup_state.
const (
	SourceActions     = "actions"
	SourceDelegations = "delegations"
)

const (
	defaultSettle        = 15 * time.Second
	defaultBatch         = 1000
	defaultMaxBatches    = 20
	defaultEgressLook    = 7 * 24 * time.Hour
	defaultInflightHold  = 10 * time.Minute
	maxSamples           = 5
	maxEdgeLabels        = 64
	eventEdges           = 100 // edge rows per Diary event
	pruneChunk           = 5000
	pruneChunksPerTick   = 20
	defaultActor         = "system:commap"
	rollupLockName       = "fortik.commap.rollup"
	maxAlertsPerBatch    = 200
	maxAlertActionIDs    = 5
	maxSignalDetailBytes = 4 << 10
)

// Options tunes the rollup worker (zero values = defaults).
type Options struct {
	// Settle: only actions and delegations at least this old are folded,
	// and never past the start of a writing transaction still in flight
	// (minus Settle), so a decision that commits late is not skipped by
	// the (ts, id) cursor. Default 15s. Tests may set a negative value
	// for "no settle delay".
	Settle time.Duration
	// BatchSize rows per source per transaction (default 1000);
	// MaxBatches per tick (default 20).
	BatchSize  int
	MaxBatches int
	// SensitiveLabels: labels that count for hidden signals 1 and 3.
	// Empty = every data label counts.
	SensitiveLabels []string
	// MemoryMCPServers: MCP servers that are memory stores (default
	// ["memory"], as in policies/fortik/memory/data.json).
	MemoryMCPServers []string
	// EgressLookback: how far back "has made external calls" looks
	// (signal 3; default 7 days).
	EgressLookback time.Duration
	// InflightHold: a writing transaction open longer than this no longer
	// holds the horizon back (logged; default 10m).
	InflightHold time.Duration
	Actor        string
	Now          func() time.Time
}

// Worker folds actions and delegations into edges (exactly once).
type Worker struct {
	pool   *pgxpool.Pool
	diary  *diary.Diary
	alerts alerts.TxRaiser
	cfg    config.MapConfig
	opts   Options
	log    *slog.Logger
}

// ValidateConfig checks the map section (the rollup and the API rely on it).
func ValidateConfig(c config.MapConfig) error {
	switch {
	case c.Window < time.Minute || c.Window > time.Hour || c.Window%time.Second != 0 || int64(time.Hour/time.Second)%int64(c.Window/time.Second) != 0:
		return fmt.Errorf("commap: map.window must be whole seconds between 1m and 1h that divide an hour (got %s)", c.Window)
	case c.RollupInterval <= 0:
		return errors.New("commap: map.rollup_interval must be positive")
	case c.Retention < c.Window:
		return errors.New("commap: map.retention must be at least one window")
	case c.EncodedParamMin < EncodedParamFloor:
		return fmt.Errorf("commap: map.encoded_param_min must be at least %d", EncodedParamFloor)
	}
	return nil
}

// NewWorker returns the rollup worker. All dependencies are required: an
// edge marked hidden without its alert would hide the very signal the map
// exists to surface.
func NewWorker(pool *pgxpool.Pool, d *diary.Diary, raiser alerts.TxRaiser, cfg config.MapConfig, log *slog.Logger, opts Options) (*Worker, error) {
	if pool == nil || d == nil || raiser == nil {
		return nil, errors.New("commap: pool, diary and alert raiser are required")
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	if opts.Settle == 0 {
		opts.Settle = defaultSettle
	}
	if opts.Settle < 0 {
		opts.Settle = 0
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = defaultBatch
	}
	if opts.MaxBatches <= 0 {
		opts.MaxBatches = defaultMaxBatches
	}
	if opts.MemoryMCPServers == nil {
		opts.MemoryMCPServers = []string{"memory"}
	}
	if opts.EgressLookback <= 0 {
		opts.EgressLookback = defaultEgressLook
	}
	if opts.InflightHold <= 0 {
		opts.InflightHold = defaultInflightHold
	}
	if opts.Actor == "" {
		opts.Actor = defaultActor
	}
	for _, l := range opts.SensitiveLabels {
		if !ValidLabel(l) {
			return nil, fmt.Errorf("commap: sensitive label %q is not a valid data label", l)
		}
	}
	return &Worker{pool: pool, diary: d, alerts: raiser, cfg: cfg, opts: opts, log: log}, nil
}

func (w *Worker) now() time.Time {
	if w.opts.Now != nil {
		return w.opts.Now().UTC()
	}
	return time.Now().UTC()
}

// Run rolls up every map.rollup_interval and prunes expired windows until
// ctx ends. Failures are logged and retried on the next tick (the cursor
// only moves with a committed batch, so nothing is lost or doubled).
func (w *Worker) Run(ctx context.Context) {
	t := time.NewTicker(w.cfg.RollupInterval)
	defer t.Stop()
	for {
		if res, err := w.RollupOnce(ctx); err != nil {
			if ctx.Err() == nil {
				w.log.Error("map rollup failed; will retry", "err", err)
			}
		} else if res.Hidden > 0 {
			w.log.Info("map rollup marked hidden signals", "edges", res.Edges, "hidden", res.Hidden)
		}
		if n, err := w.Prune(ctx); err != nil {
			if ctx.Err() == nil {
				w.log.Error("map retention prune failed", "err", err)
			}
		} else if n > 0 {
			w.log.Info("map retention pruned edges", "edges", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Result summarises one RollupOnce call.
type Result struct {
	Actions     int  `json:"actions"`
	Delegations int  `json:"delegations"`
	Edges       int  `json:"edges"`  // edge rows inserted or updated
	Hidden      int  `json:"hidden"` // edge rows marked hidden
	Alerts      int  `json:"alerts"`
	Busy        bool `json:"busy"` // another worker held the rollup lock
}

// RollupOnce folds everything committed up to the horizon, in batches.
func (w *Worker) RollupOnce(ctx context.Context) (Result, error) {
	var total Result
	for i := 0; i < w.opts.MaxBatches; i++ {
		r, more, err := w.batch(ctx)
		total.Actions += r.Actions
		total.Delegations += r.Delegations
		total.Edges += r.Edges
		total.Hidden += r.Hidden
		total.Alerts += r.Alerts
		if err != nil {
			return total, err
		}
		if r.Busy {
			total.Busy = true
			return total, nil
		}
		if !more {
			return total, nil
		}
	}
	return total, nil
}

type cursor struct {
	TS time.Time
	ID string
}

// agg accumulates contributions to one edge within a batch.
type agg struct {
	key      edgeKey
	count    int64
	bytes    int64
	labels   []string
	class    string
	samples  []string
	hiddenID []string // samples that carry a hidden signal (kept first)
	signals  map[string]*sigAgg
	agentID  string
}

type sigAgg struct {
	kind      string
	detail    map[string]any
	actionIDs []string
	labels    []string
	executed  bool // an action carrying this signal ran (allow / allow_reduced)
}

func (w *Worker) mapper(ctx context.Context, q pgx.Tx) (*mapper, error) {
	m := &mapper{window: w.cfg.Window, encodedMin: w.cfg.EncodedParamMin, memoryMCPServers: map[string]bool{}}
	for _, s := range w.opts.MemoryMCPServers {
		m.memoryMCPServers[s] = true
	}
	if len(w.opts.SensitiveLabels) > 0 {
		m.sensitive = map[string]bool{}
		for _, l := range w.opts.SensitiveLabels {
			m.sensitive[l] = true
		}
	}
	var raw []byte
	err := q.QueryRow(ctx, `SELECT config_json FROM integrations WHERE key = 'google_workspace'`).Scan(&raw)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("google_workspace domains: %w", err)
	}
	if err == nil {
		var c struct {
			Primary  string `json:"primary_domain"`
			Internal any    `json:"internal_domains"`
		}
		if json.Unmarshal(raw, &c) == nil {
			if p := normDomain(c.Primary); p != "" {
				m.internalMail = map[string]bool{p: true}
				var list []string
				switch t := c.Internal.(type) {
				case []any:
					list = strList(t)
				case string:
					list = strings.FieldsFunc(t, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' })
				}
				for _, d := range list {
					if d = normDomain(d); d != "" {
						m.internalMail[d] = true
					}
				}
			}
		}
	}
	return m, nil
}

func normDomain(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// horizon is the newest timestamp that is safe to fold: Settle before now,
// and Settle before the start of the oldest writing transaction still open
// (its rows may carry earlier timestamps than rows already committed).
//
// Everything is on the database clock: actions.ts is never earlier than its
// writing transaction's start (decide stamps GREATEST(ts, now())), so an
// action still being written is always newer than this horizon, whatever the
// skew between the Fortik processes' clocks and the database's.
func (w *Worker) horizon(ctx context.Context, tx pgx.Tx) (time.Time, error) {
	var oldest *time.Time
	var dbNow time.Time
	var stale int
	err := tx.QueryRow(ctx, `
		SELECT clock_timestamp(),
		       min(xact_start) FILTER (WHERE xact_start > now() - make_interval(secs => $1)),
		       count(*) FILTER (WHERE xact_start <= now() - make_interval(secs => $1))
		FROM pg_stat_activity
		WHERE datname = current_database() AND pid <> pg_backend_pid() AND backend_xid IS NOT NULL`,
		w.opts.InflightHold.Seconds()).Scan(&dbNow, &oldest, &stale)
	if err != nil {
		return time.Time{}, fmt.Errorf("in-flight transactions: %w", err)
	}
	h := dbNow.UTC().Add(-w.opts.Settle)
	if stale > 0 {
		w.log.Warn("map rollup: writing transactions open longer than the in-flight hold are not waited for; rows they commit later with older timestamps would be missed",
			"transactions", stale, "hold", w.opts.InflightHold)
	}
	if oldest != nil {
		if t := oldest.UTC().Add(-w.opts.Settle); t.Before(h) {
			h = t
		}
	}
	return h, nil
}

func (w *Worker) batch(ctx context.Context) (Result, bool, error) {
	var res Result
	more := false
	err := pgx.BeginFunc(ctx, w.pool, func(tx pgx.Tx) error {
		var got bool
		if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_xact_lock(hashtextextended($1, 0))`, rollupLockName).Scan(&got); err != nil {
			return fmt.Errorf("rollup lock: %w", err)
		}
		if !got {
			res.Busy = true
			return nil
		}
		if _, err := tx.Exec(ctx, `INSERT INTO edge_rollup_state (source) VALUES ($1), ($2) ON CONFLICT (source) DO NOTHING`,
			SourceActions, SourceDelegations); err != nil {
			return fmt.Errorf("rollup state: %w", err)
		}
		cur := map[string]cursor{}
		rows, err := tx.Query(ctx, `SELECT source, last_ts, last_id FROM edge_rollup_state WHERE source IN ($1, $2) FOR UPDATE`,
			SourceActions, SourceDelegations)
		if err != nil {
			return fmt.Errorf("rollup state: %w", err)
		}
		for rows.Next() {
			var s string
			var c cursor
			if err := rows.Scan(&s, &c.TS, &c.ID); err != nil {
				rows.Close()
				return err
			}
			cur[s] = c
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		h, err := w.horizon(ctx, tx)
		if err != nil {
			return err
		}
		acts, err := w.readActions(ctx, tx, cur[SourceActions], h)
		if err != nil {
			return err
		}
		dels, err := w.readDelegations(ctx, tx, cur[SourceDelegations], h)
		if err != nil {
			return err
		}
		res.Actions, res.Delegations = len(acts), len(dels)
		more = len(acts) == w.opts.BatchSize || len(dels) == w.opts.BatchSize
		if len(acts) == 0 && len(dels) == 0 {
			return nil
		}
		m, err := w.mapper(ctx, tx)
		if err != nil {
			return err
		}
		cutoff := windowStart(w.now().Add(-w.cfg.Retention), w.cfg.Window)
		var contribs []contrib
		for _, a := range acts {
			contribs = append(contribs, m.edges(a)...)
		}
		for _, d := range dels {
			if c, ok := m.delegationEdge(d); ok {
				contribs = append(contribs, c)
			}
		}
		kept := contribs[:0]
		for _, c := range contribs {
			if !c.Key.Window.Before(cutoff) {
				kept = append(kept, c)
			}
		}
		if err := w.resolveEgress(ctx, tx, kept); err != nil {
			return err
		}
		aggs := aggregate(kept)
		updated, err := w.upsert(ctx, tx, aggs)
		if err != nil {
			return err
		}
		if err := upsertLinks(ctx, tx, kept); err != nil {
			return err
		}
		res.Edges = len(aggs)
		if len(acts) > 0 {
			last := acts[len(acts)-1]
			if _, err := tx.Exec(ctx, `UPDATE edge_rollup_state SET last_ts = $2, last_id = $3 WHERE source = $1`,
				SourceActions, last.TS, last.ID); err != nil {
				return err
			}
		}
		if len(dels) > 0 {
			last := dels[len(dels)-1]
			if _, err := tx.Exec(ctx, `UPDATE edge_rollup_state SET last_ts = $2, last_id = $3 WHERE source = $1`,
				SourceDelegations, last.CreatedAt, last.ID); err != nil {
				return err
			}
		}
		// Alerts and the Diary event come last: both take the Diary head
		// lock, which every decision also needs, so it is held only briefly.
		n, hidden, err := w.raise(ctx, tx, aggs)
		if err != nil {
			return err
		}
		res.Alerts, res.Hidden = n, hidden
		if len(updated) > 0 {
			if err := w.event(ctx, tx, updated, res); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Result{}, false, err
	}
	return res, more, nil
}

func (w *Worker) readActions(ctx context.Context, tx pgx.Tx, c cursor, horizon time.Time) ([]actionRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT a.action_id, a.agent_id, COALESCE(a.instance_id, ''), a.system, a.verb, a.class, a.decision, a.rule_id,
		       a.target, a.payload_summary, COALESCE(a.decision_json->'matched', '[]'::jsonb), a.ts, COALESCE(g.sponsor, '')
		FROM actions a LEFT JOIN agents g ON g.agent_id = a.agent_id
		WHERE (a.ts, a.action_id) > ($1, $2) AND a.ts <= $3
		ORDER BY a.ts, a.action_id
		LIMIT $4`, c.TS, c.ID, horizon, w.opts.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("read actions: %w", err)
	}
	defer rows.Close()
	var out []actionRow
	for rows.Next() {
		var a actionRow
		var target, summary, matched []byte
		if err := rows.Scan(&a.ID, &a.AgentID, &a.InstanceID, &a.System, &a.Verb, &a.Class, &a.Decision, &a.RuleID,
			&target, &summary, &matched, &a.TS, &a.Sponsor); err != nil {
			return nil, err
		}
		// Unparseable JSON degrades to "no detail", never to a skipped
		// action: the edge (and its class) is still recorded.
		_ = json.Unmarshal(target, &a.Target)
		_ = json.Unmarshal(summary, &a.Summary)
		var ms []struct {
			RuleID string `json:"rule_id"`
		}
		if json.Unmarshal(matched, &ms) == nil {
			for _, m := range ms {
				a.Matched = append(a.Matched, m.RuleID)
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// delegationRow is a delegation hop with the action that opened it (if any).
type delegationRow struct {
	ID        string
	From      string
	To        string
	Status    string
	CreatedAt time.Time
	ActionID  string
	// From the linked action ("" when none).
	ActSystem   string
	ActVerb     string
	ActAgent    string
	ActToAgent  string
	ActClass    string
	ActDecision string
	Summary     action.PayloadSummary
}

func (w *Worker) readDelegations(ctx context.Context, tx pgx.Tx, c cursor, horizon time.Time) ([]delegationRow, error) {
	rows, err := tx.Query(ctx, `
		SELECT d.delegation_id, d.from_agent, d.to_agent, d.status, d.created_at, COALESCE(d.action_id, ''),
		       COALESCE(a.system, ''), COALESCE(a.verb, ''), COALESCE(a.agent_id, ''), COALESCE(a.target->>'to_agent', ''),
		       COALESCE(a.class, ''), COALESCE(a.decision, ''), COALESCE(a.payload_summary, '{}'::jsonb)
		FROM delegations d LEFT JOIN actions a ON a.action_id = d.action_id
		WHERE (d.created_at, d.delegation_id) > ($1, $2) AND d.created_at <= $3
		ORDER BY d.created_at, d.delegation_id
		LIMIT $4`, c.TS, c.ID, horizon, w.opts.BatchSize)
	if err != nil {
		return nil, fmt.Errorf("read delegations: %w", err)
	}
	defer rows.Close()
	var out []delegationRow
	for rows.Next() {
		var d delegationRow
		var summary []byte
		if err := rows.Scan(&d.ID, &d.From, &d.To, &d.Status, &d.CreatedAt, &d.ActionID, &d.ActSystem, &d.ActVerb,
			&d.ActAgent, &d.ActToAgent, &d.ActClass, &d.ActDecision, &summary); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(summary, &d.Summary)
		out = append(out, d)
	}
	return out, rows.Err()
}

// delegationEdge maps a delegation hop to a DELEGATE agent -> agent edge,
// unless the action that opened it already produced that edge (an a2a
// DELEGATE from the same agent to the same agent): each hop counts once.
func (m *mapper) delegationEdge(d delegationRow) (contrib, bool) {
	if d.ActSystem == action.SystemA2A && d.ActVerb == string(action.VerbDelegate) && d.ActAgent == d.From && d.ActToAgent == d.To {
		return contrib{}, false
	}
	from, to := AgentNode(d.From), AgentNode(d.To)
	if from == "" || to == "" {
		return contrib{}, false
	}
	class := d.ActClass
	switch {
	case class == ClassGreen || class == ClassYellow || class == ClassRed:
	case d.Status == "refused":
		class = ClassRed
	default:
		class = ClassGreen
	}
	labels := validLabels(d.Summary.DataLabels)
	c := contrib{Key: edgeKey{windowStart(d.CreatedAt, m.window), from, to, string(action.VerbDelegate)},
		Bytes: max(d.Summary.Bytes, 0), Labels: labels, Class: class, ActionID: d.ActionID, AgentID: d.From,
		Decision: d.ActDecision}
	if from != to && len(m.flagged(labels)) > 0 {
		c.egressTo = d.To
	}
	return c, true
}

// resolveEgress applies hidden signal 3: labelled data passed to an agent
// whose http access profile allows external egress, or that has made
// external calls within the lookback.
func (w *Worker) resolveEgress(ctx context.Context, tx pgx.Tx, cs []contrib) error {
	var ids []string
	for _, c := range cs {
		if c.egressTo != "" && !slices.Contains(ids, c.egressTo) {
			ids = append(ids, c.egressTo)
		}
	}
	if len(ids) == 0 {
		return nil
	}
	rows, err := tx.Query(ctx, `
		SELECT g.id,
		       COALESCE((SELECT p.profile_json->>'external' FROM access_profiles p
		                 WHERE p.agent_id = g.id AND p.system = 'http' ORDER BY p.version DESC LIMIT 1), ''),
		       EXISTS (SELECT 1 FROM actions a WHERE a.agent_id = g.id AND a.ts > $2
		                 AND (a.target->>'external' = 'true'
		                      OR (jsonb_typeof(a.target->'external_domains') = 'number' AND (a.target->>'external_domains')::numeric > 0)))
		FROM unnest($1::text[]) AS g(id)`, ids, w.now().Add(-w.opts.EgressLookback))
	if err != nil {
		return fmt.Errorf("egress check: %w", err)
	}
	defer rows.Close()
	egress := map[string][]string{}
	for rows.Next() {
		var id, ext string
		var called bool
		if err := rows.Scan(&id, &ext, &called); err != nil {
			return err
		}
		var why []string
		switch ext {
		case "any", "allowlist":
			why = append(why, "http_profile:"+ext)
		case "":
			// No http profile: external READ is open by default.
			why = append(why, "no_http_profile:external_read_open")
		}
		if called {
			why = append(why, "external_calls")
		}
		if len(why) > 0 {
			egress[id] = why
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for i := range cs {
		c := &cs[i]
		if why, ok := egress[c.egressTo]; ok && c.egressTo != "" {
			c.Signals = append(c.Signals, signal{Kind: SignalLabelToEgress, Detail: map[string]any{
				"to_agent": c.egressTo, "egress": why}})
		}
	}
	return nil
}

func aggregate(cs []contrib) []*agg {
	byKey := map[edgeKey]*agg{}
	var order []*agg
	for _, c := range cs {
		g, ok := byKey[c.Key]
		if !ok {
			g = &agg{key: c.Key, class: ClassGreen, signals: map[string]*sigAgg{}, agentID: c.AgentID}
			byKey[c.Key] = g
			order = append(order, g)
		}
		g.count++
		g.bytes += c.Bytes
		for _, l := range c.Labels {
			if !slices.Contains(g.labels, l) {
				g.labels = append(g.labels, l)
			}
		}
		g.class = worse(g.class, c.Class)
		if len(c.Signals) > 0 {
			g.class = ClassHidden
			if c.ActionID != "" && !slices.Contains(g.hiddenID, c.ActionID) {
				g.hiddenID = append(g.hiddenID, c.ActionID)
			}
			for _, s := range c.Signals {
				sa, ok := g.signals[s.Kind]
				if !ok {
					sa = &sigAgg{kind: s.Kind, detail: s.Detail}
					g.signals[s.Kind] = sa
				}
				if c.Decision == "allow" || c.Decision == "allow_reduced" {
					sa.executed = true
				}
				if c.ActionID != "" && len(sa.actionIDs) < maxAlertActionIDs && !slices.Contains(sa.actionIDs, c.ActionID) {
					sa.actionIDs = append(sa.actionIDs, c.ActionID)
				}
				for _, l := range c.Labels {
					if !slices.Contains(sa.labels, l) {
						sa.labels = append(sa.labels, l)
					}
				}
			}
		} else if c.ActionID != "" && !slices.Contains(g.samples, c.ActionID) {
			g.samples = append(g.samples, c.ActionID)
		}
	}
	for _, g := range order {
		sort.Strings(g.labels)
		if len(g.labels) > maxEdgeLabels {
			g.labels = g.labels[:maxEdgeLabels]
		}
		s := append(append([]string{}, g.hiddenID...), g.samples...)
		if len(s) > maxSamples {
			s = s[:maxSamples]
		}
		g.samples = s
	}
	return order
}

const upsertSQL = `
	INSERT INTO edges (window_start, from_node, to_node, verb, count, bytes, data_labels, worst_class, sample_action_ids)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
	ON CONFLICT (window_start, from_node, to_node, verb) DO UPDATE SET
		count = edges.count + EXCLUDED.count,
		bytes = edges.bytes + EXCLUDED.bytes,
		data_labels = (SELECT COALESCE(array_agg(DISTINCT l ORDER BY l), '{}')
		               FROM unnest(edges.data_labels || EXCLUDED.data_labels) AS l)[1:64],
		worst_class = CASE WHEN array_position(ARRAY['green','yellow','red','hidden'], EXCLUDED.worst_class)
		                      > array_position(ARRAY['green','yellow','red','hidden'], edges.worst_class)
		                   THEN EXCLUDED.worst_class ELSE edges.worst_class END,
		sample_action_ids = CASE WHEN EXCLUDED.worst_class = 'hidden' AND edges.worst_class <> 'hidden'
		                         THEN (EXCLUDED.sample_action_ids || edges.sample_action_ids)[1:5]
		                         ELSE (edges.sample_action_ids || EXCLUDED.sample_action_ids)[1:5] END
	RETURNING count, bytes, data_labels, worst_class, sample_action_ids`

func (w *Worker) upsert(ctx context.Context, tx pgx.Tx, aggs []*agg) ([]Edge, error) {
	if len(aggs) == 0 {
		return nil, nil
	}
	b := &pgx.Batch{}
	for _, g := range aggs {
		labels := g.labels
		if labels == nil {
			labels = []string{}
		}
		samples := g.samples
		if samples == nil {
			samples = []string{}
		}
		b.Queue(upsertSQL, g.key.Window, g.key.From, g.key.To, g.key.Verb, g.count, g.bytes, labels, g.class, samples)
	}
	br := tx.SendBatch(ctx, b)
	out := make([]Edge, 0, len(aggs))
	for _, g := range aggs {
		ws := g.key.Window
		u := Edge{WindowStart: &ws, From: g.key.From, To: g.key.To, Verb: g.key.Verb}
		if err := br.QueryRow().Scan(&u.Count, &u.Bytes, &u.Labels, &u.WorstClass, &u.SampleActionIDs); err != nil {
			_ = br.Close()
			return nil, fmt.Errorf("upsert edge: %w", err)
		}
		out = append(out, u)
	}
	if err := br.Close(); err != nil {
		return nil, err
	}
	return out, nil
}

// pendingSignal is one hidden signal on one aggregated edge, to alert on.
type pendingSignal struct {
	g    *agg
	kind string
}

// raise records one hidden_signal alert per (signal, edge, window): repeats
// in the same window bump the open alert's count. At most maxAlertsPerBatch
// per batch, executed signals first; the rest is never dropped silently: one
// overflow alert lists it (those edges stay marked hidden).
func (w *Worker) raise(ctx context.Context, tx pgx.Tx, aggs []*agg) (int, int, error) {
	var all []pendingSignal
	hidden := 0
	for _, g := range aggs {
		if len(g.signals) == 0 {
			continue
		}
		hidden++
		kinds := make([]string, 0, len(g.signals))
		for k := range g.signals {
			kinds = append(kinds, k)
		}
		sort.Strings(kinds)
		for _, k := range kinds {
			all = append(all, pendingSignal{g, k})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		return all[i].g.signals[all[i].kind].executed && !all[j].g.signals[all[j].kind].executed
	})
	n := 0
	for i, p := range all {
		if n >= maxAlertsPerBatch {
			w.log.Warn("map rollup: alert cap reached for this batch; one overflow alert lists the rest", "cap", maxAlertsPerBatch, "rest", len(all)-i)
			return n, hidden, w.raiseOverflow(ctx, tx, all[i:])
		}
		g, k := p.g, p.kind
		s := g.signals[k]
		sev := alerts.SevWarning
		if s.executed {
			sev = alerts.SevHigh
		}
		details := map[string]any{
			"signal": s.kind, "from": g.key.From, "to": g.key.To, "verb": g.key.Verb,
			"window_start": g.key.Window.Format(time.RFC3339), "action_ids": nonNil(s.actionIDs), "labels": nonNil(s.labels),
			"executed": s.executed,
		}
		if b, err := json.Marshal(s.detail); err == nil && len(b) <= maxSignalDetailBytes {
			details["detail"] = s.detail
		}
		raw, err := json.Marshal(details)
		if err != nil {
			return n, hidden, err
		}
		first := ""
		if len(s.actionIDs) > 0 {
			first = s.actionIDs[0]
		}
		sum := sha256.Sum256([]byte(strings.Join([]string{s.kind, g.key.From, g.key.To, g.key.Verb,
			g.key.Window.Format(time.RFC3339)}, "\x00")))
		agentID := g.agentID
		if len(agentID) > 128 {
			agentID = ""
		}
		if _, err := w.alerts.RaiseTx(ctx, tx, alerts.Alert{
			Kind: AlertKind, Severity: sev, AgentID: agentID, ActionID: first,
			Summary: fmt.Sprintf("hidden signal %s: %s -> %s (%s) in the window from %s",
				s.kind, g.key.From, g.key.To, g.key.Verb, g.key.Window.Format(time.RFC3339)),
			Details:  raw,
			DedupKey: "hidden_signal:" + hex.EncodeToString(sum[:16]),
		}); err != nil {
			return n, hidden, fmt.Errorf("raise hidden_signal alert: %w", err)
		}
		n++
	}
	return n, hidden, nil
}

// raiseOverflow raises one high-severity alert for the hidden signals past
// the per-batch cap, listing up to 50 of them: a burst of cheap signals must
// not bury a real one.
func (w *Worker) raiseOverflow(ctx context.Context, tx pgx.Tx, rest []pendingSignal) error {
	type item struct {
		Signal, From, To, Verb, Window string
		Executed                       bool
	}
	items := make([]item, 0, min(len(rest), 50))
	for _, p := range rest[:min(len(rest), 50)] {
		items = append(items, item{p.kind, p.g.key.From, p.g.key.To, p.g.key.Verb, p.g.key.Window.Format(time.RFC3339),
			p.g.signals[p.kind].executed})
	}
	raw, err := json.Marshal(map[string]any{"signal": "overflow", "not_alerted": len(rest), "edges": items, "cap": maxAlertsPerBatch})
	if err != nil {
		return err
	}
	if _, err := w.alerts.RaiseTx(ctx, tx, alerts.Alert{
		Kind: AlertKind, Severity: alerts.SevHigh,
		Summary: fmt.Sprintf("hidden signals: %d more in one rollup batch than the %d alerted; the edges are marked hidden on the map (see details)",
			len(rest), maxAlertsPerBatch),
		Details:  raw,
		DedupKey: "hidden_signal:overflow:" + rest[0].g.key.Window.Format(time.RFC3339),
	}); err != nil {
		return fmt.Errorf("raise hidden_signal overflow alert: %w", err)
	}
	return nil
}

// event writes the updated edge rows (each the full row after the upsert)
// to the Diary in chunks: /v1/map/live sends each row as "edge.updated".
func (w *Worker) event(ctx context.Context, tx pgx.Tx, updated []Edge, res Result) error {
	var evs []diary.Event
	for i := 0; i < len(updated); i += eventEdges {
		chunk := updated[i:min(i+eventEdges, len(updated))]
		evs = append(evs, diary.Event{EventType: EventEdgesUpdated, Actor: w.opts.Actor, Data: map[string]any{
			"edges": chunk, "part": i/eventEdges + 1, "parts": (len(updated) + eventEdges - 1) / eventEdges,
			"actions": res.Actions, "delegations": res.Delegations, "hidden": res.Hidden,
		}})
	}
	_, err := w.diary.AppendTx(ctx, tx, evs...)
	return err
}

// upsertLinks records, per window, which agent's calls through a hub app
// went to which external domain (edge_links), in key order.
func upsertLinks(ctx context.Context, tx pgx.Tx, cs []contrib) error {
	type linkKey struct {
		ws                      time.Time
		hub, dest, verb, origin string
	}
	counts := map[linkKey]int64{}
	for _, c := range cs {
		if c.Origin != "" {
			counts[linkKey{c.Key.Window, c.Key.From, c.Key.To, c.Key.Verb, c.Origin}]++
		}
	}
	if len(counts) == 0 {
		return nil
	}
	keys := make([]linkKey, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		switch {
		case !a.ws.Equal(b.ws):
			return a.ws.Before(b.ws)
		case a.hub != b.hub:
			return a.hub < b.hub
		case a.dest != b.dest:
			return a.dest < b.dest
		case a.verb != b.verb:
			return a.verb < b.verb
		}
		return a.origin < b.origin
	})
	b := &pgx.Batch{}
	for _, k := range keys {
		b.Queue(`INSERT INTO edge_links (window_start, origin, hub, dest, verb, count) VALUES ($1, $2, $3, $4, $5, $6)
			ON CONFLICT (window_start, hub, dest, verb, origin) DO UPDATE SET count = edge_links.count + EXCLUDED.count`,
			k.ws, k.origin, k.hub, k.dest, k.verb, counts[k])
	}
	if err := tx.SendBatch(ctx, b).Close(); err != nil {
		return fmt.Errorf("edge links: %w", err)
	}
	return nil
}

// Prune deletes edge windows older than map.retention (in chunks).
func (w *Worker) Prune(ctx context.Context) (int64, error) {
	cutoff := windowStart(w.now().Add(-w.cfg.Retention), w.cfg.Window)
	var total int64
	for i := 0; i < pruneChunksPerTick; i++ {
		tag, err := w.pool.Exec(ctx, `
			DELETE FROM edges WHERE (window_start, from_node, to_node, verb) IN (
				SELECT window_start, from_node, to_node, verb FROM edges WHERE window_start < $1 LIMIT $2)`,
			cutoff, pruneChunk)
		if err != nil {
			return total, err
		}
		total += tag.RowsAffected()
		if tag.RowsAffected() < pruneChunk {
			break
		}
	}
	if _, err := w.pool.Exec(ctx, `DELETE FROM edge_links WHERE window_start < $1`, cutoff); err != nil {
		return total, err
	}
	return total, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
