package shadow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
)

// Traffic sources.
const (
	SourceGateway = "gateway"
	SourceHook    = "hook"
	SourcePGProxy = "pgproxy"
	SourceAgentGW = "agentgw"
)

// TrafficEvent is one failed authentication with well-formed credentials
// seen by an interception point. It never carries a secret: an unknown
// bearer token is identified by TokenRef(token) only.
type TrafficEvent struct {
	Source    string // gateway | hook | pgproxy | agentgw
	Kind      string // unknown_token | unknown_agent | unknown_host | unknown_oauth_client
	TokenRef  string // TokenRef(token) for unknown_token (12 hex); never the token
	AgentID   string // the agent id the caller claimed (pgproxy user), if any
	ClientID  string // OAuth client id, for unknown_oauth_client
	Host      string // the caller's address (IP or host, no port)
	UserAgent string // HTTP User-Agent or Postgres application_name
	Detail    string // short context, e.g. "path=/gw/gmail"
}

// TrafficRecorder is what the gateway, hook and pgproxy call on an
// authentication failure. Implementations must never block or fail the
// request path. A nil *Recorder is a valid no-op recorder.
type TrafficRecorder interface {
	RecordTraffic(ev TrafficEvent)
}

// HostOf returns the host part of a "host:port" remote address.
func HostOf(remoteAddr string) string {
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return h
	}
	return remoteAddr
}

// RecorderConfig wires a Recorder. Pool, Diary and Alerts are required.
type RecorderConfig struct {
	Pool   *pgxpool.Pool
	Diary  *diary.Diary
	Alerts AlertRaiser
	// FlushInterval: how often aggregated events are written (default 10s).
	FlushInterval time.Duration
	// MaxPending bounds distinct callers held between flushes (default
	// 1000); further new callers are dropped and counted.
	MaxPending int
	// MaxWritesPerFlush bounds the findings written per flush (default 200).
	MaxWritesPerFlush int
	// MaxNewPerHour bounds NEW traffic findings per hour (default 200), so a
	// flood of random tokens cannot fill the table or the Diary.
	MaxNewPerHour int
	// RegisterAfter: a caller is registered as a discovered agent only after
	// this many failed attempts (default 3), so one random probe never
	// creates an agent.
	RegisterAfter int
	// MaxAgentsPerHour bounds discovered agents created from traffic per
	// hour (default 20).
	MaxAgentsPerHour int
	Log              *slog.Logger
	Now              func() time.Time
}

// Recorder aggregates traffic events in memory (bounded, deduplicated) and
// writes them as findings from a background flusher (Run).
type Recorder struct {
	svc *Service
	cfg RecorderConfig
	log *slog.Logger

	mu      sync.Mutex
	pending map[string]*trafficAgg
	dropped int64
	written int64

	budgetMu    sync.Mutex
	windowStart time.Time
	newInWindow int
	agentsInWin int
}

type trafficAgg struct {
	ev         TrafficEvent
	kind, ref  string
	holder     string
	count      int
	hosts      map[string]bool
	userAgents map[string]bool
	sources    map[string]bool
}

var _ TrafficRecorder = (*Recorder)(nil)

// NewRecorder validates cfg.
func NewRecorder(cfg RecorderConfig) (*Recorder, error) {
	if cfg.Pool == nil || cfg.Diary == nil || cfg.Alerts == nil {
		return nil, errors.New("shadow: recorder needs pool, diary and alerts")
	}
	def := func(v *int, d int) {
		if *v <= 0 {
			*v = d
		}
	}
	def(&cfg.MaxPending, 1000)
	def(&cfg.MaxWritesPerFlush, 200)
	def(&cfg.MaxNewPerHour, 200)
	def(&cfg.RegisterAfter, 3)
	def(&cfg.MaxAgentsPerHour, 20)
	if cfg.FlushInterval <= 0 {
		cfg.FlushInterval = 10 * time.Second
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	svc := &Service{pool: cfg.Pool, diary: cfg.Diary, alerts: cfg.Alerts, log: cfg.Log, now: cfg.Now, revokers: map[string]Revoker{}}
	return &Recorder{svc: svc, cfg: cfg, log: cfg.Log.With("component", "shadow-traffic"), pending: map[string]*trafficAgg{}}, nil
}

var (
	tokenRefPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)
	agentIDPattern  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	knownSources    = map[string]bool{SourceGateway: true, SourceHook: true, SourcePGProxy: true, SourceAgentGW: true}
)

// RecordTraffic queues ev. It never blocks on I/O and never fails: an
// invalid event or a full buffer is dropped (and counted).
func (r *Recorder) RecordTraffic(ev TrafficEvent) {
	if r == nil {
		return
	}
	if !knownSources[ev.Source] {
		r.drop()
		return
	}
	var ref, holder string
	switch ev.Kind {
	case KindUnknownToken:
		if !tokenRefPattern.MatchString(ev.TokenRef) {
			r.drop()
			return
		}
		ref = "token:" + ev.TokenRef
		if agentIDPattern.MatchString(ev.AgentID) {
			holder = ev.AgentID
		}
	case KindUnknownAgent:
		id := ev.AgentID
		if id == "" {
			r.drop()
			return
		}
		if agentIDPattern.MatchString(id) {
			ref = "agent:" + id
		} else {
			ref = "agent-hash:" + shortHash("claimed-agent", id)[:12]
		}
	case KindUnknownOAuthClient:
		c := Clean(ev.ClientID, 128)
		if c == "" {
			r.drop()
			return
		}
		ref = "client:" + c
	case KindUnknownHost:
		h := Clean(ev.Host, 128)
		if h == "" {
			r.drop()
			return
		}
		ref = "host:" + h
	default:
		r.drop()
		return
	}
	key := ev.Kind + "|" + ref
	host, ua := Clean(ev.Host, 128), Clean(ev.UserAgent, 200)
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.pending[key]
	if !ok {
		if len(r.pending) >= r.cfg.MaxPending {
			r.dropped++
			return
		}
		a = &trafficAgg{ev: ev, kind: ev.Kind, ref: ref, holder: holder, hosts: map[string]bool{}, userAgents: map[string]bool{}, sources: map[string]bool{}}
		r.pending[key] = a
	}
	a.count++
	a.ev.Detail = Clean(ev.Detail, 200)
	a.sources[ev.Source] = true
	if host != "" && len(a.hosts) < 10 {
		a.hosts[host] = true
	}
	if ua != "" && len(a.userAgents) < 5 {
		a.userAgents[ua] = true
	}
}

func (r *Recorder) drop() {
	r.mu.Lock()
	r.dropped++
	r.mu.Unlock()
}

// RecorderStats are counters for logs and tests.
type RecorderStats struct {
	Pending int   `json:"pending"`
	Dropped int64 `json:"dropped"`
	Written int64 `json:"written"`
}

// Stats returns the recorder's counters.
func (r *Recorder) Stats() RecorderStats {
	if r == nil {
		return RecorderStats{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return RecorderStats{Pending: len(r.pending), Dropped: r.dropped, Written: r.written}
}

// Run flushes every FlushInterval until ctx ends, then flushes once more.
func (r *Recorder) Run(ctx context.Context) {
	if r == nil {
		return
	}
	t := time.NewTicker(r.cfg.FlushInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			fctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
			_ = r.Flush(fctx)
			cancel()
			return
		case <-t.C:
			fctx, cancel := context.WithTimeout(ctx, r.cfg.FlushInterval+30*time.Second)
			if err := r.Flush(fctx); err != nil {
				r.log.Error("shadow traffic flush failed", "err", err)
			}
			cancel()
		}
	}
}

func setList(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func mergeList(old any, add []string, max int) []any {
	seen := map[string]bool{}
	var out []any
	if l, ok := old.([]any); ok {
		for _, v := range l {
			if s, ok := v.(string); ok && !seen[s] && len(out) < max {
				seen[s] = true
				out = append(out, s)
			}
		}
	}
	for _, s := range add {
		if !seen[s] && len(out) < max {
			seen[s] = true
			out = append(out, s)
		}
	}
	if out == nil {
		out = []any{}
	}
	return out
}

func (r *Recorder) rollWindow() {
	now := r.cfg.Now()
	if now.Sub(r.windowStart) >= time.Hour {
		r.windowStart, r.newInWindow, r.agentsInWin = now, 0, 0
	}
}

// seedBudget starts a new hourly window from what the database already holds
// (traffic findings and traffic-found agents created in the last hour), so a
// restart, or another Fortik process, does not hand out a fresh budget. On a
// query failure the in-memory window is used as before.
func (r *Recorder) seedBudget(ctx context.Context) {
	r.budgetMu.Lock()
	defer r.budgetMu.Unlock()
	now := r.cfg.Now()
	if now.Sub(r.windowStart) < time.Hour {
		return
	}
	var findings, agents int
	err := r.svc.pool.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM shadow_findings WHERE system = $1 AND first_seen >= now() - interval '1 hour'),
		(SELECT count(*) FROM shadow_findings f JOIN agents a ON a.agent_id = f.agent_id
			WHERE f.system = $1 AND a.created_at >= now() - interval '1 hour')`,
		SystemTraffic).Scan(&findings, &agents)
	if err != nil {
		r.log.Warn("traffic budget not seeded from the database", "err", err)
		return
	}
	r.windowStart, r.newInWindow, r.agentsInWin = now, findings, agents
}

// Flush writes the pending events now.
func (r *Recorder) Flush(ctx context.Context) error {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	batch := r.pending
	r.pending = map[string]*trafficAgg{}
	r.mu.Unlock()
	if len(batch) == 0 {
		return nil
	}
	r.seedBudget(ctx)
	keys := make([]string, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []error
	var written, dropped int64
	for i, k := range keys {
		if i >= r.cfg.MaxWritesPerFlush {
			dropped += int64(len(keys) - i)
			break
		}
		a := batch[k]
		ok, err := r.write(ctx, a)
		if err != nil {
			errs = append(errs, err)
			dropped++
			continue
		}
		if ok {
			written++
		} else {
			dropped++
		}
	}
	r.mu.Lock()
	r.written += written
	r.dropped += dropped
	r.mu.Unlock()
	if len(errs) > 0 {
		return fmt.Errorf("shadow: %d traffic finding(s) not written: %w", len(errs), errors.Join(errs...))
	}
	return nil
}

func (r *Recorder) write(ctx context.Context, a *trafficAgg) (bool, error) {
	r.budgetMu.Lock()
	r.rollWindow()
	budgetLeft := r.newInWindow < r.cfg.MaxNewPerHour
	r.budgetMu.Unlock()
	if !budgetLeft {
		var exists bool
		if err := r.svc.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM shadow_findings WHERE system = $1 AND kind = $2 AND credential_ref = $3)`,
			SystemTraffic, a.kind, a.ref).Scan(&exists); err != nil {
			return false, err
		}
		if !exists {
			return false, nil // hourly cap on new traffic findings reached
		}
	}
	hosts, uas, sources := setList(a.hosts), setList(a.userAgents), setList(a.sources)
	label := "unknown caller " + a.ref
	if a.holder != "" {
		label = "unknown token claiming agent " + a.holder
	}
	// Unauthenticated callers can mint these at will: every traffic-found
	// agent from one interception point bumps ONE open alert (each finding
	// and agent is still listed and in the Diary), so a flood cannot bury
	// the alert queue.
	src := a.ev.Source
	if len(a.sources) > 0 {
		src = setList(a.sources)[0]
	}
	in := upsertIn{
		system: SystemTraffic, kind: a.kind, ref: a.ref, holder: a.holder, software: true, label: label, actor: actorTraffic,
		alertDedup: "shadow-traffic:" + src,
		merge: func(old map[string]any) map[string]any {
			ev := map[string]any{}
			for k, v := range old {
				ev[k] = v
			}
			prev := 0
			if n, ok := ev["attempts"].(float64); ok && n > 0 {
				prev = int(n)
			}
			ev["attempts"] = prev + a.count
			ev["sources"] = mergeList(ev["sources"], sources, 4)
			ev["hosts"] = mergeList(ev["hosts"], hosts, 10)
			ev["user_agents"] = mergeList(ev["user_agents"], uas, 5)
			if a.ev.Detail != "" {
				ev["last_detail"] = a.ev.Detail
			}
			if a.ev.AgentID != "" && a.kind == KindUnknownAgent {
				ev["claimed_agent_id"] = Clean(a.ev.AgentID, 128)
			}
			ev["why"] = "failed authentication with a well-formed credential Fortik does not know"
			return ev
		},
		mayFlag: func(f Finding, ev map[string]any) bool {
			n, _ := ev["attempts"].(float64)
			if int(n) < r.cfg.RegisterAfter {
				return false
			}
			r.budgetMu.Lock()
			defer r.budgetMu.Unlock()
			r.rollWindow()
			if r.agentsInWin >= r.cfg.MaxAgentsPerHour {
				return false
			}
			r.agentsInWin++
			return true
		},
	}
	var out upsertOut
	err := pgx.BeginFunc(ctx, r.svc.pool, func(tx pgx.Tx) error {
		var err error
		out, err = r.svc.upsertTx(ctx, tx, in)
		return err
	})
	if err != nil {
		return false, err
	}
	if out.isNew {
		r.budgetMu.Lock()
		r.newInWindow++
		r.budgetMu.Unlock()
	}
	return true, nil
}

// String keeps a recorder printable without internals.
func (r *Recorder) String() string {
	st := r.Stats()
	return fmt.Sprintf("shadow.Recorder{pending=%d dropped=%d written=%d}", st.Pending, st.Dropped, st.Written)
}
