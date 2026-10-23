package shadow

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/control"
	"fortik/internal/diary"
)

// Config wires a Service. Pool, Diary and Alerts are required.
type Config struct {
	Pool   *pgxpool.Pool
	Diary  *diary.Diary
	Alerts AlertRaiser
	// Discoverers scan one system each. A discoverer that also implements
	// Revoker revokes that system's findings.
	Discoverers []Discoverer
	// Revokers adds revokers that are not discoverers.
	Revokers []Revoker
	// ScanTimeout bounds one scan (default 5m).
	ScanTimeout time.Duration
	Log         *slog.Logger
	Now         func() time.Time
}

// Service runs scans and the security actions on findings.
type Service struct {
	pool        *pgxpool.Pool
	diary       *diary.Diary
	alerts      AlertRaiser
	discoverers []Discoverer
	revokers    map[string]Revoker
	timeout     time.Duration
	log         *slog.Logger
	now         func() time.Time

	scanMu sync.Mutex // one scan at a time
	lastMu sync.Mutex
	last   *Report
}

// NewService validates cfg.
func NewService(cfg Config) (*Service, error) {
	if cfg.Pool == nil || cfg.Diary == nil || cfg.Alerts == nil {
		return nil, errors.New("shadow: pool, diary and alerts are required")
	}
	if cfg.ScanTimeout <= 0 {
		cfg.ScanTimeout = defaultScanTimeout
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	s := &Service{pool: cfg.Pool, diary: cfg.Diary, alerts: cfg.Alerts, timeout: cfg.ScanTimeout,
		log: cfg.Log.With("component", "shadow"), now: cfg.Now, revokers: map[string]Revoker{}}
	seen := map[string]bool{}
	for _, d := range cfg.Discoverers {
		if d == nil {
			return nil, errors.New("shadow: nil discoverer")
		}
		if seen[d.System()] {
			return nil, fmt.Errorf("shadow: two discoverers for %s", d.System())
		}
		if !validSystem[d.System()] || d.System() == SystemTraffic {
			return nil, fmt.Errorf("shadow: discoverer for unknown system %q", d.System())
		}
		seen[d.System()] = true
		s.discoverers = append(s.discoverers, d)
		if r, ok := d.(Revoker); ok {
			s.revokers[d.System()] = r
		}
	}
	for _, r := range cfg.Revokers {
		if r == nil {
			return nil, errors.New("shadow: nil revoker")
		}
		s.revokers[r.System()] = r
	}
	return s, nil
}

// allSystems are reported in every scan: a system without a discoverer is
// "not_configured" (not scanned), never "nothing found".
var allSystems = []string{SystemPostgres, SystemGitHub, SystemAWS, SystemGoogle}

// Scan runs every discoverer and applies what they found. Only one scan
// runs at a time (ErrScanRunning).
func (s *Service) Scan(ctx context.Context, actor, reason string) (Report, error) {
	if !s.scanMu.TryLock() {
		return Report{}, ErrScanRunning
	}
	defer s.scanMu.Unlock()
	if actor == "" {
		actor = actorScanner
	}
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	rep := Report{ScanID: action.NewID("shs"), Actor: actor, Reason: Clean(reason, 1000), StartedAt: s.now().UTC(), Systems: []ScanResult{}, NotScanned: []string{}}

	results := make([][]ScanResult, len(s.discoverers))
	var wg sync.WaitGroup
	for i, d := range s.discoverers {
		wg.Add(1)
		go func(i int, d Discoverer) {
			defer wg.Done()
			defer func() {
				if p := recover(); p != nil {
					s.log.Error("shadow discoverer panicked", "system", d.System(), "panic", fmt.Sprint(p))
					results[i] = []ScanResult{{System: d.System(), Status: ScanError, Detail: "discoverer failed unexpectedly; not scanned"}}
				}
			}()
			results[i] = d.Discover(ctx)
		}(i, d)
	}
	wg.Wait()
	covered := map[string]bool{}
	for i, d := range s.discoverers {
		res := results[i]
		if len(res) == 0 {
			res = []ScanResult{{System: d.System(), Status: ScanError, Detail: "discoverer returned no result; not scanned"}}
		}
		for _, r := range res {
			if r.System == "" {
				r.System = d.System()
			}
			covered[r.System] = true
			rep.Systems = append(rep.Systems, s.applyResult(ctx, r, actor))
		}
	}
	for _, sys := range allSystems {
		if !covered[sys] {
			rep.Systems = append(rep.Systems, ScanResult{System: sys, Status: ScanNotConfigured,
				Detail: "no discoverer is wired for this system: not scanned"})
		}
	}
	for _, r := range rep.Systems {
		rep.Found += r.Found
		rep.Software += r.Software
		rep.New += r.New
		rep.Flagged += r.Flagged
		if r.Status == ScanNotConfigured || r.Status == ScanError {
			name := r.System
			if r.Integration != "" && r.Integration != r.System {
				name = r.Integration
			}
			rep.NotScanned = append(rep.NotScanned, name)
		}
	}
	rep.FinishedAt = s.now().UTC()
	sys := make([]map[string]any, 0, len(rep.Systems))
	for _, r := range rep.Systems {
		sys = append(sys, map[string]any{"system": r.System, "integration": r.Integration, "status": r.Status, "detail": r.Detail,
			"credentials": r.Found, "used_by_software": r.Software, "new_findings": r.New, "newly_flagged": r.Flagged, "not_recorded": r.Failed})
	}
	if _, err := s.diary.Append(context.WithoutCancel(ctx), diary.Event{EventType: EventScanned, Actor: actor, Data: map[string]any{
		"scan_id": rep.ScanID, "reason": rep.Reason, "systems": sys, "credentials": rep.Found, "used_by_software": rep.Software,
		"new_findings": rep.New, "newly_flagged": rep.Flagged, "not_scanned": rep.NotScanned}}); err != nil {
		s.log.Error("shadow: could not record scan in the diary", "err", err)
	}
	s.lastMu.Lock()
	cp := rep
	s.last = &cp
	s.lastMu.Unlock()
	return rep, nil
}

func (s *Service) applyResult(ctx context.Context, r ScanResult, actor string) ScanResult {
	r.Found = len(r.Credentials)
	r.Software, r.New, r.Flagged = 0, 0, 0
	if r.Status == "" {
		r.Status = ScanScanned
	}
	r.Detail = Clean(r.Detail, 1000)
	for _, c := range r.Credentials {
		if c.Software {
			r.Software++
		}
		c := c
		var out upsertOut
		err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
			var err error
			out, err = s.upsertTx(ctx, tx, upsertIn{system: r.System, kind: c.Kind, ref: c.Ref, holder: c.Holder, software: c.Software,
				integration: c.Integration, label: c.Label, evidence: c.Evidence, reactivate: true, actor: actor})
			return err
		})
		if err != nil {
			r.Failed++
			s.log.Error("shadow: could not record finding", "system", r.System, "kind", c.Kind, "err", err)
			continue
		}
		if out.isNew {
			r.New++
		}
		if out.flagged {
			r.Flagged++
		}
	}
	if r.Failed > 0 {
		r.Status = ScanPartial
		r.Detail = strings.TrimSpace(r.Detail + fmt.Sprintf(" %d finding(s) could not be recorded (see logs)", r.Failed))
	}
	return r
}

// LastScan returns the most recent scan report of this process (nil if none).
func (s *Service) LastScan() *Report {
	s.lastMu.Lock()
	defer s.lastMu.Unlock()
	if s.last == nil {
		return nil
	}
	cp := *s.last
	return &cp
}

// List returns findings.
func (s *Service) List(ctx context.Context, f Filter) ([]Finding, error) {
	if f.Status != "" && !validStatus[f.Status] {
		return nil, fmt.Errorf("%w: unknown status", ErrInvalid)
	}
	if f.System != "" && !validSystem[f.System] {
		return nil, fmt.Errorf("%w: unknown system", ErrInvalid)
	}
	return listFindings(ctx, s.pool, f)
}

// Get returns one finding.
func (s *Service) Get(ctx context.Context, id string) (Finding, error) {
	if !ValidFindingID(id) {
		return Finding{}, ErrNotFound
	}
	return getFinding(ctx, s.pool, id, false)
}

// Revoke revokes the finding's credential where Fortik can and records
// exactly what happened. Only an OutcomeRevoked result moves the finding
// to "revoked". The reason is optional and recorded in the Diary.
func (s *Service) Revoke(ctx context.Context, id, actor, reason string) (Finding, RevokeResult, error) {
	if err := validText("reason", reason, 1000, false); err != nil {
		return Finding{}, RevokeResult{}, err
	}
	reason = strings.TrimSpace(reason)
	f, err := s.Get(ctx, id)
	if err != nil {
		return Finding{}, RevokeResult{}, err
	}
	if f.Status == StatusRevoked {
		return f, RevokeResult{}, fmt.Errorf("%w: already revoked", ErrState)
	}
	var res RevokeResult
	if f.System == SystemTraffic {
		res = RevokeResult{Outcome: OutcomeManualRequired, Detail: "Fortik did not issue this credential (an unknown caller of Fortik itself); " +
			"Fortik already refuses it. Find and stop the caller at its source (see the hosts in the evidence)."}
	} else if rv, ok := s.revokers[f.System]; ok {
		res = rv.Revoke(ctx, f)
	} else {
		res = RevokeResult{Outcome: OutcomeManualRequired, Detail: fmt.Sprintf("flagged: Fortik cannot revoke %s credentials here; revoke %q in the %s console", f.System, f.CredentialRef, f.System)}
	}
	switch res.Outcome {
	case OutcomeRevoked, OutcomeNotRevoked, OutcomeManualRequired:
	default:
		res = RevokeResult{Outcome: OutcomeNotRevoked, Detail: "revoker returned no outcome: treated as NOT revoked"}
	}
	res.Detail = Clean(res.Detail, 1000)
	ctx = context.WithoutCancel(ctx) // what happened upstream must be recorded
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getFinding(ctx, tx, id, true)
		if err != nil {
			return err
		}
		ev := EventRevokeFailed
		if res.Outcome == OutcomeRevoked {
			ev = EventRevoked
			if cur, err = scanFinding(tx.QueryRow(ctx, `UPDATE shadow_findings SET status = $2, updated_by = $3 WHERE finding_id = $1 RETURNING `+findingColumns,
				id, StatusRevoked, actor)); err != nil {
				return err
			}
		}
		f = cur
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: cur.AgentID, EventType: ev, Actor: actor, Data: map[string]any{
			"finding_id": id, "system": cur.System, "kind": cur.Kind, "credential_ref": cur.CredentialRef,
			"outcome": res.Outcome, "detail": res.Detail, "reason": reason, "status": cur.Status}})
		return err
	})
	if err != nil {
		// The revoke itself may have happened; say so rather than hide it.
		return f, res, fmt.Errorf("%w: revoke outcome %q (%s): %v", ErrNotRecorded, res.Outcome, res.Detail, err)
	}
	return f, res, nil
}

// Dismiss closes a finding as known and accepted. The reason is optional
// and recorded in the Diary.
func (s *Service) Dismiss(ctx context.Context, id, actor, reason string) (Finding, error) {
	if err := validText("reason", reason, 1000, false); err != nil {
		return Finding{}, err
	}
	reason = strings.TrimSpace(reason)
	if !ValidFindingID(id) {
		return Finding{}, ErrNotFound
	}
	var f Finding
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getFinding(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Status != StatusOpen && cur.Status != StatusFlagged {
			return fmt.Errorf("%w: finding is %s", ErrState, cur.Status)
		}
		if f, err = scanFinding(tx.QueryRow(ctx, `UPDATE shadow_findings SET status = $2, updated_by = $3 WHERE finding_id = $1 RETURNING `+findingColumns,
			id, StatusDismissed, actor)); err != nil {
			return err
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: f.AgentID, EventType: EventDismissed, Actor: actor, Data: map[string]any{
			"finding_id": id, "system": f.System, "kind": f.Kind, "credential_ref": f.CredentialRef, "previous_status": cur.Status, "reason": reason}})
		return err
	})
	return f, err
}

// RegisterInput is the body of POST /v1/shadow/{id}/register.
type RegisterInput struct {
	Sponsor string `json:"sponsor"`
	Name    string `json:"name"`
	Team    string `json:"team"`
	Reason  string `json:"reason,omitempty"`
}

func validText(field, v string, max int, required bool) error {
	if required && strings.TrimSpace(v) == "" {
		return fmt.Errorf("%w: %s is required", ErrInvalid, field)
	}
	if len(v) > max {
		return fmt.Errorf("%w: %s is longer than %d bytes", ErrInvalid, field, max)
	}
	if Clean(v, max) != strings.TrimSpace(v) {
		return fmt.Errorf("%w: %s contains control characters or invalid UTF-8", ErrInvalid, field)
	}
	return nil
}

func looksLikeEmail(v string) bool {
	local, domain, ok := strings.Cut(v, "@")
	return ok && local != "" && domain != "" && strings.Contains(domain, ".") && !strings.ContainsAny(v, " \t") && !strings.Contains(domain, "@")
}

// Register gives the finding's agent an owner (creating the agent if the
// finding has none). The agent keeps its level (ISOLATED for a discovered
// agent): stepping up is a separate, audited level change.
func (s *Service) Register(ctx context.Context, id, actor string, in RegisterInput) (Finding, error) {
	in.Sponsor = strings.ToLower(strings.TrimSpace(in.Sponsor))
	in.Name, in.Team = strings.TrimSpace(in.Name), strings.TrimSpace(in.Team)
	if err := validText("sponsor", in.Sponsor, 254, true); err != nil {
		return Finding{}, err
	}
	if !looksLikeEmail(in.Sponsor) {
		return Finding{}, fmt.Errorf("%w: sponsor must be the owner's email address", ErrInvalid)
	}
	if err := validText("name", in.Name, 200, true); err != nil {
		return Finding{}, err
	}
	if err := validText("team", in.Team, 200, false); err != nil {
		return Finding{}, err
	}
	if err := validText("reason", in.Reason, 1000, false); err != nil {
		return Finding{}, err
	}
	if !ValidFindingID(id) {
		return Finding{}, ErrNotFound
	}
	var f Finding
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		cur, err := getFinding(ctx, tx, id, true)
		if err != nil {
			return err
		}
		if cur.Status == StatusRegistered {
			return fmt.Errorf("%w: already registered", ErrState)
		}
		agentID := cur.AgentID
		if agentID == "" {
			agentID = AgentID(cur.System, cur.Kind, cur.CredentialRef)
		}
		created, err := ensureDiscoveredAgent(ctx, tx, agentID, in.Name, cur.System)
		if err != nil {
			return err
		}
		var level int16
		if err := tx.QueryRow(ctx, `UPDATE agents SET sponsor = $2, name = $3, business_unit = $4, updated_at = now()
			WHERE agent_id = $1 RETURNING level`, agentID, in.Sponsor, in.Name, in.Team).Scan(&level); err != nil {
			return fmt.Errorf("shadow: register agent: %w", err)
		}
		if f, err = scanFinding(tx.QueryRow(ctx, `UPDATE shadow_findings SET status = $2, agent_id = $3, updated_by = $4 WHERE finding_id = $1 RETURNING `+findingColumns,
			id, StatusRegistered, agentID, actor)); err != nil {
			return err
		}
		events := []diary.Event{}
		if created {
			events = append(events, diary.Event{AgentID: agentID, EventType: EventAgentFound, Actor: actor, Data: map[string]any{
				"finding_id": id, "system": f.System, "kind": f.Kind, "credential_ref": f.CredentialRef, "name": in.Name,
				"level": control.Isolated.String(), "discovered": true, "copy_cap": 0}})
		}
		events = append(events,
			diary.Event{AgentID: agentID, EventType: diary.EventAgentRegistered, Actor: actor, Data: map[string]any{
				"name": in.Name, "type": AgentTypeShadow, "platform": f.System, "sponsor": in.Sponsor, "business_unit": in.Team,
				"new": created, "via": "shadow_register", "finding_id": id, "discovered": true, "level": control.Level(level).String()}},
			diary.Event{AgentID: agentID, EventType: EventRegistered, Actor: actor, Data: map[string]any{
				"finding_id": id, "system": f.System, "kind": f.Kind, "credential_ref": f.CredentialRef, "sponsor": in.Sponsor,
				"name": in.Name, "team": in.Team, "previous_status": cur.Status, "reason": in.Reason, "level": control.Level(level).String()}})
		_, err = s.diary.AppendTx(ctx, tx, events...)
		return err
	})
	return f, err
}

// Run scans every interval until ctx ends (interval <= 0: manual scans
// only, Run returns at once). The first scan runs after min(interval, 1m).
func (s *Service) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		s.log.Info("shadow discovery: scheduled scans disabled (shadow.sweep_interval = 0); manual scans only")
		return
	}
	first := interval
	if first > time.Minute {
		first = time.Minute
	}
	t := time.NewTimer(first)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		rep, err := s.Scan(ctx, actorScanner, "scheduled scan (shadow.sweep_interval)")
		switch {
		case errors.Is(err, ErrScanRunning):
			s.log.Info("shadow discovery: a scan is already running; skipping this tick")
		case err != nil:
			s.log.Error("shadow discovery scan failed", "err", err)
		default:
			sort.Strings(rep.NotScanned)
			s.log.Info("shadow discovery scan finished", "credentials", rep.Found, "used_by_software", rep.Software,
				"new", rep.New, "flagged", rep.Flagged, "not_scanned", strings.Join(rep.NotScanned, ","))
		}
		t.Reset(interval)
	}
}
