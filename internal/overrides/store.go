package overrides

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/access"
	"fortik/internal/action"
	"fortik/internal/diary"
)

// Diary event types (docs/PHASE3_DESIGN.md §5). Each is written in the same
// transaction as the state change it records.
const (
	EventCreated        = "override.created"
	EventReleased       = "override.released"
	EventExtended       = "override.extended"
	EventMadePermanent  = "override.made_permanent"
	EventRestored       = "override.restored"
	EventRestoreBlocked = "override.restore_blocked"
	// EventSuperseded: at expiry a newer override for the same scope and
	// system was already in force, so this one stepped aside (the newer one
	// keeps enforcing and decides the restore).
	EventSuperseded = "override.superseded"
	// EventCredentialRevoked is broker.EventRevoked: one per agent whose
	// credentials for the suspended system were revoked on create.
	EventCredentialRevoked = "credential.revoked"
)

// Scopes and statuses.
const (
	ScopeAgent = "agent"
	ScopeTeam  = "team" // agents.business_unit

	StatusActive     = "active"
	StatusRestored   = "restored"
	StatusReleased   = "released"
	StatusBlocked    = "blocked" // restore checks failed: still enforced until released
	StatusSuperseded = "superseded"
)

// Duration bounds for timed overrides (API contract: 1 minute .. 30 days).
const (
	MinDuration = time.Minute
	MaxDuration = 30 * 24 * time.Hour
)

// Actor is the Diary actor for changes made by the restore worker.
const Actor = "system:overrides"

// Systems that can be suspended: every system Decide sees actions for.
var Systems = []string{"gmail", "drive", "github", "aws", "postgres", "memory", "mcp", "a2a", "http", "shell", "files", "agents"}

var (
	ErrInvalid       = errors.New("invalid override")
	ErrNotFound      = errors.New("override not found")
	ErrScopeNotFound = errors.New("agent or team not found")
	ErrConflict      = errors.New("override state does not allow this change")
)

const (
	maxReasonLen  = 1000
	maxListLimit  = 1000
	defaultLimit  = 200
	revokeTimeout = 15 * time.Second
)

var (
	agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	idPattern      = regexp.MustCompile(`^ovr_[0-9A-Z]{26}$`)
)

// Revoker revokes every live credential an agent holds on ONE system, with
// that system's real semantics, and describes what was achieved.
// broker.Adapter satisfies it (the lead passes the broker adapters keyed by
// system; the Google adapters are keyed gmail and drive).
type Revoker interface {
	RevokeAgent(ctx context.Context, agentID string) (string, error)
}

// ProfileReverter restores a saved access-profile version (access.PGStore
// satisfies it). It appends a new version and writes access.changed itself.
type ProfileReverter interface {
	Revert(ctx context.Context, agentID, system string, version int, actor, reason string) (access.Profile, error)
}

// CreateRequest is a validated request to create an override.
type CreateRequest struct {
	Scope         string
	ScopeID       string
	System        string
	Mode          string
	Duration      time.Duration // > 0 for a timed override
	UntilReleased bool          // true for "until released" (Duration must be 0)
	Reason        string
}

// ListFilter selects overrides. AgentID matches agent-scope overrides for the
// agent and team-scope overrides for its business unit.
type ListFilter struct {
	AgentID string
	Status  string
	Limit   int
}

// Authorizer runs inside a change transaction with the override row locked,
// so an ownership verdict cannot go stale before commit. A non-nil error
// aborts the change and is returned unchanged.
type Authorizer func(ctx context.Context, q pgx.Tx, o Override) error

// PGStore persists overrides in access_overrides. Every change and its Diary
// event commit in one transaction.
type PGStore struct {
	pool     *pgxpool.Pool
	diary    *diary.Diary
	revokers map[string]Revoker
	log      *slog.Logger
	// Duration bounds (constants in production; tests shorten minDuration).
	minDuration, maxDuration time.Duration
}

// NewPGStore returns the override store. revokers maps a system to the
// broker adapter that revokes that system's credentials; a system without a
// revoker is reported honestly in revoke_result.
func NewPGStore(pool *pgxpool.Pool, d *diary.Diary, revokers map[string]Revoker, log *slog.Logger) *PGStore {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	rv := make(map[string]Revoker, len(revokers))
	for k, v := range revokers {
		if v != nil {
			rv[k] = v
		}
	}
	return &PGStore{pool: pool, diary: d, revokers: rv, log: log, minDuration: MinDuration, maxDuration: MaxDuration}
}

const cols = `override_id, scope, scope_id, system, mode, starts_at, expires_at, restore_profile_version,
	reason, created_by, status, restored_at, revoke_result, blocked_reason`

func scan(row pgx.Row) (Override, error) {
	var o Override
	var expires, restored *time.Time
	var revoke []byte
	var blocked *string
	if err := row.Scan(&o.OverrideID, &o.Scope, &o.ScopeID, &o.System, &o.Mode, &o.StartsAt, &expires,
		&o.RestoreProfileVersion, &o.Reason, &o.CreatedBy, &o.Status, &restored, &revoke, &blocked); err != nil {
		return Override{}, err
	}
	o.StartsAt = o.StartsAt.UTC()
	if expires != nil {
		t := expires.UTC()
		o.ExpiresAt = &t
	}
	if restored != nil {
		t := restored.UTC()
		o.RestoredAt = &t
	}
	if len(revoke) > 0 {
		o.RevokeResult = json.RawMessage(revoke)
	}
	if blocked != nil {
		o.BlockedReason = *blocked
	}
	return o, nil
}

func invalid(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, args...))
}

// ValidMode reports whether m is a known mode.
func ValidMode(m string) bool { return m == ModeSuspended || m == ModeReadOnly }

// KnownSystem reports whether a system can be suspended.
func KnownSystem(s string) bool { return slices.Contains(Systems, s) }

// ValidStatus reports whether s is a stored status.
func ValidStatus(s string) bool {
	switch s {
	case StatusActive, StatusRestored, StatusReleased, StatusBlocked, StatusSuperseded:
		return true
	}
	return false
}

// InForce reports whether an override is enforced (active or blocked).
func (o Override) InForce() bool { return o.Status == StatusActive || o.Status == StatusBlocked }

func cleanReason(r string) (string, error) {
	r = strings.TrimSpace(r)
	if r == "" {
		return "", invalid("a reason is required")
	}
	if len(r) > maxReasonLen || !utf8.ValidString(r) || strings.ContainsRune(r, 0) {
		return "", invalid("reason must be valid text of at most %d bytes", maxReasonLen)
	}
	return r, nil
}

// optionalReason validates a reason that may be empty.
func optionalReason(r string) (string, error) {
	if strings.TrimSpace(r) == "" {
		return "", nil
	}
	return cleanReason(r)
}

func validTeam(s string) bool {
	if s == "" || len(s) > 128 || !utf8.ValidString(s) || strings.TrimSpace(s) != s {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

func (s *PGStore) checkDuration(d time.Duration) error {
	if d < s.minDuration || d > s.maxDuration {
		return invalid("duration must be between %s and %s", s.minDuration, s.maxDuration)
	}
	return nil
}

// Validate checks a create request and returns it normalised.
func (s *PGStore) Validate(req CreateRequest) (CreateRequest, error) {
	switch req.Scope {
	case ScopeAgent:
		if !agentIDPattern.MatchString(req.ScopeID) {
			return req, invalid("scope_id must be an agent id")
		}
	case ScopeTeam:
		if !validTeam(req.ScopeID) {
			return req, invalid("scope_id must be a team (business unit) name of at most 128 printable characters")
		}
	default:
		return req, invalid("scope must be %q or %q", ScopeAgent, ScopeTeam)
	}
	if !KnownSystem(req.System) {
		return req, invalid("unknown system %q (one of %s)", req.System, strings.Join(Systems, ", "))
	}
	if !ValidMode(req.Mode) {
		return req, invalid("mode must be %q or %q", ModeSuspended, ModeReadOnly)
	}
	switch {
	case req.UntilReleased && req.Duration != 0:
		return req, invalid("give either a duration or until_released, not both")
	case !req.UntilReleased:
		if err := s.checkDuration(req.Duration); err != nil {
			return req, err
		}
	}
	r, err := cleanReason(req.Reason)
	if err != nil {
		return req, err
	}
	req.Reason = r
	return req, nil
}

// Create stores a new override (enforced from commit), writes
// override.created, then revokes the live credentials of the affected
// agent(s) for THAT system only and records revoke_result and one
// credential.revoked event per agent. The override is in force before the
// revocation runs, so no new credential can be issued in between.
func (s *PGStore) Create(ctx context.Context, req CreateRequest, actor string, authorize Authorizer) (Override, error) {
	req, err := s.Validate(req)
	if err != nil {
		return Override{}, err
	}
	if actor == "" {
		return Override{}, errors.New("overrides: actor is required")
	}
	id := action.NewID("ovr")
	var o Override
	var targets []string
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		profileVersion := 0
		switch req.Scope {
		case ScopeAgent:
			// Lock order agents -> diary_head, as everywhere else.
			var one int
			err := tx.QueryRow(ctx, `SELECT 1 FROM agents WHERE agent_id = $1 FOR SHARE`, req.ScopeID).Scan(&one)
			if errors.Is(err, pgx.ErrNoRows) {
				return fmt.Errorf("%w: agent %s", ErrScopeNotFound, req.ScopeID)
			}
			if err != nil {
				return err
			}
			if access.KnownSystem(req.System) {
				if err := tx.QueryRow(ctx, `SELECT coalesce(max(version), 0) FROM access_profiles WHERE agent_id = $1 AND system = $2`,
					req.ScopeID, req.System).Scan(&profileVersion); err != nil {
					return err
				}
			}
			targets = []string{req.ScopeID}
		case ScopeTeam:
			rows, err := tx.Query(ctx, `SELECT agent_id FROM agents WHERE business_unit = $1 ORDER BY agent_id`, req.ScopeID)
			if err != nil {
				return err
			}
			targets, err = pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			if len(targets) == 0 {
				return fmt.Errorf("%w: no agents in team %q", ErrScopeNotFound, req.ScopeID)
			}
		}
		if authorize != nil {
			probe := Override{Scope: req.Scope, ScopeID: req.ScopeID, System: req.System, Mode: req.Mode, CreatedBy: actor}
			if err := authorize(ctx, tx, probe); err != nil {
				return err
			}
		}
		var secs any
		if !req.UntilReleased {
			secs = req.Duration.Seconds()
		}
		o, err = scan(tx.QueryRow(ctx, `INSERT INTO access_overrides
				(override_id, scope, scope_id, system, mode, expires_at, restore_profile_version, reason, created_by)
			VALUES ($1, $2, $3, $4, $5,
				CASE WHEN $6::float8 IS NULL THEN NULL ELSE now() + make_interval(secs => $6::float8) END,
				$7, $8, $9)
			RETURNING `+cols,
			id, req.Scope, req.ScopeID, req.System, req.Mode, secs, profileVersion, req.Reason, actor))
		if err != nil {
			return fmt.Errorf("insert override: %w", err)
		}
		data := eventData(o)
		data["until_released"] = o.ExpiresAt == nil
		data["affected_agents"] = targets
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentOf(o), EventType: EventCreated, Actor: actor, Data: data})
		return err
	})
	if err != nil {
		return Override{}, err
	}
	o.RevokeResult = s.revoke(ctx, o, targets, actor)
	return o, nil
}

// revoke runs the system's revoker for each target agent (each with its own
// timeout, independent of the caller's cancellation) and records the result.
// Recording failures are logged: the override is already in force.
func (s *PGStore) revoke(ctx context.Context, o Override, targets []string, actor string) json.RawMessage {
	rctx := context.WithoutCancel(ctx)
	rv, hasRevoker := s.revokers[o.System]
	descs := make(map[string]string, len(targets))
	ok := make(map[string]bool, len(targets))
	for _, agent := range targets {
		if !hasRevoker {
			descs[agent] = fmt.Sprintf("no credential revoker for %s: credentials already issued stay valid until they expire; "+
				"every new action and credential on %s is refused while the override is in force", o.System, o.System)
			continue
		}
		c, cancel := context.WithTimeout(rctx, revokeTimeout)
		desc, err := rv.RevokeAgent(c, agent)
		cancel()
		if err != nil {
			s.log.Error("override: credential revocation failed", "override_id", o.OverrideID, "system", o.System, "agent_id", agent, "err", err)
			desc = "revocation FAILED: " + sanitize(err.Error())
		} else {
			ok[agent] = true
		}
		descs[agent] = sanitize(desc)
	}
	result, err := json.Marshal(map[string]map[string]string{o.System: descs})
	if err != nil { // a map of strings always marshals
		return nil
	}
	wctx, cancel := context.WithTimeout(rctx, 5*time.Second)
	defer cancel()
	err = pgx.BeginFunc(wctx, s.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(wctx, `UPDATE access_overrides SET revoke_result = $2 WHERE override_id = $1`, o.OverrideID, result); err != nil {
			return err
		}
		events := make([]diary.Event, 0, len(targets))
		for _, agent := range targets {
			var marked int64
			if ok[agent] {
				tag, err := tx.Exec(wctx, `UPDATE credential_issuances SET revoked_at = now(), revoke_method = $3
					WHERE agent_id = $1 AND system = $2 AND revoked_at IS NULL AND expires_at > now()`, agent, o.System, descs[agent])
				if err != nil {
					return err
				}
				marked = tag.RowsAffected()
			}
			events = append(events, diary.Event{AgentID: agent, EventType: EventCredentialRevoked, Actor: actor, Data: map[string]any{
				"system":           o.System,
				"succeeded":        ok[agent],
				"method":           descs[agent],
				"issuances_marked": marked,
				"reason":           "override " + o.OverrideID + ": " + o.Reason,
				"override_id":      o.OverrideID,
			}})
		}
		_, err := s.diary.AppendTx(wctx, tx, events...)
		return err
	})
	if err != nil {
		s.log.Error("override: could not record credential revocation", "override_id", o.OverrideID, "err", err)
	}
	return result
}

// sanitize keeps an adapter message short and single-line.
func sanitize(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 300 {
		s = s[:300] + "..."
	}
	return s
}

func agentOf(o Override) string {
	if o.Scope == ScopeAgent {
		return o.ScopeID
	}
	return ""
}

func eventData(o Override) map[string]any {
	d := map[string]any{
		"override_id": o.OverrideID,
		"scope":       o.Scope,
		"scope_id":    o.ScopeID,
		"system":      o.System,
		"mode":        o.Mode,
		"starts_at":   o.StartsAt.Format(time.RFC3339Nano),
		"expires_at":  nil,
		"reason":      o.Reason,
		"created_by":  o.CreatedBy,
		"status":      o.Status,
	}
	if o.ExpiresAt != nil {
		d["expires_at"] = o.ExpiresAt.Format(time.RFC3339Nano)
	}
	if o.RestoreProfileVersion > 0 {
		d["restore_profile_version"] = o.RestoreProfileVersion
	}
	return d
}

// Get returns one override.
func (s *PGStore) Get(ctx context.Context, id string) (Override, error) {
	if !idPattern.MatchString(id) {
		return Override{}, ErrNotFound
	}
	o, err := scan(s.pool.QueryRow(ctx, `SELECT `+cols+` FROM access_overrides WHERE override_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Override{}, ErrNotFound
	}
	return o, err
}

// List returns overrides newest first.
func (s *PGStore) List(ctx context.Context, f ListFilter) ([]Override, error) {
	if f.Status != "" && !ValidStatus(f.Status) {
		return nil, invalid("unknown status %q", f.Status)
	}
	if f.AgentID != "" && !agentIDPattern.MatchString(f.AgentID) {
		return nil, invalid("agent_id is not a valid agent id")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = defaultLimit
	}
	limit = min(limit, maxListLimit)
	rows, err := s.pool.Query(ctx, `SELECT `+cols+` FROM access_overrides o
		WHERE ($1 = '' OR (o.scope = 'agent' AND o.scope_id = $1)
		               OR (o.scope = 'team' AND o.scope_id = (SELECT business_unit FROM agents WHERE agent_id = $1 AND business_unit <> '')))
		  AND ($2 = '' OR o.status = $2)
		ORDER BY o.created_at DESC, o.override_id DESC LIMIT $3`, f.AgentID, f.Status, limit)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Override, error) { return scan(r) })
	if err != nil {
		return nil, err
	}
	if out == nil {
		out = []Override{}
	}
	return out, nil
}

// InForce returns the overrides in force (active or blocked) for an agent,
// directly or through its team, on one system, most restrictive first.
func (s *PGStore) InForce(ctx context.Context, agentID, team, system string) ([]Override, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+cols+` FROM access_overrides
		WHERE status IN ('active', 'blocked') AND system = $3
		  AND ((scope = 'agent' AND scope_id = $1) OR ($2 <> '' AND scope = 'team' AND scope_id = $2))`,
		agentID, team, system)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (Override, error) { return scan(r) })
	if err != nil {
		return nil, err
	}
	SortMostRestrictive(out)
	if out == nil {
		out = []Override{}
	}
	return out, nil
}

// SortMostRestrictive orders overrides so the most restrictive comes first:
// suspended before read_only; then open-ended (until released, or blocked)
// before timed; then the latest restore time first; ties by id.
func SortMostRestrictive(list []Override) {
	sort.SliceStable(list, func(i, j int) bool {
		a, b := list[i], list[j]
		if ra, rb := modeRank(a.Mode), modeRank(b.Mode); ra != rb {
			return ra < rb
		}
		oa, ob := openEnded(a), openEnded(b)
		if oa != ob {
			return oa
		}
		if !oa && !a.ExpiresAt.Equal(*b.ExpiresAt) {
			return a.ExpiresAt.After(*b.ExpiresAt)
		}
		return a.OverrideID < b.OverrideID
	})
}

// MostRestrictive returns the override that wins, or false when none.
func MostRestrictive(list []Override) (Override, bool) {
	if len(list) == 0 {
		return Override{}, false
	}
	c := slices.Clone(list)
	SortMostRestrictive(c)
	return c[0], true
}

// modeRank: unknown modes rank as suspended (fail closed).
func modeRank(m string) int {
	if m == ModeReadOnly {
		return 1
	}
	return 0
}

func openEnded(o Override) bool { return o.ExpiresAt == nil || o.Status == StatusBlocked }

// change locks one override row, authorizes, and applies fn in one
// transaction with the Diary event fn returns.
func (s *PGStore) change(ctx context.Context, id, actor string, authorize Authorizer,
	fn func(tx pgx.Tx, o Override) (Override, diary.Event, error)) (Override, error) {
	if actor == "" {
		return Override{}, errors.New("overrides: actor is required")
	}
	if !idPattern.MatchString(id) {
		return Override{}, ErrNotFound
	}
	var out Override
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		o, err := scan(tx.QueryRow(ctx, `SELECT `+cols+` FROM access_overrides WHERE override_id = $1 FOR UPDATE`, id))
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		if authorize != nil {
			if err := authorize(ctx, tx, o); err != nil {
				return err
			}
		}
		next, ev, err := fn(tx, o)
		if err != nil {
			return err
		}
		ev.AgentID, ev.Actor = agentOf(next), actor
		if _, err := s.diary.AppendTx(ctx, tx, ev); err != nil {
			return err
		}
		out = next
		return nil
	})
	return out, err
}

// Release lifts an override in force now (status released).
func (s *PGStore) Release(ctx context.Context, id, actor, reason string, authorize Authorizer) (Override, error) {
	reason, err := optionalReason(reason)
	if err != nil {
		return Override{}, err
	}
	return s.change(ctx, id, actor, authorize, func(tx pgx.Tx, o Override) (Override, diary.Event, error) {
		if !o.InForce() {
			return o, diary.Event{}, fmt.Errorf("%w: override is %s", ErrConflict, o.Status)
		}
		next, err := scan(tx.QueryRow(ctx, `UPDATE access_overrides SET status = 'released', restored_at = now()
			WHERE override_id = $1 RETURNING `+cols, o.OverrideID))
		if err != nil {
			return o, diary.Event{}, err
		}
		data := eventData(next)
		data["previous_status"] = o.Status
		data["release_reason"] = reason
		return next, diary.Event{EventType: EventReleased, Data: data}, nil
	})
}

// Extend moves a timed, active override's restore time later by d (from its
// current expiry, or from now when that has already passed).
func (s *PGStore) Extend(ctx context.Context, id string, d time.Duration, actor, reason string, authorize Authorizer) (Override, error) {
	if err := s.checkDuration(d); err != nil {
		return Override{}, err
	}
	reason, err := optionalReason(reason)
	if err != nil {
		return Override{}, err
	}
	return s.change(ctx, id, actor, authorize, func(tx pgx.Tx, o Override) (Override, diary.Event, error) {
		switch {
		case o.Status == StatusBlocked:
			return o, diary.Event{}, fmt.Errorf("%w: automatic restore was blocked; release it or make it permanent", ErrConflict)
		case o.Status != StatusActive:
			return o, diary.Event{}, fmt.Errorf("%w: override is %s", ErrConflict, o.Status)
		case o.ExpiresAt == nil:
			return o, diary.Event{}, fmt.Errorf("%w: override is already until released", ErrConflict)
		}
		var withinMax bool
		next, err := scan(tx.QueryRow(ctx, `UPDATE access_overrides
			SET expires_at = greatest(expires_at, now()) + make_interval(secs => $2::float8)
			WHERE override_id = $1 RETURNING `+cols, o.OverrideID, d.Seconds()))
		if err != nil {
			return o, diary.Event{}, err
		}
		if err := tx.QueryRow(ctx, `SELECT $1::timestamptz <= now() + make_interval(secs => $2::float8)`,
			*next.ExpiresAt, s.maxDuration.Seconds()).Scan(&withinMax); err != nil {
			return o, diary.Event{}, err
		}
		if !withinMax {
			return o, diary.Event{}, invalid("an override may not end more than %s from now; make it permanent instead", s.maxDuration)
		}
		data := eventData(next)
		data["from_expires_at"] = o.ExpiresAt.Format(time.RFC3339Nano)
		data["extended_by_seconds"] = int64(d.Seconds())
		data["extend_reason"] = reason
		return next, diary.Event{EventType: EventExtended, Data: data}, nil
	})
}

// MakePermanent turns an override in force into "until released" (a blocked
// override becomes active, still until released).
func (s *PGStore) MakePermanent(ctx context.Context, id, actor, reason string, authorize Authorizer) (Override, error) {
	reason, err := optionalReason(reason)
	if err != nil {
		return Override{}, err
	}
	return s.change(ctx, id, actor, authorize, func(tx pgx.Tx, o Override) (Override, diary.Event, error) {
		if !o.InForce() {
			return o, diary.Event{}, fmt.Errorf("%w: override is %s", ErrConflict, o.Status)
		}
		if o.Status == StatusActive && o.ExpiresAt == nil {
			return o, diary.Event{}, fmt.Errorf("%w: override is already until released", ErrConflict)
		}
		next, err := scan(tx.QueryRow(ctx, `UPDATE access_overrides SET expires_at = NULL, status = 'active'
			WHERE override_id = $1 RETURNING `+cols, o.OverrideID))
		if err != nil {
			return o, diary.Event{}, err
		}
		data := eventData(next)
		data["previous_status"] = o.Status
		data["permanent_reason"] = reason
		if o.ExpiresAt != nil {
			data["from_expires_at"] = o.ExpiresAt.Format(time.RFC3339Nano)
		}
		return next, diary.Event{EventType: EventMadePermanent, Data: data}, nil
	})
}
