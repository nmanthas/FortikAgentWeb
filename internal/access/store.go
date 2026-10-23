package access

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
)

// EventChanged is the Diary event written for every new profile version.
const EventChanged = "access.changed"

// ErrAgentNotFound is returned when writing a profile for an unregistered agent.
var ErrAgentNotFound = errors.New("agent not registered")

const (
	maxReasonLen    = 1000
	maxProfileBytes = 64 << 10
	defaultHistory  = 50
	maxHistory      = 1000
)

// Guard runs inside the write transaction, after the agent row is locked and
// the current version read, so its verdict cannot go stale before commit.
// prev is the current profile (nil when none); next is the validated new
// one. A non-nil error aborts the write and is returned unchanged.
type Guard func(prev, next json.RawMessage) error

// PGStore implements Store on the access_profiles table. Versions are
// append-only (a database trigger forbids UPDATE/DELETE); every new version
// and its access.changed Diary event commit in one transaction.
type PGStore struct {
	pool  *pgxpool.Pool
	diary *diary.Diary
}

var _ Store = (*PGStore)(nil)

func NewPGStore(pool *pgxpool.Pool, d *diary.Diary) *PGStore {
	return &PGStore{pool: pool, diary: d}
}

const profileCols = `agent_id, system, version, profile_json, changed_by, changed_at, reason`

func scanProfile(row pgx.Row) (Profile, error) {
	var p Profile
	var raw []byte
	if err := row.Scan(&p.AgentID, &p.System, &p.Version, &raw, &p.ChangedBy, &p.ChangedAt, &p.Reason); err != nil {
		return Profile{}, err
	}
	p.Profile = json.RawMessage(raw)
	p.ChangedAt = p.ChangedAt.UTC()
	return p, nil
}

// Current returns the newest version, or ErrNotFound.
func (s *PGStore) Current(ctx context.Context, agentID, system string) (Profile, error) {
	p, err := scanProfile(s.pool.QueryRow(ctx, `SELECT `+profileCols+` FROM access_profiles
		WHERE agent_id = $1 AND system = $2 ORDER BY version DESC LIMIT 1`, agentID, system))
	if errors.Is(err, pgx.ErrNoRows) {
		return Profile{}, ErrNotFound
	}
	if err != nil {
		return Profile{}, fmt.Errorf("access profile %s/%s: %w", agentID, system, err)
	}
	return p, nil
}

// All returns the current version for every system that has one, ordered by system.
func (s *PGStore) All(ctx context.Context, agentID string) ([]Profile, error) {
	rows, err := s.pool.Query(ctx, `SELECT DISTINCT ON (system) `+profileCols+` FROM access_profiles
		WHERE agent_id = $1 ORDER BY system, version DESC`, agentID)
	if err != nil {
		return nil, fmt.Errorf("access profiles %s: %w", agentID, err)
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// History returns versions newest first (limit <= 0 means 50; capped at 1000).
func (s *PGStore) History(ctx context.Context, agentID, system string, limit int) ([]Profile, error) {
	if limit <= 0 {
		limit = defaultHistory
	}
	limit = min(limit, maxHistory)
	rows, err := s.pool.Query(ctx, `SELECT `+profileCols+` FROM access_profiles
		WHERE agent_id = $1 AND system = $2 ORDER BY version DESC LIMIT $3`, agentID, system, limit)
	if err != nil {
		return nil, fmt.Errorf("access history %s/%s: %w", agentID, system, err)
	}
	defer rows.Close()
	out := []Profile{}
	for rows.Next() {
		p, err := scanProfile(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PolicyInput returns input.access for Decide. Systems without profiles
// (not in Systems) and agents without a profile get version 0 and a JSON
// null profile (policy denies the latter with POL-020). Store errors are
// returned so Decide fails closed.
func (s *PGStore) PolicyInput(ctx context.Context, agentID, system string) (PolicyInput, error) {
	none := PolicyInput{System: system, Version: 0, Profile: json.RawMessage("null")}
	if !KnownSystem(system) {
		return none, nil
	}
	p, err := s.Current(ctx, agentID, system)
	if errors.Is(err, ErrNotFound) {
		return none, nil
	}
	if err != nil {
		return PolicyInput{}, err
	}
	return PolicyInput{System: system, Version: p.Version, Profile: p.Profile}, nil
}

// Put validates and appends a new version.
func (s *PGStore) Put(ctx context.Context, agentID, system string, profile json.RawMessage, actor, reason string) (Profile, error) {
	return s.PutGuarded(ctx, agentID, system, profile, actor, reason, nil)
}

// PutGuarded is Put with a Guard evaluated against the locked current version.
func (s *PGStore) PutGuarded(ctx context.Context, agentID, system string, profile json.RawMessage, actor, reason string, guard Guard) (Profile, error) {
	if len(profile) > maxProfileBytes {
		return Profile{}, invalid("profile larger than %d bytes", maxProfileBytes)
	}
	next, err := Validate(system, profile)
	if err != nil {
		return Profile{}, err
	}
	return s.write(ctx, agentID, system, actor, reason, guard, func(context.Context, pgx.Tx) (json.RawMessage, map[string]any, error) {
		return next, nil, nil
	})
}

// Revert appends a new version copying `version`.
func (s *PGStore) Revert(ctx context.Context, agentID, system string, version int, actor, reason string) (Profile, error) {
	return s.RevertGuarded(ctx, agentID, system, version, actor, reason, nil)
}

// RevertGuarded is Revert with a Guard evaluated against the locked current version.
// The copied profile is re-validated against today's schema.
func (s *PGStore) RevertGuarded(ctx context.Context, agentID, system string, version int, actor, reason string, guard Guard) (Profile, error) {
	if version < 1 {
		return Profile{}, invalid("version must be >= 1")
	}
	return s.write(ctx, agentID, system, actor, reason, guard, func(ctx context.Context, tx pgx.Tx) (json.RawMessage, map[string]any, error) {
		var raw []byte
		err := tx.QueryRow(ctx, `SELECT profile_json FROM access_profiles WHERE agent_id = $1 AND system = $2 AND version = $3`,
			agentID, system, version).Scan(&raw)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("%w: version %d of %s", ErrNotFound, version, system)
		}
		if err != nil {
			return nil, nil, err
		}
		next, err := Validate(system, raw)
		if err != nil {
			return nil, nil, fmt.Errorf("version %d no longer validates: %w", version, err)
		}
		return next, map[string]any{"reverted_from": version}, nil
	})
}

// write appends one version: lock the agent row (serialises version
// allocation per agent and proves the agent exists), read the current
// version, run the guard, insert, record the Diary event; one transaction.
func (s *PGStore) write(ctx context.Context, agentID, system, actor, reason string, guard Guard,
	nextFn func(context.Context, pgx.Tx) (json.RawMessage, map[string]any, error)) (Profile, error) {
	if !KnownSystem(system) {
		return Profile{}, invalid("unknown system %q (one of %s)", system, strings.Join(Systems, ", "))
	}
	reason = strings.TrimSpace(reason)
	if reason == "" {
		return Profile{}, invalid("a reason is required")
	}
	if len(reason) > maxReasonLen || !utf8.ValidString(reason) || strings.ContainsRune(reason, 0) {
		return Profile{}, invalid("reason must be valid text of at most %d bytes", maxReasonLen)
	}
	if actor == "" {
		return Profile{}, errors.New("access: actor is required")
	}
	var out Profile
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var one int
		err := tx.QueryRow(ctx, `SELECT 1 FROM agents WHERE agent_id = $1 FOR UPDATE`, agentID).Scan(&one)
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrAgentNotFound, agentID)
		}
		if err != nil {
			return err
		}
		var fromVersion int
		var prev json.RawMessage
		var raw []byte
		err = tx.QueryRow(ctx, `SELECT version, profile_json FROM access_profiles
			WHERE agent_id = $1 AND system = $2 ORDER BY version DESC LIMIT 1`, agentID, system).Scan(&fromVersion, &raw)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
		case err != nil:
			return err
		default:
			prev = json.RawMessage(raw)
		}
		next, extra, err := nextFn(ctx, tx)
		if err != nil {
			return err
		}
		if guard != nil {
			if err := guard(prev, next); err != nil {
				return err
			}
		}
		out, err = scanProfile(tx.QueryRow(ctx, `INSERT INTO access_profiles (agent_id, system, version, profile_json, changed_by, reason)
			VALUES ($1, $2, $3, $4, $5, $6) RETURNING `+profileCols, agentID, system, fromVersion+1, []byte(next), actor, reason))
		if err != nil {
			return fmt.Errorf("insert access profile: %w", err)
		}
		// agents.access_profile_version counts profile changes across systems
		// (a cheap "did anything change" marker for caches and the console).
		if _, err := tx.Exec(ctx, `UPDATE agents SET access_profile_version = access_profile_version + 1, updated_at = now()
			WHERE agent_id = $1`, agentID); err != nil {
			return err
		}
		data := map[string]any{
			"system":       system,
			"from_version": fromVersion,
			"to_version":   out.Version,
			"old":          jsonValue(prev),
			"new":          jsonValue(out.Profile),
			"reason":       reason,
		}
		for k, v := range extra {
			data[k] = v
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: EventChanged, Actor: actor, Data: data})
		return err
	})
	if err != nil {
		return Profile{}, err
	}
	return out, nil
}

// jsonValue decodes a profile for embedding in a Diary event (nil = null).
func jsonValue(raw json.RawMessage) any {
	if isNull(raw) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil
	}
	return v
}
