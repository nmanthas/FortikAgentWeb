package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/diary"
	"fortik/internal/secrets"
)

// Diary event types.
const (
	EventConfigured = "integration.configured"
	EventTested     = "integration.tested"
	EventDeleted    = "integration.deleted"
)

// CacheTTL bounds how stale Source reads may be in another process; writes
// through this store invalidate its own cache immediately.
const CacheTTL = 2 * time.Second

// ErrChanged is returned by RecordTest when the settings were changed while
// the test ran (the result would describe settings that no longer exist).
var ErrChanged = errors.New("integration settings changed during the test; run it again")

// advisoryClass namespaces the integration advisory locks ("Fint").
const advisoryClass = 0x46696e74

// PGStore keeps integration settings: non-secret config in the integrations
// table, secret fields only in the secret store under SecretName(key, field).
// It implements Source for adapters.
type PGStore struct {
	pool    *pgxpool.Pool
	diary   *diary.Diary
	secrets secrets.Store
	now     func() time.Time
	ttl     time.Duration

	mu    sync.Mutex
	gen   uint64
	byKey map[string]cachedResolved
	bySys map[string]cachedList
}

type cachedResolved struct {
	at  time.Time
	res Resolved
	err error // only ErrNotConfigured is cached
}

type cachedList struct {
	at  time.Time
	res []Resolved
}

var _ Source = (*PGStore)(nil)

// NewPGStore builds the store. sec must be writable for Configure/Delete
// (wrap read-only providers with secrets.AsStore: writes then fail with
// secrets.ErrReadOnly).
func NewPGStore(pool *pgxpool.Pool, d *diary.Diary, sec secrets.Store) *PGStore {
	return &PGStore{
		pool: pool, diary: d, secrets: sec,
		now: func() time.Time { return time.Now().UTC() }, ttl: CacheTTL,
		byKey: map[string]cachedResolved{}, bySys: map[string]cachedList{},
	}
}

// ConfigureInput is the body of PUT /v1/integrations/{key}. A secret set to
// a string replaces it, null removes an optional secret, and an omitted
// secret keeps its current value.
type ConfigureInput struct {
	Config  map[string]json.RawMessage `json:"config"`
	Secrets map[string]*string         `json:"secrets"`
}

const rowCols = `key, system, config_json, secret_fields, status, last_tested_at, COALESCE(last_error, ''), updated_by, updated_at`

func scanRow(row pgx.Row) (Integration, error) {
	var in Integration
	var cfg []byte
	err := row.Scan(&in.Key, &in.System, &cfg, &in.SecretFields, &in.Status, &in.LastTestedAt, &in.LastError, &in.UpdatedBy, &in.UpdatedAt)
	if err != nil {
		return Integration{}, err
	}
	in.Config = json.RawMessage(cfg)
	if in.SecretFields == nil {
		in.SecretFields = []string{}
	}
	in.UpdatedAt = in.UpdatedAt.UTC()
	if in.LastTestedAt != nil {
		t := in.LastTestedAt.UTC()
		in.LastTestedAt = &t
	}
	return in, nil
}

type querier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func getRow(ctx context.Context, q querier, key string) (Integration, error) {
	in, err := scanRow(q.QueryRow(ctx, `SELECT `+rowCols+` FROM integrations WHERE key = $1`, key))
	if errors.Is(err, pgx.ErrNoRows) {
		return Integration{}, fmt.Errorf("%w: %s", ErrNotConfigured, key)
	}
	if err != nil {
		return Integration{}, fmt.Errorf("integrations: read %s: %w", key, err)
	}
	return in, nil
}

// GetIntegration returns one configured integration (no secret values).
func (s *PGStore) GetIntegration(ctx context.Context, key string) (Integration, error) {
	if _, err := ParseKey(key); err != nil {
		return Integration{}, err
	}
	return getRow(ctx, s.pool, key)
}

// ListIntegrations returns every configured integration (no secret values).
func (s *PGStore) ListIntegrations(ctx context.Context) ([]Integration, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+rowCols+` FROM integrations ORDER BY key`)
	if err != nil {
		return nil, fmt.Errorf("integrations: list: %w", err)
	}
	defer rows.Close()
	out := []Integration{}
	for rows.Next() {
		in, err := scanRow(rows)
		if err != nil {
			return nil, fmt.Errorf("integrations: list: %w", err)
		}
		out = append(out, in)
	}
	return out, rows.Err()
}

// lockKey serialises writers of one integration across processes with a
// session-level advisory lock held on a dedicated connection for the whole
// write (secret store first, then the DB transaction).
func (s *PGStore) lockKey(ctx context.Context, key string) (*pgxpool.Conn, func(), error) {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("integrations: acquire connection: %w", err)
	}
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1, hashtext($2))`, advisoryClass, key); err != nil {
		conn.Release()
		return nil, nil, fmt.Errorf("integrations: lock %s: %w", key, err)
	}
	unlock := func() {
		uctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := conn.Exec(uctx, `SELECT pg_advisory_unlock($1, hashtext($2))`, advisoryClass, key); err != nil {
			// Closing the session releases its locks; the pool drops the closed conn.
			_ = conn.Conn().Close(uctx)
		}
		conn.Release()
	}
	return conn, unlock, nil
}

// secretSnapshot remembers the previous value of secrets about to change so
// they can be put back if a later step fails.
type secretSnapshot struct {
	name    string
	value   []byte
	existed bool
	known   bool // false: the previous value could not be read (not restorable)
}

func (s *PGStore) snapshot(ctx context.Context, key string, fields []string) []secretSnapshot {
	out := make([]secretSnapshot, 0, len(fields))
	for _, f := range fields {
		name := SecretName(key, f)
		v, err := s.secrets.Get(ctx, name)
		switch {
		case err == nil:
			out = append(out, secretSnapshot{name: name, value: v, existed: true, known: true})
		case errors.Is(err, secrets.ErrNotFound):
			out = append(out, secretSnapshot{name: name, known: true})
		default:
			out = append(out, secretSnapshot{name: name})
		}
	}
	return out
}

// restore puts snapshotted secrets back (best effort, with its own timeout
// so a cancelled request still restores). It returns a description of what
// could not be restored, or "".
func (s *PGStore) restore(snaps []secretSnapshot) string {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var failed []string
	for _, sn := range snaps {
		var err error
		switch {
		case !sn.known:
			err = errors.New("previous value unreadable")
		case sn.existed:
			err = s.secrets.Put(ctx, sn.name, sn.value)
		default:
			err = s.secrets.Delete(ctx, sn.name)
		}
		if err != nil {
			failed = append(failed, sn.name)
		}
	}
	if len(failed) == 0 {
		return ""
	}
	return fmt.Sprintf("; could not restore secrets %v (re-enter them)", failed)
}

// Configure validates and saves an integration. Secrets are written to the
// secret store first, then the row and the integration.configured Diary
// event commit in one transaction; if that fails the previous secret values
// are restored (best effort). Validation errors wrap ErrInvalid.
func (s *PGStore) Configure(ctx context.Context, key string, in ConfigureInput, actor string) (Integration, error) {
	system, err := ParseKey(key)
	if err != nil {
		return Integration{}, err
	}
	if actor == "" {
		return Integration{}, errors.New("integrations: actor is required")
	}
	schema, _ := SchemaFor(system)
	cfg, err := normalizeConfig(schema, in.Config)
	if err != nil {
		return Integration{}, err
	}
	set, remove, err := validateSecrets(schema, in.Secrets)
	if err != nil {
		return Integration{}, err
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return Integration{}, fmt.Errorf("integrations: encode config: %w", err)
	}

	conn, unlock, err := s.lockKey(ctx, key)
	if err != nil {
		return Integration{}, err
	}
	defer unlock()
	defer s.invalidate()

	prev, err := getRow(ctx, conn, key)
	exists := err == nil
	if err != nil && !errors.Is(err, ErrNotConfigured) {
		return Integration{}, err
	}

	// Final set of secret fields: kept + newly set - removed.
	var final, kept []string
	for _, f := range secretFieldNames(schema) {
		_, isSet := set[f]
		wasSet := exists && slices.Contains(prev.SecretFields, f)
		switch {
		case isSet:
			final = append(final, f)
		case slices.Contains(remove, f):
		case wasSet:
			final = append(final, f)
			kept = append(kept, f)
		}
	}
	for _, f := range schema.Fields {
		if f.Secret && f.Required && !slices.Contains(final, f.Key) {
			return Integration{}, invalid("secret %s (%s) is required", f.Key, f.Label)
		}
	}
	// A kept secret must really be in the store, or the integration would
	// claim settings it cannot use.
	for _, f := range kept {
		if _, err := s.secrets.Get(ctx, SecretName(key, f)); errors.Is(err, secrets.ErrNotFound) {
			return Integration{}, invalid("secret %s is missing from the secret store; enter it again", f)
		} else if err != nil {
			return Integration{}, fmt.Errorf("integrations: check secret %s: %w", f, err)
		}
	}

	changed := make([]string, 0, len(set)+len(remove))
	for f := range set {
		changed = append(changed, f)
	}
	slices.Sort(changed)
	changed = append(changed, remove...)
	snaps := s.snapshot(ctx, key, changed)

	// 1. Secret store.
	var applied []secretSnapshot
	fingerprints := map[string]any{}
	for i, f := range changed {
		var err error
		if v, ok := set[f]; ok {
			err = s.secrets.Put(ctx, SecretName(key, f), []byte(v))
			fingerprints[f] = Fingerprint(v)
		} else {
			err = s.secrets.Delete(ctx, SecretName(key, f))
		}
		if err != nil {
			note := s.restore(applied)
			return Integration{}, fmt.Errorf("integrations: save secret %s: %w%s", f, err, note)
		}
		applied = append(applied, snaps[i])
	}

	// 2. Row + Diary in one transaction.
	var out Integration
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		var err error
		out, err = scanRow(tx.QueryRow(ctx, `
			INSERT INTO integrations (key, system, config_json, secret_fields, status, last_tested_at, last_error, updated_by, updated_at)
			VALUES ($1, $2, $3, $4, 'configured', NULL, NULL, $5, now())
			ON CONFLICT (key) DO UPDATE SET
				config_json = EXCLUDED.config_json, secret_fields = EXCLUDED.secret_fields,
				status = 'configured', last_tested_at = NULL, last_error = NULL,
				updated_by = EXCLUDED.updated_by, updated_at = now()
			RETURNING `+rowCols, key, system, cfgJSON, nonNilStrings(final), actor))
		if err != nil {
			return err
		}
		data := map[string]any{
			"key":                 key,
			"system":              system,
			"created":             !exists,
			"config":              cfg,
			"secret_fields":       nonNilStrings(final),
			"secrets_changed":     fingerprints,
			"secrets_removed":     nonNilStrings(remove),
			"secrets_kept":        nonNilStrings(kept),
			"fingerprint_note":    "sha256 prefix (8 hex) of each changed secret; values are never recorded",
			"previous_status":     prev.Status,
			"previous_updated_by": prev.UpdatedBy,
		}
		if exists {
			var pc any
			_ = json.Unmarshal(prev.Config, &pc)
			data["previous_config"] = pc
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventConfigured, Actor: actor, Data: data})
		return err
	})
	if err != nil {
		note := s.restore(applied)
		return Integration{}, fmt.Errorf("integrations: save %s: %w%s", key, err, note)
	}
	return out, nil
}

// Delete removes an integration's secrets and row, recording
// integration.deleted. A missing integration is ErrNotConfigured.
func (s *PGStore) Delete(ctx context.Context, key, actor string) error {
	system, err := ParseKey(key)
	if err != nil {
		return err
	}
	if actor == "" {
		return errors.New("integrations: actor is required")
	}
	schema, _ := SchemaFor(system)
	conn, unlock, err := s.lockKey(ctx, key)
	if err != nil {
		return err
	}
	defer unlock()
	defer s.invalidate()

	prev, err := getRow(ctx, conn, key)
	if err != nil {
		return err
	}
	// Every schema secret field, not only the recorded ones, so no orphan
	// credential survives a delete.
	fields := secretFieldNames(schema)
	snaps := s.snapshot(ctx, key, fields)
	var applied []secretSnapshot
	for i, f := range fields {
		if err := s.secrets.Delete(ctx, SecretName(key, f)); err != nil {
			note := s.restore(applied)
			return fmt.Errorf("integrations: delete secret %s: %w%s", f, err, note)
		}
		applied = append(applied, snaps[i])
	}
	err = pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM integrations WHERE key = $1`, key)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return fmt.Errorf("%w: %s", ErrNotConfigured, key)
		}
		var pc any
		_ = json.Unmarshal(prev.Config, &pc)
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventDeleted, Actor: actor, Data: map[string]any{
			"key": key, "system": system, "config": pc, "secrets_deleted": nonNilStrings(prev.SecretFields),
			"previous_status": prev.Status,
		}})
		return err
	})
	if err != nil {
		note := s.restore(applied)
		return fmt.Errorf("integrations: delete %s: %w%s", key, err, note)
	}
	return nil
}

// TestResult is a sanitised live-test outcome.
type TestResult struct {
	OK       bool
	Error    string // sanitised; "" when OK
	Duration time.Duration
}

// RecordTest stores a test outcome (status ok|error, last_tested_at,
// last_error) and writes integration.tested in the same transaction.
// testedVersion is the UpdatedAt of the settings that were tested; if the
// settings changed meanwhile, only the Diary event is written and ErrChanged
// is returned.
func (s *PGStore) RecordTest(ctx context.Context, key string, testedVersion time.Time, res TestResult, actor string) (Integration, error) {
	system, err := ParseKey(key)
	if err != nil {
		return Integration{}, err
	}
	if actor == "" {
		return Integration{}, errors.New("integrations: actor is required")
	}
	defer s.invalidate()
	status, lastErr := StatusOK, ""
	if !res.OK {
		status, lastErr = StatusError, truncate(res.Error, MaxErrorLen)
		if lastErr == "" {
			lastErr = "test failed"
		}
	}
	var out Integration
	stale := false
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = scanRow(tx.QueryRow(ctx, `
			UPDATE integrations SET status = $2, last_tested_at = now(), last_error = NULLIF($3, '')
			WHERE key = $1 AND updated_at = $4
			RETURNING `+rowCols, key, status, lastErr, testedVersion))
		if errors.Is(err, pgx.ErrNoRows) {
			// Deleted or reconfigured during the test.
			if out, err = getRow(ctx, tx, key); err != nil {
				return err
			}
			stale = true
		} else if err != nil {
			return err
		}
		data := map[string]any{"key": key, "system": system, "ok": res.OK, "duration_ms": res.Duration.Milliseconds()}
		if lastErr != "" {
			data["error"] = lastErr
		}
		if stale {
			data["stale"] = true
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventTested, Actor: actor, Data: data})
		return err
	})
	if err != nil {
		return Integration{}, err
	}
	if stale {
		return out, ErrChanged
	}
	return out, nil
}

// --- Source -------------------------------------------------------------------

func (s *PGStore) invalidate() {
	s.mu.Lock()
	s.gen++
	clear(s.byKey)
	clear(s.bySys)
	s.mu.Unlock()
}

// Get returns the current settings and secrets for key, cached for up to
// CacheTTL. ErrNotConfigured if the row is missing or unconfigured;
// ErrSecretMissing (which wraps ErrNotConfigured) if the row is configured
// but a required secret is missing.
func (s *PGStore) Get(ctx context.Context, key string) (Resolved, error) {
	if _, err := ParseKey(key); err != nil {
		return Resolved{}, err
	}
	s.mu.Lock()
	c, ok := s.byKey[key]
	gen := s.gen
	s.mu.Unlock()
	if ok && s.now().Sub(c.at) < s.ttl {
		if c.err != nil {
			return Resolved{}, c.err
		}
		return copyResolved(c.res), nil
	}
	res, err := s.Resolve(ctx, key)
	if err == nil || errors.Is(err, ErrNotConfigured) {
		s.mu.Lock()
		if s.gen == gen {
			s.byKey[key] = cachedResolved{at: s.now(), res: copyResolved(res), err: err}
		}
		s.mu.Unlock()
	}
	return res, err
}

// Broken returns the keys of a system's integrations that are configured
// but cannot be used because a required secret is missing from the secret
// store. List skips them; callers that must not silently ignore an
// integration (credential revocation) report them instead.
func (s *PGStore) Broken(ctx context.Context, system string) ([]string, error) {
	rows, err := s.pool.Query(ctx, `SELECT key FROM integrations WHERE system = $1 ORDER BY key`, system)
	if err != nil {
		return nil, fmt.Errorf("integrations: list %s: %w", system, err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("integrations: list %s: %w", system, err)
	}
	var out []string
	for _, k := range keys {
		if _, err := s.Resolve(ctx, k); errors.Is(err, ErrSecretMissing) {
			out = append(out, k)
		}
	}
	return out, nil
}

// BrokenLister is implemented by sources that can report configured
// integrations whose secrets are missing (see PGStore.Broken).
type BrokenLister interface {
	Broken(ctx context.Context, system string) ([]string, error)
}

// List returns every fully configured integration of a system (Postgres
// upstreams; at most one for the others). Incomplete ones are skipped.
func (s *PGStore) List(ctx context.Context, system string) ([]Resolved, error) {
	if _, ok := SchemaFor(system); !ok {
		return nil, fmt.Errorf("%w: unknown system %q", ErrInvalid, truncate(system, 64))
	}
	s.mu.Lock()
	c, ok := s.bySys[system]
	gen := s.gen
	s.mu.Unlock()
	if ok && s.now().Sub(c.at) < s.ttl {
		return copyResolvedList(c.res), nil
	}
	rows, err := s.pool.Query(ctx, `SELECT key FROM integrations WHERE system = $1 ORDER BY key`, system)
	if err != nil {
		return nil, fmt.Errorf("integrations: list %s: %w", system, err)
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("integrations: list %s: %w", system, err)
	}
	out := []Resolved{}
	for _, k := range keys {
		r, err := s.Resolve(ctx, k)
		if errors.Is(err, ErrNotConfigured) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	s.mu.Lock()
	if s.gen == gen {
		s.bySys[system] = cachedList{at: s.now(), res: copyResolvedList(out)}
	}
	s.mu.Unlock()
	return out, nil
}

// Resolve reads the settings and secrets for key without the cache (used by
// the connection test, which must see what was just saved).
func (s *PGStore) Resolve(ctx context.Context, key string) (Resolved, error) {
	system, err := ParseKey(key)
	if err != nil {
		return Resolved{}, err
	}
	in, err := getRow(ctx, s.pool, key)
	if err != nil {
		return Resolved{}, err
	}
	if in.Status == StatusUnconfigured {
		return Resolved{}, fmt.Errorf("%w: %s", ErrNotConfigured, key)
	}
	schema, _ := SchemaFor(system)
	res := Resolved{Integration: in, Secrets: map[string]string{}}
	if err := json.Unmarshal(in.Config, &res.ConfigMap); err != nil || res.ConfigMap == nil {
		return Resolved{}, fmt.Errorf("integrations: %s: stored config is not a JSON object", key)
	}
	for _, f := range schema.Fields {
		if !f.Secret {
			continue
		}
		if !slices.Contains(in.SecretFields, f.Key) {
			if f.Required {
				// The row is configured but does not record a secret the
				// schema requires (e.g. it predates the requirement).
				return Resolved{}, fmt.Errorf("%w: %s: secret %s not set", ErrSecretMissing, key, f.Key)
			}
			continue
		}
		v, err := s.secrets.Get(ctx, SecretName(key, f.Key))
		if errors.Is(err, secrets.ErrNotFound) {
			if f.Required {
				return Resolved{}, fmt.Errorf("%w: %s: secret %s missing from the secret store", ErrSecretMissing, key, f.Key)
			}
			continue
		}
		if err != nil {
			return Resolved{}, fmt.Errorf("integrations: %s: read secret %s: %w", key, f.Key, err)
		}
		res.Secrets[f.Key] = string(v)
	}
	return res, nil
}

func copyResolved(r Resolved) Resolved {
	out := r
	out.SecretFields = append([]string(nil), r.SecretFields...)
	out.Config = append(json.RawMessage(nil), r.Config...)
	if r.LastTestedAt != nil {
		t := *r.LastTestedAt
		out.LastTestedAt = &t
	}
	out.ConfigMap = nil
	if len(r.Config) > 0 {
		_ = json.Unmarshal(r.Config, &out.ConfigMap) // fresh nested values; never shared
	}
	if r.Secrets != nil {
		out.Secrets = make(map[string]string, len(r.Secrets))
		for k, v := range r.Secrets {
			out.Secrets[k] = v
		}
	}
	return out
}

func copyResolvedList(l []Resolved) []Resolved {
	out := make([]Resolved, len(l))
	for i, r := range l {
		out[i] = copyResolved(r)
	}
	return out
}

func nonNilStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
