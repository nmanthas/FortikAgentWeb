package alerts

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/action"
	"fortik/internal/diary"
)

// Alert statuses.
const (
	StatusOpen         = "open"
	StatusAcknowledged = "acknowledged"
	StatusResolved     = "resolved"
)

// Diary event types written by the store.
const (
	EventRaised       = "alert.raised"
	EventRepeated     = "alert.repeated" // an open alert with the same dedup key was bumped
	EventAcknowledged = "alert.acknowledged"
	EventResolved     = "alert.resolved"
)

// DefaultDedupWindow: an open alert absorbs repeats of its dedup key only if
// it was last bumped within this window; an older one is resolved by the
// system and a fresh alert opens, so a new incident is never hidden inside a
// stale one.
const DefaultDedupWindow = time.Hour

// Actor used in the Diary for changes the store makes on its own.
const systemActor = "system:alerts"

var (
	ErrNotFound = errors.New("alert not found")
	// ErrState: the alert's status does not allow the change (e.g. ack of a
	// resolved alert).
	ErrState = errors.New("alert status does not allow this change")
	// ErrInvalid wraps every validation failure of an Alert passed to Raise.
	ErrInvalid = errors.New("invalid alert")
)

// Limits on stored fields (alerts carry summaries, never payloads).
const (
	maxSummary  = 500
	maxDetails  = 16 << 10
	maxIDField  = 128
	maxDedupKey = 256
	maxNote     = 500
)

var (
	kindPattern = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	severities  = map[string]int{SevInfo: 0, SevWarning: 1, SevHigh: 2, SevCritical: 3}
)

// TxRaiser raises an alert inside the caller's transaction (a decision
// observer), so the alert commits or rolls back with the decision.
type TxRaiser interface {
	RaiseTx(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error)
}

// PGStore is the Postgres-backed alert store. Every change is written to the
// Diary in the same transaction (alert.raised reaches the console live via
// the Diary tailer).
type PGStore struct {
	pool  *pgxpool.Pool
	diary *diary.Diary
	// DedupWindow overrides DefaultDedupWindow; negative = no window (an open
	// alert absorbs repeats until it is acknowledged or resolved).
	DedupWindow time.Duration
	Now         func() time.Time
}

var (
	_ Raiser   = (*PGStore)(nil)
	_ TxRaiser = (*PGStore)(nil)
)

func NewPGStore(pool *pgxpool.Pool, d *diary.Diary) *PGStore {
	return &PGStore{pool: pool, diary: d}
}

func (s *PGStore) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC().Truncate(time.Microsecond)
	}
	return time.Now().UTC().Truncate(time.Microsecond)
}

func (s *PGStore) window() time.Duration {
	if s.DedupWindow == 0 {
		return DefaultDedupWindow
	}
	return s.DedupWindow
}

// Raise records a in its own transaction.
func (s *PGStore) Raise(ctx context.Context, a Alert) (Alert, error) {
	var out Alert
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, err = s.RaiseTx(ctx, tx, a)
		return err
	})
	return out, err
}

// RaiseTx records a inside tx. With a DedupKey, an open alert with the same
// key (bumped within the dedup window) has its count and updated_at bumped
// instead of a new alert being inserted; severity only ever escalates.
func (s *PGStore) RaiseTx(ctx context.Context, tx pgx.Tx, a Alert) (Alert, error) {
	if err := normalize(&a); err != nil {
		return Alert{}, err
	}
	now := s.now()
	if a.DedupKey == "" {
		return s.insert(ctx, tx, a, now)
	}
	var (
		existingID string
		updatedAt  time.Time
	)
	err := tx.QueryRow(ctx, `SELECT alert_id, updated_at FROM alerts WHERE dedup_key = $1 AND status = 'open' FOR UPDATE`, a.DedupKey).
		Scan(&existingID, &updatedAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Insert; a concurrent raise of the same key that commits first turns
		// this into a bump through the partial unique index.
		return s.upsert(ctx, tx, a, now)
	case err != nil:
		return Alert{}, fmt.Errorf("alerts: dedup lookup: %w", err)
	}
	if w := s.window(); w < 0 || updatedAt.After(now.Add(-w)) {
		return s.bump(ctx, tx, existingID, a, now)
	}
	// The open alert is older than the window: close it so the new incident
	// gets its own alert (and its own live notification).
	if _, err := tx.Exec(ctx, `UPDATE alerts SET status = 'resolved', acked_by = COALESCE(acked_by, $2), updated_at = $3 WHERE alert_id = $1`,
		existingID, systemActor, now); err != nil {
		return Alert{}, fmt.Errorf("alerts: supersede: %w", err)
	}
	if a.ID == "" {
		a.ID = action.NewID("alr")
	}
	if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: EventResolved, Actor: systemActor, Data: map[string]any{
		"alert_id": existingID, "kind": a.Kind, "dedup_key": a.DedupKey, "previous_status": StatusOpen,
		"reason": fmt.Sprintf("dedup window of %s elapsed; superseded by %s", s.window(), a.ID),
	}}); err != nil {
		return Alert{}, err
	}
	return s.insert(ctx, tx, a, now)
}

const alertColumns = `alert_id, kind, severity, COALESCE(agent_id, ''), COALESCE(agent_type, ''), COALESCE(action_id, ''),
	summary, details, COALESCE(dedup_key, ''), count, status, created_at, updated_at, COALESCE(acked_by, '')`

func scanAlert(row pgx.Row, extra ...any) (Alert, error) {
	var a Alert
	var details []byte
	dest := append([]any{&a.ID, &a.Kind, &a.Severity, &a.AgentID, &a.AgentType, &a.ActionID, &a.Summary, &details,
		&a.DedupKey, &a.Count, &a.Status, &a.CreatedAt, &a.UpdatedAt, &a.AckedBy}, extra...)
	if err := row.Scan(dest...); err != nil {
		return Alert{}, err
	}
	a.Details = json.RawMessage(details)
	a.CreatedAt, a.UpdatedAt = a.CreatedAt.UTC(), a.UpdatedAt.UTC()
	return a, nil
}

func (s *PGStore) insert(ctx context.Context, tx pgx.Tx, a Alert, now time.Time) (Alert, error) {
	if a.ID == "" {
		a.ID = action.NewID("alr")
	}
	out, err := scanAlert(tx.QueryRow(ctx, `
		INSERT INTO alerts (alert_id, kind, severity, agent_id, agent_type, action_id, summary, details, dedup_key, count, status, created_at, updated_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7, $8, NULLIF($9, ''), 1, 'open', $10, $10)
		RETURNING `+alertColumns,
		a.ID, a.Kind, a.Severity, a.AgentID, a.AgentType, a.ActionID, a.Summary, []byte(a.Details), a.DedupKey, now))
	if err != nil {
		return Alert{}, fmt.Errorf("alerts: insert: %w", err)
	}
	return out, s.record(ctx, tx, out, a.ActionID, true)
}

func (s *PGStore) upsert(ctx context.Context, tx pgx.Tx, a Alert, now time.Time) (Alert, error) {
	if a.ID == "" {
		a.ID = action.NewID("alr")
	}
	var inserted bool
	out, err := scanAlert(tx.QueryRow(ctx, `
		INSERT INTO alerts (alert_id, kind, severity, agent_id, agent_type, action_id, summary, details, dedup_key, count, status, created_at, updated_at)
		VALUES ($1, $2, $3, NULLIF($4, ''), NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, 1, 'open', $10, $10)
		ON CONFLICT (dedup_key) WHERE status = 'open' AND dedup_key IS NOT NULL DO UPDATE SET
			count = alerts.count + 1,
			updated_at = EXCLUDED.updated_at,
			summary = EXCLUDED.summary,
			details = EXCLUDED.details,
			action_id = COALESCE(EXCLUDED.action_id, alerts.action_id),
			severity = CASE WHEN `+sevRank("EXCLUDED.severity")+` > `+sevRank("alerts.severity")+` THEN EXCLUDED.severity ELSE alerts.severity END
		RETURNING `+alertColumns+`, (xmax = 0)`,
		a.ID, a.Kind, a.Severity, a.AgentID, a.AgentType, a.ActionID, a.Summary, []byte(a.Details), a.DedupKey, now), &inserted)
	if err != nil {
		return Alert{}, fmt.Errorf("alerts: upsert: %w", err)
	}
	return out, s.record(ctx, tx, out, a.ActionID, inserted)
}

func (s *PGStore) bump(ctx context.Context, tx pgx.Tx, id string, a Alert, now time.Time) (Alert, error) {
	out, err := scanAlert(tx.QueryRow(ctx, `
		UPDATE alerts SET count = count + 1, updated_at = $2, summary = $3, details = $4,
			action_id = COALESCE(NULLIF($5, ''), action_id),
			severity = CASE WHEN `+sevRank("$6::text")+` > `+sevRank("severity")+` THEN $6 ELSE severity END
		WHERE alert_id = $1
		RETURNING `+alertColumns, id, now, a.Summary, []byte(a.Details), a.ActionID, a.Severity))
	if err != nil {
		return Alert{}, fmt.Errorf("alerts: bump: %w", err)
	}
	return out, s.record(ctx, tx, out, a.ActionID, false)
}

func sevRank(expr string) string {
	return `(CASE ` + expr + ` WHEN 'critical' THEN 3 WHEN 'high' THEN 2 WHEN 'warning' THEN 1 ELSE 0 END)`
}

// record writes alert.raised (new alert) or alert.repeated (bump).
func (s *PGStore) record(ctx context.Context, tx pgx.Tx, a Alert, actionID string, inserted bool) error {
	data := map[string]any{
		"alert_id": a.ID, "kind": a.Kind, "severity": a.Severity, "summary": a.Summary, "count": a.Count,
	}
	for k, v := range map[string]string{"agent_type": a.AgentType, "dedup_key": a.DedupKey, "action_id": actionID} {
		if v != "" {
			data[k] = v
		}
	}
	ev := EventRepeated
	if inserted {
		ev = EventRaised
		data["details"] = a.Details
	}
	_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: ev, Actor: systemActor, Data: data})
	return err
}

// normalize validates a and bounds its free-text fields.
func normalize(a *Alert) error {
	if !kindPattern.MatchString(a.Kind) {
		return fmt.Errorf("%w: kind must match %s", ErrInvalid, kindPattern)
	}
	if _, ok := severities[a.Severity]; !ok {
		return fmt.Errorf("%w: severity must be info|warning|high|critical", ErrInvalid)
	}
	a.Summary = clip(cleanText(a.Summary), maxSummary)
	if a.Summary == "" {
		return fmt.Errorf("%w: summary is required", ErrInvalid)
	}
	for name, v := range map[string]string{"agent_id": a.AgentID, "agent_type": a.AgentType, "action_id": a.ActionID, "alert_id": a.ID} {
		if len(v) > maxIDField || strings.ContainsRune(v, 0) {
			return fmt.Errorf("%w: %s must be at most %d bytes without NUL", ErrInvalid, name, maxIDField)
		}
	}
	if len(a.DedupKey) > maxDedupKey || strings.ContainsRune(a.DedupKey, 0) {
		return fmt.Errorf("%w: dedup_key must be at most %d bytes without NUL", ErrInvalid, maxDedupKey)
	}
	if len(a.Details) == 0 || string(a.Details) == "null" {
		a.Details = json.RawMessage(`{}`)
	}
	if len(a.Details) > maxDetails {
		return fmt.Errorf("%w: details exceed %d bytes", ErrInvalid, maxDetails)
	}
	var obj map[string]any
	if err := json.Unmarshal(a.Details, &obj); err != nil || obj == nil {
		return fmt.Errorf("%w: details must be a JSON object", ErrInvalid)
	}
	return nil
}

// cleanText drops control characters (including NUL) and trims.
func cleanText(s string) string {
	if !utf8.ValidString(s) {
		s = strings.ToValidUTF8(s, "?")
	}
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			if r == '\n' || r == '\t' {
				return ' '
			}
			return -1
		}
		return r
	}, s)
	return strings.TrimSpace(s)
}

func clip(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n-1]) + "…"
}

// Filter selects alerts for List.
type Filter struct {
	Status  string // open | acknowledged | resolved | "" (any)
	Kind    string
	AgentID string
	Limit   int // default 100, max 1000
}

// List returns alerts newest first.
func (s *PGStore) List(ctx context.Context, f Filter) ([]Alert, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	if f.Limit > 1000 {
		f.Limit = 1000
	}
	rows, err := s.pool.Query(ctx, `SELECT `+alertColumns+` FROM alerts
		WHERE ($1 = '' OR status = $1) AND ($2 = '' OR kind = $2) AND ($3 = '' OR agent_id = $3)
		ORDER BY created_at DESC, alert_id DESC LIMIT $4`, f.Status, f.Kind, f.AgentID, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Alert{}
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Get returns one alert.
func (s *PGStore) Get(ctx context.Context, id string) (Alert, error) {
	a, err := scanAlert(s.pool.QueryRow(ctx, `SELECT `+alertColumns+` FROM alerts WHERE alert_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Alert{}, ErrNotFound
	}
	return a, err
}

// Ack moves an open alert to acknowledged (Diary alert.acknowledged).
func (s *PGStore) Ack(ctx context.Context, id, actor, note string) (Alert, error) {
	return s.transition(ctx, id, actor, note, StatusAcknowledged, EventAcknowledged, StatusOpen)
}

// Resolve closes an open or acknowledged alert (Diary alert.resolved).
func (s *PGStore) Resolve(ctx context.Context, id, actor, note string) (Alert, error) {
	return s.transition(ctx, id, actor, note, StatusResolved, EventResolved, StatusOpen, StatusAcknowledged)
}

func (s *PGStore) transition(ctx context.Context, id, actor, note, to, event string, from ...string) (Alert, error) {
	if actor == "" {
		return Alert{}, errors.New("alerts: actor is required")
	}
	note = clip(cleanText(note), maxNote)
	var out Alert
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var cur, agentID, kind string
		err := tx.QueryRow(ctx, `SELECT status, COALESCE(agent_id, ''), kind FROM alerts WHERE alert_id = $1 FOR UPDATE`, id).Scan(&cur, &agentID, &kind)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		if err != nil {
			return err
		}
		allowed := false
		for _, f := range from {
			allowed = allowed || cur == f
		}
		if !allowed {
			return fmt.Errorf("%w: alert is %s", ErrState, cur)
		}
		out, err = scanAlert(tx.QueryRow(ctx, `UPDATE alerts SET status = $2, acked_by = COALESCE(acked_by, $3), updated_at = $4
			WHERE alert_id = $1 RETURNING `+alertColumns, id, to, actor, s.now()))
		if err != nil {
			return err
		}
		data := map[string]any{"alert_id": id, "kind": kind, "previous_status": cur}
		if note != "" {
			data["note"] = note
		}
		_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: agentID, EventType: event, Actor: actor, Data: data})
		return err
	})
	return out, err
}
