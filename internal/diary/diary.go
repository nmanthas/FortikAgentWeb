// Package diary is the Agent Diary: an append-only, hash-chained event log.
//
//	hash = sha256(prev_hash || body_json)
//
// prev_hash is the previous entry's hash as 64 lowercase hex characters and
// body_json is the exact canonical JSON stored in the row (sorted keys), so
// any reader can recompute the chain byte-for-byte. The genesis prev_hash is
// 64 zeros. Appends lock the single diary_head row inside the caller's
// transaction, so the chain is serialised, seq is gapless, and an event
// becomes visible atomically with the state change it records.
package diary

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Event types written in Phase 1.
const (
	EventActionDecided    = "action.decided"
	EventActionHeld       = "action.held"
	EventLevelChanged     = "agent.level_changed"
	EventAgentRegistered  = "agent.registered"
	EventAgentSuspended   = "agent.suspended"
	EventAgentResumed     = "agent.resumed"
	EventUndoPrepared     = "undo.prepared"
	EventUndoActivated    = "undo.activated"
	EventUndoVoided       = "undo.voided"
	EventUndoClaimed      = "undo.claimed"
	EventUndoExecuted     = "undo.executed"
	EventUndoExpired      = "undo.expired"
	EventUndoFailed       = "undo.failed"
	EventPolicyReloaded   = "policy.reloaded"
	EventPolicyReloadFail = "policy.reload_failed"
	EventRootSealed       = "diary.root_sealed"
	EventExported         = "diary.exported"
)

// GenesisHash is prev_hash of the first entry.
var GenesisHash = string(bytes.Repeat([]byte("0"), 64))

// Event is what callers append.
type Event struct {
	AgentID   string         // optional
	EventType string         // required
	Actor     string         // who caused it: "system:decide", "interceptor:pgproxy", "user:alice"...
	Data      map[string]any // event payload (summaries only; never secrets or raw payloads)
}

// Entry is a stored diary row.
type Entry struct {
	Seq       int64           `json:"seq"`
	TS        time.Time       `json:"ts"`
	AgentID   string          `json:"agent_id,omitempty"`
	EventType string          `json:"event_type"`
	Actor     string          `json:"actor"`
	BodyJSON  string          `json:"body_json"`
	Body      json.RawMessage `json:"body"`
	PrevHash  string          `json:"prev_hash"`
	Hash      string          `json:"hash"`
}

// Diary appends to and reads the chain.
type Diary struct {
	pool *pgxpool.Pool
	now  func() time.Time
	// trusted are the public keys sealed roots may be signed with (current
	// key plus retired keys after a rotation). Empty = roots are checked
	// against their embedded key only, and verification warns.
	trusted []ed25519.PublicKey
}

// TrustRootKeys pins the public keys sealed daily roots must verify against.
func (d *Diary) TrustRootKeys(pubs ...ed25519.PublicKey) { d.trusted = append(d.trusted, pubs...) }

func New(pool *pgxpool.Pool) *Diary {
	return &Diary{pool: pool, now: func() time.Time { return time.Now().UTC() }}
}

// ComputeHash returns sha256(prevHash || body) as lowercase hex.
func ComputeHash(prevHash, body string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte(body))
	return hex.EncodeToString(h.Sum(nil))
}

// Canonical marshals v with sorted object keys and no insignificant
// whitespace (round-tripping structs through map form).
func Canonical(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var generic any
	if err := dec.Decode(&generic); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(generic); err != nil {
		return "", err
	}
	return string(bytes.TrimRight(buf.Bytes(), "\n")), nil
}

// AppendTx appends events inside tx (the caller commits). Use this whenever
// the event records a state change made in the same transaction.
func (d *Diary) AppendTx(ctx context.Context, tx pgx.Tx, events ...Event) ([]Entry, error) {
	if len(events) == 0 {
		return nil, nil
	}
	var seq int64
	var prev string
	if err := tx.QueryRow(ctx, `SELECT seq, hash FROM diary_head WHERE id FOR UPDATE`).Scan(&seq, &prev); err != nil {
		return nil, fmt.Errorf("diary head: %w", err)
	}
	out := make([]Entry, 0, len(events))
	ts := d.now().Truncate(time.Microsecond) // Postgres timestamptz precision
	for _, ev := range events {
		if ev.EventType == "" || ev.Actor == "" {
			return nil, errors.New("diary: event_type and actor are required")
		}
		seq++
		body, err := Canonical(map[string]any{
			"seq":        seq,
			"ts":         ts.Format(time.RFC3339Nano),
			"agent_id":   ev.AgentID,
			"event_type": ev.EventType,
			"actor":      ev.Actor,
			"data":       nonNil(ev.Data),
		})
		if err != nil {
			return nil, fmt.Errorf("diary: encode body: %w", err)
		}
		hash := ComputeHash(prev, body)
		if _, err := tx.Exec(ctx,
			`INSERT INTO diary (seq, ts, agent_id, event_type, actor, body_json, prev_hash, hash)
			 VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8)`,
			seq, ts, ev.AgentID, ev.EventType, ev.Actor, body, prev, hash); err != nil {
			return nil, fmt.Errorf("diary insert: %w", err)
		}
		out = append(out, Entry{Seq: seq, TS: ts, AgentID: ev.AgentID, EventType: ev.EventType, Actor: ev.Actor,
			BodyJSON: body, Body: json.RawMessage(body), PrevHash: prev, Hash: hash})
		prev = hash
	}
	if _, err := tx.Exec(ctx, `UPDATE diary_head SET seq = $1, hash = $2 WHERE id`, seq, prev); err != nil {
		return nil, fmt.Errorf("diary head update: %w", err)
	}
	return out, nil
}

// Append appends in its own transaction.
func (d *Diary) Append(ctx context.Context, events ...Event) ([]Entry, error) {
	var out []Entry
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		var err error
		out, err = d.AppendTx(ctx, tx, events...)
		return err
	})
	return out, err
}

func nonNil(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// Filter selects entries for reads and exports.
type Filter struct {
	AgentID  string
	From, To time.Time // inclusive from, exclusive to; zero = unbounded
	AfterSeq int64
	MaxSeq   int64  // inclusive upper bound on seq; 0 = unbounded
	ActionID string // only entries whose data names this action
	Limit    int
}

// Query returns entries in seq order.
func (d *Diary) Query(ctx context.Context, f Filter) ([]Entry, error) {
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 1000
	}
	rows, err := d.pool.Query(ctx, `
		SELECT seq, ts, COALESCE(agent_id, ''), event_type, actor, body_json, prev_hash, hash
		FROM diary
		WHERE ($1 = '' OR agent_id = $1)
		  AND ($2::timestamptz IS NULL OR ts >= $2)
		  AND ($3::timestamptz IS NULL OR ts < $3)
		  AND seq > $4
		  AND ($6 = 0 OR seq <= $6)
		  AND ($7 = '' OR (body_json::jsonb -> 'data' ->> 'action_id') = $7)
		ORDER BY seq
		LIMIT $5`, f.AgentID, nullTime(f.From), nullTime(f.To), f.AfterSeq, f.Limit, f.MaxSeq, f.ActionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Entry
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.Seq, &e.TS, &e.AgentID, &e.EventType, &e.Actor, &e.BodyJSON, &e.PrevHash, &e.Hash); err != nil {
			return nil, err
		}
		e.Body = json.RawMessage(e.BodyJSON)
		e.TS = e.TS.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}

// Head returns the current chain head.
func (d *Diary) Head(ctx context.Context) (int64, string, error) {
	var seq int64
	var hash string
	err := d.pool.QueryRow(ctx, `SELECT seq, hash FROM diary_head WHERE id`).Scan(&seq, &hash)
	return seq, hash, err
}
