package decide

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/action"
	"fortik/internal/diary"
	"fortik/internal/policy"
)

// Spool keeps fail-path decisions that could not be written to the database
// (Fortik's own Postgres down) in a local append-only file, so that what
// Fortik refused or allowed while degraded is never lost: Drain appends them
// to the Diary once the database is back (config fail.spool_dir).
type Spool struct {
	path string
	mu   sync.Mutex
}

// spoolRecord is one fail-path decision.
type spoolRecord struct {
	Action    action.Action  `json:"action"`
	Result    policy.Result  `json:"result"`
	Extra     map[string]any `json:"extra,omitempty"`
	LatencyUS int64          `json:"latency_us"`
	Actor     string         `json:"actor"`
	SpooledAt time.Time      `json:"spooled_at"`
}

// NewSpool opens (creating) the spool directory; "" disables spooling.
func NewSpool(dir string) (*Spool, error) {
	if dir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("fail spool: %w", err)
	}
	return &Spool{path: filepath.Join(dir, "fail-spool.jsonl")}, nil
}

// Append writes one record and fsyncs it.
func (sp *Spool) append(r spoolRecord) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	f, err := os.OpenFile(sp.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// Pending returns how many records wait in the spool.
func (sp *Spool) Pending() int {
	if sp == nil {
		return 0
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	recs, _ := sp.read()
	return len(recs)
}

func (sp *Spool) read() ([]spoolRecord, error) {
	f, err := os.Open(sp.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []spoolRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		var r spoolRecord
		if json.Unmarshal(sc.Bytes(), &r) == nil && r.Action.ActionID != "" {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

// DrainSpool appends spooled decisions to actions and the Diary (marked
// recovered_from_spool), oldest first, and keeps whatever could not be
// written. It returns how many were recorded.
func (s *Service) DrainSpool(ctx context.Context) (int, error) {
	sp := s.Spool
	if sp == nil {
		return 0, nil
	}
	sp.mu.Lock()
	defer sp.mu.Unlock()
	recs, err := sp.read()
	if err != nil || len(recs) == 0 {
		return 0, err
	}
	done := 0
	var firstErr error
	var left []spoolRecord
	for _, r := range recs {
		if firstErr != nil {
			left = append(left, r)
			continue
		}
		extra := map[string]any{"recovered_from_spool": true, "spooled_at": r.SpooledAt}
		for k, v := range r.Extra {
			extra[k] = v
		}
		err := pgx.BeginFunc(ctx, s.Pool, func(tx pgx.Tx) error {
			if _, err := s.insertAction(ctx, tx, r.Action, r.Result, extra, true, r.LatencyUS); err != nil {
				return err
			}
			data := map[string]any{"action_id": r.Action.ActionID, "system": r.Action.System, "verb": string(r.Action.Verb),
				"class": string(r.Result.Class), "decision": string(r.Result.Decision), "rule_id": r.Result.RuleID,
				"reason": r.Result.Reason, "fail_closed": true}
			for k, v := range extra {
				data[k] = v
			}
			_, err := s.Diary.AppendTx(ctx, tx, diary.Event{AgentID: r.Action.AgentID, EventType: diary.EventActionDecided, Actor: r.Actor, Data: data})
			return err
		})
		var pgErr *pgconn.PgError
		switch {
		case err == nil:
			done++
		case errors.As(err, &pgErr) && pgErr.Code == "23505":
			// already recorded (e.g. a late best-effort write succeeded)
		default:
			firstErr = err
			left = append(left, r)
		}
	}
	if err := sp.rewrite(left); err != nil {
		return done, err
	}
	return done, firstErr
}

func (sp *Spool) rewrite(recs []spoolRecord) error {
	if len(recs) == 0 {
		err := os.Remove(sp.path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	tmp := sp.path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	for _, r := range recs {
		b, _ := json.Marshal(r)
		w.Write(append(b, '\n'))
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, sp.path)
}

// SpoolWorker drains the spool every interval (and once at start).
func (s *Service) SpoolWorker(ctx context.Context, every time.Duration) {
	if s.Spool == nil {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		if n, err := s.DrainSpool(ctx); n > 0 && s.Log != nil {
			s.Log.Info("fail-path decisions recovered from the local spool into the Diary", "recorded", n)
		} else if err != nil && s.Log != nil {
			s.Log.Warn("fail spool not drained yet (database unavailable?)", "err", err, "pending", s.Spool.Pending())
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}
