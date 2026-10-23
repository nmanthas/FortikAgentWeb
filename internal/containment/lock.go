package containment

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Containment operations on one agent are serialised (F4): every operation
// holds a Postgres session advisory lock keyed on the agent id for the whole
// of that agent's steps, so a suspend cannot interleave with a resume (or a
// kill with a release) and leave queues or copies in the other op's state.
//
//   - Single-agent and instance operations take the lock before the target
//     is read for the last time (the role checks of D2 run under it) and hold
//     it until the operation is recorded as finished.
//   - Team and fleet operations take each agent's lock around that agent's
//     steps only, one agent at a time per worker, so no operation ever waits
//     for a second advisory lock while holding one (no lock cycles).
//   - The level API path (RevokeAll) takes the same lock.
//
// Row locks (agents -> instances / memory_access -> diary_head) are only
// taken inside the steps' own short transactions, always after the advisory
// lock, and no step waits for an advisory lock, so the two cannot deadlock.
//
// One dedicated connection per operation holds its locks. Waiting polls
// pg_try_advisory_lock (the connection is shared by the operation's
// workers, so it must never block in a lock wait).

const (
	// lockWait bounds how long an operation waits for another operation on
	// the same agent to finish (a whole operation's steps are bounded by
	// stepTimeout each).
	lockWait      = 5 * time.Minute
	lockPollMin   = 10 * time.Millisecond
	lockPollMax   = 200 * time.Millisecond
	unlockTimeout = 5 * time.Second
)

// ErrBusy: another containment operation on the agent did not finish in
// time; nothing was done.
var ErrBusy = errors.New("containment busy")

// LockKey is the advisory-lock key text of an agent's containment lock
// (hashed with hashtextextended(key, 0)).
func LockKey(agentID string) string { return "fortik.containment.agent:" + agentID }

type agentLocks struct {
	mu     sync.Mutex
	conn   *pgxpool.Conn
	held   map[string]bool
	broken bool
}

func (m *Manager) newLocks(ctx context.Context) (*agentLocks, error) {
	conn, err := m.pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("containment: lock connection: %w", err)
	}
	return &agentLocks{conn: conn, held: map[string]bool{}}, nil
}

// lock takes the agent's lock, waiting at most wait (and never past ctx).
func (l *agentLocks) lock(ctx context.Context, agentID string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	poll := lockPollMin
	for {
		l.mu.Lock()
		var ok bool
		err := l.conn.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended($1, 0))`, LockKey(agentID)).Scan(&ok)
		if err == nil && ok {
			l.held[agentID] = true
		}
		l.mu.Unlock()
		switch {
		case err != nil:
			return fmt.Errorf("containment: lock agent %s: %w", agentID, err)
		case ok:
			return nil
		case !time.Now().Before(deadline):
			return fmt.Errorf("%w: another containment operation on agent %s did not finish within %s", ErrBusy, agentID, wait)
		}
		t := time.NewTimer(poll)
		select {
		case <-ctx.Done():
			t.Stop()
			return fmt.Errorf("%w: waiting for another containment operation on agent %s: %v", ErrBusy, agentID, ctx.Err())
		case <-t.C:
		}
		poll = min(2*poll, lockPollMax)
	}
}

func (l *agentLocks) unlock(agentID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.held[agentID] {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
	defer cancel()
	var ok bool
	if err := l.conn.QueryRow(ctx, `SELECT pg_advisory_unlock(hashtextextended($1, 0))`, LockKey(agentID)).Scan(&ok); err != nil || !ok {
		l.broken = true
	}
	delete(l.held, agentID)
}

// close releases every lock still held and the connection. If a lock could
// not be released cleanly the connection is closed instead of returned to
// the pool (closing the session releases its advisory locks).
func (l *agentLocks) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.broken && len(l.held) > 0 {
		ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
		_, err := l.conn.Exec(ctx, `SELECT pg_advisory_unlock_all()`)
		cancel()
		l.broken = err != nil
		clear(l.held)
	}
	if l.broken {
		c := l.conn.Hijack()
		ctx, cancel := context.WithTimeout(context.Background(), unlockTimeout)
		_ = c.Close(ctx)
		cancel()
		return
	}
	l.conn.Release()
}
