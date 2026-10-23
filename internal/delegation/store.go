package delegation

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"

	"fortik/internal/config"
	"fortik/internal/diary"
	"fortik/internal/secrets"
)

// Diary events written by this package. Each carries the chain, root,
// delegator and delegatee (or executor); never a token.
const (
	EventOpened        = "delegation.opened"
	EventClosed        = "delegation.closed"
	EventBypassBlocked = "delegation.bypass_blocked"
)

// Channels a hop may be recorded on (delegations.channel).
const (
	ChannelA2A      = "a2a"
	ChannelMCP      = "mcp"
	ChannelSpawn    = "spawn"
	ChannelHookTask = "hook_task"
)

// Hop statuses.
const (
	StatusOpen    = "open"
	StatusClosed  = "closed"
	StatusExpired = "expired"
	StatusRefused = "refused"
)

// ErrNotFound is returned by Close for an unknown delegation id.
var ErrNotFound = errors.New("delegation not found")

// ErrInvalidHop wraps every validation failure of a hop passed to Open.
var ErrInvalidHop = errors.New("invalid delegation hop")

var (
	agentIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	channels       = []string{ChannelA2A, ChannelMCP, ChannelSpawn, ChannelHookTask}
)

const (
	defaultTTL      = 15 * time.Minute
	defaultMaxDepth = 5
	maxReasonLen    = 500
	// keyLen is the size of an auto-created signing key.
	keyLen = 32
)

// PGStore implements Store on the delegations table. Every state change and
// its Diary event commit in one transaction.
type PGStore struct {
	pool     *pgxpool.Pool
	diary    *diary.Diary
	signer   *signer
	ttl      time.Duration
	maxDepth int
	actor    string
	log      *slog.Logger
	now      func() time.Time
}

var _ Store = (*PGStore)(nil)

// Option configures a PGStore.
type Option func(*PGStore)

// WithClock overrides the time source (tests).
func WithClock(now func() time.Time) Option { return func(s *PGStore) { s.now = now } }

// WithLogger sets the logger (default: discard).
func WithLogger(l *slog.Logger) Option { return func(s *PGStore) { s.log = l } }

// WithActor sets the Diary actor for store-initiated events (default "system:delegation").
func WithActor(actor string) Option { return func(s *PGStore) { s.actor = actor } }

// NewPGStore loads the HMAC signing key from the secret store
// (cfg.SigningKeySecret), creating a random 32-byte key with secrets.Store.Put
// when it does not exist yet. A key that exists but cannot be read, or is
// shorter than 32 bytes, is an error: Fortik refuses to start rather than
// sign with a weak or unknown key.
func NewPGStore(ctx context.Context, pool *pgxpool.Pool, d *diary.Diary, sec secrets.Store, cfg config.DelegationConfig, opts ...Option) (*PGStore, error) {
	if pool == nil || d == nil || sec == nil {
		return nil, errors.New("delegation: pool, diary and secret store are required")
	}
	key, err := loadOrCreateKey(ctx, sec, cfg.SigningKeySecret)
	if err != nil {
		return nil, err
	}
	sg, err := newSigner(key)
	clear(key)
	if err != nil {
		return nil, err
	}
	s := &PGStore{pool: pool, diary: d, signer: sg, ttl: cfg.TokenTTL, maxDepth: cfg.MaxDepth,
		actor: "system:delegation", log: slog.New(slog.DiscardHandler), now: time.Now}
	if s.ttl <= 0 {
		s.ttl = defaultTTL
	}
	if s.maxDepth <= 0 {
		s.maxDepth = defaultMaxDepth
	}
	for _, o := range opts {
		o(s)
	}
	return s, nil
}

func loadOrCreateKey(ctx context.Context, sec secrets.Store, name string) ([]byte, error) {
	if name == "" {
		return nil, errors.New("delegation: signing_key_secret is not configured")
	}
	key, err := sec.Get(ctx, name)
	if err == nil {
		if len(key) < MinKeyLen {
			clear(key)
			return nil, fmt.Errorf("delegation: signing key %s is shorter than %d bytes", name, MinKeyLen)
		}
		return key, nil
	}
	if !errors.Is(err, secrets.ErrNotFound) {
		return nil, fmt.Errorf("delegation: read signing key %s: %w", name, err)
	}
	key = make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("delegation: generate signing key: %w", err)
	}
	if err := sec.Put(ctx, name, key); err != nil {
		clear(key)
		return nil, fmt.Errorf("delegation: store new signing key %s: %w", name, err)
	}
	clear(key)
	// Read back what is stored, so concurrent first starts converge on the
	// key that won the write.
	stored, err := sec.Get(ctx, name)
	if err != nil {
		return nil, fmt.Errorf("delegation: read back signing key %s: %w", name, err)
	}
	if len(stored) < MinKeyLen {
		clear(stored)
		return nil, fmt.Errorf("delegation: signing key %s is shorter than %d bytes", name, MinKeyLen)
	}
	return stored, nil
}

// TTL is how long a new hop (and its token) stays valid.
func (s *PGStore) TTL() time.Duration { return s.ttl }

// MaxDepth is the deepest hop Open records (config delegation.max_depth).
func (s *PGStore) MaxDepth() int { return s.maxDepth }

// Verify checks a token presented by holder (see Store): the signature,
// expiry and holder, then that its hop is still recorded as open, unexpired
// and delegated to holder, so closing a hop revokes its token. A database
// failure is returned as is (callers fail closed).
func (s *PGStore) Verify(ctx context.Context, token, holder string) (Claims, error) {
	now := s.now()
	c, err := s.signer.verify(token, holder, now)
	if err != nil {
		return Claims{}, err
	}
	var open bool
	err = s.pool.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM delegations
		WHERE delegation_id = $1 AND to_agent = $2 AND status = 'open' AND expires_at > $3)`,
		c.DelegationID, holder, now).Scan(&open)
	if err != nil {
		return Claims{}, fmt.Errorf("delegation token hop: %w", err)
	}
	if !open {
		return Claims{}, ErrRevokedToken
	}
	return c, nil
}

// Open records the hop in its own transaction (see OpenTx).
func (s *PGStore) Open(ctx context.Context, h Hop) (Hop, string, error) {
	var out Hop
	var tok string
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		var err error
		out, tok, err = s.OpenTx(ctx, tx, h, s.actor)
		return err
	})
	if err != nil {
		return Hop{}, "", err
	}
	return out, tok, nil
}

// OpenTx records a hop inside tx (the decision transaction when called by
// the observer) together with its delegation.opened Diary event, and returns
// the stored hop and the signed token for the delegatee.
//
// The caller supplies From, To, Chain (root ... From, To), Channel and
// optionally ParentID, TaskID, ActionID and Depth (default len(Chain)-1).
// The store assigns DelegationID, Root, Status, CreatedAt and ExpiresAt.
func (s *PGStore) OpenTx(ctx context.Context, tx pgx.Tx, h Hop, actor string) (Hop, string, error) {
	if err := s.prepare(&h); err != nil {
		return Hop{}, "", err
	}
	tok, err := s.signer.sign(Claims{DelegationID: h.DelegationID, Root: h.Root, Chain: h.Chain, Depth: h.Depth,
		TaskID: h.TaskID, IssuedAt: h.CreatedAt, ExpiresAt: h.ExpiresAt})
	if err != nil {
		return Hop{}, "", err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO delegations (delegation_id, parent_id, root_agent, from_agent, to_agent, chain, depth, task_id,
			channel, action_id, status, created_at, expires_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, $5, $6, $7, NULLIF($8, ''), $9, NULLIF($10, ''), 'open', $11, $12)`,
		h.DelegationID, h.ParentID, h.Root, h.From, h.To, h.Chain, h.Depth, h.TaskID, h.Channel, h.ActionID,
		h.CreatedAt, h.ExpiresAt)
	if err != nil {
		return Hop{}, "", fmt.Errorf("insert delegation: %w", err)
	}
	if actor == "" {
		actor = s.actor
	}
	if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: h.From, EventType: EventOpened, Actor: actor, Data: map[string]any{
		"delegation_id": h.DelegationID,
		"parent_id":     h.ParentID,
		"chain":         h.Chain,
		"root":          h.Root,
		"from":          h.From,
		"to":            h.To,
		"channel":       h.Channel,
		"depth":         h.Depth,
		"task_id":       h.TaskID,
		"action_id":     h.ActionID,
		"expires_at":    h.ExpiresAt,
	}}); err != nil {
		return Hop{}, "", err
	}
	return h, tok, nil
}

// prepare validates a hop for Open and fills the store-assigned fields.
func (s *PGStore) prepare(h *Hop) error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: %s", ErrInvalidHop, fmt.Sprintf(format, a...))
	}
	n := len(h.Chain)
	switch {
	case !agentIDPattern.MatchString(h.From) || !agentIDPattern.MatchString(h.To):
		return bad("from and to must be agent ids")
	case n < 2 || n > MaxChainLen:
		return bad("chain must have 2..%d agents", MaxChainLen)
	case h.Chain[n-1] != h.To || h.Chain[n-2] != h.From:
		return bad("chain must end with from, to")
	case !slices.Contains(channels, h.Channel):
		return bad("channel must be one of %s", strings.Join(channels, ", "))
	case len(h.TaskID) > maxTaskLen || !printable(h.TaskID):
		return bad("task id must be printable text of at most %d bytes", maxTaskLen)
	case h.ParentID != "" && !agentIDPattern.MatchString(h.ParentID):
		return bad("malformed parent id")
	case h.ActionID != "" && !agentIDPattern.MatchString(h.ActionID):
		return bad("malformed action id")
	}
	for _, a := range h.Chain {
		if !agentIDPattern.MatchString(a) {
			return bad("malformed agent id in chain")
		}
	}
	if h.Depth == 0 {
		h.Depth = n - 1
	}
	if h.Depth < 1 || h.Depth > n-1 {
		return bad("depth %d out of range for a chain of %d agents", h.Depth, n)
	}
	if h.Depth > s.maxDepth {
		return bad("depth %d exceeds max_depth %d", h.Depth, s.maxDepth)
	}
	now := s.now().UTC().Truncate(time.Microsecond) // timestamptz precision
	h.DelegationID = "dlg_" + ulid.Make().String()
	h.Root = h.Chain[0]
	h.Status = StatusOpen
	h.CreatedAt = now
	h.ExpiresAt = now.Add(s.ttl)
	h.ClosedAt = nil
	h.Chain = slices.Clone(h.Chain)
	return nil
}

func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

const hopCols = `delegation_id, COALESCE(parent_id, ''), root_agent, from_agent, to_agent, chain, depth, COALESCE(task_id, ''),
	channel, COALESCE(action_id, ''), status, created_at, expires_at, closed_at`

func scanHop(row pgx.Row) (Hop, error) {
	var h Hop
	if err := row.Scan(&h.DelegationID, &h.ParentID, &h.Root, &h.From, &h.To, &h.Chain, &h.Depth, &h.TaskID,
		&h.Channel, &h.ActionID, &h.Status, &h.CreatedAt, &h.ExpiresAt, &h.ClosedAt); err != nil {
		return Hop{}, err
	}
	h.CreatedAt, h.ExpiresAt = h.CreatedAt.UTC(), h.ExpiresAt.UTC()
	if h.ClosedAt != nil {
		t := h.ClosedAt.UTC()
		h.ClosedAt = &t
	}
	return h, nil
}

func collectHops(rows pgx.Rows) ([]Hop, error) {
	defer rows.Close()
	out := []Hop{}
	for rows.Next() {
		h, err := scanHop(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// OpenInbound lists unexpired open hops delegated TO agent, oldest first.
func (s *PGStore) OpenInbound(ctx context.Context, agent string) ([]Hop, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+hopCols+` FROM delegations
		WHERE to_agent = $1 AND status = 'open' AND expires_at > $2 ORDER BY created_at, delegation_id`, agent, s.now())
	if err != nil {
		return nil, fmt.Errorf("open inbound delegations for %s: %w", agent, err)
	}
	return collectHops(rows)
}

// Get returns one hop.
func (s *PGStore) Get(ctx context.Context, id string) (Hop, error) {
	h, err := scanHop(s.pool.QueryRow(ctx, `SELECT `+hopCols+` FROM delegations WHERE delegation_id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Hop{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return h, err
}

// Directions for List.
const (
	DirInbound  = "inbound"
	DirOutbound = "outbound"
	DirAll      = "all"
)

// List returns hops to (inbound), from (outbound) or involving (all) an
// agent anywhere in the chain, newest first. status "" means any.
func (s *PGStore) List(ctx context.Context, agent, direction, status string, limit int) ([]Hop, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	var where string
	switch direction {
	case DirInbound:
		where = `to_agent = $1`
	case DirOutbound:
		where = `from_agent = $1`
	case DirAll, "":
		where = `$1 = ANY (chain)`
	default:
		return nil, fmt.Errorf("unknown direction %q", direction)
	}
	if status != "" && !slices.Contains([]string{StatusOpen, StatusClosed, StatusExpired, StatusRefused}, status) {
		return nil, fmt.Errorf("unknown status %q", status)
	}
	rows, err := s.pool.Query(ctx, `SELECT `+hopCols+` FROM delegations WHERE `+where+`
		AND ($2 = '' OR status = $2) ORDER BY created_at DESC, delegation_id DESC LIMIT $3`, agent, status, limit)
	if err != nil {
		return nil, fmt.Errorf("list delegations for %s: %w", agent, err)
	}
	return collectHops(rows)
}

// Close marks an open hop closed (the delegated task finished) and records
// delegation.closed. Closing a hop that is no longer open is a no-op; an
// unknown id is ErrNotFound.
func (s *PGStore) Close(ctx context.Context, delegationID, reason string) error {
	reason, err := cleanReason(reason)
	if err != nil {
		return err
	}
	return pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		h, err := scanHop(tx.QueryRow(ctx, `UPDATE delegations SET status = 'closed', closed_at = $2, close_reason = $3
			WHERE delegation_id = $1 AND status = 'open' RETURNING `+hopCols, delegationID, s.now(), reason))
		if errors.Is(err, pgx.ErrNoRows) {
			var exists bool
			if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM delegations WHERE delegation_id = $1)`, delegationID).Scan(&exists); err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("%w: %s", ErrNotFound, delegationID)
			}
			return nil
		}
		if err != nil {
			return fmt.Errorf("close delegation: %w", err)
		}
		return s.closedEvent(ctx, tx, h, StatusClosed, reason)
	})
}

// CloseTask closes every open hop from -> to for an A2A task id (the callout
// saw the task reach a terminal state). It returns how many hops closed.
func (s *PGStore) CloseTask(ctx context.Context, from, to, taskID, reason string) (int, error) {
	if taskID == "" {
		return 0, fmt.Errorf("%w: task id is required", ErrInvalidHop)
	}
	reason, err := cleanReason(reason)
	if err != nil {
		return 0, err
	}
	n := 0
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE delegations SET status = 'closed', closed_at = $4, close_reason = $5
			WHERE from_agent = $1 AND to_agent = $2 AND task_id = $3 AND status = 'open' RETURNING `+hopCols,
			from, to, taskID, s.now(), reason)
		if err != nil {
			return err
		}
		hops, err := collectHops(rows)
		if err != nil {
			return err
		}
		for _, h := range hops {
			if err := s.closedEvent(ctx, tx, h, StatusClosed, reason); err != nil {
				return err
			}
		}
		n = len(hops)
		return nil
	})
	return n, err
}

// ExpireDue marks up to limit open hops past expires_at as expired, each
// with a delegation.closed event (reason "expired"), and returns how many.
// Concurrent sweepers skip each other's rows. Expired hops are already
// ignored by OpenInbound; this keeps the table and the Diary truthful.
func (s *PGStore) ExpireDue(ctx context.Context, limit int) (int, error) {
	if limit <= 0 {
		limit = 500
	}
	n := 0
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `UPDATE delegations SET status = 'expired', closed_at = $1, close_reason = 'expired'
			WHERE delegation_id IN (SELECT delegation_id FROM delegations WHERE status = 'open' AND expires_at <= $1
				ORDER BY expires_at LIMIT $2 FOR UPDATE SKIP LOCKED)
			RETURNING `+hopCols, s.now(), limit)
		if err != nil {
			return err
		}
		hops, err := collectHops(rows)
		if err != nil {
			return err
		}
		for _, h := range hops {
			if err := s.closedEvent(ctx, tx, h, StatusExpired, "expired"); err != nil {
				return err
			}
		}
		n = len(hops)
		return nil
	})
	return n, err
}

// RunExpiry sweeps expired hops every interval until ctx ends.
func (s *PGStore) RunExpiry(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for {
			n, err := s.ExpireDue(ctx, 500)
			if err != nil {
				if ctx.Err() == nil {
					s.log.Error("delegation expiry sweep failed", "err", err)
				}
				break
			}
			if n < 500 {
				break
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (s *PGStore) closedEvent(ctx context.Context, tx pgx.Tx, h Hop, status, reason string) error {
	_, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: h.From, EventType: EventClosed, Actor: s.actor, Data: map[string]any{
		"delegation_id": h.DelegationID,
		"chain":         h.Chain,
		"root":          h.Root,
		"from":          h.From,
		"to":            h.To,
		"channel":       h.Channel,
		"depth":         h.Depth,
		"task_id":       h.TaskID,
		"status":        status,
		"reason":        reason,
	}})
	return err
}

func cleanReason(r string) (string, error) {
	r = strings.TrimSpace(r)
	if r == "" {
		return "", errors.New("delegation: a close reason is required")
	}
	if len(r) > maxReasonLen || !printable(r) {
		return "", fmt.Errorf("delegation: close reason must be printable text of at most %d bytes", maxReasonLen)
	}
	return r, nil
}
