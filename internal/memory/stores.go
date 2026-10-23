package memory

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/integrations"
)

// ErrStoreNotConfigured: no usable memory:<name> integration. It matches
// integrations.ErrNotConfigured with errors.Is.
var ErrStoreNotConfigured = fmt.Errorf("memory store %w", integrations.ErrNotConfigured)

// StoreResolver finds the customer's memory stores.
type StoreResolver interface {
	// Store returns the store for memory:<name> (ErrStoreNotConfigured when
	// the integration is missing or incomplete).
	Store(ctx context.Context, name string) (*PGStore, error)
	// Names lists the configured store names.
	Names(ctx context.Context) ([]string, error)
}

// Stores resolves memory:<name> integrations (through integrations.Source,
// so settings changed in the console apply within the source's cache TTL)
// and keeps one small connection pool per store. A pool is replaced when the
// store's connection settings change.
type Stores struct {
	src   integrations.Source
	delay time.Duration
	log   *slog.Logger

	mu     sync.Mutex
	open   map[string]*openStore
	closed bool
}

type openStore struct {
	fingerprint string
	store       *PGStore
	pool        *pgxpool.Pool
}

var _ StoreResolver = (*Stores)(nil)

// NewStores builds the resolver. promotionDelay is
// config.MemoryConfig.PromotionDelay.
func NewStores(src integrations.Source, promotionDelay time.Duration, log *slog.Logger) *Stores {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Stores{src: src, delay: promotionDelay, log: log, open: map[string]*openStore{}}
}

// Store returns the PGStore for memory:<name>.
func (s *Stores) Store(ctx context.Context, name string) (*PGStore, error) {
	if !ValidStoreName(name) {
		return nil, invalidf("store name must match %s", storeName)
	}
	if s.src == nil {
		return nil, ErrStoreNotConfigured
	}
	r, err := s.src.Get(ctx, IntegrationKey(name))
	if errors.Is(err, integrations.ErrNotConfigured) {
		return nil, fmt.Errorf("%w: %s", ErrStoreNotConfigured, IntegrationKey(name))
	}
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", IntegrationKey(name), err)
	}
	if r.Key == "" {
		r.Key = IntegrationKey(name)
	}
	if r.Key != IntegrationKey(name) {
		return nil, fmt.Errorf("%w: integration source returned %q for %q", integrations.ErrInvalid, r.Key, IntegrationKey(name))
	}
	set, err := ParseSettings(r)
	if err != nil {
		return nil, err
	}
	fp := fingerprint(set)

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("memory stores closed")
	}
	if o, ok := s.open[name]; ok && o.fingerprint == fp {
		return o.store, nil
	}
	cfg, err := set.poolConfig()
	if err != nil {
		return nil, err
	}
	pool, err := pgxpool.NewWithConfig(context.WithoutCancel(ctx), cfg) // connects lazily
	if err != nil {
		return nil, fmt.Errorf("memory store %s: %s", set.Key, sanitize(err))
	}
	st := NewPGStore(pool, set.Key, set.Dimension, s.delay)
	if old, ok := s.open[name]; ok {
		// Close in the background: Close waits for in-flight queries.
		go old.pool.Close()
		s.log.Info("memory store settings changed; reconnecting", "store", set.Key)
	}
	s.open[name] = &openStore{fingerprint: fp, store: st, pool: pool}
	return st, nil
}

// fingerprint identifies the connection settings (the password only as a hash).
func fingerprint(s Settings) string {
	h := sha256.New()
	for _, v := range []string{s.Key, s.Host, strconv.Itoa(s.Port), s.Database, s.SSLMode, s.AdminUser, strconv.Itoa(s.Dimension), s.password} {
		h.Write([]byte(v))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Names lists every configured memory store.
func (s *Stores) Names(ctx context.Context) ([]string, error) {
	if s.src == nil {
		return []string{}, nil
	}
	rs, err := s.src.List(ctx, System)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, r := range rs {
		if name, err := StoreNameFromKey(r.Key); err == nil {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out, nil
}

// Close closes every pool.
func (s *Stores) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for k, o := range s.open {
		o.pool.Close()
		delete(s.open, k)
	}
}
