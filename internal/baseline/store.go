package baseline

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"fortik/internal/config"
)

// ErrStoreUnavailable wraps every hot-store failure. The enricher fails the
// decision closed on it.
var ErrStoreUnavailable = errors.New("baseline store unavailable")

// Row is one hourly count.
type Row struct {
	AgentID string
	Verb    string
	Hour    int64 // unix seconds of the UTC hour start
	Count   int64
}

// Store is the hot copy of the hourly counts (Redis when counters.provider is
// redis, so every Fortik process sees the same counts; memory otherwise).
// baseline_hourly in Postgres is the durable copy.
type Store interface {
	// Add adds n to the count of (agent, verb, hour).
	Add(ctx context.Context, agentID, verb string, hour, n int64) error
	// Get returns the count of one hour (0 when absent).
	Get(ctx context.Context, agentID, verb string, hour int64) (int64, error)
	// Series returns every stored hour >= from (unix hour start -> count).
	Series(ctx context.Context, agentID, verb string, from int64) (map[int64]int64, error)
	// Verbs lists the verbs with stored counts for the agent.
	Verbs(ctx context.Context, agentID string) ([]string, error)
	// Merge raises stored counts to at least the given values (backfill from
	// the durable copy; never lowers a hot count).
	Merge(ctx context.Context, rows []Row) error
	// Prune drops hours before `before` where the backend does not expire
	// them itself.
	Prune(ctx context.Context, before int64) error
	Close() error
}

// LoadMarker is implemented by hot stores that can lose their contents
// behind Fortik's back (a Redis restart without persistence, FLUSHALL,
// eviction). A marker written after each load from baseline_hourly lets the
// service notice the loss and reload before deciding, instead of seeing "no
// history" (which would quietly loosen every baseline until the next
// hourly re-sync).
type LoadMarker interface {
	Loaded(ctx context.Context) (bool, error)
	MarkLoaded(ctx context.Context) error
}

// NewStore builds the hot store for counters.provider. The redis provider is
// pinged once; an unreachable Redis at startup is an error.
func NewStore(ctx context.Context, c config.CountersConfig, p Params) (Store, error) {
	switch c.Provider {
	case "", "memory":
		return NewMemoryStore(), nil
	case "redis":
		rs, err := NewRedisStore(c.RedisURL, p.Retention())
		if err != nil {
			return nil, err
		}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := rs.Ping(pctx); err != nil {
			_ = rs.Close()
			return nil, err
		}
		return rs, nil
	default:
		return nil, fmt.Errorf("baseline: unknown counters provider %q", c.Provider)
	}
}

func checkKey(agentID, verb string) error {
	if agentID == "" || len(agentID) > 256 || verb == "" || len(verb) > 32 {
		return fmt.Errorf("%w: invalid agent or verb", ErrStoreUnavailable)
	}
	return nil
}

// --- memory ------------------------------------------------------------------

// MemoryStore is the single-process hot store (dev, tests, single node).
type MemoryStore struct {
	mu   sync.Mutex
	keys map[memKey]map[int64]int64
}

type memKey struct{ agent, verb string }

func NewMemoryStore() *MemoryStore { return &MemoryStore{keys: map[memKey]map[int64]int64{}} }

func (m *MemoryStore) Add(ctx context.Context, agentID, verb string, hour, n int64) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	if err := checkKey(agentID, verb); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey{agentID, verb}
	hours := m.keys[k]
	if hours == nil {
		hours = map[int64]int64{}
		m.keys[k] = hours
	}
	hours[hour] += n
	return nil
}

func (m *MemoryStore) Get(ctx context.Context, agentID, verb string, hour int64) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.keys[memKey{agentID, verb}][hour], nil
}

func (m *MemoryStore) Series(ctx context.Context, agentID, verb string, from int64) (map[int64]int64, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[int64]int64{}
	for h, c := range m.keys[memKey{agentID, verb}] {
		if h >= from {
			out[h] = c
		}
	}
	return out, nil
}

func (m *MemoryStore) Verbs(ctx context.Context, agentID string) ([]string, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for k, hours := range m.keys {
		if k.agent == agentID && len(hours) > 0 {
			out = append(out, k.verb)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (m *MemoryStore) Merge(ctx context.Context, rows []Row) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %v", ErrStoreUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range rows {
		if checkKey(r.AgentID, r.Verb) != nil {
			continue
		}
		k := memKey{r.AgentID, r.Verb}
		hours := m.keys[k]
		if hours == nil {
			hours = map[int64]int64{}
			m.keys[k] = hours
		}
		if r.Count > hours[r.Hour] {
			hours[r.Hour] = r.Count
		}
	}
	return nil
}

func (m *MemoryStore) Prune(ctx context.Context, before int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, hours := range m.keys {
		for h := range hours {
			if h < before {
				delete(hours, h)
			}
		}
		if len(hours) == 0 {
			delete(m.keys, k)
		}
	}
	return nil
}

func (m *MemoryStore) Close() error { return nil }

// --- redis -------------------------------------------------------------------

// RedisStore keeps one Redis hash per (agent, verb) (field = unix hour start,
// value = count) and one set of verbs per agent. Keys expire after the
// retention unless written again; the first write of a new hour also drops
// the hash's fields older than the retention.
type RedisStore struct {
	client    *redis.Client
	prefix    string
	retention time.Duration
}

// NewRedisStore connects lazily to url (redis://[:password@]host:port/db).
// Short timeouts: the store sits on the decision path, and a slow Redis must
// fail the decision closed rather than stall it.
func NewRedisStore(url string, retention time.Duration) (*RedisStore, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		// The URL may carry a password: never echo it.
		return nil, errors.New("baseline: invalid counters.redis_url")
	}
	opt.DialTimeout = time.Second
	opt.ReadTimeout = 500 * time.Millisecond
	opt.WriteTimeout = 500 * time.Millisecond
	opt.MaxRetries = 1
	if retention <= 0 {
		retention = 15 * 24 * time.Hour
	}
	return &RedisStore{client: redis.NewClient(opt), prefix: "fortik:bl:", retention: retention}, nil
}

func (r *RedisStore) Ping(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("%w: redis ping: %v", ErrStoreUnavailable, err)
	}
	return nil
}

func (r *RedisStore) Close() error { return r.client.Close() }

func (r *RedisStore) loadedKey() string { return r.prefix + "loaded" }

// Loaded reports whether the marker of the last load is still present.
func (r *RedisStore) Loaded(ctx context.Context) (bool, error) {
	n, err := r.client.Exists(ctx, r.loadedKey()).Result()
	if err != nil {
		return false, fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	return n == 1, nil
}

// MarkLoaded writes the marker (no expiry: it disappears only with the data).
func (r *RedisStore) MarkLoaded(ctx context.Context) error {
	if err := r.client.Set(ctx, r.loadedKey(), time.Now().UTC().Format(time.RFC3339), 0).Err(); err != nil {
		return fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	return nil
}

// Verbs never contain ':' (fixed upper-case set), so the key is unambiguous.
func (r *RedisStore) hashKey(agentID, verb string) string {
	return r.prefix + "h:" + verb + ":" + agentID
}
func (r *RedisStore) verbsKey(agentID string) string { return r.prefix + "v:" + agentID }

// KEYS[1] hash, KEYS[2] verbs set; ARGV[1] hour, ARGV[2] n, ARGV[3] ttl
// seconds, ARGV[4] verb, ARGV[5] oldest hour kept.
var addScript = redis.NewScript(`
local v = redis.call('HINCRBY', KEYS[1], ARGV[1], ARGV[2])
redis.call('EXPIRE', KEYS[1], ARGV[3])
redis.call('SADD', KEYS[2], ARGV[4])
redis.call('EXPIRE', KEYS[2], ARGV[3])
if v == tonumber(ARGV[2]) then
  local fields = redis.call('HKEYS', KEYS[1])
  local old = {}
  local cutoff = tonumber(ARGV[5])
  for i = 1, #fields do
    if tonumber(fields[i]) < cutoff then old[#old + 1] = fields[i] end
  end
  if #old > 0 then redis.call('HDEL', KEYS[1], unpack(old)) end
end
return v
`)

// KEYS[1] hash, KEYS[2] verbs set; ARGV[1] ttl, ARGV[2] verb, then pairs
// hour, count: each field is raised to at least count.
var mergeScript = redis.NewScript(`
for i = 3, #ARGV, 2 do
  local cur = tonumber(redis.call('HGET', KEYS[1], ARGV[i]) or '0')
  if tonumber(ARGV[i + 1]) > cur then redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1]) end
end
redis.call('EXPIRE', KEYS[1], ARGV[1])
redis.call('SADD', KEYS[2], ARGV[2])
redis.call('EXPIRE', KEYS[2], ARGV[1])
return 1
`)

func (r *RedisStore) ttl() string { return strconv.FormatInt(int64(r.retention.Seconds()), 10) }

func (r *RedisStore) Add(ctx context.Context, agentID, verb string, hour, n int64) error {
	if err := checkKey(agentID, verb); err != nil {
		return err
	}
	cutoff := hour - int64(r.retention.Seconds())
	err := addScript.Run(ctx, r.client, []string{r.hashKey(agentID, verb), r.verbsKey(agentID)},
		strconv.FormatInt(hour, 10), strconv.FormatInt(n, 10), r.ttl(), verb, strconv.FormatInt(cutoff, 10)).Err()
	if err != nil {
		return fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	return nil
}

func (r *RedisStore) Get(ctx context.Context, agentID, verb string, hour int64) (int64, error) {
	if err := checkKey(agentID, verb); err != nil {
		return 0, err
	}
	v, err := r.client.HGet(ctx, r.hashKey(agentID, verb), strconv.FormatInt(hour, 10)).Int64()
	if errors.Is(err, redis.Nil) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	return v, nil
}

func (r *RedisStore) Series(ctx context.Context, agentID, verb string, from int64) (map[int64]int64, error) {
	if err := checkKey(agentID, verb); err != nil {
		return nil, err
	}
	all, err := r.client.HGetAll(ctx, r.hashKey(agentID, verb)).Result()
	if err != nil {
		return nil, fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	out := make(map[int64]int64, len(all))
	for f, v := range all {
		h, err1 := strconv.ParseInt(f, 10, 64)
		c, err2 := strconv.ParseInt(v, 10, 64)
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("%w: malformed hash field %q", ErrStoreUnavailable, f)
		}
		if h >= from {
			out[h] = c
		}
	}
	return out, nil
}

func (r *RedisStore) Verbs(ctx context.Context, agentID string) ([]string, error) {
	if agentID == "" || len(agentID) > 256 {
		return nil, fmt.Errorf("%w: invalid agent", ErrStoreUnavailable)
	}
	v, err := r.client.SMembers(ctx, r.verbsKey(agentID)).Result()
	if err != nil {
		return nil, fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	sort.Strings(v)
	return v, nil
}

func (r *RedisStore) Merge(ctx context.Context, rows []Row) error {
	type key struct{ agent, verb string }
	byKey := map[key][]string{}
	var order []key
	for _, row := range rows {
		if checkKey(row.AgentID, row.Verb) != nil {
			continue
		}
		k := key{row.AgentID, row.Verb}
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], strconv.FormatInt(row.Hour, 10), strconv.FormatInt(row.Count, 10))
	}
	if len(order) == 0 {
		return nil
	}
	// EVAL (not EVALSHA): a pipelined EVALSHA on a fresh server would answer
	// NOSCRIPT only at Exec. Merge runs at startup and hourly, never per decision.
	pipe := r.client.Pipeline()
	for _, k := range order {
		args := append([]any{r.ttl(), k.verb}, toAny(byKey[k])...)
		mergeScript.Eval(ctx, pipe, []string{r.hashKey(k.agent, k.verb), r.verbsKey(k.agent)}, args...)
	}
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("%w: redis: %v", ErrStoreUnavailable, err)
	}
	return nil
}

// Prune is a no-op: keys expire after the retention and old fields are
// dropped on the first write of each hour.
func (r *RedisStore) Prune(context.Context, int64) error { return nil }

func toAny(ss []string) []any {
	out := make([]any, len(ss))
	for i, s := range ss {
		out[i] = s
	}
	return out
}
