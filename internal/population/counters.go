package population

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"

	"fortik/internal/config"
)

// Counters are hot sliding-window counters (spawn rates, action rates,
// denial surges). A key must always be used with the same window. Any error
// means the counters are unavailable: callers on the decision path fail
// closed.
//
// Both implementations count in one-second buckets: Count(key, w) is the sum
// of the buckets of the last ceil(w/1s) seconds, including the current one.
type Counters interface {
	// Incr adds one event now and returns the count within window,
	// including this event.
	Incr(ctx context.Context, key string, window time.Duration) (int64, error)
	// Count returns the number of events within window.
	Count(ctx context.Context, key string, window time.Duration) (int64, error)
}

// ErrCountersUnavailable wraps every counters backend failure.
var ErrCountersUnavailable = errors.New("population counters unavailable")

// maxWindow bounds windows (and so the buckets kept per key).
const maxWindow = 24 * time.Hour

func windowSeconds(w time.Duration) (int64, error) {
	if w <= 0 || w > maxWindow {
		return 0, fmt.Errorf("%w: window %s out of range (0, %s]", ErrCountersUnavailable, w, maxWindow)
	}
	return int64(math.Ceil(w.Seconds())), nil
}

func checkKey(key string) error {
	if key == "" || len(key) > 512 {
		return fmt.Errorf("%w: invalid counter key", ErrCountersUnavailable)
	}
	return nil
}

// NewCounters builds the configured counters (counters.provider). The redis
// provider is pinged once; an unreachable Redis at startup is an error.
func NewCounters(ctx context.Context, c config.CountersConfig) (Counters, func() error, error) {
	switch c.Provider {
	case "", "memory":
		return NewMemoryCounters(), func() error { return nil }, nil
	case "redis":
		rc, err := NewRedisCounters(c.RedisURL)
		if err != nil {
			return nil, nil, err
		}
		pctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		if err := rc.Ping(pctx); err != nil {
			_ = rc.Close()
			return nil, nil, err
		}
		return rc, rc.Close, nil
	default:
		return nil, nil, fmt.Errorf("population: unknown counters provider %q", c.Provider)
	}
}

// --- memory ------------------------------------------------------------------

// MemoryCounters is a single-process implementation (dev, tests, single
// node). Idle keys are swept periodically so memory stays bounded by the
// number of keys active within their window.
type MemoryCounters struct {
	// Now is the clock (tests); default time.Now.
	Now func() time.Time

	mu   sync.Mutex
	keys map[string]*memKey
	ops  int
}

type memKey struct {
	window  int64           // seconds
	buckets map[int64]int64 // unix second -> count
}

func NewMemoryCounters() *MemoryCounters { return &MemoryCounters{keys: map[string]*memKey{}} }

func (m *MemoryCounters) nowSec() int64 {
	if m.Now != nil {
		return m.Now().Unix()
	}
	return time.Now().Unix()
}

func (m *MemoryCounters) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	return m.add(ctx, key, window, 1)
}

func (m *MemoryCounters) Count(ctx context.Context, key string, window time.Duration) (int64, error) {
	return m.add(ctx, key, window, 0)
}

func (m *MemoryCounters) add(ctx context.Context, key string, window time.Duration, n int64) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %v", ErrCountersUnavailable, err)
	}
	if err := checkKey(key); err != nil {
		return 0, err
	}
	w, err := windowSeconds(window)
	if err != nil {
		return 0, err
	}
	now := m.nowSec()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops++
	if m.ops%1024 == 0 {
		m.sweep(now)
	}
	k := m.keys[key]
	if k == nil {
		if n == 0 {
			return 0, nil
		}
		k = &memKey{window: w, buckets: map[int64]int64{}}
		m.keys[key] = k
	}
	if w > k.window {
		k.window = w
	}
	if n > 0 {
		k.buckets[now] += n
	}
	var total int64
	for sec, c := range k.buckets {
		switch {
		case sec > now-w:
			total += c
		case sec <= now-k.window:
			delete(k.buckets, sec)
		}
	}
	return total, nil
}

// sweep drops keys with no bucket inside their window. Caller holds mu.
func (m *MemoryCounters) sweep(now int64) {
	for key, k := range m.keys {
		live := false
		for sec := range k.buckets {
			if sec > now-k.window {
				live = true
				break
			}
		}
		if !live {
			delete(m.keys, key)
		}
	}
}

// --- redis -------------------------------------------------------------------

// RedisCounters keeps each counter as a Redis hash of one-second buckets,
// updated and summed atomically by a Lua script using the Redis server clock
// (so several Fortik processes agree on the window).
type RedisCounters struct {
	client *redis.Client
	prefix string
}

// NewRedisCounters connects lazily to url (redis://[:password@]host:port/db).
// Short timeouts: the counters sit on the decision path, and a slow Redis
// must fail the decision closed rather than stall it.
func NewRedisCounters(url string) (*RedisCounters, error) {
	opt, err := redis.ParseURL(url)
	if err != nil {
		// The URL may carry a password: never echo it.
		return nil, errors.New("population: invalid counters.redis_url")
	}
	opt.DialTimeout = time.Second
	opt.ReadTimeout = 500 * time.Millisecond
	opt.WriteTimeout = 500 * time.Millisecond
	opt.MaxRetries = 1
	return &RedisCounters{client: redis.NewClient(opt), prefix: "fortik:ctr:"}, nil
}

func (r *RedisCounters) Ping(ctx context.Context) error {
	if err := r.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("%w: redis ping: %v", ErrCountersUnavailable, err)
	}
	return nil
}

func (r *RedisCounters) Close() error { return r.client.Close() }

// KEYS[1] counter hash; ARGV[1] window seconds; ARGV[2] increment (0 = read).
var slidingScript = redis.NewScript(`
local t = redis.call('TIME')
local now = tonumber(t[1])
local w = tonumber(ARGV[1])
local n = tonumber(ARGV[2])
if n > 0 then
  redis.call('HINCRBY', KEYS[1], now, n)
  redis.call('EXPIRE', KEYS[1], w + 1)
end
local vals = redis.call('HGETALL', KEYS[1])
local total = 0
local old = {}
for i = 1, #vals, 2 do
  local sec = tonumber(vals[i])
  if sec > now - w then
    total = total + tonumber(vals[i + 1])
  else
    old[#old + 1] = vals[i]
  end
end
if n > 0 and #old > 0 then
  redis.call('HDEL', KEYS[1], unpack(old))
end
return total
`)

func (r *RedisCounters) Incr(ctx context.Context, key string, window time.Duration) (int64, error) {
	return r.run(ctx, key, window, 1)
}

func (r *RedisCounters) Count(ctx context.Context, key string, window time.Duration) (int64, error) {
	return r.run(ctx, key, window, 0)
}

func (r *RedisCounters) run(ctx context.Context, key string, window time.Duration, n int) (int64, error) {
	if err := checkKey(key); err != nil {
		return 0, err
	}
	w, err := windowSeconds(window)
	if err != nil {
		return 0, err
	}
	v, err := slidingScript.Run(ctx, r.client, []string{r.prefix + key}, strconv.FormatInt(w, 10), strconv.Itoa(n)).Int64()
	if err != nil {
		return 0, fmt.Errorf("%w: redis: %v", ErrCountersUnavailable, err)
	}
	return v, nil
}
