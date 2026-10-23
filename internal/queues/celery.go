package queues

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"

	"fortik/internal/integrations"
)

// Celery over a Redis broker (kombu's Redis transport):
//
//   - a queue is a Redis list; producers LPUSH a JSON envelope and workers
//     BRPOP from the right, so the right end is the oldest message;
//   - priority sub-queues are "<queue>\x06\x16<step>" for steps 3, 6, 9;
//   - messages a worker has fetched but not acknowledged (prefetched or
//     running) are in the hash "unacked" (delivery tag -> [envelope,
//     exchange, routing key]) with the score index "unacked_index";
//   - broadcast control commands (revoke) are PUBLISHed to
//     "/<db>.celery.pidbox".
//
// Messages are attributed to an agent by the Celery protocol v2 header
// fortik_agent_id (task.apply_async(..., headers={"fortik_agent_id": id})).
const (
	CeleryAgentHeader = "fortik_agent_id"
	celeryHeldPrefix  = "fortik:held:"
	celerySep         = "\x06\x16"
	celeryUnacked     = "unacked"
	celeryUnackedIdx  = "unacked_index"
	celeryPidbox      = "celery.pidbox"
	celeryRevokeBatch = 1000
)

// celeryPriorityLists are kombu's default priority steps (0 is the queue).
var celeryPrioritySteps = []string{"3", "6", "9"}

// The scripts run atomically inside Redis, so a worker's BRPOP never sees a
// half-moved queue. They touch only messages whose fortik_agent_id header
// equals ARGV[1]; anything else (other agents, untagged or undecodable
// messages) stays exactly where it was, in order.
const celeryLuaCommon = `
local agent = ARGV[1]
local function decode(raw)
  local ok, msg = pcall(cjson.decode, raw)
  if ok and type(msg) == 'table' then return msg end
  return nil
end
local function owner(msg)
  if msg == nil then return nil end
  local h = msg['headers']
  if type(h) ~= 'table' then return nil end
  local a = h['fortik_agent_id']
  if type(a) == 'string' then return a end
  return nil
end
local function task_id(msg)
  local h = msg['headers']
  if type(h) == 'table' and type(h['id']) == 'string' then return h['id'] end
  local p = msg['properties']
  if type(p) == 'table' and type(p['correlation_id']) == 'string' then return p['correlation_id'] end
  return nil
end
local function rpush_all(key, items)
  for i = 1, #items, 500 do
    redis.call('RPUSH', key, unpack(items, i, math.min(i + 499, #items)))
  end
end
-- prepend items to key keeping their order: key becomes items .. key
local function lprepend_all(key, items)
  local rev = {}
  for i = #items, 1, -1 do rev[#rev + 1] = items[i] end
  for i = 1, #rev, 500 do
    redis.call('LPUSH', key, unpack(rev, i, math.min(i + 499, #rev)))
  end
end
-- split removes the agent's messages from a queue list, keeping the rest in
-- order, and returns the removed ones (oldest last, like the list).
local function split(src)
  local items = redis.call('LRANGE', src, 0, -1)
  local keep, take = {}, {}
  for _, raw in ipairs(items) do
    if owner(decode(raw)) == agent then take[#take + 1] = raw else keep[#keep + 1] = raw end
  end
  if #take > 0 then
    redis.call('DEL', src)
    rpush_all(src, keep)
  end
  return take
end
`

// KEYS: queue1, held1, queue2, held2, ... Returns the number moved. Messages
// already held stay older than the ones moved now (held = new .. old).
var celeryPauseScript = redis.NewScript(celeryLuaCommon + `
local moved = 0
for k = 1, #KEYS, 2 do
  local take = split(KEYS[k])
  if #take > 0 then
    lprepend_all(KEYS[k + 1], take)
    moved = moved + #take
  end
end
return moved
`)

// KEYS: queue1, held1, ... Held messages go back to the consuming (right)
// end in their original order: they were queued before anything that
// arrived during the pause, so they run first. Only messages owned by
// ARGV[1] are released (defence in depth: a held list never holds another
// agent's messages, but if one did they stay held). Returns the number
// moved.
var celeryResumeScript = redis.NewScript(celeryLuaCommon + `
local moved = 0
for k = 1, #KEYS, 2 do
  local take = split(KEYS[k + 1])
  if #take > 0 then
    rpush_all(KEYS[k], take)
    moved = moved + #take
  end
end
return moved
`)

// KEYS: queue1, held1, ..., unacked, unacked_index. Deletes the agent's
// queued and held messages and its unacknowledged deliveries (so a dead
// worker's prefetched messages are not restored later), and returns
// {queued, held, unacked, task ids...}. Held entries are filtered by owner
// too (another agent's message in the held list is never deleted).
var celeryCancelScript = redis.NewScript(celeryLuaCommon + `
local queued, held, unacked = 0, 0, 0
local ids = {}
local function add_id(msg)
  if msg ~= nil then
    local id = task_id(msg)
    if id ~= nil then ids[#ids + 1] = id end
  end
end
local n = #KEYS - 2
for k = 1, n, 2 do
  local take = split(KEYS[k])
  for _, raw in ipairs(take) do add_id(decode(raw)) end
  queued = queued + #take
  local h = split(KEYS[k + 1])
  for _, raw in ipairs(h) do add_id(decode(raw)) end
  held = held + #h
end
local ua, uidx = KEYS[n + 1], KEYS[n + 2]
local all = redis.call('HGETALL', ua)
for i = 1, #all, 2 do
  local entry = decode(all[i + 1])
  if type(entry) == 'table' and type(entry[1]) == 'table' and owner(entry[1]) == agent then
    add_id(entry[1])
    redis.call('HDEL', ua, all[i])
    redis.call('ZREM', uidx, all[i])
    unacked = unacked + 1
  end
end
local out = {queued, held, unacked}
for _, id in ipairs(ids) do out[#out + 1] = id end
return out
`)

// KEYS: unacked. Counts the agent's unacknowledged deliveries (read only).
var celeryCountUnackedScript = redis.NewScript(celeryLuaCommon + `
local n = 0
local all = redis.call('HGETALL', KEYS[1])
for i = 1, #all, 2 do
  local entry = decode(all[i + 1])
  if type(entry) == 'table' and type(entry[1]) == 'table' and owner(entry[1]) == agent then n = n + 1 end
end
return n
`)

// Celery is the queue adapter for Celery with a Redis broker.
type Celery struct {
	src integrations.Source
	// dial opens a client for one operation (tests may override).
	dial func(opts *redis.Options) *redis.Client
	// reholdEvery is the HoldWorker interval (nanoseconds) while one is
	// running, 0 otherwise; Pause's detail states it honestly.
	reholdEvery atomic.Int64
}

var (
	_ Adapter             = (*Celery)(nil)
	_ integrations.Tester = (*Celery)(nil)
)

// NewCelery builds the adapter. It opens a short-lived Redis connection per
// operation with the broker URL from the "celery" integration.
func NewCelery(src integrations.Source) *Celery {
	return &Celery{src: src, dial: redis.NewClient}
}

func (*Celery) System() string { return SystemCelery }

type celerySettings struct {
	opts   *redis.Options
	queues []string
}

func parseCelery(r integrations.Resolved) (celerySettings, error) {
	raw := r.Secret("redis_url")
	if raw == "" {
		return celerySettings{}, fmt.Errorf("%w: celery: broker URL not set", ErrNotConfigured)
	}
	opts, err := redis.ParseURL(raw)
	if err != nil {
		// Never wrap the parse error: it may quote the URL (and password).
		return celerySettings{}, errors.New("celery: the configured broker URL is not a valid redis:// or rediss:// URL")
	}
	opts.DialTimeout = 5 * time.Second
	opts.ReadTimeout = 15 * time.Second
	opts.WriteTimeout = 15 * time.Second
	opts.PoolSize = 2
	opts.MaxRetries = 1
	opts.ClientName = "fortik-queues"
	opts.DisableIdentity = true
	queues := r.Strings("queues")
	if len(queues) == 0 {
		queues = []string{"celery"}
	}
	for _, q := range queues {
		if q == "" || len(q) > 200 || strings.ContainsAny(q, celerySep+" \t\r\n") {
			return celerySettings{}, errors.New("celery: invalid queue name in settings")
		}
	}
	return celerySettings{opts: opts, queues: queues}, nil
}

// celeryLists returns every Redis list of the configured queues (with the
// priority sub-queues).
func celeryLists(queues []string) []string {
	var out []string
	for _, q := range queues {
		out = append(out, q)
		for _, step := range celeryPrioritySteps {
			out = append(out, q+celerySep+step)
		}
	}
	return out
}

// celeryHeldSep separates the agent id from the list name in held keys.
// Agent ids (agentIDPattern) never contain '/', so the first '/' after the
// prefix always ends the agent id: two (agent, list) pairs never share a
// key, whatever the queue names contain (':' is allowed in both agent ids
// and queue names, which made "<agent>:<list>" ambiguous).
const celeryHeldSep = "/"

// CeleryHeldKey is where Pause keeps an agent's messages from one list:
// fortik:held:<agent>/<list>.
func CeleryHeldKey(agentID, list string) string {
	return celeryHeldPrefix + agentID + celeryHeldSep + list
}

func pairKeys(agentID string, lists []string) []string {
	keys := make([]string, 0, 2*len(lists))
	for _, l := range lists {
		keys = append(keys, l, CeleryHeldKey(agentID, l))
	}
	return keys
}

func (c *Celery) open(ctx context.Context) (*redis.Client, celerySettings, error) {
	r, err := resolve(ctx, c.src, SystemCelery)
	if err != nil {
		return nil, celerySettings{}, err
	}
	return c.openResolved(r)
}

func (c *Celery) openResolved(r integrations.Resolved) (*redis.Client, celerySettings, error) {
	s, err := parseCelery(r)
	if err != nil {
		return nil, s, err
	}
	return c.dial(s.opts), s, nil
}

// redisErr describes a Redis error without the address or credentials.
func redisErr(op string, err error) error {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("celery: %s: timed out", op)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("celery: %s: cancelled", op)
	}
	var re redis.Error
	if errors.As(err, &re) {
		return fmt.Errorf("celery: %s: redis error: %s", op, re.Error())
	}
	return fmt.Errorf("celery: %s: cannot reach the Redis broker", op)
}

const celeryPrefetchNote = "Celery workers reserve messages in advance (prefetch and ETA/countdown tasks); "

// CeleryLaterArrivalsNote is the honest limit of a Celery hold: it moves the
// messages present when it runs. Producers are not gated, so later messages
// (including Celery retries) are taken by workers unless a later hold run
// (HoldWorker, when it is running) moves them first.
const CeleryLaterArrivalsNote = "messages enqueued after this moment are NOT held"

// Pause moves the agent's waiting messages out of the queues into
// fortik:held:<agent>/<queue>, atomically. Messages a worker has already
// fetched are not in Redis's queues any more and cannot be held; the detail
// says how many there are.
func (c *Celery) Pause(ctx context.Context, agentID, reason string) (Result, error) {
	res := Result{System: SystemCelery}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	rdb, s, err := c.open(ctx)
	if err != nil {
		return res, err
	}
	defer rdb.Close()
	lists := celeryLists(s.queues)
	moved, err := celeryPauseScript.Run(ctx, rdb, pairKeys(agentID, lists), agentID).Int()
	if err != nil {
		return res, redisErr("hold messages", err)
	}
	res.Affected = moved
	res.Detail = fmt.Sprintf("held %s from %s (moved to %s<queue>; Resume puts them back in order); %s",
		plural(moved, "queued message", "queued messages"), plural(len(s.queues), "queue", "queues"), CeleryHeldKey(agentID, ""), CeleryLaterArrivalsNote)
	if every := time.Duration(c.reholdEvery.Load()); every > 0 {
		res.Detail += fmt.Sprintf(" by this step (Fortik re-holds new ones every %s while the agent stays suspended or quarantined; a worker can take one before that)", every)
	} else {
		res.Detail += " (no periodic re-hold is running: workers will run them)"
	}
	inflight, err := celeryCountUnackedScript.Run(ctx, rdb, []string{celeryUnacked}, agentID).Int()
	switch {
	case err != nil:
		res.Detail += "; could not count messages already fetched by workers"
	case inflight > 0:
		res.Detail += "; " + celeryPrefetchNote + plural(inflight, "message of this agent was", "messages of this agent were") +
			" already fetched by a worker and will still run unless the queue is cancelled"
	}
	return res, nil
}

// Resume moves held messages back to the consuming end of their queues.
func (c *Celery) Resume(ctx context.Context, agentID, reason string) (Result, error) {
	res := Result{System: SystemCelery}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	rdb, s, err := c.open(ctx)
	if err != nil {
		return res, err
	}
	defer rdb.Close()
	moved, err := celeryResumeScript.Run(ctx, rdb, pairKeys(agentID, celeryLists(s.queues)), agentID).Int()
	if err != nil {
		return res, redisErr("release held messages", err)
	}
	res.Affected = moved
	res.Detail = fmt.Sprintf("returned %s to the front of their queues in original order", plural(moved, "held message", "held messages"))
	return res, nil
}

// Cancel deletes the agent's queued, held and unacknowledged messages and
// broadcasts revoke for their task ids, so workers that already fetched
// them discard them instead of running them. Running tasks are not
// terminated. Not reversible.
func (c *Celery) Cancel(ctx context.Context, agentID, reason string) (Result, error) {
	res := Result{System: SystemCelery}
	if err := checkAgentID(agentID); err != nil {
		return res, err
	}
	rdb, s, err := c.open(ctx)
	if err != nil {
		return res, err
	}
	defer rdb.Close()
	keys := append(pairKeys(agentID, celeryLists(s.queues)), celeryUnacked, celeryUnackedIdx)
	vals, err := celeryCancelScript.Run(ctx, rdb, keys, agentID).Slice()
	if err != nil {
		return res, redisErr("delete messages", err)
	}
	if len(vals) < 3 {
		return res, errors.New("celery: unexpected reply from the cancel script")
	}
	queued, held, unacked := toInt(vals[0]), toInt(vals[1]), toInt(vals[2])
	ids := uniqueStrings(vals[3:])
	res.Affected = queued + held + unacked
	res.Detail = fmt.Sprintf("deleted %s, %s and %s fetched by workers",
		plural(queued, "queued message", "queued messages"), plural(held, "held message", "held messages"), plural(unacked, "message", "messages"))
	if len(ids) == 0 {
		res.Detail += "; nothing to revoke; cancellation is not reversible"
		return res, nil
	}
	receivers, err := publishRevoke(ctx, rdb, s.opts.DB, ids)
	if err != nil {
		res.Detail += fmt.Sprintf("; revoke broadcast for %s FAILED (workers that already fetched them may still run them)",
			plural(len(ids), "task id", "task ids"))
		return res, err
	}
	res.Detail += fmt.Sprintf("; broadcast revoke for %s to %s", plural(len(ids), "task id", "task ids"),
		plural(int(receivers), "listening worker connection", "listening worker connections"))
	if receivers == 0 {
		res.Detail += " (no worker was listening: a worker that comes back with these tasks in memory is not told)"
	} else {
		res.Detail += " (workers discard revoked tasks before they start; running tasks are not terminated; revocations live in worker memory)"
	}
	res.Detail += "; cancellation is not reversible: resubmit jobs to run them"
	return res, nil
}

// Test checks the broker is reachable, the credentials work and Lua
// scripting with cjson is available (Pause/Resume/Cancel need it).
func (c *Celery) Test(ctx context.Context, r integrations.Resolved) error {
	rdb, _, err := c.openResolved(r)
	if err != nil {
		return err
	}
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return redisErr("ping", err)
	}
	got, err := rdb.Eval(ctx, `return cjson.decode(ARGV[1])['ok']`, nil, `{"ok":"yes"}`).Text()
	if err != nil || got != "yes" {
		if err == nil {
			err = errors.New("unexpected reply")
		}
		return fmt.Errorf("%w (Fortik needs EVAL with cjson to move messages atomically)", redisErr("lua scripting", err))
	}
	return nil
}

// publishRevoke sends Celery's broadcast "revoke" control command (kombu
// pidbox message, as celery.app.control.Control.revoke sends it) over the
// Redis fanout channel "/<db>.celery.pidbox". It returns the number of
// subscribed connections that received it.
func publishRevoke(ctx context.Context, rdb *redis.Client, db int, ids []string) (int64, error) {
	var total int64
	for start := 0; start < len(ids); start += celeryRevokeBatch {
		batch := ids[start:min(start+celeryRevokeBatch, len(ids))]
		msg, err := celeryRevokeMessage(batch)
		if err != nil {
			return total, err
		}
		n, err := rdb.Publish(ctx, CeleryPidboxChannel(db), msg).Result()
		if err != nil {
			return total, redisErr("publish revoke", err)
		}
		total = max(total, n)
	}
	return total, nil
}

// CeleryPidboxChannel is kombu's Redis fanout topic for celery.pidbox.
func CeleryPidboxChannel(db int) string { return "/" + strconv.Itoa(db) + "." + celeryPidbox }

func celeryRevokeMessage(ids []string) ([]byte, error) {
	body, err := json.Marshal(map[string]any{
		"method":      "revoke",
		"arguments":   map[string]any{"task_id": ids, "terminate": false, "signal": "SIGTERM"},
		"destination": nil,
		"pattern":     nil,
		"matcher":     nil,
	})
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{
		"body":             base64.StdEncoding.EncodeToString(body),
		"content-encoding": "utf-8",
		"content-type":     "application/json",
		// expires 0 = never (as Celery sends broadcasts without a reply).
		"headers": map[string]any{"clock": 1, "expires": 0},
		"properties": map[string]any{
			"delivery_mode": 2,
			"delivery_info": map[string]any{"exchange": celeryPidbox, "routing_key": ""},
			"priority":      0,
			"body_encoding": "base64",
			"delivery_tag":  newUUID(),
		},
	})
}

func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func toInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func uniqueStrings(vals []any) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range vals {
		s, ok := v.(string)
		if !ok || s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
