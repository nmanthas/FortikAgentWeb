package queues

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"

	"fortik/internal/control"
)

// holdMaxAgents caps the contained agents one HoldWorker pass handles (the
// rest are logged and handled once the first ones are released).
const holdMaxAgents = 10000

// celeryHoldManyScript is the Celery hold for many agents in one pass: each
// queue list is read once (a hold runs inside Redis and blocks it, so a
// per-agent pass over the same lists would multiply that cost).
//
// KEYS: queue lists. ARGV[1]: held key prefix, ARGV[2]: separator,
// ARGV[3..]: agent ids (validated by the caller; they become key names).
// Messages of those agents move to <prefix><agent><sep><list>, exactly as
// Pause moves them. Returns {agent, moved, agent, moved, ...}.
var celeryHoldManyScript = redis.NewScript(celeryLuaCommon + `
local prefix, sep = ARGV[1], ARGV[2]
local set = {}
for i = 3, #ARGV do set[ARGV[i]] = true end
local moved, order = {}, {}
for k = 1, #KEYS do
  local src = KEYS[k]
  local items = redis.call('LRANGE', src, 0, -1)
  local keep, take, any = {}, {}, false
  for _, raw in ipairs(items) do
    local a = owner(decode(raw))
    if a ~= nil and set[a] then
      if take[a] == nil then take[a] = {} end
      local l = take[a]
      l[#l + 1] = raw
      any = true
    else
      keep[#keep + 1] = raw
    end
  end
  if any then
    redis.call('DEL', src)
    rpush_all(src, keep)
    for a, l in pairs(take) do
      lprepend_all(prefix .. a .. sep .. src, l)
      if moved[a] == nil then moved[a] = 0; order[#order + 1] = a end
      moved[a] = moved[a] + #l
    end
  end
end
local out = {}
for _, a in ipairs(order) do out[#out + 1] = a; out[#out + 1] = moved[a] end
return out
`)

// HoldWorker closes the gap of the one-shot Celery hold (F21): Pause moves
// the messages present at that moment, but producers are not gated, so
// messages enqueued later for a contained agent would run. While an agent
// stays suspended (agents.suspended_at set) or quarantined/killed (level >=
// QUARANTINED), the worker periodically moves its newly queued messages to
// the same held lists Pause uses, so Resume releases them in order.
//
// A worker can still take a message that arrives between two passes; the
// Pause detail says so. Temporal needs no sweeper (new workflows check the
// pause marker) and the webhook system holds its own work.
type HoldWorker struct {
	pool     *pgxpool.Pool
	celery   *Celery
	interval time.Duration
	log      *slog.Logger
	// afterHold runs between the hold and the re-check (tests only).
	afterHold func()
}

// NewHoldWorker builds the re-hold sweeper (interval <= 0 means 10s). log
// may be nil.
func NewHoldWorker(pool *pgxpool.Pool, celery *Celery, interval time.Duration, log *slog.Logger) *HoldWorker {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &HoldWorker{pool: pool, celery: celery, interval: interval, log: log.With("component", "queues.hold")}
}

// Run re-holds every interval until ctx ends. While it runs, Celery's Pause
// detail states the re-hold interval.
func (w *HoldWorker) Run(ctx context.Context) {
	w.celery.reholdEvery.Store(int64(w.interval))
	defer w.celery.reholdEvery.Store(0)
	t := time.NewTicker(w.interval)
	defer t.Stop()
	for {
		if _, err := w.RunOnce(ctx); err != nil && ctx.Err() == nil {
			w.log.Warn("celery re-hold failed; contained agents' new messages may run", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// contained returns the agents whose queued work must stay held.
func (w *HoldWorker) contained(ctx context.Context) ([]string, error) {
	rows, err := w.pool.Query(ctx, `SELECT agent_id FROM agents
		WHERE suspended_at IS NOT NULL OR level >= $2 ORDER BY agent_id LIMIT $1`, holdMaxAgents+1, int16(control.Quarantined))
	if err != nil {
		return nil, fmt.Errorf("queues: list contained agents: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("queues: list contained agents: %w", err)
	}
	return ids, nil
}

// RunOnce runs one pass and returns how many messages it held per agent.
// An unconfigured Celery integration is not an error (nothing to hold).
func (w *HoldWorker) RunOnce(ctx context.Context) (map[string]int, error) {
	ids, err := w.contained(ctx)
	if err != nil {
		return nil, err
	}
	if len(ids) > holdMaxAgents {
		w.log.Error("more contained agents than one re-hold pass handles; the rest are not re-held this pass", "limit", holdMaxAgents)
		ids = ids[:holdMaxAgents]
	}
	valid := ids[:0:0]
	for _, id := range ids {
		if checkAgentID(id) != nil {
			w.log.Error("contained agent id cannot be used in Redis keys; its new messages are not re-held", "agent_id", id)
			continue
		}
		valid = append(valid, id)
	}
	if len(valid) == 0 {
		return map[string]int{}, nil
	}
	rdb, s, err := w.celery.open(ctx)
	if errors.Is(err, ErrNotConfigured) {
		return map[string]int{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer rdb.Close()

	args := make([]any, 0, len(valid)+2)
	args = append(args, celeryHeldPrefix, celeryHeldSep)
	for _, id := range valid {
		args = append(args, id)
	}
	lists := celeryLists(s.queues)
	vals, err := celeryHoldManyScript.Run(ctx, rdb, lists, args...).Slice()
	if err != nil {
		return nil, redisErr("re-hold messages", err)
	}
	held := map[string]int{}
	for i := 0; i+1 < len(vals); i += 2 {
		if a, ok := vals[i].(string); ok {
			held[a] = toInt(vals[i+1])
		}
	}
	if len(held) == 0 {
		return held, nil
	}
	if w.afterHold != nil {
		w.afterHold()
	}

	// An agent resumed while this pass ran: its resume may already have
	// released the held lists, so what this pass just held would stay held
	// for an agent that is no longer contained. Re-read the state after
	// holding and release those agents' messages (Resume clears the flag
	// before it releases, so one of the two always runs last).
	still, err := w.contained(ctx)
	if err != nil {
		return held, fmt.Errorf("re-held messages but could not re-check the agents (a resumed agent's messages may stay held until its next resume): %w", err)
	}
	isContained := make(map[string]bool, len(still))
	for _, id := range still {
		isContained[id] = true
	}
	var errs []error
	for a, n := range held {
		if isContained[a] {
			w.log.Info("re-held messages enqueued for a contained agent", "agent_id", a, "messages", n)
			continue
		}
		moved, err := celeryResumeScript.Run(ctx, rdb, pairKeys(a, lists), a).Int()
		if err != nil {
			errs = append(errs, fmt.Errorf("agent %s was resumed during the re-hold and its messages could not be released: %w", a, redisErr("release held messages", err)))
			continue
		}
		w.log.Info("released messages re-held while the agent was being resumed", "agent_id", a, "messages", moved)
		delete(held, a)
	}
	return held, errors.Join(errs...)
}
