package population

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/decide"
	"fortik/internal/diary"
	"fortik/internal/policy"
)

// Diary event types written by the population subsystem.
const (
	EventInstanceRegistered = "instance.registered"
	EventInstanceRefused    = "instance.refused"
	EventInstancePaused     = "instance.paused"
	EventInstanceStopped    = "instance.stopped"
	EventAgentTypeChanged   = "agent_type.changed"
)

const systemActor = "system:population"

// ErrSpawnRaceLost: between enrichment and commit another registration took
// the last free copy or type slot. The observer refuses to commit the
// allowed spawn (the decision fails closed); the registration handler
// decides again with fresh counts, which policy then refuses by rule.
var ErrSpawnRaceLost = errors.New("population: a concurrent registration took the last slot")

// raceFlagKey carries a flag the observer sets when it refuses to commit a
// spawn because of ErrSpawnRaceLost, so the register handler re-decides only
// in that case (the decision's fail-closed outcome does not say why).
type raceFlagKey struct{}

func withRaceFlag(ctx context.Context, f *atomic.Bool) context.Context {
	return context.WithValue(ctx, raceFlagKey{}, f)
}

func markRaceLost(ctx context.Context) {
	if f, ok := ctx.Value(raceFlagKey{}).(*atomic.Bool); ok {
		f.Store(true)
	}
}

var (
	instanceIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$`)
	maxHostLen        = 255
	maxReasonLen      = 500
)

// AfterDecide implements decide.Observer. Inside the decision transaction it:
//   - stores the instance of a spawn decision (live when allowed, refused
//     otherwise) with instance.registered / instance.refused, and counts
//     allowed spawns in spawn_stats;
//   - raises copy_cap, population_exceeded, spawn_spike (and starts the
//     spike cooldown) and rate_limited alerts for refused actions, deduped;
//   - counts POL-015 denials and raises unregistered_agent_surge above the
//     per-minute threshold.
//
// Any error rolls the decision back and fails it closed.
func (s *Service) AfterDecide(ctx context.Context, tx pgx.Tx, out *decide.Outcome, in policy.Input) error {
	a := out.Action
	refused := !out.Result.Decision.Executes()
	pc := contextFrom(in)

	if refused && out.Result.RuleID == RuleUnregistered {
		if err := s.countUnregistered(ctx, tx, a); err != nil {
			return err
		}
	}
	if IsSpawn(a) && in.Agent.Registered {
		var err error
		if refused {
			err = s.refuseSpawnTx(ctx, tx, a, out.Result)
		} else {
			err = s.admitSpawnTx(ctx, tx, a, in.Agent.Type)
		}
		if err != nil {
			return err
		}
	}
	if refused && pc != nil && in.Agent.Registered {
		return s.raiseConditionAlerts(ctx, tx, a, *pc, out.Result)
	}
	return nil
}

func contextFrom(in policy.Input) *EnrichedContext {
	switch v := in.Context[ContextKey].(type) {
	case *EnrichedContext:
		return v
	case EnrichedContext:
		return &v
	}
	return nil
}

// spawnTarget is the target of a spawn action (set by the register handler).
type spawnTarget struct {
	InstanceID string
	Host       string
	Parent     string
}

func parseSpawnTarget(a action.Action) (spawnTarget, error) {
	str := func(k string) string { v, _ := a.Target[k].(string); return v }
	t := spawnTarget{InstanceID: str("instance_id"), Host: str("host"), Parent: str("parent_instance_id")}
	if !instanceIDPattern.MatchString(t.InstanceID) {
		return t, fmt.Errorf("population: spawn action %s has no valid target.instance_id", a.ActionID)
	}
	if len(t.Host) > maxHostLen || strings.ContainsRune(t.Host, 0) {
		return t, fmt.Errorf("population: spawn action %s has an invalid target.host", a.ActionID)
	}
	if t.Parent != "" && !instanceIDPattern.MatchString(t.Parent) {
		return t, fmt.Errorf("population: spawn action %s has an invalid target.parent_instance_id", a.ActionID)
	}
	return t, nil
}

// admitSpawnTx stores the allowed instance as live after re-checking the
// copy cap and the type population under a per-scope lock (the counts the
// policy saw were read before this transaction).
func (s *Service) admitSpawnTx(ctx context.Context, tx pgx.Tx, a action.Action, agentType string) error {
	t, err := parseSpawnTarget(a)
	if err != nil {
		return err
	}
	now := s.now()
	scope := spawnScope(a.AgentID, agentType)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "fortik.population.spawn:"+scope); err != nil {
		return err
	}
	var copyCap, agentLive, typeLive, expectedMax int
	var newHost bool
	if err := tx.QueryRow(ctx, `
		SELECT a.copy_cap,
			(SELECT count(*) FROM instances i WHERE i.agent_id = a.agent_id AND (i.status = 'live' AND i.last_heartbeat > $2 OR i.status = 'suspended')),
			CASE WHEN a.type = '' THEN 0 ELSE
				(SELECT count(*) FROM instances i JOIN agents b ON b.agent_id = i.agent_id
				 WHERE b.type = a.type AND (i.status = 'live' AND i.last_heartbeat > $2 OR i.status = 'suspended')) END,
			COALESCE(t.expected_max_instances, 0),
			$3 <> '' AND NOT EXISTS (SELECT 1 FROM instances i WHERE i.agent_id = a.agent_id AND i.host = $3 AND i.status <> 'refused')
		FROM agents a LEFT JOIN agent_types t ON t.type = a.type WHERE a.agent_id = $1`,
		a.AgentID, now.Add(-s.cfg.StaleAfter), t.Host).Scan(&copyCap, &agentLive, &typeLive, &expectedMax, &newHost); err != nil {
		return fmt.Errorf("population: recount: %w", err)
	}
	if agentLive >= copyCap || (expectedMax > 0 && typeLive >= expectedMax) {
		markRaceLost(ctx)
		return ErrSpawnRaceLost
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO instances (instance_id, agent_id, host, parent_instance_id, started_at, last_heartbeat, status, new_host)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5, 'live', $6)`,
		t.InstanceID, a.AgentID, t.Host, t.Parent, now, newHost); err != nil {
		return fmt.Errorf("population: insert instance: %w", err)
	}
	if agentType != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO spawn_stats (hour, agent_type, count) VALUES ($1, $2, 1)
			ON CONFLICT (hour, agent_type) DO UPDATE SET count = spawn_stats.count + 1`,
			now.Truncate(time.Hour), agentType); err != nil {
			return fmt.Errorf("population: spawn_stats: %w", err)
		}
	}
	data := map[string]any{
		"instance_id": t.InstanceID, "host": t.Host, "new_host": newHost, "action_id": a.ActionID,
		"agent_live": agentLive + 1, "copy_cap": copyCap,
	}
	if t.Parent != "" {
		data["parent_instance_id"] = t.Parent
	}
	if agentType != "" {
		data["agent_type"], data["type_live"] = agentType, typeLive+1
	}
	_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: EventInstanceRegistered, Actor: "agent:" + a.AgentID, Data: data})
	return err
}

// refuseSpawnTx stores the refused instance (status refused) so later
// actions and heartbeats carrying its id are refused too.
func (s *Service) refuseSpawnTx(ctx context.Context, tx pgx.Tx, a action.Action, res policy.Result) error {
	t, err := parseSpawnTarget(a)
	if err != nil {
		// Nothing identifiable to store; the refusal itself is recorded.
		return nil
	}
	reason := clip(fmt.Sprintf("%s: %s", res.RuleID, res.Reason), maxReasonLen)
	tag, err := tx.Exec(ctx, `
		INSERT INTO instances (instance_id, agent_id, host, parent_instance_id, started_at, last_heartbeat, status, reason)
		VALUES ($1, $2, $3, NULLIF($4, ''), $5, $5, 'refused', $6)
		ON CONFLICT (instance_id) DO NOTHING`,
		t.InstanceID, a.AgentID, t.Host, t.Parent, s.now(), reason)
	if err != nil {
		return fmt.Errorf("population: insert refused instance: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return nil // the id is already known (e.g. a duplicate registration); nothing changed
	}
	_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: a.AgentID, EventType: EventInstanceRefused, Actor: "agent:" + a.AgentID, Data: map[string]any{
		"instance_id": t.InstanceID, "host": t.Host, "action_id": a.ActionID, "decision": string(res.Decision),
		"rule_id": res.RuleID, "reason": clip(res.Reason, maxReasonLen),
	}})
	return err
}

func (s *Service) raiseConditionAlerts(ctx context.Context, tx pgx.Tx, a action.Action, pc EnrichedContext, res policy.Result) error {
	var list []alerts.Alert
	details := func(m map[string]any) json.RawMessage {
		m["action_id"], m["rule_id"] = a.ActionID, res.RuleID
		if a.InstanceID != "" {
			m["instance_id"] = a.InstanceID
		}
		b, _ := json.Marshal(m)
		return b
	}
	scope := spawnScope(a.AgentID, pc.AgentType)
	if IsSpawn(a) {
		if pc.copyCapReached() {
			list = append(list, alerts.Alert{
				Kind: alerts.KindCopyCap, Severity: alerts.SevHigh, AgentID: a.AgentID, AgentType: pc.AgentType, ActionID: a.ActionID,
				Summary:  fmt.Sprintf("agent %s tried to start a copy beyond its cap (%d live or suspended, copy_cap %d): refused, no credentials", a.AgentID, pc.AgentLive, pc.CopyCap),
				Details:  details(map[string]any{"agent_live": pc.AgentLive, "copy_cap": pc.CopyCap}),
				DedupKey: "copy_cap:agent:" + a.AgentID,
			})
		}
		if pc.typeMaxReached() {
			list = append(list, alerts.Alert{
				Kind: alerts.KindPopulation, Severity: alerts.SevHigh, AgentID: a.AgentID, AgentType: pc.AgentType, ActionID: a.ActionID,
				Summary:  fmt.Sprintf("agent type %s is at its expected population (%d live, expected max %d): new copy refused", pc.AgentType, pc.TypeLive, pc.TypeExpectedMax),
				Details:  details(map[string]any{"type_live": pc.TypeLive, "type_expected_max": pc.TypeExpectedMax}),
				DedupKey: "population_exceeded:type:" + pc.AgentType,
			})
		}
		if exceeded := pc.spawnRateExceeded(); exceeded || pc.SpawnThrottled {
			if exceeded {
				// Start (or extend) the cooldown: spawns stay throttled for
				// spike_cooldown after the last attempt over the limit.
				if _, err := s.counters.Incr(ctx, spikeCounterKey(scope), s.cfg.SpikeCooldown); err != nil {
					return err
				}
			}
			subject := "agent type " + pc.AgentType
			if pc.AgentType == "" {
				subject = "agent " + a.AgentID
			}
			list = append(list, alerts.Alert{
				Kind: alerts.KindSpawnSpike, Severity: alerts.SevHigh, AgentID: a.AgentID, AgentType: pc.AgentType, ActionID: a.ActionID,
				Summary: fmt.Sprintf("spawn spike for %s: %d spawns in the last minute (limit %d, baseline %.2f): throttled for %s",
					subject, pc.SpawnsLastMinute, pc.SpawnRateLimit, pc.SpawnBaselineLimit, s.cfg.SpikeCooldown),
				Details: details(map[string]any{"spawns_last_minute": pc.SpawnsLastMinute, "spawn_rate_limit": pc.SpawnRateLimit,
					"spawn_baseline_limit": pc.SpawnBaselineLimit, "cooldown_seconds": int(s.cfg.SpikeCooldown.Seconds()), "throttled": pc.SpawnThrottled}),
				DedupKey: "spawn_spike:" + scope,
			})
		}
	}
	if pc.actionRateReached() {
		list = append(list, alerts.Alert{
			Kind: alerts.KindRateLimited, Severity: alerts.SevWarning, AgentID: a.AgentID, AgentType: pc.AgentType, ActionID: a.ActionID,
			Summary:  fmt.Sprintf("agent %s is rate limited: %d actions in the last minute (limit %d)", a.AgentID, pc.ActionsLastMinute, pc.ActionRateLimit),
			Details:  details(map[string]any{"actions_last_minute": pc.ActionsLastMinute, "action_rate_limit": pc.ActionRateLimit, "system": a.System}),
			DedupKey: "rate_limited:agent:" + a.AgentID,
		})
	}
	for _, al := range list {
		if _, err := s.alerts.RaiseTx(ctx, tx, al); err != nil {
			return err
		}
	}
	return nil
}

func (s *Service) countUnregistered(ctx context.Context, tx pgx.Tx, a action.Action) error {
	threshold := s.surgeThreshold()
	if threshold < 0 {
		return nil
	}
	n, err := s.counters.Incr(ctx, unregisteredDenialsKey, time.Minute)
	if err != nil {
		return err
	}
	if n <= int64(threshold) {
		return nil
	}
	b, _ := json.Marshal(map[string]any{"denials_last_minute": n, "threshold": threshold, "last_agent_id": a.AgentID,
		"last_action_id": a.ActionID, "system": a.System, "source": a.Source})
	_, err = s.alerts.RaiseTx(ctx, tx, alerts.Alert{
		Kind: alerts.KindUnregisteredSurge, Severity: alerts.SevHigh, ActionID: a.ActionID,
		Summary:  fmt.Sprintf("%d actions by unregistered agents in the last minute (threshold %d)", n, threshold),
		Details:  b,
		DedupKey: "unregistered_agent_surge",
	})
	return err
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && (s[cut]&0xC0) == 0x80 { // do not split a UTF-8 sequence
		cut--
	}
	return s[:cut]
}
