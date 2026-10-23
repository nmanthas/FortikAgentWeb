package population

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"fortik/internal/diary"
)

// Diary event types for containment of copies (docs/PHASE4_DESIGN.md §1).
const (
	EventInstanceSuspended = "instance.suspended"
	EventInstanceResumed   = "instance.resumed"
)

// SuspendedError is returned by Heartbeat for a suspended instance: it is
// still registered but must pause until resumed. The handler answers 423
// {"action":"pause"}.
type SuspendedError struct{ Instance Instance }

func (e *SuspendedError) Error() string {
	return fmt.Sprintf("instance %s is suspended: pause until resumed", e.Instance.InstanceID)
}

// InstanceControl is the containment service's view of copies (it satisfies
// containment.Instances). Each method acts on one instance of the agent, or
// on all of its instances when instanceID is "", runs in its own transaction
// with one Diary event per changed instance, is idempotent, and returns the
// ids it changed plus an honest human summary.
type InstanceControl struct{ svc *Service }

// InstanceControl returns the containment adapter of the service.
func (s *Service) InstanceControl() *InstanceControl { return &InstanceControl{svc: s} }

// lockAgentInstances locks the agent row (lock order agents -> instances ->
// diary_head, as in decisions) and returns the copy cap. With an instance
// id it also checks the instance belongs to the agent.
func (c *InstanceControl) lockAgentInstances(ctx context.Context, tx pgx.Tx, agentID, instanceID string) (int, error) {
	var copyCap int
	if err := tx.QueryRow(ctx, `SELECT copy_cap FROM agents WHERE agent_id = $1 FOR UPDATE`, agentID).Scan(&copyCap); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrAgentNotFound
		}
		return 0, err
	}
	if instanceID != "" {
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM instances WHERE instance_id = $1 AND agent_id = $2)`, instanceID, agentID).Scan(&ok); err != nil {
			return 0, err
		}
		if !ok {
			return 0, ErrInstanceNotFound
		}
	}
	return copyCap, nil
}

func copiesScope(instanceID string) string {
	if instanceID == "" {
		return "the agent's copies"
	}
	return "instance " + instanceID
}

// SuspendInstances moves live copies (stale ones included: a stale copy that
// comes back must pause too) to "suspended". They answer 423 "pause" on
// heartbeat and their actions are refused (POL-705). Paused, stopped and
// refused copies already must stop and are left as they are.
func (c *InstanceControl) SuspendInstances(ctx context.Context, agentID, instanceID, actor, reason string) ([]string, string, error) {
	why := clip("suspended: "+strings.TrimSpace(reason), maxReasonLen)
	var ids []string
	err := pgx.BeginFunc(ctx, c.svc.pool, func(tx pgx.Tx) error {
		if _, err := c.lockAgentInstances(ctx, tx, agentID, instanceID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `UPDATE instances SET status = 'suspended', reason = $3
			WHERE agent_id = $1 AND ($2 = '' OR instance_id = $2) AND status = 'live'
			RETURNING instance_id`, agentID, instanceID, why)
		if err != nil {
			return err
		}
		if ids, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
			return err
		}
		return c.appendEvents(ctx, tx, agentID, EventInstanceSuspended, actor, ids, map[string]any{"reason": why, "previous_status": StatusLive,
			"scope": suspendScope(instanceID)})
	})
	if err != nil {
		return nil, "", err
	}
	if len(ids) == 0 {
		return ids, fmt.Sprintf("no live copies in %s to suspend", copiesScope(instanceID)), nil
	}
	return ids, fmt.Sprintf("%d copies told to pause (heartbeat answers 423 pause; actions refused): %s", len(ids), strings.Join(ids, ", ")), nil
}

// ResumeInstances moves suspended copies back to "live". Copies that kept
// heartbeating while suspended resume, oldest first, up to the agent's
// copy_cap; live copies and the suspended copies this call does not resume
// count against it (a suspended copy keeps its slot). Any beyond the cap are
// paused (they must stop, 410). Copies that stopped heartbeating while
// suspended are stopped (they must register again and pass the caps). Only
// resumed ids are returned; the summary names every copy that was paused,
// stopped or left suspended.
//
// Which suspension a copy is under comes from its latest instance.suspended
// Diary event (actor and scope), written in the transaction that suspended
// it. With instanceID "" (the agent's resume) a copy suspended on its own
// (scope "instance") is left suspended: it is lifted only by resuming that
// copy. With onlyImposedBy non-empty (a caller without the security role),
// only copies whose suspension that actor imposed are resumed; for one
// instance anything else is refused with *ImposedError and nothing changes.
func (c *InstanceControl) ResumeInstances(ctx context.Context, agentID, instanceID, actor, reason, onlyImposedBy string) ([]string, string, error) {
	reason = clip(strings.TrimSpace(reason), maxReasonLen)
	var resumed, paused, stopped, alone, others []string
	var copyCap int
	err := pgx.BeginFunc(ctx, c.svc.pool, func(tx pgx.Tx) error {
		var err error
		if copyCap, err = c.lockAgentInstances(ctx, tx, agentID, instanceID); err != nil {
			return err
		}
		cutoff := c.svc.staleBefore()
		rows, err := tx.Query(ctx, `SELECT instance_id, last_heartbeat > $3 FROM instances
			WHERE agent_id = $1 AND ($2 = '' OR instance_id = $2) AND status = 'suspended'
			ORDER BY started_at ASC, instance_id ASC FOR UPDATE`, agentID, instanceID, cutoff)
		if err != nil {
			return err
		}
		type cand struct {
			id    string
			fresh bool
		}
		cands, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cand, error) {
			var x cand
			return x, r.Scan(&x.id, &x.fresh)
		})
		if err != nil {
			return err
		}
		ids := make([]string, len(cands))
		for i, x := range cands {
			ids[i] = x.id
		}
		by, err := suspensionsOf(ctx, tx, agentID, ids)
		if err != nil {
			return err
		}
		var act []cand
		for _, x := range cands {
			s := by[x.id]
			switch {
			case instanceID == "" && s.scope == scopeInstance:
				alone = append(alone, x.id)
			case onlyImposedBy != "" && s.actor != onlyImposedBy:
				if instanceID != "" {
					return &ImposedError{InstanceID: x.id, By: s.actor}
				}
				others = append(others, x.id)
			default:
				act = append(act, x)
			}
		}
		// Slots in use: fresh live copies plus every suspended copy this
		// call leaves suspended.
		var occupied int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM instances WHERE agent_id = $1
			AND (status = 'live' AND last_heartbeat > $2 OR status = 'suspended')`, agentID, cutoff).Scan(&occupied); err != nil {
			return err
		}
		occupied -= len(act)
		for _, x := range act {
			switch {
			case !x.fresh:
				stopped = append(stopped, x.id)
			case occupied < copyCap:
				resumed = append(resumed, x.id)
				occupied++
			default:
				paused = append(paused, x.id)
			}
		}
		set := func(ids []string, status, why string) error {
			if len(ids) == 0 {
				return nil
			}
			_, err := tx.Exec(ctx, `UPDATE instances SET status = $2, reason = $3 WHERE instance_id = ANY($1)`, ids, status, why)
			return err
		}
		resumeWhy := clip("resumed: "+reason, maxReasonLen)
		pauseWhy := fmt.Sprintf("paused: above copy_cap %d on resume", copyCap)
		stopWhy := fmt.Sprintf("stopped: no heartbeat within %s while suspended; register again", c.svc.cfg.StaleAfter)
		if err := set(resumed, StatusLive, resumeWhy); err != nil {
			return err
		}
		if err := set(paused, StatusPaused, pauseWhy); err != nil {
			return err
		}
		if err := set(stopped, StatusStopped, stopWhy); err != nil {
			return err
		}
		prev := map[string]any{"previous_status": StatusSuspended}
		if err := c.appendEvents(ctx, tx, agentID, EventInstanceResumed, actor, resumed, mergeData(prev, map[string]any{"reason": resumeWhy})); err != nil {
			return err
		}
		if err := c.appendEvents(ctx, tx, agentID, EventInstancePaused, actor, paused, mergeData(prev, map[string]any{"reason": pauseWhy, "copy_cap": copyCap})); err != nil {
			return err
		}
		return c.appendEvents(ctx, tx, agentID, EventInstanceStopped, actor, stopped, mergeData(prev, map[string]any{"reason": stopWhy}))
	})
	if err != nil {
		return nil, "", err
	}
	if len(resumed)+len(paused)+len(stopped)+len(alone)+len(others) == 0 {
		return resumed, fmt.Sprintf("no suspended copies in %s", copiesScope(instanceID)), nil
	}
	parts := []string{fmt.Sprintf("%d copies resumed (live)", len(resumed))}
	if len(resumed) > 0 {
		parts[0] += ": " + strings.Join(resumed, ", ")
	}
	if len(paused) > 0 {
		parts = append(parts, fmt.Sprintf("%d paused above copy_cap %d (live and suspended copies count against it; must stop): %s",
			len(paused), copyCap, strings.Join(paused, ", ")))
	}
	if len(stopped) > 0 {
		parts = append(parts, fmt.Sprintf("%d stopped (no heartbeat while suspended; must register again): %s", len(stopped), strings.Join(stopped, ", ")))
	}
	if len(alone) > 0 {
		parts = append(parts, fmt.Sprintf("%d suspended on their own left suspended (resume each copy): %s", len(alone), strings.Join(alone, ", ")))
	}
	if len(others) > 0 {
		parts = append(parts, fmt.Sprintf("%d suspended by someone else left suspended (lifting them requires the security role): %s",
			len(others), strings.Join(others, ", ")))
	}
	return resumed, strings.Join(parts, "; "), nil
}

// SuspendedBy returns the actor whose suspension a suspended copy of the
// agent is under (from its latest instance.suspended Diary event), and
// false when the copy is not suspended.
func (c *InstanceControl) SuspendedBy(ctx context.Context, agentID, instanceID string) (string, bool, error) {
	var status string
	err := c.svc.pool.QueryRow(ctx, `SELECT status FROM instances WHERE instance_id = $1 AND agent_id = $2`, instanceID, agentID).Scan(&status)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, ErrInstanceNotFound
	}
	if err != nil || status != StatusSuspended {
		return "", false, err
	}
	by, err := suspensionsOf(ctx, c.svc.pool, agentID, []string{instanceID})
	if err != nil {
		return "", false, err
	}
	return by[instanceID].actor, true, nil
}

// ImposedError: a caller without the security role asked to lift a copy's
// suspension that someone else imposed.
type ImposedError struct{ InstanceID, By string }

func (e *ImposedError) Error() string {
	by := e.By
	if by == "" {
		by = "an unrecorded actor"
	}
	return fmt.Sprintf("lifting a containment imposed by %s requires the security role", by)
}

// Suspension scopes recorded in instance.suspended events.
const (
	scopeInstance = "instance" // this copy alone (POST /v1/instances/{id}/suspend)
	scopeAgent    = "agent"    // every copy of the agent (agent suspend, e-stop, quarantine)
)

func suspendScope(instanceID string) string {
	if instanceID != "" {
		return scopeInstance
	}
	return scopeAgent
}

type suspension struct{ actor, scope string }

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// suspensionsOf reads the latest instance.suspended event of each copy. An
// event without a scope (written before scopes were recorded) counts as an
// agent-wide suspension; a copy without any event gets an empty actor, which
// no caller matches (fail closed).
func suspensionsOf(ctx context.Context, q querier, agentID string, ids []string) (map[string]suspension, error) {
	out := make(map[string]suspension, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT DISTINCT ON (iid) iid, actor, scope FROM (
			SELECT d.seq, d.actor, d.body_json::jsonb #>> '{data,instance_id}' AS iid,
				COALESCE(d.body_json::jsonb #>> '{data,scope}', 'agent') AS scope
			FROM diary d WHERE d.agent_id = $1 AND d.event_type = $2) e
		WHERE iid = ANY($3) ORDER BY iid, seq DESC`, agentID, EventInstanceSuspended, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var s suspension
		if err := rows.Scan(&id, &s.actor, &s.scope); err != nil {
			return nil, err
		}
		out[id] = s
	}
	return out, rows.Err()
}

// StopInstances stops every copy that is not already stopped or refused
// (kill): heartbeats answer 410 and the copies must not act again.
func (c *InstanceControl) StopInstances(ctx context.Context, agentID, instanceID, actor, reason string) ([]string, string, error) {
	why := clip("stopped: "+strings.TrimSpace(reason), maxReasonLen)
	var ids []string
	err := pgx.BeginFunc(ctx, c.svc.pool, func(tx pgx.Tx) error {
		if _, err := c.lockAgentInstances(ctx, tx, agentID, instanceID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH prev AS (
				SELECT instance_id, status FROM instances
				WHERE agent_id = $1 AND ($2 = '' OR instance_id = $2) AND status NOT IN ('stopped', 'refused') FOR UPDATE)
			UPDATE instances i SET status = 'stopped', reason = $3 FROM prev WHERE i.instance_id = prev.instance_id
			RETURNING i.instance_id, prev.status`, agentID, instanceID, why)
		if err != nil {
			return err
		}
		type stoppedRow struct{ id, prev string }
		got, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (stoppedRow, error) {
			var x stoppedRow
			return x, r.Scan(&x.id, &x.prev)
		})
		if err != nil {
			return err
		}
		events := make([]diary.Event, 0, len(got))
		for _, x := range got {
			ids = append(ids, x.id)
			events = append(events, diary.Event{AgentID: agentID, EventType: EventInstanceStopped, Actor: actor,
				Data: map[string]any{"instance_id": x.id, "previous_status": x.prev, "reason": why}})
		}
		_, err = c.svc.diary.AppendTx(ctx, tx, events...)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	if len(ids) == 0 {
		return ids, fmt.Sprintf("no running copies in %s to stop", copiesScope(instanceID)), nil
	}
	return ids, fmt.Sprintf("%d copies stopped (heartbeat answers 410; actions refused): %s", len(ids), strings.Join(ids, ", ")), nil
}

// PauseExtra pauses the newest live copies above the agent's copy_cap (see
// Service.PauseExtra).
func (c *InstanceControl) PauseExtra(ctx context.Context, agentID, actor, reason string) ([]string, string, error) {
	res, err := c.svc.PauseExtra(ctx, agentID, actor, reason)
	if err != nil {
		return nil, "", err
	}
	if len(res.Paused) == 0 {
		return res.Paused, fmt.Sprintf("%d live copies, within copy_cap %d: none paused", res.LiveBefore, res.CopyCap), nil
	}
	return res.Paused, fmt.Sprintf("%d of %d live copies paused above copy_cap %d (must stop): %s",
		len(res.Paused), res.LiveBefore, res.CopyCap, strings.Join(res.Paused, ", ")), nil
}

func (c *InstanceControl) appendEvents(ctx context.Context, tx pgx.Tx, agentID, eventType, actor string, ids []string, data map[string]any) error {
	if len(ids) == 0 {
		return nil
	}
	events := make([]diary.Event, 0, len(ids))
	for _, id := range ids {
		events = append(events, diary.Event{AgentID: agentID, EventType: eventType, Actor: actor, Data: mergeData(data, map[string]any{"instance_id": id})})
	}
	_, err := c.svc.diary.AppendTx(ctx, tx, events...)
	return err
}

func mergeData(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}
