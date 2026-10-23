package swarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"fortik/internal/action"
	"fortik/internal/alerts"
	"fortik/internal/control"
	"fortik/internal/diary"
)

// querier is a pool, a connection or a transaction.
type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

const swarmCols = `swarm_id, COALESCE(root_agent_id, ''), detected_by, signal, COALESCE(action_hash, ''), member_count, state,
	created_at, updated_at, released_at`

func scanSwarm(row pgx.Row) (Swarm, error) {
	var sw Swarm
	var signal []byte
	err := row.Scan(&sw.SwarmID, &sw.RootAgentID, &sw.DetectedBy, &signal, &sw.ActionHash, &sw.MemberCount, &sw.State,
		&sw.CreatedAt, &sw.UpdatedAt, &sw.ReleasedAt)
	if err != nil {
		return Swarm{}, err
	}
	sw.Signal = json.RawMessage(signal)
	sw.Frozen = sw.State == StateKilled
	sw.CreatedAt, sw.UpdatedAt = sw.CreatedAt.UTC(), sw.UpdatedAt.UTC()
	if sw.ReleasedAt != nil {
		t := sw.ReleasedAt.UTC()
		sw.ReleasedAt = &t
	}
	return sw, nil
}

func getSwarm(ctx context.Context, q querier, id string, forUpdate bool) (Swarm, error) {
	sql := `SELECT ` + swarmCols + ` FROM swarms WHERE swarm_id = $1`
	if forUpdate {
		sql += ` FOR UPDATE`
	}
	sw, err := scanSwarm(q.QueryRow(ctx, sql, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return Swarm{}, fmt.Errorf("%w: %s", ErrNotFound, id)
	}
	return sw, err
}

// activeOf returns the active (not released) swarms an agent belongs to,
// newest first, and the first frozen one ("" if none).
func activeOf(ctx context.Context, q querier, agentID string) ([]string, string, error) {
	rows, err := q.Query(ctx, `SELECT s.swarm_id, s.state FROM swarms s
		WHERE s.state <> 'released' AND EXISTS (SELECT 1 FROM swarm_members m WHERE m.swarm_id = s.swarm_id AND m.agent_id = $1)
		ORDER BY s.created_at DESC, s.swarm_id`, agentID)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	ids := []string{}
	frozen := ""
	for rows.Next() {
		var id, state string
		if err := rows.Scan(&id, &state); err != nil {
			return nil, "", err
		}
		ids = append(ids, id)
		if state == StateKilled && frozen == "" {
			frozen = id
		}
	}
	return ids, frozen, rows.Err()
}

// actor is an agent or one of its copies (instance "" = the agent itself).
type actor struct {
	AgentID    string `json:"agent_id"`
	InstanceID string `json:"instance_id,omitempty"`
}

func membersOf(actors []actor, role func(agent string) string) []Member {
	out := make([]Member, 0, len(actors))
	for _, a := range actors {
		out = append(out, Member{AgentID: a.AgentID, InstanceID: a.InstanceID, Role: role(a.AgentID)})
	}
	return out
}

// newSwarm is a swarm about to be created.
type newSwarm struct {
	ID         string
	Root       string
	DetectedBy string
	Signal     map[string]any
	ActionHash string
	State      string
	Members    []Member
	// Since: members' actions from this time on are tagged with the swarm.
	Since time.Time
	// EventAgent is the Diary agent of the detection event ("" = swarm-level).
	EventAgent string
}

// create inserts a swarm, its members, the swarm.detected Diary event and a
// swarm_detected alert, inside tx (which holds diary_head).
func (s *Service) create(ctx context.Context, tx pgx.Tx, ns newSwarm, by string) (Swarm, error) {
	if ns.State == "" {
		ns.State = StateDetected
	}
	sig, err := json.Marshal(ns.Signal)
	if err != nil {
		return Swarm{}, err
	}
	sw, err := scanSwarm(tx.QueryRow(ctx, `INSERT INTO swarms (swarm_id, root_agent_id, detected_by, signal, action_hash, state, created_at, updated_at)
		VALUES ($1, NULLIF($2, ''), $3, $4, NULLIF($5, ''), $6, $7, $7) RETURNING `+swarmCols,
		ns.ID, ns.Root, ns.DetectedBy, sig, ns.ActionHash, ns.State, s.now()))
	if err != nil {
		return Swarm{}, fmt.Errorf("insert swarm: %w", err)
	}
	added, err := s.insertMembers(ctx, tx, sw.SwarmID, ns.Members)
	if err != nil {
		return Swarm{}, err
	}
	if sw.MemberCount, err = s.recount(ctx, tx, sw.SwarmID); err != nil {
		return Swarm{}, err
	}
	if err := s.tag(ctx, tx, sw.SwarmID, agentsOf(added), ns.Since); err != nil {
		return Swarm{}, err
	}
	data := map[string]any{
		"swarm_id": sw.SwarmID, "detected_by": sw.DetectedBy, "root_agent_id": sw.RootAgentID, "signal": ns.Signal,
		"action_hash": sw.ActionHash, "members": added, "member_count": sw.MemberCount, "state": sw.State,
	}
	if _, err := s.diary.AppendTx(ctx, tx, diary.Event{AgentID: ns.EventAgent, EventType: EventDetected, Actor: by, Data: data}); err != nil {
		return Swarm{}, err
	}
	details, _ := json.Marshal(map[string]any{"swarm_id": sw.SwarmID, "detected_by": sw.DetectedBy, "root_agent_id": sw.RootAgentID,
		"member_count": sw.MemberCount, "signal": ns.Signal})
	summary := fmt.Sprintf("swarm %s detected (%s): %d members", sw.SwarmID, strings.ReplaceAll(sw.DetectedBy, "_", " "), sw.MemberCount)
	if sw.RootAgentID != "" {
		summary += ", root " + sw.RootAgentID
	}
	if _, err := s.alerts.RaiseTx(ctx, tx, alerts.Alert{Kind: AlertKind, Severity: alerts.SevHigh, AgentID: sw.RootAgentID,
		Summary: summary, Details: details, DedupKey: "swarm:" + sw.SwarmID}); err != nil {
		return Swarm{}, fmt.Errorf("raise swarm alert: %w", err)
	}
	return sw, nil
}

func (s *Service) insertMembers(ctx context.Context, tx pgx.Tx, swarmID string, ms []Member) ([]Member, error) {
	added := []Member{}
	seen := map[actor]bool{}
	for _, m := range ms {
		k := actor{m.AgentID, m.InstanceID}
		if seen[k] || m.AgentID == "" {
			continue
		}
		seen[k] = true
		role := m.Role
		if role == "" {
			role = RoleMember
		}
		var at time.Time
		err := tx.QueryRow(ctx, `INSERT INTO swarm_members (swarm_id, agent_id, instance_id, role, added_at)
			VALUES ($1, $2, $3, $4, $5) ON CONFLICT (swarm_id, agent_id, instance_id) DO NOTHING RETURNING added_at`,
			swarmID, m.AgentID, m.InstanceID, role, s.now()).Scan(&at)
		if errors.Is(err, pgx.ErrNoRows) {
			if role == RoleRoot {
				// An existing member found to be the root is promoted.
				if _, err := tx.Exec(ctx, `UPDATE swarm_members SET role = 'root' WHERE swarm_id = $1 AND agent_id = $2 AND instance_id = $3`,
					swarmID, m.AgentID, m.InstanceID); err != nil {
					return nil, err
				}
			}
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("insert swarm member: %w", err)
		}
		added = append(added, Member{AgentID: m.AgentID, InstanceID: m.InstanceID, Role: role, AddedAt: at.UTC()})
	}
	return added, nil
}

// recount keeps swarms.member_count current.
func (s *Service) recount(ctx context.Context, tx pgx.Tx, swarmID string) (int, error) {
	var n int
	err := tx.QueryRow(ctx, `UPDATE swarms SET member_count = (SELECT count(*) FROM swarm_members WHERE swarm_id = $1), updated_at = $2
		WHERE swarm_id = $1 RETURNING member_count`, swarmID, s.now()).Scan(&n)
	return n, err
}

// grow adds members to an existing swarm and records swarm.member_added.
func (s *Service) grow(ctx context.Context, tx pgx.Tx, swarmID string, ms []Member, since time.Time, why, by, eventAgent string) ([]Member, error) {
	if by == systemActor {
		// Automatic detection never adds agents to a swarm security already
		// suspended, isolated or killed: membership there freezes the agent
		// (POL-653), and that containment was a human decision about a
		// specific set of agents. A matching call is still held; the agent
		// is not frozen.
		var state string
		if err := tx.QueryRow(ctx, `SELECT state FROM swarms WHERE swarm_id = $1`, swarmID).Scan(&state); err != nil {
			return nil, err
		}
		if state == StateSuspended || state == StateIsolated || state == StateKilled {
			return nil, nil
		}
	}
	added, err := s.insertMembers(ctx, tx, swarmID, ms)
	if err != nil || len(added) == 0 {
		return added, err
	}
	// A release vote approves releasing the swarm as it was: new members
	// void earlier votes.
	if err := s.clearVotes(ctx, tx, swarmID, by, "members added: "+why); err != nil {
		return nil, err
	}
	n, err := s.recount(ctx, tx, swarmID)
	if err != nil {
		return nil, err
	}
	if err := s.tag(ctx, tx, swarmID, agentsOf(added), since); err != nil {
		return nil, err
	}
	_, err = s.diary.AppendTx(ctx, tx, diary.Event{AgentID: eventAgent, EventType: EventMemberAdded, Actor: by, Data: map[string]any{
		"swarm_id": swarmID, "members": added, "member_count": n, "why": why,
	}})
	return added, err
}

// tag sets actions.swarm_id on the new members' actions since `since` and
// held_actions.swarm_id on their pending holds (not overwriting another
// swarm's tag).
func (s *Service) tag(ctx context.Context, tx pgx.Tx, swarmID string, agents []string, since time.Time) error {
	if len(agents) == 0 {
		return nil
	}
	// Rows another transaction holds (e.g. a hold being approved, which
	// locks it before the Diary head) are skipped rather than waited for:
	// this transaction already holds the Diary head, so waiting could
	// deadlock. The tag is informational; the next tagging pass catches up.
	if _, err := tx.Exec(ctx, `UPDATE actions SET swarm_id = $1 WHERE action_id IN (
			SELECT action_id FROM actions WHERE swarm_id IS NULL AND agent_id = ANY($2) AND ts >= $3 FOR UPDATE SKIP LOCKED)`,
		swarmID, agents, since); err != nil {
		return fmt.Errorf("tag actions: %w", err)
	}
	if _, err := tx.Exec(ctx, `UPDATE held_actions SET swarm_id = $1 WHERE action_id IN (
			SELECT action_id FROM held_actions WHERE swarm_id IS NULL AND agent_id = ANY($2) AND outcome = 'pending' FOR UPDATE SKIP LOCKED)`,
		swarmID, agents); err != nil {
		return fmt.Errorf("tag held actions: %w", err)
	}
	return nil
}

func agentsOf(ms []Member) []string {
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.AgentID)
	}
	return slices.Compact(slices.Sorted(slices.Values(ids)))
}

// raise moves the swarm to state unless it is already stricter (or released).
func raise(ctx context.Context, tx pgx.Tx, id, state string, now time.Time) (bool, error) {
	var cur string
	if err := tx.QueryRow(ctx, `SELECT state FROM swarms WHERE swarm_id = $1 FOR UPDATE`, id).Scan(&cur); err != nil {
		return false, err
	}
	if cur == StateReleased || stateRank[cur] >= stateRank[state] {
		return false, nil
	}
	_, err := tx.Exec(ctx, `UPDATE swarms SET state = $2, updated_at = $3 WHERE swarm_id = $1`, id, state, now)
	return err == nil, err
}

// clearVotes drops release votes cast before a new containment action: a
// vote approves releasing the swarm as it was, not after a later kill.
func (s *Service) clearVotes(ctx context.Context, tx pgx.Tx, id, by, why string) error {
	rows, err := tx.Query(ctx, `DELETE FROM swarm_release_votes WHERE swarm_id = $1 RETURNING approver`, id)
	if err != nil {
		return err
	}
	voters, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil || len(voters) == 0 {
		return err
	}
	sort.Strings(voters)
	_, err = s.diary.AppendTx(ctx, tx, diary.Event{EventType: EventVotesCleared, Actor: by, Data: map[string]any{
		"swarm_id": id, "approvers": voters, "why": why,
	}})
	return err
}

// rootOf returns the single delegation root shared by the agents (each is
// the root itself or has an open inbound delegation from that root's tree),
// or "".
func (s *Service) rootOf(ctx context.Context, q querier, agents []string) (string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT to_agent, root_agent FROM delegations
		WHERE to_agent = ANY($1) AND status = 'open' AND expires_at > $2 AND from_agent <> to_agent`, agents, s.now())
	if err != nil {
		return "", err
	}
	defer rows.Close()
	roots := map[string]map[string]bool{}
	all := map[string]bool{}
	for rows.Next() {
		var to, root string
		if err := rows.Scan(&to, &root); err != nil {
			return "", err
		}
		if roots[to] == nil {
			roots[to] = map[string]bool{}
		}
		roots[to][root] = true
		all[root] = true
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	if len(all) != 1 {
		return "", nil
	}
	var r string
	for k := range all {
		r = k
	}
	for _, a := range agents {
		if a != r && !roots[a][r] {
			return "", nil
		}
	}
	return r, nil
}

// treeOf lists the agents in the root's open delegation tree.
func (s *Service) treeOf(ctx context.Context, q querier, root string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT to_agent FROM delegations
		WHERE root_agent = $1 AND status = 'open' AND expires_at > $2 AND from_agent <> to_agent ORDER BY to_agent`, root, s.now())
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

// pickID is the root delegation id when every non-root member's open
// inbound delegation descends from one top-level delegation (and no swarm
// has that id yet); otherwise swm_<ulid>.
func (s *Service) pickID(ctx context.Context, q querier, agents []string, root string) (string, error) {
	var others []string
	for _, a := range agents {
		if a != root {
			others = append(others, a)
		}
	}
	if len(others) > 0 {
		rows, err := q.Query(ctx, `WITH RECURSIVE up AS (
				SELECT d.to_agent AS member, d.delegation_id, d.parent_id FROM delegations d
				WHERE d.to_agent = ANY($1) AND d.status = 'open' AND d.expires_at > $2 AND d.from_agent <> d.to_agent
				UNION
				SELECT up.member, p.delegation_id, p.parent_id FROM up JOIN delegations p ON p.delegation_id = up.parent_id
			)
			SELECT member, delegation_id FROM up WHERE parent_id IS NULL`, others, s.now())
		if err != nil {
			return "", err
		}
		tops := map[string]map[string]bool{}
		for rows.Next() {
			var m, id string
			if err := rows.Scan(&m, &id); err != nil {
				rows.Close()
				return "", err
			}
			if tops[m] == nil {
				tops[m] = map[string]bool{}
			}
			tops[m][id] = true
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return "", err
		}
		var shared []string
		for id := range tops[others[0]] {
			ok := true
			for _, m := range others[1:] {
				ok = ok && tops[m][id]
			}
			if ok {
				shared = append(shared, id)
			}
		}
		if len(shared) == 1 {
			var exists bool
			if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM swarms WHERE swarm_id = $1)`, shared[0]).Scan(&exists); err != nil {
				return "", err
			}
			if !exists {
				return shared[0], nil
			}
		}
	}
	return action.NewID("swm"), nil
}

// List returns swarms, newest first, optionally by state.
func (s *Service) List(ctx context.Context, state string, limit int) ([]Swarm, error) {
	if state != "" {
		if _, ok := stateRank[state]; !ok && state != StateReleased && state != "active" {
			return nil, fmt.Errorf("%w: state must be one of detected, breaker_tripped, suspended, isolated, killed, released or active", ErrInvalid)
		}
	}
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `SELECT `+swarmCols+` FROM swarms
		WHERE $1 = '' OR state = $1 OR ($1 = 'active' AND state <> 'released')
		ORDER BY created_at DESC, swarm_id DESC LIMIT $2`, state, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Swarm{}
	for rows.Next() {
		sw, err := scanSwarm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sw)
	}
	return out, rows.Err()
}

const maxHeldCalls = 1000

// Get returns a swarm with its members, breakers, held calls, release
// votes, spawn tree and containment ops.
func (s *Service) Get(ctx context.Context, id string) (Detail, error) {
	if err := checkID(id); err != nil {
		return Detail{}, err
	}
	var d Detail
	err := pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, func(tx pgx.Tx) error {
		var err error
		if d.Swarm, err = getSwarm(ctx, tx, id, false); err != nil {
			return err
		}
		if d.Members, err = members(ctx, tx, id); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `SELECT b.action_hash, b.swarm_id, b.state, b.tripped_at, b.released_at,
				(SELECT count(*) FROM held_actions h JOIN actions a USING (action_id) WHERE h.swarm_id = b.swarm_id AND a.action_hash = b.action_hash)
			FROM swarm_breakers b WHERE b.swarm_id = $1 ORDER BY b.tripped_at`, id)
		if err != nil {
			return err
		}
		if d.Breakers, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Breaker, error) {
			var b Breaker
			err := r.Scan(&b.ActionHash, &b.SwarmID, &b.State, &b.TrippedAt, &b.ReleasedAt, &b.Matched)
			b.TrippedAt = b.TrippedAt.UTC()
			return b, err
		}); err != nil {
			return err
		}
		if d.Held, err = heldCalls(ctx, tx, id, maxHeldCalls+1); err != nil {
			return err
		}
		if len(d.Held) > maxHeldCalls {
			d.Held, d.HeldTruncated = d.Held[:maxHeldCalls], true
		}
		rows, err = tx.Query(ctx, `SELECT approver, reason, created_at FROM swarm_release_votes WHERE swarm_id = $1 ORDER BY created_at`, id)
		if err != nil {
			return err
		}
		if d.ReleaseVotes, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (ReleaseVote, error) {
			var v ReleaseVote
			err := r.Scan(&v.Approver, &v.Reason, &v.CreatedAt)
			v.CreatedAt = v.CreatedAt.UTC()
			return v, err
		}); err != nil {
			return err
		}
		if d.SpawnTree, err = spawnTree(ctx, tx, d.RootAgentID); err != nil {
			return err
		}
		d.Ops, err = ops(ctx, tx, id)
		return err
	})
	if err != nil {
		return Detail{}, err
	}
	d.ReleaseRequired = ReleaseApprovals
	return d, nil
}

func members(ctx context.Context, q querier, id string) ([]Member, error) {
	rows, err := q.Query(ctx, `SELECT m.agent_id, m.instance_id, m.role, m.added_at, a.level, a.suspended_at IS NOT NULL
		FROM swarm_members m LEFT JOIN agents a ON a.agent_id = m.agent_id
		WHERE m.swarm_id = $1 ORDER BY m.role DESC, m.agent_id, m.instance_id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Member, error) {
		var m Member
		var lvl *int16
		var susp *bool
		err := r.Scan(&m.AgentID, &m.InstanceID, &m.Role, &m.AddedAt, &lvl, &susp)
		m.AddedAt = m.AddedAt.UTC()
		if lvl != nil {
			m.Level = control.Level(*lvl).String()
		} else {
			m.Level = "UNREGISTERED"
		}
		m.Suspended = susp != nil && *susp
		return m, err
	})
}

// heldCalls lists the swarm's held calls in the GET /v1/held row shape,
// plus approvals and swarm_id.
func heldCalls(ctx context.Context, q querier, id string, limit int) ([]json.RawMessage, error) {
	rows, err := q.Query(ctx, `
		SELECT jsonb_build_object('action_id', h.action_id, 'agent_id', h.agent_id, 'rule_id', h.rule_id, 'reason', h.reason,
			'approvals_required', h.approvals_required, 'approver_role', h.approver_role, 'safe_form', h.safe_form,
			'expires_at', h.expires_at, 'outcome', h.outcome, 'created_at', h.created_at,
			'class', a.class, 'decision', a.decision, 'system', a.system, 'verb', a.verb, 'target', a.target,
			'level_at_decision', a.decision_json->'level_before', 'level_after', a.decision_json->'level_after',
			'undo_available', false, 'swarm_id', h.swarm_id,
			'approvals', (SELECT count(*) FROM held_approvals v WHERE v.action_id = h.action_id AND v.decision = 'approve'))
		FROM held_actions h JOIN actions a USING (action_id)
		WHERE h.swarm_id = $1 ORDER BY h.created_at, h.action_id LIMIT $2`, id, limit)
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[json.RawMessage])
	if out == nil {
		out = []json.RawMessage{}
	}
	return out, err
}

// ops lists the containment operations on the swarm, newest first.
func ops(ctx context.Context, q querier, id string) ([]Op, error) {
	rows, err := q.Query(ctx, `SELECT op_id, op, target_type, target_id, actor, reason, status, steps, created_at, finished_at
		FROM containment_ops WHERE target_type = 'swarm' AND target_id = $1 ORDER BY created_at DESC, op_id DESC LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Op, error) {
		var o Op
		var steps []byte
		if err := r.Scan(&o.OpID, &o.Op, &o.TargetType, &o.TargetID, &o.Actor, &o.Reason, &o.Status, &steps, &o.CreatedAt, &o.FinishedAt); err != nil {
			return o, err
		}
		o.CreatedAt = o.CreatedAt.UTC()
		if o.FinishedAt != nil {
			t := o.FinishedAt.UTC()
			o.FinishedAt = &t
		}
		o.Steps = []Step{}
		return o, json.Unmarshal(steps, &o.Steps)
	})
}

const maxTreeHops = 5000

func spawnTree(ctx context.Context, q querier, root string) ([]TreeHop, error) {
	if root == "" {
		return []TreeHop{}, nil
	}
	rows, err := q.Query(ctx, `SELECT delegation_id, COALESCE(parent_id, ''), from_agent, to_agent, depth, channel, status,
			COALESCE(task_id, ''), COALESCE(action_id, ''), created_at
		FROM delegations WHERE root_agent = $1 AND from_agent <> to_agent ORDER BY created_at, delegation_id LIMIT $2`, root, maxTreeHops)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (TreeHop, error) {
		var h TreeHop
		err := r.Scan(&h.DelegationID, &h.ParentID, &h.From, &h.To, &h.Depth, &h.Channel, &h.Status, &h.TaskID, &h.ActionID, &h.CreatedAt)
		h.CreatedAt = h.CreatedAt.UTC()
		return h, err
	})
}

// memberAgents lists the swarm's distinct member agents.
func memberAgents(ctx context.Context, q querier, id string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT agent_id FROM swarm_members WHERE swarm_id = $1 ORDER BY agent_id`, id)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}

func isUnique(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func newSwarmID() string { return action.NewID("swm") }
