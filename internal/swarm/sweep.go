package swarm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/mail"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// SweepResult says what one detection pass found and changed.
type SweepResult struct {
	Created   []string `json:"created"`   // new swarm ids
	Grown     []string `json:"grown"`     // existing swarms that gained members
	Truncated bool     `json:"truncated"` // the converging-target pass hit its scan limit
	Errors    []string `json:"errors"`    // signals that could not be evaluated (the others still ran)
	Signals   int      `json:"signals"`   // signals found (new or already known)
	Duration  int64    `json:"duration_ms"`
}

// Run sweeps every swarm.sweep_interval until ctx ends. Errors are logged;
// the next pass retries.
func (s *Service) Run(ctx context.Context) {
	t := time.NewTicker(s.cfg.SweepInterval)
	defer t.Stop()
	for {
		res, err := s.Sweep(ctx)
		if err != nil && ctx.Err() == nil {
			s.log.Error("swarm sweep failed", "err", err)
		} else if len(res.Created)+len(res.Grown) > 0 {
			s.log.Info("swarm sweep", "created", res.Created, "grown", res.Grown)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// signal is one detection found by the sweep.
type signal struct {
	detectedBy string
	key        string // identifies the signal so a later pass grows the same swarm
	root       string
	members    []Member
	data       map[string]any
	since      time.Time
}

// Sweep runs the background detections once: spawn trees (one root's open
// delegations exceed fanout_limit, or a chain deeper than depth_limit),
// copy surges (an agent's live copies exceed its copy_cap) and converging
// targets (at least converge_n distinct agents hit one external domain,
// table or repo within converge_window). Each signal creates a swarm or
// grows the active swarm that already has it. Detection reads run outside
// any lock; each change commits in its own transaction holding the Diary
// head (the same serialisation as decisions).
func (s *Service) Sweep(ctx context.Context) (SweepResult, error) {
	start := time.Now()
	res := SweepResult{Created: []string{}, Grown: []string{}, Errors: []string{}}
	var sigs []signal
	for _, f := range []struct {
		name string
		fn   func(context.Context, *SweepResult) ([]signal, error)
	}{{"spawn_tree", s.spawnTrees}, {"copy_surge", s.copySurges}, {"converging_targets", s.converging}} {
		got, err := f.fn(ctx, &res)
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			res.Errors = append(res.Errors, f.name+": "+err.Error())
			s.log.Error("swarm sweep: detection failed", "signal", f.name, "err", err)
			continue
		}
		sigs = append(sigs, got...)
	}
	res.Signals = len(sigs)
	for _, sg := range sigs {
		id, created, grew, err := s.apply(ctx, sg)
		if err != nil {
			if ctx.Err() != nil {
				return res, ctx.Err()
			}
			res.Errors = append(res.Errors, sg.detectedBy+" "+sg.key+": "+err.Error())
			s.log.Error("swarm sweep: could not record a signal", "signal", sg.detectedBy, "key", sg.key, "err", err)
			continue
		}
		switch {
		case created:
			res.Created = append(res.Created, id)
		case grew:
			res.Grown = append(res.Grown, id)
		}
	}
	res.Duration = time.Since(start).Milliseconds()
	if len(res.Errors) > 0 {
		return res, errors.New("swarm sweep: " + strings.Join(res.Errors, "; "))
	}
	return res, nil
}

// apply records one signal: grow the active swarm that has it, or create one.
func (s *Service) apply(ctx context.Context, sg signal) (id string, created, grew bool, err error) {
	err = pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		if err := lockDiaryHead(ctx, tx); err != nil {
			return err
		}
		id, created, grew = "", false, false
		var existing string
		var q string
		var args []any
		switch sg.detectedBy {
		case DetectedSpawnTree:
			// Any active swarm rooted at this agent (e.g. one the breaker
			// created for its workers) gains the tree.
			q, args = `SELECT swarm_id FROM swarms WHERE state <> 'released' AND root_agent_id = $1 ORDER BY created_at DESC LIMIT 1`, []any{sg.root}
		case DetectedCopySurge:
			q, args = `SELECT swarm_id FROM swarms WHERE state <> 'released' AND detected_by = 'copy_surge' AND root_agent_id = $1
				ORDER BY created_at DESC LIMIT 1`, []any{sg.root}
		default:
			q, args = `SELECT swarm_id FROM swarms WHERE state <> 'released' AND detected_by = 'converging_targets' AND signal->>'target' = $1
				ORDER BY created_at DESC LIMIT 1`, []any{sg.key}
		}
		if err := tx.QueryRow(ctx, q, args...).Scan(&existing); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		agents := agentsOf(sg.members)
		if existing == "" {
			// The signal's agents already act as one active swarm (e.g. the
			// breaker's workers converging on one domain): that swarm grows
			// rather than a second swarm being created for the same agents.
			err := tx.QueryRow(ctx, `SELECT s.swarm_id FROM swarms s WHERE s.state <> 'released'
				  AND NOT EXISTS (SELECT 1 FROM unnest($1::text[]) x(agent)
				                  WHERE NOT EXISTS (SELECT 1 FROM swarm_members m WHERE m.swarm_id = s.swarm_id AND m.agent_id = x.agent))
				ORDER BY s.created_at DESC, s.swarm_id LIMIT 1`, agents).Scan(&existing)
			if err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if existing != "" {
			added, err := s.grow(ctx, tx, existing, sg.members, sg.since, strings.ReplaceAll(sg.detectedBy, "_", " ")+" signal: "+sg.key, systemActor, "")
			id, grew = existing, len(added) > 0
			return err
		}
		swID := ""
		if sg.detectedBy == DetectedSpawnTree {
			var err error
			if swID, err = s.pickID(ctx, tx, agents, sg.root); err != nil {
				return err
			}
		} else {
			swID = newSwarmID()
		}
		sw, err := s.create(ctx, tx, newSwarm{ID: swID, Root: sg.root, DetectedBy: sg.detectedBy, Signal: sg.data,
			Members: sg.members, Since: sg.since, EventAgent: sg.root}, systemActor)
		if err != nil {
			return err
		}
		id, created = sw.SwarmID, true
		return nil
	})
	return id, created, grew, err
}

// spawnTrees: roots whose open delegations exceed fanout_limit, or whose
// tree is deeper than depth_limit (self-delegations excluded).
func (s *Service) spawnTrees(ctx context.Context, _ *SweepResult) ([]signal, error) {
	now := s.now()
	rows, err := s.pool.Query(ctx, `SELECT root_agent, count(*), max(depth), array_agg(DISTINCT to_agent ORDER BY to_agent)
		FROM delegations WHERE status = 'open' AND expires_at > $1 AND from_agent <> to_agent
		GROUP BY root_agent HAVING count(*) > $2 OR max(depth) > $3 ORDER BY root_agent`,
		now, s.cfg.FanoutLimit, s.cfg.DepthLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []signal
	for rows.Next() {
		var root string
		var hops, depth int
		var to []string
		if err := rows.Scan(&root, &hops, &depth, &to); err != nil {
			return nil, err
		}
		ms := []Member{{AgentID: root, Role: RoleRoot}}
		for _, a := range to {
			if a != root {
				ms = append(ms, Member{AgentID: a, Role: RoleMember})
			}
		}
		why := []string{}
		if hops > s.cfg.FanoutLimit {
			why = append(why, fmt.Sprintf("%d open delegations > fanout_limit %d", hops, s.cfg.FanoutLimit))
		}
		if depth > s.cfg.DepthLimit {
			why = append(why, fmt.Sprintf("depth %d > depth_limit %d", depth, s.cfg.DepthLimit))
		}
		out = append(out, signal{detectedBy: DetectedSpawnTree, key: root, root: root, members: ms, since: now.Add(-s.cfg.ConvergeWindow),
			data: map[string]any{"root_agent": root, "open_delegations": hops, "max_depth": depth, "fanout_limit": s.cfg.FanoutLimit,
				"depth_limit": s.cfg.DepthLimit, "why": strings.Join(why, "; ")}})
	}
	return out, rows.Err()
}

// copySurges: agents whose live copies (fresh live, suspended, or paused
// within converge_window: pause-extra pauses the copies over the cap)
// exceed copy_cap.
func (s *Service) copySurges(ctx context.Context, _ *SweepResult) ([]signal, error) {
	now := s.now()
	rows, err := s.pool.Query(ctx, `SELECT a.agent_id, a.copy_cap, array_agg(i.instance_id ORDER BY i.instance_id),
			count(*) FILTER (WHERE i.status = 'live'), count(*) FILTER (WHERE i.status = 'suspended'), count(*) FILTER (WHERE i.status = 'paused')
		FROM agents a JOIN instances i ON i.agent_id = a.agent_id
		WHERE (i.status = 'live' AND i.last_heartbeat > $1) OR i.status = 'suspended' OR (i.status = 'paused' AND i.last_heartbeat > $2)
		GROUP BY a.agent_id, a.copy_cap HAVING count(*) > a.copy_cap ORDER BY a.agent_id`,
		now.Add(-s.opt.StaleAfter), now.Add(-s.cfg.ConvergeWindow))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []signal
	for rows.Next() {
		var agent string
		var capN, live, susp, paused int
		var insts []string
		if err := rows.Scan(&agent, &capN, &insts, &live, &susp, &paused); err != nil {
			return nil, err
		}
		ms := []Member{{AgentID: agent, Role: RoleRoot}}
		for _, i := range insts {
			ms = append(ms, Member{AgentID: agent, InstanceID: i, Role: RoleMember})
		}
		out = append(out, signal{detectedBy: DetectedCopySurge, key: agent, root: agent, members: ms, since: now.Add(-s.cfg.ConvergeWindow),
			data: map[string]any{"agent_id": agent, "copies": len(insts), "copy_cap": capN, "live": live, "suspended": susp, "paused": paused}})
	}
	return out, rows.Err()
}

// converging: at least converge_n distinct agents hit one external domain
// (any verb), or one table or repo (non-READ verbs) within converge_window.
// Denied and fail-closed attempts count too: a refused swarm is still a
// swarm.
func (s *Service) converging(ctx context.Context, res *SweepResult) ([]signal, error) {
	now := s.now()
	since := now.Add(-s.cfg.ConvergeWindow)
	rows, err := s.pool.Query(ctx, `SELECT agent_id, system, verb, target FROM actions
		WHERE ts > $1 ORDER BY ts DESC LIMIT $2`, since, s.opt.ConvergeScanLimit+1)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hits := map[string]map[string]bool{}
	n := 0
	for rows.Next() {
		n++
		if n > s.opt.ConvergeScanLimit {
			res.Truncated = true
			break
		}
		var agent, system, verb string
		var raw []byte
		if err := rows.Scan(&agent, &system, &verb, &raw); err != nil {
			return nil, err
		}
		var t map[string]any
		if json.Unmarshal(raw, &t) != nil {
			continue
		}
		for _, k := range targetKeys(system, verb, t) {
			if hits[k] == nil {
				hits[k] = map[string]bool{}
			}
			hits[k][agent] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(hits))
	for k, agents := range hits {
		if len(agents) >= s.cfg.ConvergeN {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	var out []signal
	for _, k := range keys {
		agents := make([]string, 0, len(hits[k]))
		for a := range hits[k] {
			agents = append(agents, a)
		}
		sort.Strings(agents)
		ms := make([]Member, 0, len(agents))
		for _, a := range agents {
			ms = append(ms, Member{AgentID: a, Role: RoleMember})
		}
		out = append(out, signal{detectedBy: DetectedConverging, key: k, members: ms, since: since,
			data: map[string]any{"target": k, "distinct_agents": len(agents), "converge_n": s.cfg.ConvergeN,
				"window_seconds": int(s.cfg.ConvergeWindow / time.Second)}})
	}
	return out, nil
}

// targetKeys names what an action hits: domain:<host> for external hosts
// (http/mcp target.domain when external, shell external_hosts, Gmail
// recipient domains of a send with external recipients), table:<upstream>/
// <table> and repo:<org/repo> for non-READ verbs.
func targetKeys(system, verb string, t map[string]any) []string {
	var keys []string
	str := func(k string) string { v, _ := t[k].(string); return strings.TrimSpace(v) }
	list := func(k string) []string {
		var out []string
		switch v := t[k].(type) {
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok && strings.TrimSpace(s) != "" {
					out = append(out, strings.TrimSpace(s))
				}
			}
		case string:
			if strings.TrimSpace(v) != "" {
				out = append(out, strings.TrimSpace(v))
			}
		}
		return out
	}
	if d := strings.ToLower(str("domain")); d != "" && t["external"] == true {
		keys = append(keys, "domain:"+d)
	}
	for _, h := range list("external_hosts") {
		keys = append(keys, "domain:"+strings.ToLower(h))
	}
	if system == "gmail" {
		if n, ok := t["external_domains"].(float64); ok && n > 0 {
			for _, f := range []string{"to", "cc", "bcc"} {
				for _, addr := range list(f) {
					if a, err := mail.ParseAddress(addr); err == nil {
						if at := strings.LastIndex(a.Address, "@"); at > 0 {
							keys = append(keys, "domain:"+strings.ToLower(a.Address[at+1:]))
						}
					}
				}
			}
		}
	}
	if verb != "READ" {
		up := str("upstream")
		for _, tb := range list("tables") {
			keys = append(keys, "table:"+up+"/"+strings.ToLower(tb))
		}
		if r := strings.ToLower(str("repo")); r != "" {
			keys = append(keys, "repo:"+r)
		}
		for _, r := range list("repos") {
			keys = append(keys, "repo:"+strings.ToLower(r))
		}
	}
	return slices.Compact(slices.Sorted(slices.Values(keys)))
}
