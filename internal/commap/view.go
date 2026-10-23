package commap

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"fortik/internal/config"
)

// Views of GET /v1/map.
const (
	ViewTeam     = "team"
	ViewAgent    = "agent"
	ViewSwarm    = "swarm"
	ViewExternal = "external"
	ViewBlast    = "blast"
)

// Limits bound every API result (zero values = defaults).
type Limits struct {
	MaxEdges          int           // edges per map (default 2000)
	MaxClusterMembers int           // members listed per cluster (default 1000)
	MaxPaths          int           // paths per trace (default 50)
	MaxDepth          int           // hops per path (default 8, at most 16)
	MaxPathRows       int           // partial paths explored (default 20000)
	QueryTimeout      time.Duration // per API query (default 10s)
}

// ErrNotFound: the agent, team or swarm named by id does not exist.
var ErrNotFound = errors.New("not found")

// Service answers map queries.
type Service struct {
	pool   *pgxpool.Pool
	cfg    config.MapConfig
	limits Limits
	Now    func() time.Time
}

// NewService returns the map query service.
func NewService(pool *pgxpool.Pool, cfg config.MapConfig, limits Limits) (*Service, error) {
	if pool == nil {
		return nil, errors.New("commap: pool is required")
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if limits.MaxEdges <= 0 {
		limits.MaxEdges = 2000
	}
	if limits.MaxClusterMembers <= 0 {
		limits.MaxClusterMembers = 1000
	}
	if limits.MaxPaths <= 0 {
		limits.MaxPaths = 50
	}
	if limits.MaxDepth <= 0 {
		limits.MaxDepth = 8
	}
	limits.MaxDepth = min(limits.MaxDepth, 16)
	if limits.MaxPathRows <= 0 {
		limits.MaxPathRows = 20000
	}
	if limits.QueryTimeout <= 0 {
		limits.QueryTimeout = 10 * time.Second
	}
	return &Service{pool: pool, cfg: cfg, limits: limits}, nil
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now().UTC()
	}
	return time.Now().UTC()
}

// Window is the replay range [From, To): edges whose 5-minute window
// starts in it (From is floored to its window).
type Window struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

type Node struct {
	ID         string   `json:"id"`
	Kind       string   `json:"kind"`
	Label      string   `json:"label"`
	Team       string   `json:"team,omitempty"`
	Level      string   `json:"level,omitempty"`
	Suspended  bool     `json:"suspended,omitempty"`
	Discovered bool     `json:"discovered,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	Registered *bool    `json:"registered,omitempty"` // agent nodes: false = not in the registry
	SwarmIDs   []string `json:"swarm_ids,omitempty"`
	AgentID    string   `json:"agent_id,omitempty"` // instance nodes
	Status     string   `json:"status,omitempty"`   // instance nodes
	External   bool     `json:"external,omitempty"` // domain nodes
	// Blast radius: the agent can reach this node now (a reach edge with
	// effective access other than none points at it).
	Reachable bool `json:"reachable,omitempty"`
	// Blast radius: reachable but not called in the window (the halo).
	Halo bool `json:"halo,omitempty"`
}

// Edge is one edges row: one (from, to, verb) in one rollup window. Blast
// radius adds reach edges (Reach true, no window): what the agent's current
// access allows, not what it did.
type Edge struct {
	From            string     `json:"from"`
	To              string     `json:"to"`
	Verb            string     `json:"verb"`
	WindowStart     *time.Time `json:"window_start,omitempty"`
	Count           int64      `json:"count"`
	Bytes           int64      `json:"bytes"`
	Labels          []string   `json:"labels"`
	WorstClass      string     `json:"worst_class,omitempty"`
	SampleActionIDs []string   `json:"sample_action_ids"`
	// Blast radius (Reach true).
	Reach     bool           `json:"reach,omitempty"`
	System    string         `json:"system,omitempty"`
	Granted   string         `json:"granted,omitempty"`   // what the current profile grants
	Effective string         `json:"effective,omitempty"` // after overrides and the agent's level: none | read | read_write
	Limits    []string       `json:"limits,omitempty"`    // why effective is narrower than granted
	Detail    map[string]any `json:"detail,omitempty"`
}

type Cluster struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"` // team | swarm
	Label       string   `json:"label"`
	SwarmID     string   `json:"swarm_id,omitempty"`
	State       string   `json:"state,omitempty"`
	DetectedBy  string   `json:"detected_by,omitempty"`
	RootAgentID string   `json:"root_agent_id,omitempty"`
	MemberCount int      `json:"member_count"`
	Members     []string `json:"members"`
	Truncated   bool     `json:"members_truncated,omitempty"`
	Collapsed   bool     `json:"collapsed"`
}

// MapResult is the GET /v1/map response.
type MapResult struct {
	View       string    `json:"view"`
	ID         string    `json:"id,omitempty"`
	Window     Window    `json:"window"`
	Nodes      []Node    `json:"nodes"`
	Edges      []Edge    `json:"edges"`
	Clusters   []Cluster `json:"clusters"`
	Truncated  bool      `json:"truncated"`   // more edge rows matched than were returned
	TotalEdges int       `json:"total_edges"` // edge rows that matched (before truncation)
	// Blast radius only.
	Agent      *Node    `json:"agent,omitempty"`
	Unprofiled []string `json:"unprofiled_systems,omitempty"`
}

// Query is a validated GET /v1/map request.
type Query struct {
	View   string
	ID     string
	Window Window
}

// readTx runs fn in a read-only transaction with a statement timeout.
func (s *Service) readTx(ctx context.Context, fn func(pgx.Tx) error) error {
	ctx, cancel := context.WithTimeout(ctx, s.limits.QueryTimeout+time.Second)
	defer cancel()
	return pgx.BeginTxFunc(ctx, s.pool, pgx.TxOptions{AccessMode: pgx.ReadOnly, IsoLevel: pgx.RepeatableRead}, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, fmt.Sprintf(`SET LOCAL statement_timeout = %d`, s.limits.QueryTimeout.Milliseconds())); err != nil {
			return err
		}
		return fn(tx)
	})
}

// edge selection: the rows of edges a view covers, as SQL over $1/$2
// (window range) and $3 (a text[] of member node ids or one domain node).
const (
	selAll   = `SELECT * FROM edges WHERE window_start >= $1 AND window_start < $2`
	selNodes = `
		SELECT * FROM edges WHERE window_start >= $1 AND window_start < $2 AND (from_node = ANY($3) OR to_node = ANY($3))
		UNION
		SELECT h.* FROM edges h JOIN edges a ON a.window_start = h.window_start AND a.to_node = h.from_node
		WHERE a.window_start >= $1 AND a.window_start < $2 AND a.from_node = ANY($3)
		  AND h.to_node LIKE 'domain:%' AND h.from_node NOT LIKE 'agent:%'
		  AND (h.sample_action_ids && a.sample_action_ids
		       OR EXISTS (SELECT 1 FROM edge_links l WHERE l.window_start = h.window_start AND l.hub = h.from_node
		                  AND l.dest = h.to_node AND l.verb = h.verb AND l.origin = a.from_node))`
	selExternal = `
		SELECT * FROM edges WHERE window_start >= $1 AND window_start < $2 AND to_node LIKE 'domain:%'
		  AND ($3::text = '' OR to_node = $3)
		UNION
		SELECT a.* FROM edges a JOIN edges h ON a.window_start = h.window_start AND a.to_node = h.from_node
		WHERE h.window_start >= $1 AND h.window_start < $2 AND h.to_node LIKE 'domain:%' AND ($3::text = '' OR h.to_node = $3)
		  AND h.from_node NOT LIKE 'agent:%' AND a.from_node LIKE 'agent:%'
		  AND (h.sample_action_ids && a.sample_action_ids
		       OR EXISTS (SELECT 1 FROM edge_links l WHERE l.window_start = h.window_start AND l.hub = h.from_node
		                  AND l.dest = h.to_node AND l.verb = h.verb AND l.origin = a.from_node))`
)

// rowsSQL returns the selected rows, one per (window, from, to, verb), worst
// class first then volume, at most the limit, with the total that matched.
const rowsSQL = `
	WITH sel AS MATERIALIZED (%s),
	total AS (SELECT count(*)::int AS n FROM sel)
	SELECT window_start, from_node, to_node, verb, count, bytes, data_labels, worst_class, sample_action_ids, (SELECT n FROM total)
	FROM sel
	ORDER BY array_position(ARRAY['green','yellow','red','hidden'], worst_class) DESC, count DESC,
	         window_start, from_node, to_node, verb
	LIMIT %d`

func (s *Service) loadEdges(ctx context.Context, tx pgx.Tx, sel string, w Window, arg any) ([]Edge, int, error) {
	q := fmt.Sprintf(rowsSQL, sel, s.limits.MaxEdges)
	from := windowStart(w.From, s.cfg.Window)
	args := []any{from, w.To}
	if arg != nil {
		args = append(args, arg)
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("map edges: %w", err)
	}
	defer rows.Close()
	out := []Edge{}
	total := 0
	for rows.Next() {
		var e Edge
		var ws time.Time
		if err := rows.Scan(&ws, &e.From, &e.To, &e.Verb, &e.Count, &e.Bytes, &e.Labels, &e.WorstClass, &e.SampleActionIDs, &total); err != nil {
			return nil, 0, err
		}
		ws = ws.UTC()
		e.WindowStart = &ws
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].WindowStart.Before(*out[j].WindowStart) })
	return out, total, nil
}

// Map answers GET /v1/map.
func (s *Service) Map(ctx context.Context, q Query) (MapResult, error) {
	res := MapResult{View: q.View, ID: q.ID, Window: q.Window, Nodes: []Node{}, Edges: []Edge{}, Clusters: []Cluster{}}
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		var (
			edges []Edge
			total int
			err   error
			extra []string // nodes shown even without edges (cluster members, the blast agent)
		)
		switch {
		case q.View == ViewExternal:
			arg := ""
			if q.ID != "" {
				arg = DomainNode(q.ID)
			}
			edges, total, err = s.loadEdges(ctx, tx, selExternal, q.Window, arg)
		case q.ID == "" && q.View != ViewBlast:
			edges, total, err = s.loadEdges(ctx, tx, selAll, q.Window, nil)
		default:
			var members []string
			members, err = s.members(ctx, tx, q.View, q.ID)
			if err != nil {
				return err
			}
			extra = members
			edges, total, err = s.loadEdges(ctx, tx, selNodes, q.Window, members)
		}
		if err != nil {
			return err
		}
		res.Edges, res.TotalEdges, res.Truncated = edges, total, total > len(edges)

		if q.View == ViewBlast {
			agent, reach, unprofiled, err := s.reach(ctx, tx, q.ID)
			if err != nil {
				return err
			}
			res.Unprofiled = unprofiled
			res.Edges = append(res.Edges, reach...)
			defer func() {
				for i := range res.Nodes {
					if res.Nodes[i].ID == agent {
						n := res.Nodes[i]
						res.Agent = &n
					}
				}
			}()
		}

		ids := map[string]bool{}
		var order []string
		addID := func(id string) {
			if id != "" && !ids[id] {
				ids[id] = true
				order = append(order, id)
			}
		}
		for _, id := range extra {
			addID(id)
		}
		observed, reachable := map[string]bool{}, map[string]bool{}
		for _, e := range res.Edges {
			addID(e.From)
			addID(e.To)
			if !e.Reach {
				observed[e.From], observed[e.To] = true, true
			} else if e.Effective != capName(capNone) {
				reachable[e.To] = true
			}
		}
		if q.View == ViewSwarm {
			cl, err := s.swarmClusters(ctx, tx, q.ID)
			if err != nil {
				return err
			}
			res.Clusters = cl
			for _, c := range cl {
				for _, m := range c.Members {
					addID(m)
				}
			}
		}
		nodes, err := s.nodes(ctx, tx, order)
		if err != nil {
			return err
		}
		if q.View == ViewBlast {
			for i := range nodes {
				nodes[i].Reachable = reachable[nodes[i].ID]
				if nodes[i].Reachable && !observed[nodes[i].ID] {
					nodes[i].Halo = true
				}
			}
		}
		res.Nodes = nodes
		if q.View == ViewTeam {
			res.Clusters = s.teamClusters(nodes)
		}
		return nil
	})
	if err != nil {
		return MapResult{}, err
	}
	return res, nil
}

// members resolves the node ids a scoped view is about.
func (s *Service) members(ctx context.Context, tx pgx.Tx, view, id string) ([]string, error) {
	var rows pgx.Rows
	var err error
	switch view {
	case ViewAgent, ViewBlast:
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM agents WHERE agent_id = $1)
			OR EXISTS (SELECT 1 FROM edges WHERE from_node = $2 OR to_node = $2)`, id, AgentNode(id)).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: agent %s", ErrNotFound, id)
		}
		return []string{AgentNode(id)}, nil
	case ViewTeam:
		rows, err = tx.Query(ctx, `SELECT 'agent:' || agent_id FROM agents WHERE business_unit = $1 ORDER BY agent_id LIMIT $2`,
			id, s.limits.MaxClusterMembers)
	case ViewSwarm:
		var ok bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM swarms WHERE swarm_id = $1)`, id).Scan(&ok); err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: swarm %s", ErrNotFound, id)
		}
		rows, err = tx.Query(ctx, `SELECT CASE WHEN instance_id = '' THEN 'agent:' || agent_id ELSE 'instance:' || instance_id END
			FROM swarm_members WHERE swarm_id = $1 ORDER BY added_at, agent_id, instance_id LIMIT $2`, id, s.limits.MaxClusterMembers)
	default:
		return nil, fmt.Errorf("commap: view %q has no members", view)
	}
	if err != nil {
		return nil, err
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	if view == ViewTeam && len(out) == 0 {
		return nil, fmt.Errorf("%w: team %s", ErrNotFound, id)
	}
	valid := out[:0]
	for _, n := range out {
		if ValidNode(n) {
			valid = append(valid, n)
		}
	}
	return valid, nil
}

var levelNames = []string{"FULL", "SUPERVISED", "READ_ONLY", "ISOLATED", "QUARANTINED", "KILLED"}

func levelName(l int) string {
	if l >= 0 && l < len(levelNames) {
		return levelNames[l]
	}
	return "KILLED" // unknown: shown as the most restrictive
}

// nodes builds node objects (registry attributes for agents and instances).
func (s *Service) nodes(ctx context.Context, tx pgx.Tx, ids []string) ([]Node, error) {
	out := make([]Node, 0, len(ids))
	var agentIDs, instIDs []string
	for _, id := range ids {
		n := Node{ID: id, Kind: NodeKind(id), Label: nodeLabel(id)}
		switch n.Kind {
		case KindAgent:
			if n.Label != "*" {
				agentIDs = append(agentIDs, n.Label)
			} else {
				n.Label = "any agent"
			}
		case KindInstance:
			instIDs = append(instIDs, n.Label)
		case KindDomain:
			n.External = true // domain nodes are outside the company (unknown recipients count as external)
		}
		out = append(out, n)
	}
	type agentInfo struct {
		team, owner string
		level       int
		suspended   bool
		discovered  bool
		swarms      []string
	}
	info := map[string]agentInfo{}
	if len(agentIDs) > 0 {
		rows, err := tx.Query(ctx, `
			SELECT g.agent_id, g.business_unit, g.sponsor, g.level, g.suspended_at IS NOT NULL, g.discovered,
			       COALESCE((SELECT array_agg(DISTINCT m.swarm_id ORDER BY m.swarm_id) FROM swarm_members m
			                 JOIN swarms w ON w.swarm_id = m.swarm_id AND w.state <> 'released'
			                 WHERE m.agent_id = g.agent_id), '{}')
			FROM agents g WHERE g.agent_id = ANY($1)`, agentIDs)
		if err != nil {
			return nil, fmt.Errorf("map nodes: %w", err)
		}
		for rows.Next() {
			var id string
			var a agentInfo
			if err := rows.Scan(&id, &a.team, &a.owner, &a.level, &a.suspended, &a.discovered, &a.swarms); err != nil {
				rows.Close()
				return nil, err
			}
			info[id] = a
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	type instInfo struct{ agent, status string }
	insts := map[string]instInfo{}
	if len(instIDs) > 0 {
		rows, err := tx.Query(ctx, `SELECT instance_id, agent_id, status FROM instances WHERE instance_id = ANY($1)`, instIDs)
		if err != nil {
			return nil, fmt.Errorf("map instances: %w", err)
		}
		for rows.Next() {
			var id string
			var i instInfo
			if err := rows.Scan(&id, &i.agent, &i.status); err != nil {
				rows.Close()
				return nil, err
			}
			insts[id] = i
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	for i := range out {
		n := &out[i]
		switch n.Kind {
		case KindAgent:
			if n.Label == "any agent" {
				continue
			}
			a, ok := info[n.Label]
			reg := ok
			n.Registered = &reg
			if ok {
				n.Team, n.Owner, n.Level, n.Suspended, n.Discovered = a.team, a.owner, levelName(a.level), a.suspended, a.discovered
				if len(a.swarms) > 0 {
					n.SwarmIDs = a.swarms
				}
			}
		case KindInstance:
			if in, ok := insts[n.Label]; ok {
				n.AgentID, n.Status = in.agent, in.status
			}
		}
	}
	return out, nil
}

func (s *Service) teamClusters(nodes []Node) []Cluster {
	byTeam := map[string]*Cluster{}
	var teams []string
	for _, n := range nodes {
		if n.Kind != KindAgent || n.Team == "" {
			continue
		}
		c, ok := byTeam[n.Team]
		if !ok {
			c = &Cluster{ID: "team:" + n.Team, Kind: "team", Label: n.Team, Members: []string{}, Collapsed: false}
			byTeam[n.Team] = c
			teams = append(teams, n.Team)
		}
		c.MemberCount++
		if len(c.Members) < s.limits.MaxClusterMembers {
			c.Members = append(c.Members, n.ID)
		} else {
			c.Truncated = true
		}
	}
	sort.Strings(teams)
	out := make([]Cluster, 0, len(teams))
	for _, t := range teams {
		out = append(out, *byTeam[t])
	}
	return out
}

// swarmClusters: every active swarm (or the one named), collapsed into one
// cluster that the console expands on click.
func (s *Service) swarmClusters(ctx context.Context, tx pgx.Tx, id string) ([]Cluster, error) {
	rows, err := tx.Query(ctx, `
		SELECT w.swarm_id, w.state, w.detected_by, COALESCE(w.root_agent_id, ''),
		       (SELECT count(*)::int FROM swarm_members m WHERE m.swarm_id = w.swarm_id),
		       COALESCE((SELECT array_agg(n ORDER BY n) FROM (
		           SELECT CASE WHEN m.instance_id = '' THEN 'agent:' || m.agent_id ELSE 'instance:' || m.instance_id END AS n
		           FROM swarm_members m WHERE m.swarm_id = w.swarm_id ORDER BY m.added_at, m.agent_id, m.instance_id LIMIT $2) x), '{}')
		FROM swarms w
		WHERE ($1 = '' AND w.state <> 'released') OR w.swarm_id = $1
		ORDER BY w.created_at DESC, w.swarm_id LIMIT 200`, id, s.limits.MaxClusterMembers)
	if err != nil {
		return nil, fmt.Errorf("swarm clusters: %w", err)
	}
	defer rows.Close()
	out := []Cluster{}
	for rows.Next() {
		var c Cluster
		var members []string
		if err := rows.Scan(&c.SwarmID, &c.State, &c.DetectedBy, &c.RootAgentID, &c.MemberCount, &members); err != nil {
			return nil, err
		}
		c.ID, c.Kind, c.Label, c.Collapsed = "swarm:"+c.SwarmID, "swarm", c.SwarmID, true
		c.Members = []string{}
		for _, m := range members {
			if ValidNode(m) {
				c.Members = append(c.Members, m)
			}
		}
		c.Truncated = c.MemberCount > len(c.Members)
		out = append(out, c)
	}
	return out, rows.Err()
}

// SwarmCluster returns one swarm's cluster object (any state).
func (s *Service) SwarmCluster(ctx context.Context, swarmID string) (Cluster, bool, error) {
	var out []Cluster
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		var err error
		out, err = s.swarmClusters(ctx, tx, swarmID)
		return err
	})
	if err != nil || len(out) == 0 {
		return Cluster{}, false, err
	}
	return out[0], true, nil
}
