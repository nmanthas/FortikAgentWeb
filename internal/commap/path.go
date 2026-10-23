package commap

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// PathQuery is a validated GET /v1/map/path request.
type PathQuery struct {
	Label  string
	Dest   string
	Window Window
	Depth  int // 0 = the service maximum
}

// Hop is one step of data with the label, in the direction the data moved:
// for a READ the data flows from the target to the agent (edge_from is the
// agent), otherwise from the caller to the target.
type Hop struct {
	From        string    `json:"from"`
	To          string    `json:"to"`
	Verb        string    `json:"verb"`
	WindowStart time.Time `json:"window_start"`
	ActionIDs   []string  `json:"action_ids"`
	// ActionIDsComplete is false when the edge folded more actions than
	// the samples kept (count > 5): the ids link examples, not all of them.
	ActionIDsComplete bool   `json:"action_ids_complete"`
	Count             int64  `json:"count"`
	WorstClass        string `json:"worst_class"`
	EdgeFrom          string `json:"edge_from"`
	EdgeTo            string `json:"edge_to"`
}

type Path struct {
	Nodes []string `json:"nodes"` // origin ... destination
	Hops  []Hop    `json:"hops"`
}

// PathResult is the GET /v1/map/path response.
type PathResult struct {
	Label  string `json:"label"`
	Dest   string `json:"dest"`
	Window Window `json:"window"`
	Depth  int    `json:"depth_limit"`
	Paths  []Path `json:"paths"`
	Hops   []Hop  `json:"hops"` // every distinct hop on the returned paths, in time order
	// Truncated: more partial paths existed than were explored, or more
	// complete paths than were returned.
	Truncated bool `json:"truncated"`
}

// pathSQL walks backwards from the destination over edges that carry the
// label, data-flow direction, each hop no later (by window) than the next
// one, never revisiting a node, up to $5 hops. A hop out of a shared app
// (gmail -> domain) only continues to an edge into that app from an agent
// whose calls through that app went to that domain in that window
// (edge_links), or that shares sample actions with it (the same sends): a
// busy window never links an agent that sent elsewhere. No ORDER BY: Postgres stops the recursion
// once $6 rows are fetched.
const pathSQL = `
	WITH RECURSIVE e AS MATERIALIZED (
		SELECT window_start, from_node, to_node, verb, count, sample_action_ids,
		       CASE WHEN verb = 'READ' THEN to_node ELSE from_node END AS src,
		       CASE WHEN verb = 'READ' THEN from_node ELSE to_node END AS dst
		FROM edges
		WHERE window_start >= $1 AND window_start < $2 AND $3 = ANY (data_labels)
		  AND verb NOT IN ('OWNS', 'RUNS') AND from_node <> to_node
	),
	walk AS (
		SELECT e.src, e.window_start AS ws, e.from_node AS fn, e.to_node AS tn, e.count AS cnt, e.sample_action_ids AS smp,
		       1 AS depth, ARRAY[e.dst, e.src] AS nodes,
		       ARRAY[extract(epoch FROM e.window_start)::bigint || chr(31) || e.from_node || chr(31) || e.to_node || chr(31) || e.verb] AS hops
		FROM e WHERE e.dst = $4
		UNION ALL
		SELECT e.src, e.window_start, e.from_node, e.to_node, e.count, e.sample_action_ids,
		       w.depth + 1, w.nodes || e.src,
		       w.hops || (extract(epoch FROM e.window_start)::bigint || chr(31) || e.from_node || chr(31) || e.to_node || chr(31) || e.verb)
		FROM walk w JOIN e ON e.dst = w.src AND e.window_start <= w.ws
		WHERE w.depth < $5 AND NOT (e.src = ANY (w.nodes))
		  AND (NOT (w.fn NOT LIKE 'agent:%' AND w.tn LIKE 'domain:%')
		       OR e.sample_action_ids && w.smp
		       OR EXISTS (SELECT 1 FROM edge_links l WHERE l.window_start = w.ws AND l.hub = w.fn AND l.dest = w.tn
		                  AND l.origin = e.src AND e.window_start = w.ws))
	)
	SELECT hops FROM walk LIMIT $6`

type hopKey struct {
	ws             int64
	from, to, verb string
}

func parseHopKey(s string) (hopKey, bool) {
	p := strings.Split(s, "\x1f")
	if len(p) != 4 {
		return hopKey{}, false
	}
	ws, err := strconv.ParseInt(p[0], 10, 64)
	if err != nil {
		return hopKey{}, false
	}
	return hopKey{ws, p[1], p[2], p[3]}, true
}

// Path answers GET /v1/map/path: every hop of data with the label to the
// destination node, as complete (maximal) paths.
func (s *Service) Path(ctx context.Context, q PathQuery) (PathResult, error) {
	depth := q.Depth
	if depth <= 0 || depth > s.limits.MaxDepth {
		depth = s.limits.MaxDepth
	}
	res := PathResult{Label: q.Label, Dest: q.Dest, Window: q.Window, Depth: depth, Paths: []Path{}, Hops: []Hop{}}
	err := s.readTx(ctx, func(tx pgx.Tx) error {
		from := windowStart(q.Window.From, s.cfg.Window)
		rows, err := tx.Query(ctx, pathSQL, from, q.Window.To, q.Label, q.Dest, depth, s.limits.MaxPathRows+1)
		if err != nil {
			return fmt.Errorf("path trace: %w", err)
		}
		var walks [][]string
		for rows.Next() {
			var hops []string
			if err := rows.Scan(&hops); err != nil {
				rows.Close()
				return err
			}
			walks = append(walks, hops)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(walks) > s.limits.MaxPathRows {
			walks = walks[:s.limits.MaxPathRows]
			res.Truncated = true
		}
		// A walk is a complete path unless another walk extends it by one hop.
		extended := map[string]bool{}
		for _, w := range walks {
			if len(w) > 1 {
				extended[strings.Join(w[:len(w)-1], "\x1e")] = true
			}
		}
		var complete [][]string
		for _, w := range walks {
			if !extended[strings.Join(w, "\x1e")] {
				complete = append(complete, w)
			}
		}
		sort.SliceStable(complete, func(i, j int) bool {
			if len(complete[i]) != len(complete[j]) {
				return len(complete[i]) > len(complete[j])
			}
			return strings.Join(complete[i], "\x1e") < strings.Join(complete[j], "\x1e")
		})
		if len(complete) > s.limits.MaxPaths {
			complete = complete[:s.limits.MaxPaths]
			res.Truncated = true
		}
		// Load the hops of the returned paths.
		keys := map[hopKey]bool{}
		for _, w := range complete {
			for _, h := range w {
				if k, ok := parseHopKey(h); ok {
					keys[k] = true
				}
			}
		}
		hops, err := s.loadHops(ctx, tx, keys)
		if err != nil {
			return err
		}
		for _, w := range complete {
			var p Path
			ok := true
			// Walks run destination-first; paths read origin-first.
			for i := len(w) - 1; i >= 0; i-- {
				k, good := parseHopKey(w[i])
				h, found := hops[k]
				if !good || !found {
					ok = false // pruned between the two reads: drop the path rather than show a gap
					break
				}
				if len(p.Nodes) == 0 {
					p.Nodes = append(p.Nodes, h.From)
				}
				p.Nodes = append(p.Nodes, h.To)
				p.Hops = append(p.Hops, h)
			}
			if ok && len(p.Hops) > 0 {
				res.Paths = append(res.Paths, p)
			}
		}
		seen := map[hopKey]bool{}
		for _, p := range res.Paths {
			for _, h := range p.Hops {
				k := hopKey{h.WindowStart.Unix(), h.EdgeFrom, h.EdgeTo, h.Verb}
				if !seen[k] {
					seen[k] = true
					res.Hops = append(res.Hops, h)
				}
			}
		}
		sort.SliceStable(res.Hops, func(i, j int) bool {
			if !res.Hops[i].WindowStart.Equal(res.Hops[j].WindowStart) {
				return res.Hops[i].WindowStart.Before(res.Hops[j].WindowStart)
			}
			return res.Hops[i].From+res.Hops[i].To < res.Hops[j].From+res.Hops[j].To
		})
		return nil
	})
	if err != nil {
		return PathResult{}, err
	}
	return res, nil
}

func (s *Service) loadHops(ctx context.Context, tx pgx.Tx, keys map[hopKey]bool) (map[hopKey]Hop, error) {
	out := map[hopKey]Hop{}
	if len(keys) == 0 {
		return out, nil
	}
	var ws []time.Time
	var froms, tos, verbs []string
	for k := range keys {
		ws = append(ws, time.Unix(k.ws, 0).UTC())
		froms, tos, verbs = append(froms, k.from), append(tos, k.to), append(verbs, k.verb)
	}
	rows, err := tx.Query(ctx, `
		SELECT e.window_start, e.from_node, e.to_node, e.verb, e.count, e.worst_class, e.sample_action_ids
		FROM unnest($1::timestamptz[], $2::text[], $3::text[], $4::text[]) AS k(ws, fn, tn, vb)
		JOIN edges e ON e.window_start = k.ws AND e.from_node = k.fn AND e.to_node = k.tn AND e.verb = k.vb`,
		ws, froms, tos, verbs)
	if err != nil {
		return nil, fmt.Errorf("path hops: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var h Hop
		if err := rows.Scan(&h.WindowStart, &h.EdgeFrom, &h.EdgeTo, &h.Verb, &h.Count, &h.WorstClass, &h.ActionIDs); err != nil {
			return nil, err
		}
		h.WindowStart = h.WindowStart.UTC()
		h.From, h.To = h.EdgeFrom, h.EdgeTo
		if h.Verb == "READ" {
			h.From, h.To = h.EdgeTo, h.EdgeFrom
		}
		h.ActionIDsComplete = int64(len(h.ActionIDs)) >= h.Count
		out[hopKey{h.WindowStart.Unix(), h.EdgeFrom, h.EdgeTo, h.Verb}] = h
	}
	return out, rows.Err()
}
