// Communication map graph helpers (docs/PHASE5_DESIGN.md §2, §6): swarm
// cluster collapsing, edge aggregation, live-update merging and a small
// deterministic layout (layered columns by node kind, or radial for the
// blast radius). No force simulation: the same data always draws the same
// picture, which keeps a 50-node / 200-edge map stable while it updates.

import { EDGE_RANK, nodeKindOf, nodeName, worseEdge } from '../api/normalize';
import type { CommMap, EdgeClass, MapCluster, MapEdge, MapNode, MapNodeKind, MapView } from '../api/types';

/** Id of the collapsed node standing for a swarm cluster. */
export const clusterNodeId = (swarmId: string) => `swarm:${swarmId}`;

/** Edges between the same two drawn nodes, folded together. */
export interface AggEdge {
  key: string;
  from: string;
  to: string;
  count: number;
  bytes: number;
  labels: string[];
  worst: EdgeClass;
  /** The underlying per-verb / per-window rows. */
  rows: MapEdge[];
  sampleActionIds: string[];
  /** Every row is a blast-radius reach, not an observed call. */
  reach: boolean;
}

export interface DrawGraph {
  nodes: MapNode[];
  edges: AggEdge[];
  /** Original node id -> drawn node id (a collapsed swarm member maps to its cluster). */
  alias: Map<string, string>;
  /** Expanded clusters with the drawn ids of their members (for the outline). */
  expanded: MapCluster[];
}

export const edgeKey = (from: string, to: string) => `${from}→${to}`;

/** Placeholder node for an id that only appears on an edge (e.g. from a live update). */
export function placeholderNode(id: string): MapNode {
  return { id, kind: nodeKindOf(id), label: nodeName(id), swarmIds: [] };
}

/**
 * Collapses every cluster not in `expandedIds` into one swarm node, re-targets
 * edges to it (edges inside one collapsed cluster are dropped) and folds
 * parallel edges together.
 */
export function buildGraph(map: CommMap, expandedIds: Set<string>): DrawGraph {
  const alias = new Map<string, string>();
  const nodes = new Map<string, MapNode>();
  for (const n of map.nodes) nodes.set(n.id, n);
  for (const e of map.edges) {
    if (!nodes.has(e.from)) nodes.set(e.from, placeholderNode(e.from));
    if (!nodes.has(e.to)) nodes.set(e.to, placeholderNode(e.to));
  }
  const expanded: MapCluster[] = [];
  for (const c of map.clusters) {
    if (expandedIds.has(c.swarmId)) {
      expanded.push(c);
      continue;
    }
    const cid = clusterNodeId(c.swarmId);
    for (const m of c.members) if (!alias.has(m)) alias.set(m, cid);
  }
  const drawn = new Map<string, MapNode>();
  for (const n of nodes.values()) {
    const target = alias.get(n.id);
    if (!target) {
      drawn.set(n.id, n);
      continue;
    }
    if (!drawn.has(target)) {
      const c = map.clusters.find((x) => clusterNodeId(x.swarmId) === target)!;
      drawn.set(target, {
        id: target,
        kind: 'swarm',
        label: `swarm ${c.swarmId} · ${c.members.length}`,
        swarmIds: [c.swarmId],
        team: n.team,
      });
    }
  }
  // Clusters with no member among the nodes still show up as a node.
  for (const c of map.clusters) {
    const cid = clusterNodeId(c.swarmId);
    if (!expandedIds.has(c.swarmId) && !drawn.has(cid)) drawn.set(cid, { id: cid, kind: 'swarm', label: `swarm ${c.swarmId} · ${c.members.length}`, swarmIds: [c.swarmId] });
  }
  const resolve = (id: string) => alias.get(id) ?? id;
  const agg = new Map<string, AggEdge>();
  for (const e of map.edges) {
    const from = resolve(e.from);
    const to = resolve(e.to);
    if (from === to && from.startsWith('swarm:')) continue;
    const key = edgeKey(from, to);
    let a = agg.get(key);
    if (!a) {
      a = { key, from, to, count: 0, bytes: 0, labels: [], worst: 'green', rows: [], sampleActionIds: [], reach: true };
      agg.set(key, a);
    }
    a.count += e.count;
    a.bytes += e.bytes;
    for (const l of e.labels) if (!a.labels.includes(l)) a.labels.push(l);
    for (const s of e.sampleActionIds) if (!a.sampleActionIds.includes(s) && a.sampleActionIds.length < 20) a.sampleActionIds.push(s);
    a.worst = a.rows.length === 0 ? e.worstClass : worseEdge(a.worst, e.worstClass);
    a.reach = a.reach && e.reach === true;
    a.rows.push(e);
  }
  return {
    nodes: [...drawn.values()],
    edges: [...agg.values()].sort((x, y) => EDGE_RANK[x.worst] - EDGE_RANK[y.worst] || x.key.localeCompare(y.key)),
    alias,
    expanded,
  };
}

/** Identity of one edge row for live merging: one row per (from, to, verb, 5-minute window). */
export const rowKey = (e: MapEdge) => `${e.from}|${e.to}|${e.verb}|${e.windowStart ?? ''}`;

/** Applies an edge.updated event: the row for that window replaces the old one, or is added. */
export function applyEdgeUpdate(map: CommMap, e: MapEdge): CommMap {
  const k = rowKey(e);
  const i = map.edges.findIndex((x) => rowKey(x) === k);
  const edges = i >= 0 ? map.edges.map((x, j) => (j === i ? e : x)) : [...map.edges, e];
  const nodes = [...map.nodes];
  for (const id of [e.from, e.to]) if (!nodes.some((n) => n.id === id)) nodes.push(placeholderNode(id));
  return { ...map, edges, nodes };
}

/** Applies a swarm.updated event to the clusters (and the members' swarm ids). */
export function applySwarmUpdate(map: CommMap, c: MapCluster): CommMap {
  const i = map.clusters.findIndex((x) => x.swarmId === c.swarmId);
  const merged: MapCluster = i >= 0 && c.members.length === 0 ? { ...map.clusters[i]!, state: c.state } : c;
  const clusters = i >= 0 ? map.clusters.map((x, j) => (j === i ? merged : x)) : [...map.clusters, merged];
  const nodes = map.nodes.map((n) => (merged.members.includes(n.id) && !n.swarmIds.includes(c.swarmId) ? { ...n, swarmIds: [...n.swarmIds, c.swarmId] } : n));
  return { ...map, clusters, nodes };
}

// --- layout ---------------------------------------------------------------------------

export interface Pos {
  x: number;
  y: number;
}

export interface Layout {
  pos: Map<string, Pos>;
  width: number;
  height: number;
  columns: { label: string; x: number }[];
  /** Team bands (team view): label and vertical extent. */
  bands: { label: string; y1: number; y2: number }[];
  /** Blast radius: centre and halo radius. */
  halo?: { x: number; y: number; r: number };
}

const COLUMN_OF: Record<MapNodeKind, number> = { user: 0, agent: 1, swarm: 1, unknown: 1, instance: 2, mcp: 3, app: 3, store: 3, memory: 3, domain: 4 };
const COLUMN_LABEL = ['Sponsors', 'Agents', 'Copies', 'Apps, data & memory', 'External'];
const KIND_ORDER: MapNodeKind[] = ['user', 'swarm', 'agent', 'unknown', 'instance', 'mcp', 'app', 'store', 'memory', 'domain'];

export const ROW_H = 46;
export const COL_W = 210;
const SUB_W = 180;
const PAD_X = 40;
const PAD_Y = 48;
/** Rows per sub-column before a column wraps (keeps 41 agents on screen). */
export const MAX_ROWS = 14;

function compare(view: MapView) {
  return (a: MapNode, b: MapNode) => {
    if (view === 'team') {
      const t = (a.team ?? '￿').localeCompare(b.team ?? '￿');
      if (t) return t;
    }
    return KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id);
  };
}

/** Layered layout: one column per node kind group, wrapping long columns into sub-columns. */
export function layeredLayout(nodes: MapNode[], view: MapView): Layout {
  const cols: MapNode[][] = [[], [], [], [], []];
  for (const n of nodes) cols[COLUMN_OF[n.kind] ?? 1]!.push(n);
  const pos = new Map<string, Pos>();
  const columns: Layout['columns'] = [];
  const bands: Layout['bands'] = [];
  let x = PAD_X;
  let maxRows = 1;
  cols.forEach((col, ci) => {
    if (col.length === 0) return;
    col.sort(compare(view));
    const subs = Math.ceil(col.length / MAX_ROWS);
    const rows = Math.ceil(col.length / subs);
    maxRows = Math.max(maxRows, rows);
    columns.push({ label: COLUMN_LABEL[ci]!, x });
    col.forEach((n, i) => {
      const s = Math.floor(i / rows);
      const r = i % rows;
      pos.set(n.id, { x: x + s * SUB_W, y: PAD_Y + r * ROW_H });
    });
    if (view === 'team' && ci === 1) {
      let start = 0;
      for (let i = 1; i <= col.length; i++) {
        if (i === col.length || (col[i]!.team ?? '') !== (col[start]!.team ?? '')) {
          if (subs === 1) bands.push({ label: col[start]!.team || 'No team', y1: PAD_Y + start * ROW_H - ROW_H / 2, y2: PAD_Y + (i - 1) * ROW_H + ROW_H / 2 });
          start = i;
        }
      }
    }
    x += (subs - 1) * SUB_W + COL_W;
  });
  return { pos, width: Math.max(x + PAD_X, 640), height: PAD_Y + maxRows * ROW_H, columns, bands };
}

/** Radial layout for the blast radius: the agent in the centre, what it reaches on rings around it. */
export function radialLayout(nodes: MapNode[], centerId: string): Layout {
  const inner: MapNode[] = [];
  const outer: MapNode[] = [];
  for (const n of nodes) {
    if (n.id === centerId) continue;
    if (n.kind === 'domain' || n.kind === 'user') outer.push(n);
    else inner.push(n);
  }
  inner.sort(compare('blast'));
  outer.sort(compare('blast'));
  const r1 = Math.max(150, (inner.length * 54) / (2 * Math.PI));
  const r2 = r1 + Math.max(110, (outer.length * 54) / (2 * Math.PI) - r1 + 60);
  const R = outer.length ? r2 : r1;
  const cx = R + 170;
  const cy = R + 60;
  const pos = new Map<string, Pos>();
  pos.set(centerId, { x: cx, y: cy });
  const ring = (list: MapNode[], r: number, offset: number) =>
    list.forEach((n, i) => {
      const a = offset + (2 * Math.PI * i) / Math.max(1, list.length) - Math.PI / 2;
      pos.set(n.id, { x: Math.round(cx + r * Math.cos(a)), y: Math.round(cy + r * Math.sin(a)) });
    });
  ring(inner, r1, 0);
  ring(outer, r2, Math.PI / Math.max(2, outer.length));
  return { pos, width: 2 * cx, height: 2 * cy, columns: [], bands: [], halo: { x: cx, y: cy, r: r1 + 36 } };
}

/** Drawn id of the blast-radius centre for an agent id ("agent:x" or "x"). */
export function centerIdOf(id: string): string {
  return id.includes(':') ? id : `agent:${id}`;
}

/** Edge stroke width from its count (log scale, 1.5..8 px). */
export function edgeWidth(count: number): number {
  return Math.min(8, 1.5 + Math.log2(Math.max(1, count)) * 0.9);
}

/** "1.2 MB" style byte counts. */
export function fmtBytes(n: number): string {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)} ${u[i]}`;
}

/** Edge keys (drawn ids) on a traced path. */
export function pathKeys(hops: { from: string; to: string }[], alias: Map<string, string>): Set<string> {
  const r = (id: string) => alias.get(id) ?? id;
  return new Set(hops.map((h) => edgeKey(r(h.from), r(h.to))));
}
