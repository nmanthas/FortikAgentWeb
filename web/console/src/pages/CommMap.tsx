// Communication Map (docs/PHASE5_DESIGN.md §2, §6; the v2 screen): who talks
// to what, as an SVG graph with a deterministic layout. View tabs (team,
// agent, swarm, external, blast radius), swarm clusters that expand on click,
// edges coloured by their worst class, node and edge details with Diary
// links, a path trace, a time-replay slider and live updates over SSE
// (GET /v1/map/live) with a pause toggle.
//
// Every label comes from agents or the systems they touch, so it is rendered
// as React text only (escaped), truncated for display and never as HTML.

import { useCallback, useEffect, useId, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { getMap, listAgents, MAP_LIVE_URL, tracePath } from '../api/endpoints';
import { isObj, normCluster, normMapEdge, nodeName } from '../api/normalize';
import type { Agent, CommMap, EdgeClass, MapCluster, MapEdge, MapNode, MapView, PathHop } from '../api/types';
import { LEVEL_SOLID, LevelChip } from '../components/Chips';
import { IconBot, IconBrain, IconDatabase, IconGlobe, IconPlug, IconRefresh, IconUsers, SystemIcon } from '../components/Icons';
import { ErrorBox, Loading } from '../components/ui';
import { fmtClock, fmtNum, fmtTime } from '../lib/format';
import { useEventStream } from '../lib/live';
import {
  applyEdgeUpdate,
  applySwarmUpdate,
  buildGraph,
  centerIdOf,
  clusterNodeId,
  edgeWidth,
  fmtBytes,
  layeredLayout,
  pathKeys,
  radialLayout,
  type AggEdge,
  type DrawGraph,
  type Layout,
} from '../lib/mapGraph';
import { useAsync } from '../lib/useAsync';

// --- constants ------------------------------------------------------------------------

export const EDGE_COLOR: Record<EdgeClass, string> = { green: '#16a34a', yellow: '#d97706', red: '#dc2626', hidden: '#7c3aed' };
export const EDGE_LABEL: Record<EdgeClass, string> = { green: 'Normal', yellow: 'Risky', red: 'Dangerous', hidden: 'Hidden signal' };
const EDGE_CHIP: Record<EdgeClass, string> = { green: 'green', yellow: 'amber', red: 'red', hidden: 'purple' };
const EDGE_DASH: Record<EdgeClass, string | undefined> = { green: undefined, yellow: undefined, red: undefined, hidden: '7 4' };

const VIEWS: { key: MapView; label: string; help: string }[] = [
  { key: 'team', label: 'Team', help: 'Every agent grouped by team, with what each one talks to.' },
  { key: 'agent', label: 'Agent', help: 'One agent: everything it called and everything that called it.' },
  { key: 'swarm', label: 'Swarm', help: 'Active swarms collapsed into one node each. Click a swarm to expand it.' },
  { key: 'external', label: 'External', help: 'Traffic leaving the company: calls to external domains.' },
  { key: 'blast', label: 'Blast radius', help: 'Everything one agent can reach with its current access profiles (the halo), not just what it called.' },
];

/** Replay ranges: the slider steps through frames of `frame` minutes within the last `range` minutes. */
export const RANGES = {
  '1h': { label: 'Last hour', range: 60, frame: 5 },
  '6h': { label: 'Last 6 hours', range: 360, frame: 15 },
  '24h': { label: 'Last 24 hours', range: 1440, frame: 60 },
  '7d': { label: 'Last 7 days', range: 10080, frame: 360 },
} as const;
export type RangeKey = keyof typeof RANGES;

const LABEL_MAX = 26;
const short = (s: string, n = LABEL_MAX) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);

/** Live edges that belong to the current view (others are ignored until the next reload). */
export function edgeInView(view: MapView, id: string, e: MapEdge): boolean {
  if (view === 'blast') return false;
  if (view === 'agent') {
    const c = centerIdOf(id);
    return e.from === c || e.to === c;
  }
  if (view === 'external') return e.to.startsWith('domain:') || e.from.startsWith('domain:');
  return true;
}

type Selection = { kind: 'node'; id: string } | { kind: 'edge'; key: string } | null;
type LiveMsg = { type: 'edge'; edge: MapEdge } | { type: 'swarm'; cluster: MapCluster };

/** Parses one map SSE event; null when malformed. */
export function parseMapEvent(type: string, data: string): LiveMsg | null {
  let o: unknown;
  try {
    o = JSON.parse(data);
  } catch {
    return null;
  }
  if (!isObj(o)) return null;
  if (type === 'edge.updated') {
    const e = normMapEdge(isObj(o.edge) ? o.edge : o);
    return e.from && e.to ? { type: 'edge', edge: e } : null;
  }
  if (type === 'swarm.updated') {
    const c = normCluster(isObj(o.swarm) ? o.swarm : o);
    return c.swarmId ? { type: 'swarm', cluster: c } : null;
  }
  return null;
}

// --- page -------------------------------------------------------------------------------

export function CommMapPage() {
  const [view, setView] = useState<MapView>('team');
  const [agentId, setAgentId] = useState('');
  const [rangeKey, setRangeKey] = useState<RangeKey>('1h');
  /** null = live (the default last hour); otherwise the replayed frame index (1..steps). */
  const [frame, setFrame] = useState<number | null>(null);
  const [frameDraft, setFrameDraft] = useState<number | null>(null);
  const [anchor, setAnchor] = useState(() => Date.now());
  const [paused, setPaused] = useState(false);
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<Selection>(null);
  const [hops, setHops] = useState<PathHop[] | null>(null);
  const [map, setMap] = useState<CommMap | null>(null);
  const [buffer, setBuffer] = useState<LiveMsg[]>([]);
  const [applied, setApplied] = useState(0);

  const agents = useAsync<Agent[]>((s) => listAgents(s), []);
  const needsAgent = view === 'agent' || view === 'blast';
  const range = RANGES[rangeKey];
  const steps = Math.round(range.range / range.frame);

  const win = useMemo(() => {
    if (frame === null) return null;
    const start = anchor - range.range * 60_000;
    return { from: new Date(start + (frame - 1) * range.frame * 60_000).toISOString(), to: new Date(start + frame * range.frame * 60_000).toISOString() };
  }, [frame, anchor, range]);

  const query = useMemo(() => ({ view, id: needsAgent ? agentId : undefined, from: win?.from, to: win?.to }), [view, agentId, needsAgent, win]);
  const loaded = useAsync<CommMap | null>((s) => (needsAgent && !agentId ? Promise.resolve(null) : getMap(query, s)), [query.view, query.id, query.from, query.to]);

  useEffect(() => {
    if (loaded.data !== undefined) {
      setMap(loaded.data);
      setBuffer([]);
    }
  }, [loaded.data]);

  // Debounce the slider: one request per settled position.
  useEffect(() => {
    if (frameDraft === null) return;
    const t = setTimeout(() => setFrame(frameDraft), 250);
    return () => clearTimeout(t);
  }, [frameDraft]);

  const live = frame === null;
  const apply = useCallback(
    (msgs: LiveMsg[]) => {
      if (msgs.length === 0) return;
      setMap((m) => {
        if (!m) return m;
        let out = m;
        for (const x of msgs) {
          if (x.type === 'edge') {
            if (edgeInView(view, agentId, x.edge)) out = applyEdgeUpdate(out, x.edge);
          } else if (view === 'swarm') out = applySwarmUpdate(out, x.cluster);
          // Other views have no swarm clusters (the server returns them for view=swarm only), so a
          // live swarm event must not fold their agents into a swarm node.
        }
        return out;
      });
      setApplied((n) => n + msgs.length);
    },
    [view, agentId],
  );
  const pausedRef = useRef(paused);
  pausedRef.current = paused;
  const stream = useEventStream(
    MAP_LIVE_URL,
    ['edge.updated', 'swarm.updated'],
    (type, data) => {
      const msg = parseMapEvent(type, data);
      if (!msg) return;
      if (pausedRef.current) setBuffer((b) => [...b, msg].slice(-2000));
      else apply([msg]);
    },
    { enabled: live && !(needsAgent && !agentId), onReconnect: loaded.reload },
  );

  const togglePause = () => {
    if (paused) {
      apply(buffer);
      setBuffer([]);
    }
    setPaused(!paused);
  };

  const graph = useMemo(() => (map ? buildGraph(map, expanded) : null), [map, expanded]);
  const layout = useMemo(() => {
    if (!graph) return null;
    if (view === 'blast' && agentId) return radialLayout(graph.nodes, centerIdOf(agentId));
    return layeredLayout(graph.nodes, view);
  }, [graph, view, agentId]);
  const highlight = useMemo(() => (hops && graph ? pathKeys(hops, graph.alias) : null), [hops, graph]);

  const changeView = (v: MapView) => {
    setView(v);
    setSelected(null);
    setHops(null);
    setExpanded(new Set());
  };
  const toggleCluster = (swarmId: string) =>
    setExpanded((s) => {
      const n = new Set(s);
      if (n.has(swarmId)) n.delete(swarmId);
      else n.add(swarmId);
      return n;
    });
  const onNode = (n: MapNode) => {
    setSelected({ kind: 'node', id: n.id });
    if (n.kind === 'swarm' && n.swarmIds[0]) toggleCluster(n.swarmIds[0]);
  };

  const sliderId = useId();
  const viewHelp = VIEWS.find((v) => v.key === view)?.help;

  return (
    <div className="map-page">
      <section className="card">
        <div className="card-head" style={{ flexWrap: 'wrap' }}>
          <div className="grow">
            <h2>Communication Map</h2>
            <div className="sub">{viewHelp}</div>
          </div>
          <span className={`live${live && stream.connected && !paused ? ' on' : ''}`} data-testid="map-live">
            <span className="dot" />
            {!live ? 'Replay' : paused ? 'Paused' : stream.connected ? 'Live' : 'Offline'}
          </span>
          {live && (
            <button className="btn small" onClick={togglePause} aria-pressed={paused}>
              {paused ? `Resume live${buffer.length ? ` (${buffer.length} waiting)` : ''}` : 'Pause live'}
            </button>
          )}
          <button className="btn small" onClick={loaded.reload} aria-label="Reload map" title="Reload map">
            <IconRefresh size={14} />
          </button>
        </div>
        <div className="toolbar">
          <div className="sys-tabs" role="tablist" aria-label="Map view">
            {VIEWS.map((v) => (
              <button key={v.key} role="tab" aria-selected={view === v.key} className={`sys-tab${view === v.key ? ' active' : ''}`} onClick={() => changeView(v.key)}>
                {v.label}
              </button>
            ))}
          </div>
          {needsAgent && (
            <>
              <label className="sr-only" htmlFor="map-agent">
                Agent
              </label>
              <select id="map-agent" className="select" style={{ width: 220 }} value={agentId} onChange={(e) => setAgentId(e.target.value)}>
                <option value="">Pick an agent…</option>
                {(agents.data ?? []).map((a) => (
                  <option key={a.agentId} value={a.agentId}>
                    {a.agentId}
                  </option>
                ))}
              </select>
            </>
          )}
        </div>
        <div className="toolbar replay" data-testid="replay">
          <label className="label" htmlFor={`${sliderId}-range`}>
            Time replay
          </label>
          <select
            id={`${sliderId}-range`}
            className="select"
            style={{ width: 160 }}
            value={rangeKey}
            onChange={(e) => {
              setRangeKey(e.target.value as RangeKey);
              setFrame(null);
              setFrameDraft(null);
            }}
          >
            {(Object.keys(RANGES) as RangeKey[]).map((k) => (
              <option key={k} value={k}>
                {RANGES[k].label}
              </option>
            ))}
          </select>
          <input
            id={sliderId}
            type="range"
            className="slider"
            min={1}
            max={steps}
            step={1}
            value={frameDraft ?? frame ?? steps}
            aria-label="Replay window"
            aria-valuetext={win ? `${fmtTime(win.from)} to ${fmtTime(win.to)}` : 'live'}
            onChange={(e) => {
              if (frame === null && frameDraft === null) setAnchor(Date.now());
              setFrameDraft(Number(e.target.value));
            }}
          />
          <span className="muted small" data-testid="replay-window">
            {win ? `${fmtClock(win.from)}–${fmtClock(win.to)} (${range.frame >= 60 ? `${range.frame / 60}h` : `${range.frame}m`} frame)` : map?.window.from ? `live · since ${fmtClock(map.window.from)}` : 'live · last hour'}
          </span>
          {!live && (
            <button
              className="btn small"
              onClick={() => {
                setFrame(null);
                setFrameDraft(null);
              }}
            >
              Back to live
            </button>
          )}
          {live && applied > 0 && <span className="muted small">{applied} live updates applied</span>}
        </div>
        <Legend />
      </section>

      {loaded.error && <ErrorBox error={loaded.error} onRetry={loaded.reload} />}
      {needsAgent && !agentId && (
        <div className="card">
          <div className="empty">Pick an agent to see its {view === 'blast' ? 'blast radius' : 'connections'}.</div>
        </div>
      )}
      {loaded.loading && !map && !(needsAgent && !agentId) && <Loading label="Loading the map…" />}

      {graph && layout && (
        <div className="map-grid">
          <section className="card map-card">
            {graph.nodes.length === 0 ? (
              <div className="empty">No communication recorded in this window.</div>
            ) : (
              <MapCanvas graph={graph} layout={layout} selected={selected} highlight={highlight} blastCenter={view === 'blast' ? centerIdOf(agentId) : undefined} onNode={onNode} onEdge={(k) => setSelected({ kind: 'edge', key: k })} onCollapse={toggleCluster} />
            )}
            <div className="muted small map-foot">
              {graph.nodes.length} nodes · {graph.edges.length} connections
              {map?.clusters.length ? ` · ${map.clusters.length} swarm${map.clusters.length === 1 ? '' : 's'}` : ''}
              {map?.window.from && ` · window ${fmtTime(map.window.from)} – ${fmtTime(map.window.to)}`}
            </div>
          </section>
          <div className="map-side">
            <DetailPanel graph={graph} map={map!} selected={selected} expanded={expanded} onSelect={setSelected} onToggleCluster={toggleCluster} />
            <PathTracePanel map={map!} from={win?.from} to={win?.to} hops={hops} onHops={setHops} />
          </div>
        </div>
      )}
      {graph && graph.edges.length > 0 && <ConnectionsTable graph={graph} onSelect={(k) => setSelected({ kind: 'edge', key: k })} />}
    </div>
  );
}

// --- legend --------------------------------------------------------------------------------

function Legend() {
  return (
    <div className="map-legend" aria-label="Legend">
      {(['green', 'yellow', 'red', 'hidden'] as EdgeClass[]).map((c) => (
        <span key={c} className="legend-item">
          <svg width={30} height={10} aria-hidden="true">
            <line x1={1} x2={29} y1={5} y2={5} stroke={EDGE_COLOR[c]} strokeWidth={3} strokeDasharray={EDGE_DASH[c]} />
          </svg>
          {EDGE_LABEL[c]}
        </span>
      ))}
      <span className="legend-item muted">width = number of calls</span>
      <span className="legend-sep" />
      {(['agent', 'instance', 'user', 'app', 'store', 'memory', 'mcp', 'domain', 'swarm'] as MapNode['kind'][]).map((k) => (
        <span key={k} className="legend-item">
          <svg width={26} height={26} viewBox="-13 -13 26 26" aria-hidden="true">
            <NodeShape node={{ id: k, kind: k, label: '', swarmIds: [] }} small />
          </svg>
          {KIND_LABEL[k]}
        </span>
      ))}
    </div>
  );
}

export const KIND_LABEL: Record<MapNode['kind'], string> = {
  agent: 'Agent',
  instance: 'Copy',
  user: 'Sponsor',
  app: 'App / tool',
  store: 'Data store',
  memory: 'Memory',
  mcp: 'MCP server',
  domain: 'External domain',
  swarm: 'Swarm',
  unknown: 'Other',
};

// --- canvas -------------------------------------------------------------------------------

function NodeShape({ node, small }: { node: MapNode; small?: boolean }) {
  const s = small ? 0.72 : 1;
  const icon = (el: ReactNode) => (small ? null : el);
  switch (node.kind) {
    case 'agent': {
      const stroke = node.level ? LEVEL_SOLID[node.level] : '#4f46e5';
      return (
        <g>
          <circle r={14 * s} fill="#eef2ff" stroke={stroke} strokeWidth={2.5} />
          {icon(<IconBot size={14} x={-7} y={-7} color="#4f46e5" />)}
        </g>
      );
    }
    case 'instance':
      return <circle r={9 * s} fill="#f8fafc" stroke="#64748b" strokeWidth={1.6} strokeDasharray="3 2" />;
    case 'user':
      return (
        <g>
          <rect x={-13 * s} y={-13 * s} width={26 * s} height={26 * s} rx={7 * s} fill="#f1f5f9" stroke="#475569" strokeWidth={1.6} />
          {icon(<IconUsers size={14} x={-7} y={-7} color="#475569" />)}
        </g>
      );
    case 'app':
      return (
        <g>
          <rect x={-15 * s} y={-12 * s} width={30 * s} height={24 * s} rx={6 * s} fill="#eff6ff" stroke="#2563eb" strokeWidth={1.6} />
          {icon(
            <g color="#1d4ed8" transform="translate(-7,-7)">
              <SystemIcon system={nodeName(node.id)} size={14} />
            </g>,
          )}
        </g>
      );
    case 'store':
      return (
        <g>
          <path d={`M${-13 * s},${-9 * s} v${18 * s} a${13 * s},${4 * s} 0 0 0 ${26 * s},0 v${-18 * s}`} fill="#ecfeff" stroke="#0891b2" strokeWidth={1.6} />
          <ellipse cx={0} cy={-9 * s} rx={13 * s} ry={4 * s} fill="#ecfeff" stroke="#0891b2" strokeWidth={1.6} />
          {icon(<IconDatabase size={12} x={-6} y={-4} color="#0e7490" />)}
        </g>
      );
    case 'memory':
      return (
        <g>
          <path d={`M0,${-15 * s} L${15 * s},0 L0,${15 * s} L${-15 * s},0 Z`} fill="#f5f3ff" stroke="#7c3aed" strokeWidth={1.6} />
          {icon(<IconBrain size={12} x={-6} y={-6} color="#6d28d9" />)}
        </g>
      );
    case 'mcp': {
      const r = 14 * s;
      const pts = Array.from({ length: 6 }, (_, i) => {
        const a = (Math.PI / 3) * i;
        return `${(r * Math.cos(a)).toFixed(1)},${(r * Math.sin(a)).toFixed(1)}`;
      }).join(' ');
      return (
        <g>
          <polygon points={pts} fill="#f0fdf4" stroke="#15803d" strokeWidth={1.6} />
          {icon(<IconPlug size={12} x={-6} y={-6} color="#15803d" />)}
        </g>
      );
    }
    case 'domain':
      return (
        <g>
          <circle r={16 * s} fill="none" stroke="#ea580c" strokeWidth={1} strokeDasharray="2 2" />
          <circle r={12 * s} fill="#fff7ed" stroke="#ea580c" strokeWidth={1.6} />
          {icon(<IconGlobe size={13} x={-6.5} y={-6.5} color="#c2410c" />)}
        </g>
      );
    case 'swarm':
      return (
        <g>
          <circle r={(small ? 11 : 20) * 1} fill="#dc2626" stroke="#7f1d1d" strokeWidth={2} />
          {!small && (
            <text y={4} textAnchor="middle" fontSize={11} fontWeight={700} fill="#fff">
              {short(node.label.split('·').pop()?.trim() ?? '', 4)}
            </text>
          )}
        </g>
      );
    default:
      return <circle r={11 * s} fill="#f1f5f9" stroke="#94a3b8" strokeWidth={1.6} />;
  }
}

function edgePath(a: { x: number; y: number }, b: { x: number; y: number }): string {
  const off = 18;
  if (Math.abs(a.x - b.x) < 4) {
    // Same column (e.g. agent -> agent DELEGATE): arc out to the left.
    const bend = 60 + Math.min(120, Math.abs(a.y - b.y) / 3);
    return `M${a.x - off},${a.y} C${a.x - off - bend},${a.y} ${b.x - off - bend},${b.y} ${b.x - off},${b.y}`;
  }
  const dir = b.x > a.x ? 1 : -1;
  const x1 = a.x + dir * off;
  const x2 = b.x - dir * off;
  const mx = (x1 + x2) / 2;
  return `M${x1},${a.y} C${mx},${a.y} ${mx},${b.y} ${x2},${b.y}`;
}

const keyActivate = (fn: () => void) => (e: KeyboardEvent) => {
  if (e.key === 'Enter' || e.key === ' ') {
    e.preventDefault();
    fn();
  }
};

function MapCanvas({
  graph,
  layout,
  selected,
  highlight,
  blastCenter,
  onNode,
  onEdge,
  onCollapse,
}: {
  graph: DrawGraph;
  layout: Layout;
  selected: Selection;
  highlight: Set<string> | null;
  blastCenter?: string;
  onNode: (n: MapNode) => void;
  onEdge: (key: string) => void;
  onCollapse: (swarmId: string) => void;
}) {
  const [zoom, setZoom] = useState(1);
  const onPath = useMemo(() => {
    if (!highlight) return null;
    const s = new Set<string>();
    for (const e of graph.edges) if (highlight.has(e.key)) s.add(e.from).add(e.to);
    return s;
  }, [highlight, graph.edges]);
  const selNode = selected?.kind === 'node' ? selected.id : null;
  const selEdge = selected?.kind === 'edge' ? selected.key : null;
  const touching = selNode ? new Set(graph.edges.filter((e) => e.from === selNode || e.to === selNode).map((e) => e.key)) : null;

  return (
    <div className="map-canvas-wrap">
      <div className="map-zoom btn-row">
        <button className="btn small" onClick={() => setZoom((z) => Math.max(0.4, z - 0.2))} aria-label="Zoom out">
          −
        </button>
        <span className="muted small">{Math.round(zoom * 100)}%</span>
        <button className="btn small" onClick={() => setZoom((z) => Math.min(2, z + 0.2))} aria-label="Zoom in">
          +
        </button>
      </div>
      <div className="map-scroll">
        <svg
          width={layout.width * zoom}
          height={layout.height * zoom}
          viewBox={`0 0 ${layout.width} ${layout.height}`}
          role="group"
          aria-label={`Communication map: ${graph.nodes.length} nodes, ${graph.edges.length} connections`}
          data-testid="map-svg"
        >
          <defs>
            {(['green', 'yellow', 'red', 'hidden'] as EdgeClass[]).map((c) => (
              <marker key={c} id={`arrow-${c}`} viewBox="0 0 10 10" refX={9} refY={5} markerWidth={6} markerHeight={6} orient="auto-start-reverse">
                <path d="M0,0 L10,5 L0,10 z" fill={EDGE_COLOR[c]} />
              </marker>
            ))}
            <marker id="arrow-reach" viewBox="0 0 10 10" refX={9} refY={5} markerWidth={6} markerHeight={6} orient="auto-start-reverse">
              <path d="M0,0 L10,5 L0,10 z" fill="#94a3b8" />
            </marker>
          </defs>
          {layout.halo && (
            <circle cx={layout.halo.x} cy={layout.halo.y} r={layout.halo.r} fill="rgba(220,38,38,0.06)" stroke="#fca5a5" strokeWidth={2} strokeDasharray="6 5" data-testid="blast-halo">
              <title>Blast radius: everything inside the halo is reachable with the agent's current access</title>
            </circle>
          )}
          {layout.columns.map((c) => (
            <text key={c.label} x={c.x - 14} y={18} fontSize={11} fontWeight={700} fill="#8a94a6" style={{ textTransform: 'uppercase', letterSpacing: '0.06em' }}>
              {c.label}
            </text>
          ))}
          {layout.bands.map((b, i) => (
            <g key={`${b.label}-${i}`}>
              <rect x={layout.columns.find((c) => c.label === 'Agents')?.x ?? 0} y={b.y1} width={6} height={b.y2 - b.y1} rx={3} fill={i % 2 ? '#c7d2fe' : '#a5b4fc'} transform="translate(-30,0)" />
              <text x={(layout.columns.find((c) => c.label === 'Agents')?.x ?? 0) - 34} y={(b.y1 + b.y2) / 2} fontSize={10.5} fill="#64748b" textAnchor="end" dominantBaseline="middle">
                {short(b.label, 14)}
              </text>
            </g>
          ))}
          {graph.expanded.map((c) => {
            const pts = c.members.map((m) => layout.pos.get(m)).filter((p): p is { x: number; y: number } => !!p);
            if (pts.length === 0) return null;
            const x1 = Math.min(...pts.map((p) => p.x)) - 24;
            const y1 = Math.min(...pts.map((p) => p.y)) - 24;
            const x2 = Math.max(...pts.map((p) => p.x)) + 150;
            const y2 = Math.max(...pts.map((p) => p.y)) + 22;
            return (
              <g key={c.swarmId} data-testid="cluster-outline">
                <rect x={x1} y={y1} width={x2 - x1} height={y2 - y1} rx={14} fill="rgba(220,38,38,0.04)" stroke="#dc2626" strokeDasharray="6 4" />
                <text
                  x={x1 + 8}
                  y={y1 - 6}
                  fontSize={11}
                  fill="#b91c1c"
                  fontWeight={700}
                  role="button"
                  tabIndex={0}
                  style={{ cursor: 'pointer' }}
                  aria-label={`Collapse swarm ${c.swarmId}`}
                  onClick={() => onCollapse(c.swarmId)}
                  onKeyDown={keyActivate(() => onCollapse(c.swarmId))}
                >
                  swarm {short(c.swarmId, 20)} · collapse
                </text>
              </g>
            );
          })}
          <g>
            {graph.edges.map((e) => {
              const a = layout.pos.get(e.from);
              const b = layout.pos.get(e.to);
              if (!a || !b) return null;
              const d = edgePath(a, b);
              const dim = (highlight && !highlight.has(e.key)) || (touching && !touching.has(e.key) && !highlight);
              const hot = (highlight?.has(e.key) ?? false) || selEdge === e.key;
              const color = e.reach ? '#94a3b8' : EDGE_COLOR[e.worst];
              return (
                <g
                  key={e.key}
                  className="map-edge"
                  data-testid="map-edge"
                  data-class={e.reach ? 'reach' : e.worst}
                  data-from={e.from}
                  data-to={e.to}
                  data-highlight={highlight?.has(e.key) ? 'true' : undefined}
                  opacity={dim ? 0.18 : 1}
                  onClick={() => onEdge(e.key)}
                >
                  <title>{`${e.from} → ${e.to}: ${e.count} calls, ${fmtBytes(e.bytes)}, ${e.reach ? 'reachable' : EDGE_LABEL[e.worst]}${e.labels.length ? `, labels ${e.labels.join(', ')}` : ''}`}</title>
                  {hot && <path d={d} fill="none" stroke="#fde047" strokeWidth={edgeWidth(e.count) + 7} strokeLinecap="round" opacity={0.85} />}
                  <path
                    d={d}
                    fill="none"
                    stroke={color}
                    strokeWidth={e.reach ? 1.4 : edgeWidth(e.count)}
                    strokeDasharray={e.reach ? '2 4' : EDGE_DASH[e.worst]}
                    markerEnd={`url(#arrow-${e.reach ? 'reach' : e.worst})`}
                  />
                  <path d={d} fill="none" stroke="transparent" strokeWidth={14} style={{ cursor: 'pointer' }} />
                </g>
              );
            })}
          </g>
          <g>
            {graph.nodes.map((n) => {
              const p = layout.pos.get(n.id);
              if (!p) return null;
              const dim = onPath && !onPath.has(n.id);
              const sel = selNode === n.id;
              const reach = blastCenter && (n.reachable || n.id === blastCenter);
              const aria = [
                KIND_LABEL[n.kind],
                n.label,
                n.team && `team ${n.team}`,
                n.level && `level ${n.level}`,
                n.discovered && 'discovered',
                n.suspended && 'suspended',
                n.kind === 'swarm' && 'press to expand',
              ]
                .filter(Boolean)
                .join(', ');
              return (
                <g
                  key={n.id}
                  transform={`translate(${p.x},${p.y})`}
                  className="map-node"
                  role="button"
                  tabIndex={0}
                  aria-label={aria}
                  aria-pressed={sel}
                  data-testid="map-node"
                  data-kind={n.kind}
                  data-id={n.id}
                  opacity={dim ? 0.25 : 1}
                  onClick={() => onNode(n)}
                  onKeyDown={keyActivate(() => onNode(n))}
                >
                  <title>{`${KIND_LABEL[n.kind]} ${n.id}`}</title>
                  {reach && n.id !== blastCenter && <circle r={22} fill="rgba(220,38,38,0.10)" stroke="#fca5a5" />}
                  {sel && <circle r={n.kind === 'swarm' ? 27 : 21} fill="none" stroke="#2563eb" strokeWidth={2.5} />}
                  {n.discovered && <circle r={19} fill="none" stroke="#ea580c" strokeWidth={1.6} strokeDasharray="4 3" />}
                  <NodeShape node={n} />
                  {n.suspended && <circle cx={11} cy={-11} r={4.5} fill="#ea580c" stroke="#fff" strokeWidth={1.5} />}
                  <text x={n.kind === 'swarm' ? 26 : 21} y={4} fontSize={11.5} fill="#0f172a" fontWeight={n.kind === 'swarm' || n.id === blastCenter ? 700 : 500}>
                    {short(n.label)}
                    {n.discovered ? ' · discovered' : ''}
                  </text>
                </g>
              );
            })}
          </g>
        </svg>
      </div>
    </div>
  );
}

// --- detail panel ----------------------------------------------------------------------------

export function ActionLink({ id }: { id: string }) {
  return (
    <Link to={`/actions/${encodeURIComponent(id)}`} className="mono action-link" title="Open the action and its Diary entries">
      {short(id, 30)}
    </Link>
  );
}

function nodeLink(n: MapNode): ReactNode {
  if (n.kind === 'agent') return <Link to={`/agents/${encodeURIComponent(nodeName(n.id))}`}>Open agent</Link>;
  if (n.kind === 'swarm' && n.swarmIds[0]) return <Link to={`/swarms/${encodeURIComponent(n.swarmIds[0])}`}>Open swarm</Link>;
  return null;
}

function DetailPanel({
  graph,
  map,
  selected,
  expanded,
  onSelect,
  onToggleCluster,
}: {
  graph: DrawGraph;
  map: CommMap;
  selected: Selection;
  expanded: Set<string>;
  onSelect: (s: Selection) => void;
  onToggleCluster: (id: string) => void;
}) {
  const body = (() => {
    if (!selected) return <div className="muted small">Select a node or a connection to see its details. Click a red swarm node to expand it.</div>;
    if (selected.kind === 'edge') {
      const e = graph.edges.find((x) => x.key === selected.key);
      if (!e) return <div className="muted small">This connection is not in the current window.</div>;
      return <EdgeDetail e={e} />;
    }
    const n = graph.nodes.find((x) => x.id === selected.id) ?? map.nodes.find((x) => x.id === selected.id);
    if (!n) return <div className="muted small">This node is not in the current window.</div>;
    const out = graph.edges.filter((x) => x.from === n.id);
    const inn = graph.edges.filter((x) => x.to === n.id);
    const sum = (l: AggEdge[]) => l.reduce((a, x) => a + x.count, 0);
    const bytes = (l: AggEdge[]) => l.reduce((a, x) => a + x.bytes, 0);
    const cluster = n.kind === 'swarm' ? map.clusters.find((c) => clusterNodeId(c.swarmId) === n.id) : undefined;
    return (
      <div className="stat-list" data-testid="node-detail">
        <div className="row" style={{ flexWrap: 'wrap' }}>
          <strong className="mono" style={{ overflowWrap: 'anywhere' }}>
            {n.id}
          </strong>
          <span className="chip gray">{KIND_LABEL[n.kind]}</span>
          {n.level && <LevelChip level={n.level} />}
          {n.discovered && <span className="chip orange">Discovered</span>}
          {n.suspended && <span className="chip orange">Suspended</span>}
        </div>
        <dl className="kv">
          {n.team && (
            <>
              <dt>Team</dt>
              <dd>{n.team}</dd>
            </>
          )}
          {n.owner !== undefined && (
            <>
              <dt>Owner</dt>
              <dd>{n.owner || <span className="muted">none</span>}</dd>
            </>
          )}
          <dt>Outgoing</dt>
          <dd>
            {fmtNum(sum(out))} calls · {fmtBytes(bytes(out))} · {out.length} connections
          </dd>
          <dt>Incoming</dt>
          <dd>
            {fmtNum(sum(inn))} calls · {fmtBytes(bytes(inn))} · {inn.length} connections
          </dd>
          {n.swarmIds.length > 0 && (
            <>
              <dt>Swarms</dt>
              <dd className="row" style={{ flexWrap: 'wrap', gap: 4 }}>
                {n.swarmIds.map((s) => (
                  <Link key={s} to={`/swarms/${encodeURIComponent(s)}`} className="chip red">
                    {s}
                  </Link>
                ))}
              </dd>
            </>
          )}
          {cluster && (
            <>
              <dt>Members</dt>
              <dd>
                {cluster.members.length} · state {cluster.state}
              </dd>
            </>
          )}
        </dl>
        <div className="btn-row">
          {nodeLink(n)}
          {cluster && (
            <button className="btn small" onClick={() => onToggleCluster(cluster.swarmId)}>
              {expanded.has(cluster.swarmId) ? 'Collapse swarm' : 'Expand swarm'}
            </button>
          )}
        </div>
        {[...out, ...inn].length > 0 && (
          <ul className="map-conn-list">
            {[...out, ...inn]
              .sort((a, b) => b.count - a.count)
              .slice(0, 10)
              .map((x) => (
                <li key={x.key}>
                  <button className="link-btn" onClick={() => onSelect({ kind: 'edge', key: x.key })}>
                    {x.from === n.id ? `→ ${short(x.to, 30)}` : `← ${short(x.from, 30)}`}
                  </button>
                  <span className={`chip ${x.reach ? 'gray' : EDGE_CHIP[x.worst]}`}>{x.reach ? 'reach' : EDGE_LABEL[x.worst]}</span>
                  <span className="muted small">{fmtNum(x.count)}</span>
                </li>
              ))}
          </ul>
        )}
      </div>
    );
  })();
  return (
    <section className="card" data-testid="map-detail">
      <div className="card-head">
        <h2>Details</h2>
        <div className="spacer" />
        {selected && (
          <button className="btn small ghost" onClick={() => onSelect(null)}>
            Clear
          </button>
        )}
      </div>
      <div className="card-pad">{body}</div>
    </section>
  );
}

function EdgeDetail({ e }: { e: AggEdge }) {
  return (
    <div className="stat-list" data-testid="edge-detail">
      <div className="mono small" style={{ overflowWrap: 'anywhere' }}>
        {e.from} → {e.to}
      </div>
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <span className={`chip ${EDGE_CHIP[e.worst]}`}>
          <span className="dot" />
          {e.reach ? 'Reachable (not called)' : EDGE_LABEL[e.worst]}
        </span>
        <span className="muted small">
          {fmtNum(e.count)} calls · {fmtBytes(e.bytes)}
        </span>
      </div>
      {e.labels.length > 0 && (
        <div className="row" style={{ flexWrap: 'wrap', gap: 4 }}>
          <span className="muted small">Data labels:</span>
          {e.labels.map((l) => (
            <span key={l} className="chip purple">
              {l}
            </span>
          ))}
        </div>
      )}
      <table className="table compact">
        <thead>
          <tr>
            <th>Verb</th>
            <th>Window</th>
            <th>Calls</th>
            <th>Bytes</th>
            <th>Class</th>
          </tr>
        </thead>
        <tbody>
          {e.rows.slice(0, 30).map((r, i) => (
            <tr key={i}>
              <td>{r.verb || '—'}</td>
              <td>{r.windowStart ? fmtClock(r.windowStart) : '—'}</td>
              <td>{fmtNum(r.count)}</td>
              <td>{fmtBytes(r.bytes)}</td>
              <td>
                {/* A reach row has no class from the server (it was never called): never label it "Dangerous". */}
                <span className={`chip ${r.reach ? 'gray' : EDGE_CHIP[r.worstClass]}`}>{r.reach ? 'Reachable (not called)' : EDGE_LABEL[r.worstClass]}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {e.rows.length > 30 && <div className="muted small">{e.rows.length - 30} more windows not shown.</div>}
      <div>
        <div className="section-title" style={{ marginBottom: 4 }}>
          Sample actions (Diary)
        </div>
        {e.sampleActionIds.length === 0 ? (
          <span className="muted small">{e.reach ? 'Not called in this window.' : 'No sample actions reported.'}</span>
        ) : (
          <div className="row" style={{ flexWrap: 'wrap', gap: 6 }} data-testid="edge-samples">
            {e.sampleActionIds.map((id) => (
              <ActionLink key={id} id={id} />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// --- path trace ---------------------------------------------------------------------------------

function PathTracePanel({ map, from, to, hops, onHops }: { map: CommMap; from?: string; to?: string; hops: PathHop[] | null; onHops: (h: PathHop[] | null) => void }) {
  const [label, setLabel] = useState('');
  const [dest, setDest] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const id = useId();
  const labels = useMemo(() => [...new Set(map.edges.flatMap((e) => e.labels))].sort(), [map.edges]);
  const dests = useMemo(() => map.nodes.filter((n) => n.kind !== 'user').sort((a, b) => a.id.localeCompare(b.id)), [map.nodes]);

  const run = async () => {
    if (!label.trim() || !dest.trim()) return;
    setBusy(true);
    setError(null);
    try {
      onHops(await tracePath(label.trim(), dest.trim(), from, to));
    } catch (e) {
      setError(e);
      onHops(null);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card" data-testid="path-trace">
      <div className="card-head">
        <div>
          <h2>Path trace</h2>
          <div className="sub">Every hop data with a label took to a destination.</div>
        </div>
      </div>
      <div className="card-pad stat-list">
        <div className="field">
          <label htmlFor={`${id}-label`}>Data label</label>
          <input id={`${id}-label`} className="input" list={`${id}-labels`} value={label} placeholder="e.g. customer_pii" onChange={(e) => setLabel(e.target.value)} />
          <datalist id={`${id}-labels`}>
            {labels.map((l) => (
              <option key={l} value={l} />
            ))}
          </datalist>
        </div>
        <div className="field">
          <label htmlFor={`${id}-dest`}>Destination</label>
          <input id={`${id}-dest`} className="input" list={`${id}-dests`} value={dest} placeholder="e.g. domain:paste.example" onChange={(e) => setDest(e.target.value)} />
          <datalist id={`${id}-dests`}>
            {dests.map((n) => (
              <option key={n.id} value={n.id} />
            ))}
          </datalist>
        </div>
        <div className="btn-row">
          <button className="btn small primary" onClick={() => void run()} disabled={busy || !label.trim() || !dest.trim()}>
            {busy && <span className="spinner" />} Trace
          </button>
          {hops && (
            <button className="btn small" onClick={() => onHops(null)}>
              Clear highlight
            </button>
          )}
        </div>
        <ErrorBox error={error} />
        {hops && hops.length === 0 && <div className="muted small">No data with that label reached that destination in this window.</div>}
        {hops && hops.length > 0 && (
          <ol className="steps" aria-label="Hops" data-testid="path-hops">
            {hops.map((h, i) => (
              <li key={i} className="step-row">
                <span className="step-n">{i + 1}</span>
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="mono small" style={{ overflowWrap: 'anywhere' }}>
                    {h.from} → {h.to}
                  </div>
                  <div className="muted small">
                    {h.verb || 'call'}
                    {h.windowStart && ` · ${fmtTime(h.windowStart)}`}
                  </div>
                  {h.actionIds.length > 0 && (
                    <div className="row" style={{ flexWrap: 'wrap', gap: 6, marginTop: 2 }}>
                      {h.actionIds.slice(0, 5).map((a) => (
                        <ActionLink key={a} id={a} />
                      ))}
                      {h.actionIds.length > 5 && <span className="muted small">+{h.actionIds.length - 5}</span>}
                    </div>
                  )}
                </div>
              </li>
            ))}
          </ol>
        )}
      </div>
    </section>
  );
}

// --- connections table (accessible list of every edge) -------------------------------------------

function ConnectionsTable({ graph, onSelect }: { graph: DrawGraph; onSelect: (key: string) => void }) {
  const [open, setOpen] = useState(false);
  const rows = [...graph.edges].sort((a, b) => (b.reach ? -1 : 0) - (a.reach ? -1 : 0) || ['hidden', 'red', 'yellow', 'green'].indexOf(a.worst) - ['hidden', 'red', 'yellow', 'green'].indexOf(b.worst) || b.count - a.count);
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Connections</h2>
          <div className="sub">Every connection on the map as a table, worst first.</div>
        </div>
        <div className="spacer" />
        <button className="btn small" aria-expanded={open} onClick={() => setOpen(!open)}>
          {open ? 'Hide table' : `Show ${graph.edges.length} connections`}
        </button>
      </div>
      {open && (
        <div className="table-wrap">
          <table className="table" aria-label="Connections">
            <thead>
              <tr>
                <th>From</th>
                <th>To</th>
                <th>Class</th>
                <th>Calls</th>
                <th>Bytes</th>
                <th>Labels</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.key}>
                  <td className="mono small">{short(e.from, 40)}</td>
                  <td className="mono small">{short(e.to, 40)}</td>
                  <td>
                    <span className={`chip ${e.reach ? 'gray' : EDGE_CHIP[e.worst]}`}>{e.reach ? 'reach' : EDGE_LABEL[e.worst]}</span>
                  </td>
                  <td>{fmtNum(e.count)}</td>
                  <td>{fmtBytes(e.bytes)}</td>
                  <td className="small">{e.labels.join(', ') || '—'}</td>
                  <td>
                    <button className="btn small ghost" onClick={() => onSelect(e.key)}>
                      Details
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
