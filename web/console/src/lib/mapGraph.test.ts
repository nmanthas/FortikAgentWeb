import { describe, expect, it } from 'vitest';
import { normMap } from '../api/normalize';
import { applyEdgeUpdate, applySwarmUpdate, buildGraph, clusterNodeId, edgeKey, layeredLayout, MAX_ROWS, pathKeys, radialLayout } from './mapGraph';

const raw = {
  window: { from: '2026-10-20T10:00:00Z', to: '2026-10-20T11:00:00Z' },
  nodes: [
    { id: 'agent:root', kind: 'agent', label: 'root', team: 'Sales' },
    { id: 'agent:w1', kind: 'agent', team: 'Sales', swarm_ids: ['swm_1'] },
    { id: 'agent:w2', kind: 'agent', team: 'Sales', swarm_ids: ['swm_1'] },
    { id: 'app:gmail', kind: 'app' },
  ],
  edges: [
    { from: 'agent:root', to: 'agent:w1', verb: 'DELEGATE', count: 1, worst_class: 'green' },
    { from: 'agent:w1', to: 'app:gmail', verb: 'SEND', count: 3, bytes: 100, worst_class: 'yellow', labels: ['pii'], sample_action_ids: ['a1'] },
    { from: 'agent:w2', to: 'app:gmail', verb: 'SEND', count: 2, bytes: 50, worst_class: 'red', sample_action_ids: ['a2'] },
    { from: 'agent:w1', to: 'agent:w2', verb: 'DELEGATE', count: 1, worst_class: 'green' },
    { from: 'agent:root', to: 'domain:paste.example', verb: 'POST', count: 1, worst_class: 'hidden' },
  ],
  clusters: [{ swarm_id: 'swm_1', state: 'active', members: ['agent:w1', 'w2'] }],
};

describe('map graph', () => {
  it('collapses a swarm into one node, re-targets and folds edges, keeps the worst class', () => {
    const m = normMap(raw);
    expect(m.clusters[0]!.members).toEqual(['agent:w1', 'agent:w2']);
    const g = buildGraph(m, new Set());
    const ids = g.nodes.map((n) => n.id).sort();
    expect(ids).toEqual(['agent:root', 'app:gmail', 'domain:paste.example', clusterNodeId('swm_1')].sort());
    const toGmail = g.edges.find((e) => e.key === edgeKey('swarm:swm_1', 'app:gmail'))!;
    expect(toGmail.count).toBe(5);
    expect(toGmail.bytes).toBe(150);
    expect(toGmail.worst).toBe('red');
    expect(toGmail.labels).toEqual(['pii']);
    expect(toGmail.sampleActionIds).toEqual(['a1', 'a2']);
    // The edge inside the collapsed swarm is dropped; the placeholder domain node exists.
    expect(g.edges.some((e) => e.from === e.to)).toBe(false);
    expect(g.edges.find((e) => e.to === 'domain:paste.example')!.worst).toBe('hidden');

    const open = buildGraph(m, new Set(['swm_1']));
    expect(open.nodes.some((n) => n.kind === 'swarm')).toBe(false);
    expect(open.expanded).toHaveLength(1);
    expect(open.edges.some((e) => e.key === edgeKey('agent:w1', 'agent:w2'))).toBe(true);
    // A hop between members highlights the collapsed node's edge.
    expect([...pathKeys([{ from: 'agent:w1', to: 'app:gmail' }], g.alias)]).toEqual([edgeKey('swarm:swm_1', 'app:gmail')]);
  });

  it('merges live updates by (from, to, verb, window) and adds unknown nodes', () => {
    let m = normMap(raw);
    m = applyEdgeUpdate(m, { from: 'agent:w1', to: 'app:gmail', verb: 'SEND', count: 9, bytes: 1, labels: [], sampleActionIds: [], worstClass: 'yellow' });
    expect(m.edges.filter((e) => e.from === 'agent:w1' && e.to === 'app:gmail')).toHaveLength(1);
    expect(m.edges.find((e) => e.from === 'agent:w1' && e.to === 'app:gmail')!.count).toBe(9);
    m = applyEdgeUpdate(m, { from: 'agent:new', to: 'store:postgres:prod', verb: 'SELECT', count: 1, bytes: 0, labels: [], sampleActionIds: [], worstClass: 'green' });
    expect(m.nodes.find((n) => n.id === 'store:postgres:prod')!.kind).toBe('store');
    m = applySwarmUpdate(m, { swarmId: 'swm_2', state: 'active', members: ['agent:new'] });
    expect(m.clusters).toHaveLength(2);
    expect(m.nodes.find((n) => n.id === 'agent:new')!.swarmIds).toEqual(['swm_2']);
  });

  it('lays out 41 agents deterministically within wrapped columns', () => {
    const nodes = Array.from({ length: 41 }, (_, i) => ({ id: `agent:w${i}`, kind: 'agent' as const, label: `w${i}`, swarmIds: [] }));
    const a = layeredLayout(nodes, 'team');
    const b = layeredLayout([...nodes].reverse(), 'team');
    expect([...a.pos.entries()].sort()).toEqual([...b.pos.entries()].sort());
    const ys = new Set([...a.pos.values()].map((p) => p.y));
    expect(ys.size).toBeLessThanOrEqual(MAX_ROWS);
    const r = radialLayout([...nodes, { id: 'app:gmail', kind: 'app', label: 'gmail', swarmIds: [] }], 'agent:w0');
    expect(r.halo).toBeTruthy();
    expect(r.pos.get('agent:w0')).toEqual({ x: r.halo!.x, y: r.halo!.y });
  });
});
