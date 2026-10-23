import { describe, expect, it } from 'vitest';
import { normBaseline, normBulkDeny, normMapEdge, normQueueItem, normShadowFinding, normSwarmDetail, normSwarmRelease, parseEdgeClass, swarmActive } from './normalize';

describe('Phase 5 normalisers', () => {
  it('reads a swarm detail, deriving the spawn tree from a nested tree or members', () => {
    const d = normSwarmDetail({
      swarm: { swarm_id: 'dlg_1', state: 'FROZEN', detected_by: 'spawn_tree', member_count: 3, root_agent_id: 'r' },
      members: [{ agent_id: 'r' }, { agent_id: 'a', parent: 'r', level_name: 'KILLED' }, 'b'],
      spawn_tree: { agent_id: 'r', children: [{ agent_id: 'a', children: [{ agent_id: 'b' }] }] },
      release: { votes: [{ actor: 'user:x@example.com', at: 't' }], required: 2 },
    });
    expect(d.state).toBe('frozen');
    expect(d.frozen).toBe(true);
    expect(d.root).toBe('r');
    expect(d.members.map((m) => m.id)).toEqual(['r', 'a', 'b']);
    expect(d.members[1]!.level).toBe('KILLED');
    expect(d.spawnTree).toEqual([
      { parent: 'r', child: 'a', depth: 1, delegationId: undefined },
      { parent: 'a', child: 'b', depth: 2, delegationId: undefined },
    ]);
    expect(d.releaseVotes[0]!.approver).toBe('user:x@example.com');
    // The server sends suspended (bool), not status.
    const ms = normSwarmDetail({ swarm_id: 's', members: [{ agent_id: 'x', suspended: true }, { agent_id: 'y', suspended: false }] }).members;
    expect(ms.map((m) => m.status)).toEqual(['suspended', 'active']);
    expect(normSwarmDetail({ swarm_id: 's', members: [{ agent_id: 'c', parent: 'p' }] }).spawnTree).toEqual([{ parent: 'p', child: 'c', depth: undefined }]);
    expect(swarmActive('frozen')).toBe(true);
    // The server's rule: everything not released is active (a killed swarm still holds its calls).
    expect(swarmActive('killed')).toBe(true);
    expect(swarmActive('released')).toBe(false);
  });

  it('reads release votes and never claims an unreported bulk deny', () => {
    expect(normSwarmRelease({ released: false, votes: 1, required: 2 })).toEqual({ released: false, votes: 1, required: 2, op: undefined });
    expect(normSwarmRelease({ released: true, votes: 2, required: 2, op: { op_id: 'o', op: 'release_swarm', status: 'done', steps: [] } }).op!.opId).toBe('o');
    expect(normBulkDeny({}, ['a']).every((r) => !r.ok)).toBe(true);
    expect(normBulkDeny({ results: { a: { outcome: 'denied' }, b: { error: 'gone' } } }, ['a', 'b'])).toEqual([
      { actionId: 'a', ok: true, outcome: 'denied', error: undefined },
      { actionId: 'b', ok: false, outcome: '', error: 'gone' },
    ]);
  });

  it('counts distinct approve votes and never understates an edge class', () => {
    const q = normQueueItem({ action_id: 'h', votes: [{ approver: 'user:A@x.com', decision: 'approve' }, { approver: 'a@x.com', decision: 'approve' }, { approver: 'b@x.com', decision: 'deny' }] });
    expect(q.approvals).toBe(1);
    expect(parseEdgeClass('hidden')).toBe('hidden');
    expect(parseEdgeClass('blue')).toBe('yellow');
    expect(parseEdgeClass('weird')).toBe('red');
    expect(normMapEdge({ source: 'agent:a', target: 'app:gmail', class: 'green', data_labels: ['pii'] })).toMatchObject({ from: 'agent:a', to: 'app:gmail', worstClass: 'green', labels: ['pii'] });
  });

  it('reads shadow findings and baselines without trusting shapes', () => {
    const f = normShadowFinding({ id: 'f', evidence: 'seen from 10.0.0.1', used_by_software: 'yes' });
    expect(f.findingId).toBe('f');
    expect(f.usedBySoftware).toBe(false);
    expect(f.evidence).toEqual([['detail', 'seen from 10.0.0.1']]);
    const b = normBaseline({ baseline: { hourly: [3, 4], thresholds: { threshold: 9, mean: 3.5 } } }, 'a', 'send');
    expect(b.series.map((p) => p.count)).toEqual([3, 4]);
    expect(b.threshold).toBe(9);
    expect(b.mean).toBe(3.5);
    expect(b.verb).toBe('SEND');
    expect(b.stddev).toBeNull();
  });
});
