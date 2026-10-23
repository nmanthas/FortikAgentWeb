import { describe, expect, it } from 'vitest';
import { blockedFromDiary, delegationViewFromApi, delegationViewFromDiary, normOverride } from './normalize';
import type { DiaryEvent } from './types';

// GET /v1/agents/researcher/delegations as internal/delegation.Handler writes it.
const apiBody = {
  agent_id: 'researcher',
  hops: [
    {
      delegation_id: 'dlg_1',
      root_agent: 'planner',
      from_agent: 'planner',
      to_agent: 'researcher',
      chain: ['planner', 'researcher'],
      depth: 1,
      task_id: 't1',
      channel: 'a2a',
      action_id: 'act_a',
      status: 'open',
      created_at: '2026-10-13T10:00:00Z',
      expires_at: '2026-10-13T10:15:00Z',
    },
    {
      delegation_id: 'dlg_2',
      parent_id: 'dlg_1',
      root_agent: 'planner',
      from_agent: 'researcher',
      to_agent: 'db-bot',
      chain: ['planner', 'researcher', 'db-bot'],
      depth: 2,
      channel: 'a2a',
      action_id: 'act_b',
      status: 'closed',
      created_at: '2026-10-13T10:01:00Z',
      expires_at: '2026-10-13T10:16:00Z',
      closed_at: '2026-10-13T10:02:00Z',
    },
    { delegation_id: 'dlg_3', root_agent: 'researcher', from_agent: 'researcher', to_agent: 'researcher', chain: ['researcher', 'researcher'], depth: 1, channel: 'hook_task', status: 'open', created_at: '2026-10-13T10:03:00Z' },
  ],
  blocked: [
    {
      action_id: 'act_x',
      ts: '2026-10-13T10:05:00Z',
      executor: 'db-bot',
      system: 'postgres',
      verb: 'DELETE',
      rule_id: 'POL-601',
      reason: 'delegation bypass: originating agent planner (hop 1 of 2) may not DELETE on postgres',
      delegation: { present: true, source: 'token', depth: 2, root: 'planner', chain: [{ agent_id: 'planner', level: 2 }, { agent_id: 'researcher' }] },
    },
    { action_id: 'act_y', ts: '2026-10-13T10:06:00Z', executor: 'researcher', system: 'a2a', verb: 'DELEGATE', rule_id: 'POL-603', reason: 'not allowed', delegation: null },
  ],
};

const bypassEvent: DiaryEvent = {
  seq: 42,
  ts: '2026-10-13T10:05:00Z',
  agentId: 'planner',
  eventType: 'delegation.bypass_blocked',
  data: {
    action_id: 'act_x',
    rule_id: 'POL-601',
    reason: 'delegation bypass',
    executor: 'db-bot',
    root: 'planner',
    roots: ['planner'],
    chain: ['planner', 'researcher'],
    system: 'postgres',
    verb: 'DELETE',
    stepped_down: ['planner'],
    origin_level: 'SUPERVISED',
  },
};

describe('delegation views', () => {
  it('splits API hops into inbound and outbound, newest first', () => {
    const v = delegationViewFromApi('researcher', apiBody);
    expect(v.source).toBe('api');
    expect(v.inbound.map((h) => h.delegationId)).toEqual(['dlg_1']);
    expect(v.outbound.map((h) => h.delegationId)).toEqual(['dlg_3', 'dlg_2']);
    expect(v.inbound[0]).toMatchObject({ root: 'planner', from: 'planner', to: 'researcher', depth: 1, taskId: 't1', expiresAt: '2026-10-13T10:15:00Z' });
    expect(v.outbound[1]).toMatchObject({ status: 'closed', closedAt: '2026-10-13T10:02:00Z', chain: ['planner', 'researcher', 'db-bot'] });
  });

  it('turns refusals into blocked entries with the executor appended to the chain', () => {
    const v = delegationViewFromApi('researcher', apiBody);
    expect(v.blocked.map((b) => [b.actionId, b.bypass])).toEqual([
      ['act_y', false],
      ['act_x', true],
    ]);
    const x = v.blocked[1]!;
    expect(x.chain).toEqual(['planner', 'researcher', 'db-bot']);
    expect(x.root).toBe('planner');
    expect(x.steppedDown).toEqual([]);
    expect(v.blocked[0]!.chain).toEqual(['researcher']);
  });

  it('merges who was stepped down from the Diary event', () => {
    const v = delegationViewFromApi('researcher', apiBody, [bypassEvent]);
    const x = v.blocked.find((b) => b.actionId === 'act_x')!;
    expect(x).toMatchObject({ seq: 42, steppedDown: ['planner'], originLevel: 'SUPERVISED', bypass: true });
    expect(v.blocked).toHaveLength(2);

    // A Diary-only attempt (beyond the endpoint's limit) is added; one the agent is not part of is not.
    const extra: DiaryEvent = { ...bypassEvent, seq: 50, ts: '2026-10-13T11:00:00Z', data: { ...bypassEvent.data, action_id: 'act_z' } };
    const unrelated: DiaryEvent = { ...bypassEvent, seq: 51, agentId: 'other', data: { ...bypassEvent.data, action_id: 'act_w', executor: 'x', root: 'y', roots: ['y'], chain: ['y'] } };
    const v2 = delegationViewFromApi('researcher', apiBody, [extra, unrelated]);
    expect(v2.blocked.map((b) => b.actionId)).toEqual(['act_z', 'act_y', 'act_x']);
  });

  it('accepts the legacy boolean stepped_down', () => {
    const b = blockedFromDiary('planner', { ...bypassEvent, data: { ...bypassEvent.data, stepped_down: true } })!;
    expect(b.steppedDown).toEqual(['planner']);
    expect(blockedFromDiary('planner', { ...bypassEvent, eventType: 'delegation.opened' })).toBeNull();
  });

  it('rebuilds the view from Diary events when there is no endpoint', () => {
    const events: DiaryEvent[] = [
      { seq: 1, ts: '2026-10-13T10:00:00Z', agentId: 'planner', eventType: 'delegation.opened', data: { delegation_id: 'dlg_1', chain: ['planner', 'researcher'], root: 'planner', from: 'planner', to: 'researcher', channel: 'a2a', depth: 1 } },
      { seq: 2, ts: '2026-10-13T10:01:00Z', agentId: 'researcher', eventType: 'delegation.opened', data: { delegation_id: 'dlg_2', chain: ['planner', 'researcher', 'db-bot'], root: 'planner', from: 'researcher', to: 'db-bot', channel: 'a2a', depth: 2 } },
      { seq: 3, ts: '2026-10-13T10:04:00Z', agentId: 'researcher', eventType: 'delegation.closed', data: { delegation_id: 'dlg_2', status: 'expired', from: 'researcher', to: 'db-bot' } },
      bypassEvent,
    ];
    const v = delegationViewFromDiary('researcher', events);
    expect(v.source).toBe('diary');
    expect(v.inbound.map((h) => h.delegationId)).toEqual(['dlg_1']);
    expect(v.outbound[0]).toMatchObject({ delegationId: 'dlg_2', status: 'expired', closedAt: '2026-10-13T10:04:00Z' });
    expect(v.blocked).toHaveLength(1);
    expect(v.blocked[0]!.chain).toEqual(['planner', 'researcher', 'db-bot']);
  });
});

describe('normOverride', () => {
  it('flattens revoke_result per agent and treats unknown modes as suspended', () => {
    const o = normOverride({
      override_id: 'ovr_1',
      system: 'github',
      mode: 'weird',
      status: 'active',
      revoke_result: { github: { 'billing-bot': 'installation token deleted', 'ops-bot': 'no live credential' } },
    });
    expect(o.mode).toBe('suspended');
    expect(o.expiresAt).toBeUndefined();
    expect(o.revokeResult).toEqual({ 'billing-bot': 'installation token deleted', 'ops-bot': 'no live credential' });
  });
});
