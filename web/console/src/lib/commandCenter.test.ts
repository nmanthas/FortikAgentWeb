import { describe, expect, it } from 'vitest';
import type { ActionRow, Agent, ContainmentOp, ContainmentStep } from '../api/types';
import { countBlockedToday, dangerousVerbs, incidentChain, memoryQuarantined, pickSelected, quarantinedFromAgents } from './commandCenter';

const agent = (agentId: string, extra: Partial<Agent> = {}): Agent => ({
  agentId,
  name: '',
  type: '',
  platform: '',
  sponsor: '',
  businessUnit: '',
  workspaceUser: '',
  copyCap: 1,
  level: 'FULL',
  discovered: false,
  ...extra,
});

const action = (actionId: string, ts: string, extra: Partial<ActionRow> = {}): ActionRow => ({
  actionId,
  agentId: 'bot',
  system: 'gmail',
  verb: 'SEND',
  class: 'green',
  decision: 'allow',
  ruleId: '',
  reason: '',
  reversible: true,
  source: 'gateway',
  ts,
  failClosed: false,
  held: false,
  ...extra,
});

const op = (o: string, targetType: string, targetId: string, createdAt: string, status: ContainmentOp['status'], steps: ContainmentStep[] = []): ContainmentOp => ({
  opId: `cop_${o}_${createdAt}`,
  op: o,
  targetType,
  targetId,
  actor: 'user:sec@example.com',
  reason: 'r',
  status,
  steps,
  createdAt,
});

const NOW = Date.parse('2026-10-19T12:00:00Z');

describe('Command Center computations', () => {
  it('counts only denials since 00:00 UTC', () => {
    const rows = [
      action('a1', '2026-10-19T00:00:01Z', { decision: 'deny' }),
      action('a2', '2026-10-18T23:59:59Z', { decision: 'deny' }),
      action('a3', '2026-10-19T11:00:00Z', { decision: 'allow' }),
      action('a4', 'not a time', { decision: 'deny' }),
    ];
    expect(countBlockedToday(rows, NOW)).toBe(1);
  });

  it('lists distinct red verbs per agent from the last 24 hours, most frequent first', () => {
    const rows = [
      action('a1', '2026-10-19T10:00:00Z', { class: 'red', system: 'postgres', verb: 'DROP' }),
      action('a2', '2026-10-19T10:01:00Z', { class: 'red', system: 'gmail', verb: 'SEND' }),
      action('a3', '2026-10-19T10:02:00Z', { class: 'red', system: 'gmail', verb: 'SEND' }),
      action('a4', '2026-10-17T10:00:00Z', { class: 'red', system: 'aws', verb: 'DELETE' }),
      action('a5', '2026-10-19T10:00:00Z', { class: 'yellow', system: 'drive', verb: 'SHARE' }),
    ];
    expect(dangerousVerbs(rows, NOW).get('bot')).toEqual(['gmail SEND', 'postgres DROP']);
  });

  it('derives memory quarantines from the history, counting a partial op only when its memory step took effect', () => {
    const agents = [agent('a'), agent('b', { businessUnit: 'Ops' }), agent('c', { businessUnit: 'Ops' }), agent('d'), agent('e')];
    const ops = [
      op('memory_remove', 'agent', 'a', '2026-10-19T01:00:00Z', 'done', [{ name: 'set_memory_access', agentId: 'a', status: 'done', durationMs: 1 }]),
      op('kill', 'team', 'Ops', '2026-10-19T02:00:00Z', 'partial', [
        { name: 'set_memory_access', agentId: 'b', status: 'done', durationMs: 1 },
        { name: 'set_memory_access', agentId: 'c', status: 'failed', detail: 'db down', durationMs: 1 },
      ]),
      op('memory_remove', 'agent', 'd', '2026-10-19T03:00:00Z', 'failed'),
      op('memory_remove', 'agent', 'e', '2026-10-19T04:00:00Z', 'done'),
      op('memory_restore', 'agent', 'e', '2026-10-19T05:00:00Z', 'partial', [{ name: 'set_memory_access', agentId: 'e', status: 'skipped', detail: 'rollback failed', durationMs: 0 }]),
      op('memory_restore', 'agent', 'a', '2026-10-19T06:00:00Z', 'done', [{ name: 'set_memory_access', agentId: 'a', status: 'done', durationMs: 1 }]),
    ];
    // a: cut then restored. b: cut by the team kill. c: its step failed. d: failed op. e: restore skipped, still cut.
    expect([...memoryQuarantined(ops, agents)].sort()).toEqual(['b', 'e']);
  });

  it('prefers the per-agent memory access when the server reports it', () => {
    expect(quarantinedFromAgents([agent('a'), agent('b')])).toBeNull();
    const set = quarantinedFromAgents([agent('a', { memoryAccess: 'full' }), agent('b', { memoryAccess: 'staging_only' }), agent('c', { memoryAccess: 'none' })]);
    expect([...(set ?? [])].sort()).toEqual(['b', 'c']);
  });

  it('builds the incident chain from the same agent, oldest first, ending with the red decision', () => {
    const latest = action('red', '2026-10-19T10:05:00Z', { class: 'red', verb: 'SEND' });
    const history = [
      latest,
      action('later', '2026-10-19T10:06:00Z'),
      action('h2', '2026-10-19T10:04:00Z'),
      action('h1', '2026-10-19T10:03:00Z'),
      action('other', '2026-10-19T10:04:30Z', { agentId: 'someone-else' }),
    ];
    expect(incidentChain(latest, history).map((a) => a.actionId)).toEqual(['h1', 'h2', 'red']);
    expect(incidentChain(latest, history, 1).map((a) => a.actionId)).toEqual(['h2', 'red']);
  });

  it("selects the user's pick, else the incident's agent, else the riskiest", () => {
    const agents = [agent('a'), agent('b', { worstClass24h: 'red' }), agent('c')];
    expect(pickSelected(agents, 'c', 'a')?.agentId).toBe('c');
    expect(pickSelected(agents, 'gone', 'a')?.agentId).toBe('a');
    expect(pickSelected(agents, null, null)?.agentId).toBe('b');
    expect(pickSelected([], null, null)).toBeNull();
  });
});
