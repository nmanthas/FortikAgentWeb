import { describe, expect, it } from 'vitest';
import { formatSafeForm, normAgentDetail, normAgents, normIntegration, normStats, normSummary, parseClass, parseDiaryEvent, parseLevel, statsFromActions } from './normalize';
import type { ActionRow } from './types';

describe('normalisers', () => {
  it('fails closed on unknown levels and classes', () => {
    expect(parseLevel('read-only')).toBe('READ_ONLY');
    expect(parseLevel(2)).toBe('READ_ONLY');
    expect(parseLevel('GODMODE')).toBe('KILLED');
    expect(parseClass('purple')).toBe('red');
    expect(parseClass('amber')).toBe('yellow');
  });

  it('reads the server agent view', () => {
    const [a] = normAgents({
      agents: [{ agent_id: 'bot', level: 1, level_name: 'SUPERVISED', actions_today: 4, worst_class_24h: 'yellow', systems_24h: ['gmail'], held_pending: 2, sponsor: 'o@x.com' }],
    });
    expect(a).toMatchObject({ agentId: 'bot', level: 'SUPERVISED', actionsToday: 4, worstClass24h: 'yellow', systems24h: ['gmail'], heldPending: 2 });
    expect(normAgents({ agents: [{ agent_id: 'idle', worst_class_24h: null }] })[0]!.worstClass24h).toBeNull();
  });

  it('reads who imposed a suspension and a memory cut (D2)', () => {
    const [a] = normAgents({
      agents: [
        {
          agent_id: 'bot',
          suspended: true,
          suspended_at: '2026-10-19T10:00:00Z',
          suspended_by: 'user:sec@example.com',
          suspended_reason: 'line one\nline two',
          memory_access: 'none',
          memory_access_changed_by: 'estop:cop_1',
        },
      ],
    });
    expect(a).toMatchObject({
      suspended: true,
      suspendedBy: 'user:sec@example.com',
      suspendedReason: 'line one\nline two',
      memoryAccess: 'none',
      memoryAccessChangedBy: 'estop:cop_1',
    });
    expect(normAgents({ agents: [{ agent_id: 'old' }] })[0]!.memoryAccessChangedBy).toBeUndefined();
  });

  it('reads GET /v1/agents/{id}', () => {
    const d = normAgentDetail({
      agent: { agent_id: 'bot', level_name: 'FULL' },
      counts_24h: { green: 3, yellow: 1, red: 0 },
      held: [{ action_id: 'h1', rule_id: 'POL-7', class: 'yellow', verb: 'delete' }],
      access_profiles: { gmail: { version: 3, changed_by: 'user:a' }, bogus: { version: 1 } },
      integrations: { github: 'ok' },
      token_issued: true,
    });
    expect(d.agent.agentId).toBe('bot');
    expect(d.counts24h).toEqual({ green: 3, blue: 0, yellow: 1, red: 0 });
    expect(d.held[0]).toMatchObject({ actionId: 'h1', agentId: 'bot', verb: 'DELETE' });
    expect(d.profileVersions).toEqual({ gmail: 3 });
    expect(d.tokenIssued).toBe(true);
    expect(normAgentDetail({ agent: { agent_id: 'x' } }).tokenIssued).toBeNull();
  });

  it('reads stats with hourly buckets', () => {
    const s = normStats(
      {
        hours: 3,
        by_class: { green: 2, red: 1 },
        by_verb: { send: 3 },
        hourly: [
          { hour: '2026-10-09T10:00:00Z', count: 0, worst_class: '' },
          { hour: '2026-10-09T11:00:00Z', count: 2, worst_class: 'green' },
          { hour: '2026-10-09T12:00:00Z', count: 1, worst_class: 'red' },
        ],
      },
      24,
    )!;
    expect(s.hours).toBe(3);
    expect(s.hourly).toEqual([0, 2, 1]);
    expect(s.hourlyWorst).toEqual([null, 'green', 'red']);
    expect(s.hourStarts).toHaveLength(3);
    expect(s.byVerb).toEqual({ SEND: 3 });
    expect(s.total).toBe(3);
    expect(normStats({}, 24)).toBeNull();
  });

  it('aggregates stats from actions as a fallback', () => {
    const now = Date.parse('2026-10-09T12:30:00Z');
    const mk = (ts: string, cls: ActionRow['class']): ActionRow => ({
      actionId: ts, agentId: 'a', system: 'gmail', verb: 'SEND', class: cls, decision: 'allow', ruleId: '', reason: '', reversible: false, source: '', ts, failClosed: false, held: false,
    });
    const s = statsFromActions([mk('2026-10-09T12:10:00Z', 'green'), mk('2026-10-09T12:20:00Z', 'red'), mk('2026-10-01T00:00:00Z', 'red')], 2, now);
    expect(s.total).toBe(2);
    expect(s.hourly).toEqual([0, 2]);
    expect(s.hourlyWorst).toEqual([null, 'red']);
  });

  it('reads the summary and integrations', () => {
    expect(normSummary({ agents_total: 5, actions_today: 9, held_pending: 1, red_today: 2, agents_not_full: 3, by_class_today: { green: 7, red: 2 } })).toMatchObject({
      totalAgents: 5,
      redToday: 2,
      byClassToday: { green: 7, blue: 0, yellow: 0, red: 2 },
    });
    const i = normIntegration({ key: 'github', system: 'github', config: { app_id: '1' }, secret_fields: ['private_key_pem'], secrets: { private_key_pem: { set: true } }, status: 'weird' });
    expect(i.status).toBe('error');
    expect(i.secrets.private_key_pem).toEqual({ set: true });
  });

  it('formats safe forms and parses SSE events', () => {
    expect(formatSafeForm({ kind: 'pg_rename', sql: 'ALTER TABLE t RENAME TO x' })).toBe('pg_rename: ALTER TABLE t RENAME TO x');
    expect(formatSafeForm(null)).toBe('');
    expect(parseDiaryEvent('{"seq":4,"ts":"t","agent_id":"a","event_type":"action.decided","data":{"class":"red"}}')).toMatchObject({ seq: 4, agentId: 'a', data: { class: 'red' } });
    expect(parseDiaryEvent('not json')).toBeNull();
    expect(parseDiaryEvent('{"seq":1}')).toBeNull();
  });
});
