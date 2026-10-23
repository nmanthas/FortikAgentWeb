import { describe, expect, it } from 'vitest';
import { toastFor } from './LiveToasts';

describe('toastFor', () => {
  it('toasts red decisions with rule and reason', () => {
    const t = toastFor({ seq: 1, ts: '', agentId: 'bot', eventType: 'action.decided', data: { class: 'red', decision: 'hold', system: 'aws', verb: 'DELETE', rule_id: 'POL-402', reason: 'not undoable' } });
    expect(t).toMatchObject({ tone: 'red', title: 'Dangerous action hold: bot' });
    expect(t!.body).toContain('POL-402');
  });

  it('ignores green and yellow decisions and unrelated events', () => {
    expect(toastFor({ seq: 1, ts: '', eventType: 'action.decided', data: { class: 'yellow' } })).toBeNull();
    expect(toastFor({ seq: 1, ts: '', eventType: 'integration.tested', data: {} })).toBeNull();
  });

  it('toasts level changes, red for kill', () => {
    expect(toastFor({ seq: 2, ts: '', agentId: 'bot', eventType: 'agent.level_changed', data: { from: 'FULL', to: 'KILLED', direction: 'down', reason: 'incident' } })).toMatchObject({
      tone: 'red',
      title: 'bot: FULL → KILLED',
      body: 'incident',
    });
    expect(toastFor({ seq: 3, ts: '', agentId: 'bot', eventType: 'agent.level_changed', data: { from: 'FULL', to: 'SUPERVISED', automatic: true, rule_id: 'LADDER-3Y' } })!.title).toContain('(automatic)');
  });

  it('toasts newly raised alerts by severity, never repeats', () => {
    expect(toastFor({ seq: 4, ts: '', agentId: 'coder', eventType: 'alert.raised', data: { kind: 'spawn_spike', severity: 'high', summary: '40 spawns in a minute' } })).toEqual({
      tone: 'red',
      title: 'Alert (high): spawn spike · coder',
      body: '40 spawns in a minute',
    });
    expect(toastFor({ seq: 5, ts: '', eventType: 'alert.raised', data: { kind: 'rate_limited', severity: 'warning' } })!.tone).toBe('amber');
    expect(toastFor({ seq: 6, ts: '', eventType: 'alert.raised', data: { kind: 'override_restored', severity: 'info' } })!.tone).toBe('info');
    expect(toastFor({ seq: 7, ts: '', eventType: 'alert.repeated', data: { kind: 'spawn_spike', severity: 'high' } })).toBeNull();
  });
});
