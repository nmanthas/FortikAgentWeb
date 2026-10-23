import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi } from '../test/fakeApi';
import { renderWithApp } from '../test/render';
import { DelegationsTab } from './DelegationsTab';

afterEach(() => {
  vi.unstubAllGlobals();
});

const endpoint = {
  agent_id: 'researcher',
  hops: [
    { delegation_id: 'dlg_1', root_agent: 'planner', from_agent: 'planner', to_agent: 'researcher', chain: ['planner', 'researcher'], depth: 1, channel: 'a2a', status: 'open', created_at: new Date().toISOString() },
    { delegation_id: 'dlg_2', root_agent: 'planner', from_agent: 'researcher', to_agent: 'db-bot', chain: ['planner', 'researcher', 'db-bot'], depth: 2, channel: 'a2a', status: 'closed', created_at: new Date().toISOString() },
  ],
  blocked: [
    {
      action_id: 'act_x',
      ts: new Date().toISOString(),
      executor: 'db-bot',
      system: 'postgres',
      verb: 'DELETE',
      rule_id: 'POL-601',
      reason: 'delegation bypass: originating agent planner (hop 1 of 2) may not DELETE',
      delegation: { root: 'planner', chain: [{ agent_id: 'planner' }, { agent_id: 'researcher' }] },
    },
  ],
};

const diaryBypass = {
  seq: 7,
  ts: new Date().toISOString(),
  agent_id: 'planner',
  event_type: 'delegation.bypass_blocked',
  body: { data: { action_id: 'act_x', executor: 'db-bot', root: 'planner', chain: ['planner', 'researcher'], stepped_down: ['planner'], origin_level: 'SUPERVISED' } },
};

describe('DelegationsTab', () => {
  it('draws chains and highlights blocked bypass attempts from the endpoint and Diary', async () => {
    const { calls } = installFakeApi({
      'GET /v1/agents/researcher/delegations': endpoint,
      'GET /v1/diary': { entries: [diaryBypass, { seq: 8, ts: '', event_type: 'action.decided', body: { data: {} } }] },
    });
    renderWithApp(<DelegationsTab agentId="researcher" />);
    const bypass = await screen.findByTestId('bypass-item');
    expect(within(bypass).getByText(/bypass blocked/)).toBeTruthy();
    expect(within(bypass).getByTestId('delegation-chain').getAttribute('aria-label')).toBe('chain planner → researcher → db-bot, blocked');
    expect(within(bypass).getByText(/Originating agent planner stepped down to SUPERVISED/)).toBeTruthy();

    const inbound = screen.getAllByTestId('hop-inbound');
    expect(inbound).toHaveLength(1);
    expect(within(inbound[0]!).getByTestId('delegation-chain').getAttribute('aria-label')).toBe('chain planner → researcher, open');
    expect(within(screen.getByTestId('hop-outbound')).getByTestId('delegation-chain').getAttribute('aria-label')).toBe('chain planner → researcher → db-bot, closed');
    expect(screen.queryByText(/no delegations endpoint/)).toBeNull();
    expect(calls[0]!.path).toBe('/v1/agents/researcher/delegations?direction=all&limit=200');
  });

  it('still renders for an owner who may not read the Diary', async () => {
    installFakeApi({
      'GET /v1/agents/researcher/delegations': endpoint,
      'GET /v1/diary': { status: 403, body: { error: 'auditor role required' } },
    });
    renderWithApp(<DelegationsTab agentId="researcher" />);
    const bypass = await screen.findByTestId('bypass-item');
    expect(within(bypass).queryByText(/stepped down/)).toBeNull();
  });

  it('falls back to the Diary when the server has no delegations endpoint', async () => {
    installFakeApi({
      'GET /v1/diary': {
        entries: [
          { seq: 1, ts: new Date().toISOString(), agent_id: 'planner', event_type: 'delegation.opened', body: { data: { delegation_id: 'dlg_1', chain: ['planner', 'researcher'], from: 'planner', to: 'researcher', depth: 1, channel: 'a2a' } } },
          diaryBypass,
        ],
      },
    });
    renderWithApp(<DelegationsTab agentId="researcher" />);
    expect(await screen.findByTestId('bypass-item')).toBeTruthy();
    expect(screen.getAllByTestId('hop-inbound')).toHaveLength(1);
    expect(screen.getByText(/no delegations endpoint/)).toBeTruthy();
  });
});
