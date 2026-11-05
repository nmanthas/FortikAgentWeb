import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { fmtMetric, normConnector, normEnforcement, normObserved, normPilotMetrics } from '../api/phase6';
import { normAction } from '../api/normalize';
import { DecisionChip } from '../components/Chips';
import { ObserveBanner, observeText } from '../components/ObserveBanner';
import { PilotMetricsCard } from '../components/PilotMetrics';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp, securityMe } from '../test/render';
import { EnforcementCard } from './AgentPanel';
import { ConnectorsPage } from './Connectors';

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('Phase 6 normalisers', () => {
  it('reads enforcement, observed decisions, metrics and connectors defensively', () => {
    expect(normEnforcement({ mode: 'observe', observe_agents: ['a'], enforce_agents: [1, 'b'] })).toEqual({ mode: 'observe', observeAgents: ['a'], enforceAgents: ['b'] });
    expect(normEnforcement(null).mode).toBe('enforce');
    expect(normObserved({ decision: 'hold', rule_id: 'POL-101', reason: 'r', ladder_change: { to: 'READ_ONLY' } })).toEqual({
      decision: 'hold',
      ruleId: 'POL-101',
      reason: 'r',
      ladderTo: 'READ_ONLY',
    });
    expect(normObserved({})).toBeNull();
    const a = normAction({ action_id: 'a1', decision: 'allow', class: 'red', decision_json: { observed: { decision: 'hold', rule_id: 'POL-101', reason: 'x' } } });
    expect(a.observed?.decision).toBe('hold');
    const m = normPilotMetrics({ risky_handled_without_kill: { value: 97.5, unit: '%', target: '>= 95%', met: true, n: 40 }, green_overhead_p95: { value: 2.37, unit: 'ms', met: true } });
    expect(m.metrics).toHaveLength(5);
    expect(fmtMetric(m.metrics[0]!)).toBe('97.5%');
    expect(fmtMetric(m.metrics[4]!)).toBe('2.4 ms');
    expect(m.metrics[1]!.value).toBeNull();
    expect(normConnector({ connector_id: 'con_1', scopes: ['a', 2], active_grants: 3 }).scopes).toEqual(['a']);
  });

  it('banner text: deployment observe, a few agents observed, or nothing', () => {
    expect(observeText(null)).toBeNull();
    expect(observeText({ mode: 'enforce', observeAgents: [], enforceAgents: [] })).toBeNull();
    expect(observeText({ mode: 'observe', observeAgents: [], enforceAgents: ['x'] })).toMatch(/^OBSERVE MODE .*except 1 agent set to enforce/);
    expect(observeText({ mode: 'enforce', observeAgents: ['a', 'b'], enforceAgents: [] })).toMatch(/^2 agents are in observe mode/);
  });

  it('shows the would-be decision next to the enforced one', () => {
    render(<DecisionChip decision="allow" observed={{ decision: 'hold', ruleId: 'POL-101', reason: 'r' }} />);
    expect(screen.getByTestId('observed-chip').textContent).toBe('observe: would hold');
  });
});

describe('Observe banner', () => {
  it('appears when the deployment observes, not when the server has no observe mode', async () => {
    installFakeApi({ 'GET /v1/enforcement': { mode: 'observe', observe_agents: [], enforce_agents: [] } });
    renderWithApp(<ObserveBanner />);
    expect((await screen.findByTestId('observe-banner')).textContent).toMatch(/OBSERVE MODE/);
    vi.unstubAllGlobals();
    installFakeApi({});
    const { container } = renderWithApp(<ObserveBanner />);
    await new Promise((r) => setTimeout(r, 30));
    expect(container.querySelector('[data-testid="observe-banner"]')).toBeNull();
  });
});

describe('Pilot metrics card', () => {
  it('shows each target with met / not met / no data', async () => {
    installFakeApi({
      'GET /v1/metrics/pilot': {
        decisions: 1200,
        observed_decisions: 300,
        risky_handled_without_kill: { value: 98, unit: '%', target: '>= 95%', met: true, n: 50 },
        red_false_alarm_rate: { value: 5, unit: '%', target: '< 2%', met: false, n: 20 },
        red_to_step_down_p50: { value: null, unit: 'ms', target: '< 1000 ms', met: null, n: 0 },
        undo_success: { value: 100, unit: '%', target: '100%', met: true, n: 3 },
        green_overhead_p95: { value: 2.4, unit: 'ms', target: '< 50 ms', met: true, n: 900 },
      },
    });
    renderWithApp(<PilotMetricsCard />);
    const card = await screen.findByTestId('pilot-metrics');
    expect(within(card).getAllByTestId('pilot-metric')).toHaveLength(5);
    expect(within(card).getAllByText('met')).toHaveLength(3);
    expect(within(card).getByText('not met')).toBeTruthy();
    expect(within(card).getByText('no data', { selector: '.chip' })).toBeTruthy();
    expect(card.textContent).toMatch(/300 recorded in observe mode/);
  });
});

describe('Copilot connectors', () => {
  const conn = { connector_id: 'con_1', agent_id: 'copilot_chatgpt', vendor: 'chatgpt', upstream: 'google_workspace', client_id: 'fortik-abc', redirect_uris: ['https://chat.example/cb'], scopes: ['https://www.googleapis.com/auth/gmail.readonly'], status: 'active', active_grants: 2, created_at: new Date().toISOString() };

  it('lists connectors, registers one (secret shown once) and disables one', async () => {
    const { calls } = installFakeApi({
      'GET /v1/connectors': { connectors: [conn], callback_url: 'https://fortik.test/oauth/callback' },
      'POST /v1/connectors': { connector: { ...conn, connector_id: 'con_2', client_id: 'fortik-new' }, client_secret: 'fcs_secret_once', authorize_url: 'https://fortik.test/oauth/authorize', token_url: 'https://fortik.test/oauth/token' },
      'POST /v1/connectors/con_1/disable': { connector_id: 'con_1', status: 'disabled', grants: { cgr_1: 'upstream grant revoked', cgr_2: 'upstream grant revoked' } },
    });
    renderWithApp(<ConnectorsPage />, securityMe);
    const rows = await screen.findAllByTestId('connector-row');
    expect(rows).toHaveLength(1);
    expect(screen.getByText(/https:\/\/fortik.test\/oauth\/callback/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Register connector' }));
    const dialog = screen.getByRole('dialog');
    const submit = within(dialog).getByRole('button', { name: 'Register' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    for (const [label, v] of [
      ['Agent id', 'copilot_new'],
      ['Sponsor (owner email)', 'it@acme.test'],
      ["Vendor's redirect URI(s)", 'https://chat.example/cb'],
      ['Scopes', 'https://www.googleapis.com/auth/gmail.readonly'],
      ['Reason', 'pilot'],
    ]) {
      fireEvent.change(within(dialog).getByLabelText(label!), { target: { value: v } });
    }
    fireEvent.click(submit);
    expect((await screen.findByTestId('connector-secret')).textContent).toBe('fcs_secret_once');
    expect(calls.find((c) => c.path === '/v1/connectors' && c.method === 'POST')!.body).toMatchObject({ agent_id: 'copilot_new', redirect_uris: ['https://chat.example/cb'] });
    fireEvent.click(screen.getByRole('button', { name: 'Done' }));

    fireEvent.click(screen.getByRole('button', { name: 'Disable copilot_chatgpt' }));
    fireEvent.change(within(screen.getByRole('dialog')).getByLabelText('Reason'), { target: { value: 'vendor offboarded' } });
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Disable' }));
    expect(await screen.findByText('2 grant(s) revoked upstream')).toBeTruthy();
  });

  it('is read-only for auditors and explains when the broker is off', async () => {
    installFakeApi({ 'GET /v1/connectors': { connectors: [conn] } });
    renderWithApp(<ConnectorsPage />, auditorMe);
    await screen.findAllByTestId('connector-row');
    expect((screen.getByRole('button', { name: 'Register connector' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Disable copilot_chatgpt' }) as HTMLButtonElement).disabled).toBe(true);
    vi.unstubAllGlobals();
    installFakeApi({});
    renderWithApp(<ConnectorsPage />, securityMe);
    expect(await screen.findByTestId('connectors-off')).toBeTruthy();
  });
});

describe('Agent enforcement control', () => {
  it('security switches an agent to observe mode with a reason', async () => {
    const { calls } = installFakeApi({ 'PUT /v1/agents/bot/enforcement': { agent_id: 'bot', enforcement: 'observe', effective_enforcement: 'observe' } });
    const onChanged = vi.fn();
    renderWithApp(<EnforcementCard agentId="bot" enforcement="default" effective="enforce" onChanged={onChanged} />, securityMe);
    const card = screen.getByTestId('enforcement-card');
    expect(card.textContent).toMatch(/Now: enforced \(deployment default\)/);
    fireEvent.change(within(card).getByLabelText('Enforcement mode'), { target: { value: 'observe' } });
    fireEvent.change(within(card).getByLabelText('Enforcement reason'), { target: { value: 'pilot week 1' } });
    fireEvent.click(within(card).getByRole('button', { name: 'Apply' }));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({ mode: 'observe', reason: 'pilot week 1' });
  });

  it('is disabled for auditors and hidden on a server without observe mode', () => {
    renderWithApp(<EnforcementCard agentId="bot" enforcement="observe" effective="observe" onChanged={() => undefined} />, auditorMe);
    expect((screen.getByLabelText('Enforcement mode') as HTMLSelectElement).disabled).toBe(true);
    const { container } = renderWithApp(<EnforcementCard agentId="bot" onChanged={() => undefined} />, securityMe);
    expect(container.querySelector('[data-testid="enforcement-card"]')).toBeNull();
  });
});
