import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { setCsrf } from '../api/client';
import { App } from '../App';
import { installFakeApi, type Recorded } from '../test/fakeApi';
import { FakeEventSource } from '../test/fakeEventSource';

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrf('');
});

const me = { kind: 'user', email: 'sec@example.com', name: 'Sec', roles: ['auditor', 'security'], auth_method: 'oidc', csrf: 'csrf-abc', dev_login_enabled: false, oidc_enabled: true };
const auditor = { ...me, email: 'aud@example.com', roles: ['auditor'] };

const now = new Date().toISOString();
const alert = (id: string, severity: string, kind: string, extra: Record<string, unknown> = {}) => ({
  alert_id: id,
  kind,
  severity,
  agent_id: 'billing-bot',
  summary: `${kind} summary`,
  details: { secret_looking: 'never shown' },
  count: 1,
  status: 'open',
  created_at: now,
  updated_at: now,
  ...extra,
});

function renderAt(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
      <App />
    </MemoryRouter>,
  );
}

describe('Alerts page', () => {
  it('groups open alerts by severity, acknowledges and resolves them', async () => {
    let open = [
      alert('al_1', 'warning', 'rate_limited'),
      alert('al_2', 'high', 'delegation_bypass', { count: 3 }),
      alert('al_3', 'critical', 'spawn_spike', { agent_id: undefined, agent_type: 'support' }),
      alert('al_4', 'high', 'copy_cap'),
    ];
    const { calls } = installFakeApi({
      'GET /v1/me': me,
      'GET /v1/alerts': (req: Recorded) => ({ body: { alerts: req.path.includes('status=open') ? open : [] } }),
      'POST /v1/alerts/al_2/ack': () => {
        open = open.map((a) => (a.alert_id === 'al_2' ? { ...a, status: 'acknowledged', acked_by: 'user:sec@example.com' } : a));
        return { body: open.find((a) => a.alert_id === 'al_2') };
      },
      'POST /v1/alerts/al_1/resolve': () => {
        open = open.filter((a) => a.alert_id !== 'al_1');
        return { body: { ...alert('al_1', 'warning', 'rate_limited'), status: 'resolved' } };
      },
    });
    renderAt('/alerts');

    const groups = await screen.findAllByTestId(/^severity-/);
    expect(groups.map((g) => g.getAttribute('data-testid'))).toEqual(['severity-critical', 'severity-high', 'severity-warning']);
    expect(within(screen.getByTestId('severity-high')).getAllByTestId('alert-item')).toHaveLength(2);
    expect(within(screen.getByTestId('severity-high')).getByText('×3')).toBeTruthy();
    expect(within(screen.getByTestId('severity-critical')).getByText('type support')).toBeTruthy();
    expect(screen.queryByText(/never shown/)).toBeNull();

    // Nav badge with the open count.
    expect((await screen.findByTestId('alerts-badge')).textContent).toBe('4');
    expect(screen.getByRole('link', { name: /Alerts/ })).toBeTruthy();
    expect(screen.getByRole('link', { name: /Approvals/ })).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Acknowledge delegation_bypass summary' }));
    await waitFor(() => expect(calls.some((c) => c.path === '/v1/alerts/al_2/ack')).toBe(true));
    const ack = calls.find((c) => c.path === '/v1/alerts/al_2/ack')!;
    expect(ack.method).toBe('POST');
    expect(ack.headers['x-fortik-csrf']).toBe('csrf-abc');
    expect(await screen.findByText('acknowledged by user:sec@example.com')).toBeTruthy();
    expect(screen.queryByRole('button', { name: 'Acknowledge delegation_bypass summary' })).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: 'Resolve rate_limited summary' }));
    await waitFor(() => expect(screen.queryByTestId('severity-warning')).toBeNull());
    await waitFor(() => expect(screen.getByTestId('alerts-badge').textContent).toBe('3'));
  });

  it('toasts a live alert.raised event and refreshes the badge', async () => {
    let open = [alert('al_1', 'warning', 'rate_limited')];
    installFakeApi({
      'GET /v1/me': me,
      'GET /v1/agents': { agents: [] },
      'GET /v1/stats/summary': { agents_total: 0, actions_today: 0, held_pending: 0, red_today: 0, agents_not_full: 0 },
      'GET /v1/held': { held: [] },
      'GET /v1/alerts': () => ({ body: { alerts: open } }),
    });
    renderAt('/agents');
    expect((await screen.findByTestId('alerts-badge')).textContent).toBe('1');

    open = [...open, alert('al_9', 'high', 'delegation_bypass')];
    vi.useFakeTimers({ shouldAdvanceTime: true });
    try {
      act(() => {
        FakeEventSource.latest().emit({
          event_type: 'alert.raised',
          agent_id: 'intern-bot',
          data: { alert_id: 'al_9', kind: 'delegation_bypass', severity: 'high', summary: 'delegation bypass blocked: db-bot acted for [intern-bot]' },
        });
      });
      expect(await screen.findByText('Alert (high): delegation bypass · intern-bot')).toBeTruthy();
      expect(screen.getByText('delegation bypass blocked: db-bot acted for [intern-bot]')).toBeTruthy();
      await act(async () => {
        await vi.advanceTimersByTimeAsync(1100);
      });
    } finally {
      vi.useRealTimers();
    }
    await waitFor(() => expect(screen.getByTestId('alerts-badge').textContent).toBe('2'));
  });

  it('explains that an auditor cannot change alerts', async () => {
    installFakeApi({ 'GET /v1/me': auditor, 'GET /v1/alerts': { alerts: [alert('al_1', 'info', 'override_restored')] } });
    renderAt('/alerts');
    expect(await screen.findByText(/requires the security role/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Resolve override_restored summary' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('shows an empty state', async () => {
    installFakeApi({ 'GET /v1/me': me, 'GET /v1/alerts': { alerts: [] } });
    renderAt('/alerts');
    expect(await screen.findByText('No open alerts.')).toBeTruthy();
    expect(screen.queryByTestId('alerts-badge')).toBeNull();
  });
});
