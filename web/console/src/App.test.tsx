import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCsrf } from './api/client';
import { App } from './App';
import { installFakeApi } from './test/fakeApi';

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrf('');
});

const me = { kind: 'user', email: 'sec@example.com', name: 'Sec', roles: ['auditor', 'security'], auth_method: 'dev', csrf: 'csrf-abc', dev_login_enabled: true, oidc_enabled: false };

const agentsRoutes = {
  'GET /v1/agents': {
    agents: [
      { agent_id: 'billing-bot', type: 'support', sponsor: 'owner@example.com', level_name: 'FULL', actions_today: 12, worst_class_24h: 'red', systems_24h: ['gmail'], held_pending: 1 },
      { agent_id: 'ops-bot', type: 'ops', sponsor: '', level_name: 'READ_ONLY', actions_today: 0, worst_class_24h: null, systems_24h: [], held_pending: 0 },
    ],
  },
  'GET /v1/stats/summary': { agents_total: 2, actions_today: 12, held_pending: 1, red_today: 3, agents_not_full: 1, by_class_today: { green: 9, red: 3 } },
  'GET /v1/held': { held: [] },
};

describe('App', () => {
  it('shows the login screen on 401 and signs in with dev login', async () => {
    let loggedIn = false;
    const { calls } = installFakeApi({
      'GET /v1/me': () => (loggedIn ? { body: me } : { status: 401, body: { error: 'authentication required' } }),
      'GET /auth/config': { oidc_enabled: false, dev_login_enabled: true, dev_users: [{ email: 'sec@example.com', roles: ['security'] }] },
      'POST /auth/dev-login': () => {
        loggedIn = true;
        return { body: { ok: true } };
      },
      ...agentsRoutes,
    });
    render(
      <MemoryRouter initialEntries={['/agents']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <App />
      </MemoryRouter>,
    );
    expect(await screen.findByText('Sign in to the Fortik console')).toBeTruthy();
    expect(screen.queryByText(/single sign-on/)).toBeNull();
    fireEvent.click(await screen.findByRole('button', { name: /sec@example.com/ }));
    fireEvent.click(screen.getByRole('button', { name: 'Dev login' }));

    expect(await screen.findByText('DEV LOGIN — not for production use')).toBeTruthy();
    expect(calls.find((c) => c.path === '/auth/dev-login')!.body).toEqual({ email: 'sec@example.com' });
    const chip = screen.getByTestId('user-chip');
    expect(within(chip).getByText('sec@example.com')).toBeTruthy();
    expect(within(chip).getByText('auditor, security')).toBeTruthy();
    expect(await screen.findByText('billing-bot')).toBeTruthy();
    expect(within(screen.getByTestId('kpis')).getByText('Dangerous today')).toBeTruthy();
  });

  it('filters the agent table and sends CSRF on writes', async () => {
    const { calls } = installFakeApi({
      'GET /v1/me': me,
      ...agentsRoutes,
      'POST /v1/agents': (req: { body: unknown }) => ({ status: 201, body: { agent: { agent_id: (req.body as { agent_id: string }).agent_id, level_name: 'FULL' } } }),
      'GET /v1/agents/new-bot': { agent: { agent_id: 'new-bot', level_name: 'FULL' }, counts_24h: {}, held: [] },
      'GET /v1/agents/new-bot/stats': { hours: 24, by_class: {}, by_verb: {}, hourly: [] },
      'GET /v1/actions': { actions: [] },
    });
    render(
      <MemoryRouter initialEntries={['/agents']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <App />
      </MemoryRouter>,
    );
    expect(await screen.findByText('ops-bot')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Filter by risk'), { target: { value: 'red' } });
    expect(screen.queryByText('ops-bot')).toBeNull();
    expect(screen.getByText('billing-bot')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('Filter by risk'), { target: { value: 'all' } });
    fireEvent.change(screen.getByLabelText('Search agents'), { target: { value: 'ops' } });
    expect(screen.queryByText('billing-bot')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /Register agent/ }));
    fireEvent.change(screen.getByLabelText(/Agent ID/), { target: { value: 'new-bot' } });
    fireEvent.click(screen.getByRole('button', { name: 'Register' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST' && c.path === '/v1/agents')).toBe(true));
    const post = calls.find((c) => c.method === 'POST' && c.path === '/v1/agents')!;
    expect(post.headers['x-fortik-csrf']).toBe('csrf-abc');
    expect(post.body).toMatchObject({ agent_id: 'new-bot', copy_cap: 1 });
    expect(await screen.findByRole('dialog', { name: 'Agent new-bot' })).toBeTruthy();
  });

  it('disables level changes for an auditor with an explanation', async () => {
    installFakeApi({
      'GET /v1/me': { ...me, roles: ['auditor'], auth_method: 'oidc' },
      ...agentsRoutes,
      'GET /v1/agents/billing-bot': { agent: { agent_id: 'billing-bot', level_name: 'SUPERVISED', sponsor: 'owner@example.com' }, counts_24h: { green: 1 }, held: [] },
      'GET /v1/agents/billing-bot/stats': { hours: 24, by_class: { green: 1 }, by_verb: { SEND: 1 }, hourly: [] },
      'GET /v1/actions': { actions: [] },
    });
    render(
      <MemoryRouter initialEntries={['/agents/billing-bot']} future={{ v7_startTransition: true, v7_relativeSplatPath: true }}>
        <App />
      </MemoryRouter>,
    );
    const panel = await screen.findByRole('dialog', { name: 'Agent billing-bot' });
    expect(screen.queryByText(/DEV LOGIN/)).toBeNull();
    fireEvent.click(within(panel).getByRole('tab', { name: 'Level' }));
    expect((within(panel).getByRole('button', { name: 'Kill agent' }) as HTMLButtonElement).disabled).toBe(true);
    expect((within(panel).getByRole('button', { name: /Step up to FULL/ }) as HTMLButtonElement).disabled).toBe(true);
    expect(within(panel).getByText('Killing an agent requires the security role.')).toBeTruthy();
    fireEvent.click(within(panel).getByRole('tab', { name: 'Tokens' }));
    expect((within(panel).getByRole('button', { name: 'Issue token' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
