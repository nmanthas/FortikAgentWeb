import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Agent, Override } from '../api/types';
import { overridePermissions } from '../lib/permissions';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, ownerMe, renderWithApp, securityMe } from '../test/render';
import { SuspensionsTab } from './SuspensionsTab';

afterEach(() => {
  vi.unstubAllGlobals();
});

const agent: Agent = {
  agentId: 'billing-bot',
  name: 'Billing',
  type: 'support',
  platform: 'test',
  sponsor: 'owner@example.com',
  businessUnit: 'Ops',
  workspaceUser: '',
  copyCap: 2,
  level: 'FULL',
  discovered: false,
};

const inOneHour = () => new Date(Date.now() + 3600_000).toISOString();

const activeRaw = (extra: Record<string, unknown> = {}) => ({
  override_id: 'ovr_1',
  scope: 'agent',
  scope_id: 'billing-bot',
  system: 'github',
  mode: 'suspended',
  starts_at: new Date().toISOString(),
  expires_at: inOneHour(),
  restore_profile_version: 0,
  reason: 'incident',
  created_by: 'user:sec@example.com',
  status: 'active',
  revoke_result: { github: { 'billing-bot': 'installation token deleted' } },
  ...extra,
});

describe('SuspensionsTab', () => {
  it('creates a suspension with the chosen app, mode and preset', async () => {
    let created = false;
    const { calls } = installFakeApi({
      'GET /v1/overrides': () => ({ body: { overrides: created ? [activeRaw({ system: 'aws', mode: 'read_only' })] : [] } }),
      'POST /v1/overrides': () => {
        created = true;
        return { status: 201, body: activeRaw({ system: 'aws', mode: 'read_only' }) };
      },
    });
    renderWithApp(<SuspensionsTab agent={agent} />);
    expect(await screen.findByText('No app is suspended for this agent.')).toBeTruthy();
    expect(calls[0]!.path).toBe('/v1/overrides?agent_id=billing-bot');

    fireEvent.click(screen.getByRole('button', { name: 'Suspend an app' }));
    const dialog = screen.getByRole('dialog');
    const app = within(dialog).getByLabelText('App') as HTMLSelectElement;
    expect([...app.options].map((o) => o.value)).toEqual(['gmail', 'drive', 'github', 'aws', 'postgres']);
    fireEvent.change(app, { target: { value: 'aws' } });
    fireEvent.change(within(dialog).getByLabelText('Mode'), { target: { value: 'read_only' } });
    const presets = within(within(dialog).getByRole('group', { name: 'Duration' })).getAllByRole('button');
    expect(presets.map((b) => b.textContent)).toEqual(['15m', '30m', '1h', '4h', 'Until released']);
    fireEvent.click(within(dialog).getByRole('button', { name: '30m' }));
    const suspend = within(dialog).getByRole('button', { name: /Suspend/ }) as HTMLButtonElement;
    expect(suspend.disabled).toBe(true); // reason required
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'cost spike' } });
    fireEvent.click(suspend);

    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({
      scope: 'agent',
      scope_id: 'billing-bot',
      system: 'aws',
      mode: 'read_only',
      duration_seconds: 1800,
      reason: 'cost spike',
    });
    expect(await screen.findByTestId('suspension-chip')).toBeTruthy();
    expect(screen.getByTestId('suspension-chip').textContent).toContain('AWS read-only · restores at');
  });

  it('sends until_released for the open-ended preset', async () => {
    const { calls } = installFakeApi({
      'GET /v1/overrides': { overrides: [] },
      'POST /v1/overrides': { status: 201, body: activeRaw({ expires_at: undefined }) },
    });
    renderWithApp(<SuspensionsTab agent={agent} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Suspend an app' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Until released' }));
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'investigating' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /Suspend/ }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')!.body).toMatchObject({ system: 'github', mode: 'suspended', until_released: true });
    expect(calls.find((c) => c.method === 'POST')!.body).not.toHaveProperty('duration_seconds');
  });

  it('releases, extends and makes permanent with a reason', async () => {
    const { calls } = installFakeApi({
      'GET /v1/overrides': { overrides: [activeRaw()] },
      'POST /v1/overrides/ovr_1/release': activeRaw({ status: 'released' }),
      'POST /v1/overrides/ovr_1/extend': activeRaw(),
      'POST /v1/overrides/ovr_1/permanent': activeRaw({ expires_at: undefined }),
    });
    renderWithApp(<SuspensionsTab agent={agent} />);
    expect((await screen.findByTestId('suspension-chip')).textContent).toContain('GitHub suspended · restores at');
    expect(screen.getByText(/billing-bot: installation token deleted/)).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: 'Extend GitHub suspension' }));
    let dialog = screen.getByRole('dialog');
    fireEvent.click(within(dialog).getByRole('button', { name: '+1h' }));
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'still investigating' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Extend by 1h' }));
    await waitFor(() => expect(calls.some((c) => c.path === '/v1/overrides/ovr_1/extend')).toBe(true));
    expect(calls.find((c) => c.path === '/v1/overrides/ovr_1/extend')!.body).toEqual({ duration_seconds: 3600, reason: 'still investigating' });

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    fireEvent.click(screen.getByRole('button', { name: 'Make GitHub suspension permanent' }));
    dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'confirmed compromise' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Make permanent' }));
    await waitFor(() => expect(calls.some((c) => c.path === '/v1/overrides/ovr_1/permanent')).toBe(true));
    expect(calls.find((c) => c.path === '/v1/overrides/ovr_1/permanent')!.body).toEqual({ reason: 'confirmed compromise' });

    await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
    fireEvent.click(screen.getByRole('button', { name: 'Release GitHub now' }));
    dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'resolved' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Release now' }));
    await waitFor(() => expect(calls.some((c) => c.path === '/v1/overrides/ovr_1/release')).toBe(true));
    expect(calls.find((c) => c.path === '/v1/overrides/ovr_1/release')!.body).toEqual({ reason: 'resolved' });
  });

  it('shows a blocked restore and disables actions for a read-only user', async () => {
    installFakeApi({ 'GET /v1/overrides': { overrides: [activeRaw({ status: 'blocked', blocked_reason: 'red action on github during the suspension' })] } });
    renderWithApp(<SuspensionsTab agent={agent} />, auditorMe);
    expect(await screen.findByText(/Automatic restore was blocked: red action on github/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Suspend an app' }) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Release GitHub now' }) as HTMLButtonElement).disabled).toBe(true);
  });
});

describe('overridePermissions', () => {
  const o: Override = {
    overrideId: 'ovr_1',
    scope: 'agent',
    scopeId: 'billing-bot',
    system: 'github',
    mode: 'suspended',
    startsAt: '',
    expiresAt: inOneHour(),
    reason: 'x',
    createdBy: 'user:sec@example.com',
    status: 'active',
  };

  it('lets security do everything that fits the override state', () => {
    expect(overridePermissions(securityMe, agent, o)).toMatchObject({ canRelease: true, canExtend: true, canPermanent: true });
    const open = overridePermissions(securityMe, agent, { ...o, expiresAt: undefined });
    expect(open).toMatchObject({ canRelease: true, canExtend: false, canPermanent: false });
    const blocked = overridePermissions(securityMe, agent, { ...o, status: 'blocked' });
    expect(blocked).toMatchObject({ canRelease: true, canExtend: false, canPermanent: true });
  });

  it('lets the owner tighten but only release their own suspensions', () => {
    const other = overridePermissions(ownerMe, agent, o);
    expect(other).toMatchObject({ canRelease: false, canExtend: true, canPermanent: true });
    expect(other.releaseWhy).toMatch(/security role/);
    expect(overridePermissions(ownerMe, agent, { ...o, createdBy: 'user:owner@example.com' }).canRelease).toBe(true);
    expect(overridePermissions(ownerMe, agent, { ...o, scope: 'team', scopeId: 'Ops' })).toMatchObject({ canRelease: false, canExtend: false, canPermanent: false });
  });

  it('refuses everything to an auditor', () => {
    expect(overridePermissions(auditorMe, agent, o)).toMatchObject({ canRelease: false, canExtend: false, canPermanent: false });
  });
});
