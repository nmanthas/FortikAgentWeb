import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi, type Recorded } from '../test/fakeApi';
import { auditorMe, renderWithApp } from '../test/render';
import { SettingsPage, validAgentType } from './Settings';

afterEach(() => {
  vi.unstubAllGlobals();
});

const support = { type: 'support', expected_max_instances: 10, max_agents: 5, spawn_rate_per_min: 2, action_rate_per_min: 120 };

describe('Settings → Agent types', () => {
  it('edits a type and saves the whole row with a reason', async () => {
    const { calls } = installFakeApi({
      'GET /v1/agent-types': { agent_types: [support] },
      'PUT /v1/agent-types/support': (req: Recorded) => ({ body: { type: 'support', ...(req.body as object) } }),
    });
    renderWithApp(<SettingsPage />);
    const max = (await screen.findByLabelText('Expected max instances for support')) as HTMLInputElement;
    expect(max.value).toBe('10');
    const save = screen.getByRole('button', { name: 'Save support' }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);

    fireEvent.change(max, { target: { value: '12' } });
    fireEvent.change(screen.getByLabelText('Spawns / min for support'), { target: { value: '1.5' } });
    fireEvent.click(save);
    expect(screen.getByText('Spawns / min must be a whole number from 0 to 1,000,000.')).toBeTruthy();
    expect(screen.queryByRole('dialog')).toBeNull();

    fireEvent.change(screen.getByLabelText('Spawns / min for support'), { target: { value: '3' } });
    fireEvent.click(save);
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'seasonal load' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({
      expected_max_instances: 12,
      max_agents: 5,
      spawn_rate_per_min: 3,
      action_rate_per_min: 120,
      reason: 'seasonal load',
    });
    expect(await screen.findByText('Agent type support saved')).toBeTruthy();
  });

  it('adds a new type and refuses duplicates', async () => {
    const { calls } = installFakeApi({ 'GET /v1/agent-types': { agent_types: [support] }, 'PUT /v1/agent-types/coding:claude': { type: 'coding:claude' } });
    renderWithApp(<SettingsPage />);
    await screen.findByLabelText('Expected max instances for support');
    fireEvent.click(screen.getByRole('button', { name: 'Add type' }));
    fireEvent.change(screen.getByLabelText('Type name'), { target: { value: 'support' } });
    // Two rows are named "support"; the new row's Save is the second.
    fireEvent.click(screen.getAllByRole('button', { name: 'Save support' })[1]!);
    expect(screen.getByText(/already exists/)).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Type name'), { target: { value: 'coding:claude' } });
    fireEvent.change(screen.getByLabelText('Max agents for coding:claude'), { target: { value: '3' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save coding:claude' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'new fleet' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect(calls.find((c) => c.method === 'PUT')!.path).toBe('/v1/agent-types/coding%3Aclaude');
  });

  it('is read-only for an auditor', async () => {
    installFakeApi({ 'GET /v1/agent-types': { agent_types: [support] } });
    renderWithApp(<SettingsPage />, auditorMe);
    expect(((await screen.findByLabelText('Max agents for support')) as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: 'Add type' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText('Editing agent types requires the security role.')).toBeTruthy();
  });

  it('validates names and limits like the server', () => {
    const t = { type: 'a', expectedMaxInstances: 0, maxAgents: 0, spawnRatePerMin: 0, actionRatePerMin: 0 };
    expect(validAgentType(t)).toBeNull();
    expect(validAgentType({ ...t, type: 'team@ops:v2' })).toBeNull();
    expect(validAgentType({ ...t, type: '-bad' })).toMatch(/Type names/);
    expect(validAgentType({ ...t, maxAgents: 1_000_001 })).toMatch(/Max agents/);
    expect(validAgentType({ ...t, actionRatePerMin: -1 })).toMatch(/Actions/);
  });
});
