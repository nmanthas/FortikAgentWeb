import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Agent } from '../api/types';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp } from '../test/render';
import { InstancesTab } from './InstancesTab';

afterEach(() => {
  vi.unstubAllGlobals();
});

const agent: Agent = {
  agentId: 'coder',
  name: 'Coder',
  type: 'coding',
  platform: 'claude-code',
  sponsor: 'owner@example.com',
  businessUnit: '',
  workspaceUser: '',
  copyCap: 6,
  level: 'FULL',
  discovered: false,
};

const now = new Date().toISOString();
const inst = (i: number, extra: Record<string, unknown> = {}) => ({
  instance_id: `coder-${i}`,
  agent_id: 'coder',
  host: i > 6 ? 'unknown-vm' : 'dev-laptop',
  started_at: now,
  last_heartbeat: now,
  status: 'live',
  new_host: i === 7,
  ...extra,
});

describe('InstancesTab', () => {
  it('shows "9 of 6", flags new hosts and pauses the extra copies with a reason', async () => {
    let paused = false;
    const list = () => ({
      agent_id: 'coder',
      copy_cap: 6,
      live: paused ? 6 : 9,
      instances: [...Array.from({ length: 9 }, (_, i) => inst(i + 1, paused && i >= 6 ? { status: 'paused', reason: 'paused: above copy cap' } : {})), inst(10, { status: 'refused', reason: 'POL-701: copy cap reached' })],
    });
    const { calls } = installFakeApi({
      'GET /v1/agents/coder/instances': () => ({ body: list() }),
      'POST /v1/agents/coder/instances/pause-extra': () => {
        paused = true;
        return { body: { agent_id: 'coder', copy_cap: 6, live_before: 9, live_after: 6, paused: ['coder-9', 'coder-8', 'coder-7'] } };
      },
    });
    renderWithApp(<InstancesTab agent={agent} />);
    expect((await screen.findByTestId('instance-count')).textContent).toBe('9 of 6');
    expect(screen.getByTestId('instance-count').className).toContain('over');
    expect(screen.getByText(/More copies are running than allowed/)).toBeTruthy();
    expect(screen.getAllByText('new host')).toHaveLength(1);
    expect(screen.getByText('POL-701: copy cap reached')).toBeTruthy();
    expect(screen.getAllByRole('row')).toHaveLength(11);

    fireEvent.click(screen.getByRole('button', { name: 'Pause extra copies of coder' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText(/The newest 3 live copies above the cap of 6/)).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'spawn loop' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Pause extra' }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ reason: 'spawn loop' });
    expect(await screen.findByText('Paused 3 extra copies of coder')).toBeTruthy();
    await waitFor(() => expect(screen.getByTestId('instance-count').textContent).toBe('6 of 6'));
    expect((screen.getByRole('button', { name: 'Pause extra copies of coder' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('disables Pause extra for an auditor', async () => {
    installFakeApi({ 'GET /v1/agents/coder/instances': { agent_id: 'coder', copy_cap: 1, live: 2, instances: [inst(1), inst(2)] } });
    renderWithApp(<InstancesTab agent={agent} />, auditorMe);
    expect((await screen.findByTestId('instance-count')).textContent).toBe('2 of 1');
    expect((screen.getByRole('button', { name: 'Pause extra copies of coder' }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/requires the security role or ownership/)).toBeTruthy();
  });
});
