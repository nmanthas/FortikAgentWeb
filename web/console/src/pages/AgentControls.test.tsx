import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { useState } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Agent } from '../api/types';
import { installFakeApi } from '../test/fakeApi';
import { ownerMe, renderWithApp, securityMe } from '../test/render';
import { AgentControls, DETAIL_CONTROLS } from './AgentControls';

afterEach(() => {
  vi.unstubAllGlobals();
});

const agent = (id: string, extra: Partial<Agent> = {}): Agent => ({
  agentId: id,
  name: id,
  type: 'support',
  platform: 'test',
  sponsor: 'owner@example.com',
  businessUnit: 'Support',
  workspaceUser: '',
  copyCap: 2,
  level: 'FULL',
  discovered: false,
  suspended: false,
  ...extra,
});

const opBody = (op: string, target: string) => ({
  op_id: `cop_${op}`,
  op,
  target_type: 'agent',
  target_id: target,
  status: 'done',
  steps: [{ name: 'set_memory_access', status: 'done' }],
  created_at: '2026-10-19T10:00:00Z',
});

const buttons = () => within(document.querySelector('.control-grid') as HTMLElement);

describe('AgentControls', () => {
  it('F23: freezes the target when a dialog opens, even if the surface passes another agent', async () => {
    const { calls } = installFakeApi({ 'POST /v1/agents/billing-bot/suspend': opBody('suspend', 'billing-bot') });
    let swap: (a: Agent) => void = () => undefined;
    function Surface() {
      // No key on purpose: the component itself must not follow the prop into an open dialog.
      const [a, setA] = useState(agent('billing-bot'));
      swap = setA;
      return <AgentControls agent={a} controls={DETAIL_CONTROLS} />;
    }
    renderWithApp(<Surface />, securityMe);
    fireEvent.click(buttons().getByRole('button', { name: 'Suspend' }));
    fireEvent.change(within(screen.getByRole('dialog', { name: 'Suspend: billing-bot' })).getByLabelText(/Reason/), { target: { value: 'burst' } });
    act(() => swap(agent('ops-bot')));
    const dialog = screen.getByRole('dialog', { name: 'Suspend: billing-bot' });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Suspend' }));
    await screen.findByRole('dialog', { name: 'Suspend: billing-bot — result' });
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.path)).toEqual(['/v1/agents/billing-bot/suspend']);
  });

  it('F23: reports the opened agent to the surface so it can pin its selection', () => {
    installFakeApi({});
    const onOpen = vi.fn();
    renderWithApp(<AgentControls agent={agent('billing-bot')} controls={DETAIL_CONTROLS} onOpen={onOpen} />, securityMe);
    fireEvent.click(buttons().getByRole('button', { name: 'Kill' }));
    expect(onOpen).toHaveBeenCalledWith('billing-bot');
  });

  it('F24/D1: an owner restores memory access without a rollback selector and never lists snapshots', async () => {
    const { calls } = installFakeApi({ 'POST /v1/agents/billing-bot/memory/restore': opBody('memory_restore', 'billing-bot') });
    const cut = agent('billing-bot', { memoryAccess: 'none', memoryAccessChangedBy: 'user:owner@example.com' });
    renderWithApp(<AgentControls agent={cut} controls={DETAIL_CONTROLS} />, ownerMe);
    fireEvent.click(buttons().getByRole('button', { name: 'Restore memory' }));
    const dialog = screen.getByRole('dialog', { name: 'Restore memory: billing-bot' });
    expect(within(dialog).queryByLabelText('Roll back first')).toBeNull();
    expect(within(dialog).getByTestId('rollback-unavailable').textContent).toMatch(/Rolling memory back to a snapshot requires the security role/);
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'false alarm' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore memory' }));
    await screen.findByRole('dialog', { name: 'Restore memory: billing-bot — result' });
    expect(calls.some((c) => c.path.startsWith('/v1/memory/snapshots') || c.path.endsWith('/memory'))).toBe(false);
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post).toMatchObject({ path: '/v1/agents/billing-bot/memory/restore' });
    expect(post.body).toEqual({ reason: 'false alarm' });
  });

  it("F24: security only sees clean snapshots of the agent's own store and namespace", async () => {
    const { calls } = installFakeApi({
      'GET /v1/agents/billing-bot/memory': {
        access: { mode: 'none', changed_by: 'user:sec@example.com' },
        staged: [{ store: 'main', id: 'm1', namespace: 'support', content_preview: 'x', created_at: '2026-10-19T09:00:00Z' }],
      },
      'GET /v1/memory/snapshots': {
        snapshots: [
          { snapshot_id: 'snap_ours', store_key: 'memory:main', namespace: 'support', item_count: 3, clean: true, created_at: '2026-10-19T08:00:00Z' },
          { snapshot_id: 'snap_other_store', store_key: 'memory:shared', namespace: 'support', item_count: 9, clean: true, created_at: '2026-10-19T08:30:00Z' },
          { snapshot_id: 'snap_other_ns', store_key: 'memory:main', namespace: 'finance', item_count: 9, clean: true, created_at: '2026-10-19T08:40:00Z' },
          { snapshot_id: 'snap_dirty', store_key: 'memory:main', namespace: 'support', item_count: 4, clean: false, created_at: '2026-10-19T08:50:00Z' },
        ],
      },
      'POST /v1/agents/billing-bot/memory/restore': opBody('memory_restore', 'billing-bot'),
    });
    renderWithApp(<AgentControls agent={agent('billing-bot', { memoryAccess: 'none' })} controls={DETAIL_CONTROLS} />, securityMe);
    fireEvent.click(buttons().getByRole('button', { name: 'Restore memory' }));
    const dialog = screen.getByRole('dialog', { name: 'Restore memory: billing-bot' });
    const select = within(dialog).getByLabelText('Roll back first') as HTMLSelectElement;
    await waitFor(() => expect(select.options).toHaveLength(2));
    expect([...select.options].map((o) => o.value)).toEqual(['', 'snap_ours']);
    expect(calls.filter((c) => c.path.startsWith('/v1/memory/snapshots')).map((c) => c.path)).toEqual(['/v1/memory/snapshots?namespace=support']);
    fireEvent.change(select, { target: { value: 'snap_ours' } });
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'roll back poison' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Restore memory' }));
    await screen.findByRole('dialog', { name: 'Restore memory: billing-bot — result' });
    expect(calls.at(-1)).toMatchObject({ path: '/v1/agents/billing-bot/memory/restore', body: { reason: 'roll back poison', rollback_snapshot_id: 'snap_ours' } });
  });

  it('F24: with no known namespace, no snapshot of any other namespace is offered', async () => {
    const { calls } = installFakeApi({
      'GET /v1/agents/billing-bot/memory': { access: { mode: 'none' }, staged: [] },
      'GET /v1/memory/snapshots': { snapshots: [{ snapshot_id: 'snap_any', store_key: 'memory:shared', namespace: 'everyone', item_count: 1, clean: true, created_at: '2026-10-19T08:00:00Z' }] },
    });
    renderWithApp(<AgentControls agent={agent('billing-bot', { memoryAccess: 'none' })} controls={DETAIL_CONTROLS} />, securityMe);
    fireEvent.click(buttons().getByRole('button', { name: 'Restore memory' }));
    const dialog = screen.getByRole('dialog', { name: 'Restore memory: billing-bot' });
    await within(dialog).findByText(/No clean snapshot of a namespace this agent uses is available/);
    expect((within(dialog).getByLabelText('Roll back first') as HTMLSelectElement).options).toHaveLength(1);
    expect(calls.some((c) => c.path.startsWith('/v1/memory/snapshots'))).toBe(false);
  });

  it('F26/D2: an owner cannot lift a suspension or memory cut someone else imposed; the reason is shown', () => {
    installFakeApi({});
    const imposed = agent('billing-bot', {
      suspended: true,
      suspendedBy: 'user:sec@example.com',
      memoryAccess: 'none',
      memoryAccessChangedBy: 'system:quarantine',
    });
    const { unmount } = renderWithApp(<AgentControls agent={imposed} controls={DETAIL_CONTROLS} />, ownerMe);
    const resume = buttons().getByRole('button', { name: 'Resume' }) as HTMLButtonElement;
    const restore = buttons().getByRole('button', { name: 'Restore memory' }) as HTMLButtonElement;
    expect(resume.disabled).toBe(true);
    expect(resume.title).toBe('Lifting a suspension imposed by user:sec@example.com requires the security role.');
    expect(restore.disabled).toBe(true);
    expect(screen.getByText('Restoring memory access cut by system:quarantine requires the security role.')).toBeTruthy();
    // Suspend and Remove memory stay available to the owner.
    expect((buttons().getByRole('button', { name: 'Suspend' }) as HTMLButtonElement).disabled).toBe(false);
    unmount();

    // What the owner imposed themselves, they may lift.
    const own = { ...imposed, suspendedBy: 'user:owner@example.com', memoryAccessChangedBy: 'user:owner@example.com' };
    renderWithApp(<AgentControls agent={own} controls={DETAIL_CONTROLS} />, ownerMe);
    expect((buttons().getByRole('button', { name: 'Resume' }) as HTMLButtonElement).disabled).toBe(false);
    expect((buttons().getByRole('button', { name: 'Restore memory' }) as HTMLButtonElement).disabled).toBe(false);
  });
});
