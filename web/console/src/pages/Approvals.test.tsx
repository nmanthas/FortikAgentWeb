import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp } from '../test/render';
import { ApprovalsPage } from './Approvals';

afterEach(() => {
  vi.unstubAllGlobals();
});

const later = () => new Date(Date.now() + 3600_000).toISOString();
const held = (id: string, extra: Record<string, unknown>) => ({
  action_id: id,
  agent_id: 'billing-bot',
  rule_id: 'POL-201',
  reason: 'needs a human',
  approvals_required: 1,
  approver_role: 'security',
  safe_form: null,
  expires_at: later(),
  outcome: 'pending',
  created_at: new Date().toISOString(),
  class: 'yellow',
  decision: 'hold',
  system: 'gmail',
  verb: 'SEND',
  undo_available: false,
  ...extra,
});

describe('Approvals page', () => {
  it('lists pending holds across agents, dangerous first, and approves one', async () => {
    let pending = [
      held('act_y', { agent_id: 'mail-bot', created_at: new Date(Date.now() - 1000).toISOString() }),
      held('act_r', { class: 'red', system: 'postgres', verb: 'DELETE', safe_form: { kind: 'pg_rename', sql: 'ALTER TABLE t RENAME TO fortik_trash_t' }, created_at: new Date(Date.now() - 60_000).toISOString() }),
      held('act_old', { agent_id: 'ops-bot', created_at: new Date(Date.now() - 120_000).toISOString(), expires_at: new Date(Date.now() - 1000).toISOString() }),
    ];
    const { calls } = installFakeApi({
      'GET /v1/held': () => ({ body: { held: pending } }),
      'POST /v1/held/act_r/approve': () => {
        pending = pending.filter((h) => h.action_id !== 'act_r');
        return { body: { action_id: 'act_r', outcome: 'approved', approvals: 1, approvals_required: 1, safe_form: { trash_table: 'fortik_trash_t' } } };
      },
    });
    renderWithApp(<ApprovalsPage />);
    const items = await screen.findAllByTestId('held-item');
    // No Phase 5 queue on this (fake) server: the Phase 3 list is used instead.
    expect(calls.some((c) => c.path.startsWith('/v1/approvals/queue?status=pending'))).toBe(true);
    expect(calls.some((c) => c.path === '/v1/held?status=pending&limit=1000')).toBe(true);
    expect(screen.getByText(/no approval queue yet/)).toBeTruthy();
    expect(screen.getByText('3 pending')).toBeTruthy();
    expect(within(items[0]!).getByText('postgres DELETE')).toBeTruthy();
    expect(within(items[0]!).getByText(/NOT UNDOABLE/)).toBeTruthy();
    expect(within(items[0]!).getByText('pg_rename: ALTER TABLE t RENAME TO fortik_trash_t')).toBeTruthy();
    expect(within(items[1]!).getByText('mail-bot')).toBeTruthy();
    // An expired hold can no longer be decided.
    expect(within(items[2]!).getByText('expired')).toBeTruthy();
    expect(within(items[2]!).queryByRole('button', { name: /Approve/ })).toBeNull();

    fireEvent.click(within(items[0]!).getByRole('button', { name: 'Approve postgres DELETE by billing-bot' }));
    const dialog = screen.getByRole('dialog');
    expect((within(dialog).getByLabelText(/Run the safe form instead/) as HTMLInputElement).checked).toBe(true);
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'move it aside' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /Approve safe form/ }));
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ reason: 'move it aside', use_safe_form: true });
    expect(await screen.findByText('Safe form executed')).toBeTruthy();
    await waitFor(() => expect(screen.getAllByTestId('held-item')).toHaveLength(2));
  });

  it('shows an empty state and explains the role for non-approvers', async () => {
    installFakeApi({ 'GET /v1/held': { held: [held('act_y', {})] } });
    renderWithApp(<ApprovalsPage />, auditorMe);
    expect(await screen.findByText(/requires the security role/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Approve gmail SEND by billing-bot' }) as HTMLButtonElement).disabled).toBe(true);
  });

  it('says when nothing is waiting', async () => {
    installFakeApi({ 'GET /v1/held': { held: [] } });
    renderWithApp(<ApprovalsPage />);
    expect(await screen.findByText('Nothing is waiting for approval.')).toBeTruthy();
  });
});
