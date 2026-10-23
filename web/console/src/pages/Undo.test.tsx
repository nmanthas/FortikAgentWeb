import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { normUndoEntry } from '../api/normalize';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp, securityMe } from '../test/render';
import { UndoPage } from './Undo';

afterEach(() => {
  vi.unstubAllGlobals();
});

const future = () => new Date(Date.now() + 86400_000).toISOString();
const past = () => new Date(Date.now() - 86400_000).toISOString();

const handles = () => ({
  undo: [
    {
      action_id: 'act_rows',
      agent_id: 'billing-bot',
      kind: 'pg_rows_snapshot',
      status: 'active',
      handle_json: { snapshot_table: 'fortik_undo.secret_name' },
      expires_at: future(),
      created_at: '2026-10-18T10:02:00Z',
      undoable: true,
      description: 'Restore 42 rows of public.invoices deleted by the agent.',
    },
    {
      action_id: 'act_mail',
      agent_id: 'billing-bot',
      kind: 'gmail_send',
      status: 'active',
      expires_at: future(),
      created_at: '2026-10-18T10:01:00Z',
      undoable: false,
      why_not: 'already sent: NOT undoable',
      description: 'Email to 3 recipients.',
    },
    {
      action_id: 'act_old',
      agent_id: 'ops-bot',
      kind: 'pg_rename',
      status: 'expired',
      expires_at: past(),
      created_at: '2026-10-01T10:00:00Z',
      undoable: false,
      why_not: 'expired',
      description: 'Rename fortik_trash_x back to orders.',
    },
  ],
});

describe('Undo page', () => {
  it('offers Undo only for undoable handles and says NOT UNDOABLE with the reason otherwise', async () => {
    const { calls } = installFakeApi({
      'GET /v1/undo': handles(),
      'POST /v1/undo/act_rows': { action_id: 'act_rows', kind: 'pg_rows_snapshot', status: 'used', result: {} },
    });
    renderWithApp(<UndoPage />, securityMe);
    const rows = await screen.findByTestId('undo-act_rows');
    expect(within(rows).getByText('Restore 42 rows of public.invoices deleted by the agent.')).toBeTruthy();
    expect(screen.queryByText(/secret_name/)).toBeNull(); // handle_json is never shown

    const mail = screen.getByTestId('undo-act_mail');
    expect(within(mail).queryByRole('button', { name: 'Undo' })).toBeNull();
    expect(within(mail).getByTestId('not-undoable').textContent).toContain('NOT UNDOABLE');
    expect(within(mail).getByText('already sent: NOT undoable')).toBeTruthy();
    const old = screen.getByTestId('undo-act_old');
    expect(within(old).queryByRole('button', { name: 'Undo' })).toBeNull();
    expect(within(old).getByText('expired')).toBeTruthy();

    fireEvent.click(screen.getByLabelText('Undoable only') as HTMLInputElement);
    expect(screen.queryByTestId('undo-act_mail')).toBeNull();
    fireEvent.click(screen.getByLabelText('Undoable only') as HTMLInputElement);

    fireEvent.click(within(rows).getByRole('button', { name: 'Undo' }));
    const dialog = screen.getByRole('dialog', { name: 'Undo act_rows?' });
    const confirm = within(dialog).getByRole('button', { name: /Undo/ }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'agent deleted the wrong rows' } });
    fireEvent.click(confirm);
    await waitFor(() => expect(calls.some((c) => c.method === 'POST')).toBe(true));
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.path).toBe('/v1/undo/act_rows');
    expect(post.body).toEqual({ reason: 'agent deleted the wrong rows' });
    expect(await screen.findByText('Undo of act_rows completed')).toBeTruthy();
  });

  it('disables Undo for a user without the security role, with the reason', async () => {
    installFakeApi({ 'GET /v1/undo': handles() });
    renderWithApp(<UndoPage />, auditorMe);
    const rows = await screen.findByTestId('undo-act_rows');
    const btn = within(rows).getByRole('button', { name: 'Undo' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.title).toBe('Running an undo requires the security role.');
    expect(screen.getByText('Running an undo requires the security role.')).toBeTruthy();
  });

  it('decides conservatively when an older server does not say whether a handle is undoable', () => {
    const now = Date.parse('2026-10-18T12:00:00Z');
    const active = normUndoEntry({ action_id: 'a', kind: 'pg_rename', status: 'active', expires_at: '2026-10-19T00:00:00Z' }, now);
    expect(active.undoable).toBe(true);
    expect(active.description).toMatch(/Rename the trashed table back/);
    const lapsed = normUndoEntry({ action_id: 'b', kind: 'pg_rename', status: 'active', expires_at: '2026-10-17T00:00:00Z' }, now);
    expect(lapsed).toMatchObject({ undoable: false, whyNot: 'expired' });
    expect(normUndoEntry({ action_id: 'c', status: 'used' }, now)).toMatchObject({ undoable: false, whyNot: 'already used' });
    expect(normUndoEntry({ action_id: 'd', status: 'prepared' }, now)).toMatchObject({ undoable: false, whyNot: 'not undoable' });
    // The server's answer wins, and an undoable handle carries no why_not.
    expect(normUndoEntry({ action_id: 'e', status: 'active', undoable: false, why_not: 'no undo prepared' }, now)).toMatchObject({ undoable: false, whyNot: 'no undo prepared' });
    expect(normUndoEntry({ action_id: 'f', status: 'active', undoable: true, why_not: 'stale' }, now).whyNot).toBeUndefined();
  });
});

describe('Undo page: delayed-send reasons from the server (rendered as-is)', () => {
  it('shows each why_not verbatim and offers Undo for a send past its time that the server still calls undoable', async () => {
    const reasons = [
      'being sent right now: NOT undoable',
      'already cancelled before sending: nothing was sent',
      'the send failed or its outcome is unknown: nothing left to cancel, NOT undoable',
    ];
    installFakeApi({
      'GET /v1/undo': {
        undo: [
          ...reasons.map((why, i) => ({
            action_id: `act_send_${i}`,
            agent_id: 'billing-bot',
            kind: 'gmail_delayed_send',
            status: 'active',
            expires_at: future(),
            created_at: `2026-10-18T10:0${i}:00Z`,
            undoable: false,
            why_not: why,
            description: 'Cancel the delayed email before it is sent.',
          })),
          {
            action_id: 'act_send_late',
            agent_id: 'billing-bot',
            kind: 'gmail_delayed_send',
            status: 'active',
            expires_at: future(),
            created_at: '2026-10-18T10:09:00Z',
            undoable: true,
            description: 'Cancel the delayed email to 2 recipients (send time reached: may already be sent; cancelling stops it only if it has not gone out yet).',
          },
        ],
      },
    });
    renderWithApp(<UndoPage />, securityMe);
    for (const [i, why] of reasons.entries()) {
      const row = await screen.findByTestId(`undo-act_send_${i}`);
      expect(within(row).getByTestId('not-undoable').querySelector('.why')!.textContent).toBe(why);
      expect(within(row).queryByRole('button', { name: 'Undo' })).toBeNull();
    }
    const late = screen.getByTestId('undo-act_send_late');
    expect(within(late).getByText(/send time reached: may already be sent/)).toBeTruthy();
    expect(within(late).getByRole('button', { name: 'Undo' })).toBeTruthy();
  });
});
