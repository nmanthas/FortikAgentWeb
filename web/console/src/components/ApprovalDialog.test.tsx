import { fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { setCsrf } from '../api/client';
import type { ApprovalResult, HeldAction } from '../api/types';
import { installFakeApi } from '../test/fakeApi';
import { renderWithApp } from '../test/render';
import { ApprovalDialog, approvalToast, notUndoable } from './ApprovalDialog';

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrf('');
});

const base: HeldAction = {
  actionId: 'act_1',
  agentId: 'billing-bot',
  ruleId: 'POL-101',
  reason: 'DROP TABLE on production (NOT UNDOABLE)',
  class: 'red',
  decision: 'hold',
  system: 'postgres',
  verb: 'DELETE',
  safeForm: 'pg_rename: ALTER TABLE public.invoices RENAME TO fortik_trash_invoices',
  outcome: 'pending',
  createdAt: '2026-10-13T10:00:00Z',
  undoAvailable: false,
  approvalsRequired: 1,
};

const approved = { action_id: 'act_1', outcome: 'approved', approvals: 1, approvals_required: 1 };

function open(held: HeldAction, mode: 'approve' | 'deny') {
  const onDone = vi.fn<(r: ApprovalResult) => void>();
  const onClose = vi.fn();
  renderWithApp(<ApprovalDialog held={held} mode={mode} onDone={onDone} onClose={onClose} />);
  return { onDone, onClose };
}

const reasonBox = () => screen.getByLabelText(/Reason/);
const submit = (name: RegExp) => screen.getByRole('button', { name }) as HTMLButtonElement;

describe('ApprovalDialog', () => {
  it('approves a red hold only through its safe form, with a required reason', async () => {
    setCsrf('csrf-abc');
    const { calls } = installFakeApi({
      'POST /v1/held/act_1/approve': { ...approved, safe_form: { kind: 'pg_rename', trash_table: 'fortik_trash_invoices' } },
    });
    const { onDone, onClose } = open(base, 'approve');

    const safe = screen.getByLabelText(/Run the safe form instead/) as HTMLInputElement;
    expect(safe.checked).toBe(true);
    // A reason is required.
    expect(submit(/Approve safe form/).disabled).toBe(true);
    fireEvent.change(reasonBox(), { target: { value: '  checked with the owner  ' } });
    expect(submit(/Approve safe form/).disabled).toBe(false);

    // Unticking the safe form blocks approval: red never runs unchanged.
    fireEvent.click(safe);
    expect(screen.getByText(/Red actions are never run unchanged/)).toBeTruthy();
    expect(screen.getByText(/NOT UNDOABLE — Fortik cannot reverse/)).toBeTruthy();
    expect(submit(/^\s*Approve$/).disabled).toBe(true);
    fireEvent.click(safe);

    fireEvent.click(submit(/Approve safe form/));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    const call = calls.find((c) => c.path === '/v1/held/act_1/approve')!;
    expect(call.body).toEqual({ reason: 'checked with the owner', use_safe_form: true });
    expect(call.headers['x-fortik-csrf']).toBe('csrf-abc');
    expect(onDone.mock.calls[0]![0]).toMatchObject({ outcome: 'approved', safeFormTrashTable: 'fortik_trash_invoices' });
    expect(onClose).toHaveBeenCalled();
  });

  it('cannot approve a red hold without a safe form', () => {
    installFakeApi({});
    open({ ...base, safeForm: '' }, 'approve');
    expect(screen.queryByLabelText(/Run the safe form instead/)).toBeNull();
    expect(screen.getByText(/no safe form, so it can only be denied/)).toBeTruthy();
    fireEvent.change(reasonBox(), { target: { value: 'ok' } });
    expect(submit(/^\s*Approve$/).disabled).toBe(true);
  });

  it('approves a yellow hold as a one-time grant without the safe form', async () => {
    const { calls } = installFakeApi({
      'POST /v1/held/act_2/approve': { ...approved, action_id: 'act_2', grant: { grant_id: 'g1', expires_at: '2026-10-13T10:15:00Z' } },
    });
    const yellow: HeldAction = { ...base, actionId: 'act_2', class: 'yellow', verb: 'SEND', system: 'gmail', reason: 'external recipients', safeForm: '' };
    const { onDone } = open(yellow, 'approve');
    expect(screen.getByText(/one-time grant/)).toBeTruthy();
    expect(screen.queryByText(/NOT UNDOABLE — Fortik cannot reverse/)).toBeNull();
    fireEvent.change(reasonBox(), { target: { value: 'expected mail' } });
    fireEvent.click(submit(/^\s*Approve$/));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ reason: 'expected mail', use_safe_form: false });
    expect(onDone.mock.calls[0]![0].grantExpiresAt).toBe('2026-10-13T10:15:00Z');
  });

  it('denies with a reason and shows server refusals', async () => {
    let first = true;
    const { calls } = installFakeApi({
      'POST /v1/held/act_1/deny': () => {
        if (first) {
          first = false;
          return { status: 409, body: { error: 'held action is not pending' } };
        }
        return { body: { ...approved, outcome: 'denied' } };
      },
    });
    const { onDone, onClose } = open(base, 'deny');
    expect(screen.queryByLabelText(/Run the safe form instead/)).toBeNull();
    fireEvent.change(reasonBox(), { target: { value: 'not today' } });
    fireEvent.click(submit(/^\s*Deny$/));
    expect(await screen.findByText('held action is not pending')).toBeTruthy();
    expect(onClose).not.toHaveBeenCalled();
    fireEvent.click(submit(/^\s*Deny$/));
    await waitFor(() => expect(onDone).toHaveBeenCalled());
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.body)).toEqual([{ reason: 'not today' }, { reason: 'not today' }]);
  });
});

describe('approval helpers', () => {
  it('flags red holds without undo as not undoable', () => {
    expect(notUndoable(base)).toBe(true);
    expect(notUndoable({ ...base, undoAvailable: true })).toBe(false);
    expect(notUndoable({ ...base, class: 'yellow', verb: 'SEND', reason: 'external' })).toBe(false);
  });

  it('words the toast for each outcome', () => {
    const r = (o: Partial<ApprovalResult>): ApprovalResult => ({ actionId: 'act_1', outcome: 'approved', approvals: 1, approvalsRequired: 1, ...o });
    expect(approvalToast('deny', base, r({ outcome: 'denied' })).title).toBe('Denied postgres DELETE by billing-bot');
    expect(approvalToast('approve', base, r({ outcome: 'pending', approvalsRequired: 2 })).title).toBe('Vote recorded (1 of 2)');
    expect(approvalToast('approve', base, r({ safeFormTrashTable: 'fortik_trash_x' })).body).toContain('fortik_trash_x');
  });
});
