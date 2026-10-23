// Approve / deny a held action (docs/PHASE3_DESIGN.md §6).
//
// - A reason is always required; it is recorded with the vote.
// - Red actions are never run unchanged: approving one requires its safe
//   form ("Run the safe form instead"), which Fortik executes itself. A red
//   hold without a safe form can only be denied.
// - Approving a yellow hold issues a one-time grant: the agent retries the
//   identical action within the grant's lifetime.

import { useId, useState } from 'react';
import { approveHeld, denyHeld } from '../api/endpoints';
import type { ApprovalResult, HeldAction } from '../api/types';
import { fmtTime } from '../lib/format';
import { cleanReason, reasonOk } from '../lib/reason';
import { IconAlert } from './Icons';
import { ErrorBox, Modal, ReasonField } from './ui';

export function notUndoable(h: HeldAction): boolean {
  return !h.undoAvailable && (/not undoable/i.test(h.reason) || h.verb === 'DELETE' || h.class === 'red');
}

export function ApprovalDialog({
  held,
  mode,
  onDone,
  onClose,
}: {
  held: HeldAction;
  mode: 'approve' | 'deny';
  onDone: (r: ApprovalResult) => void;
  onClose: () => void;
}) {
  const red = held.class === 'red';
  const hasSafe = held.safeForm !== '';
  const [reason, setReason] = useState('');
  const [useSafe, setUseSafe] = useState(red && hasSafe);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const safeId = useId();

  const blockedRed = mode === 'approve' && red && !useSafe;
  const canSubmit = !busy && reasonOk(reason) && !blockedRed;
  const approvals = 'approvals' in held && typeof (held as { approvals?: unknown }).approvals === 'number' ? (held as { approvals: number }).approvals : 0;
  const required = held.approvalsRequired ?? 1;

  const submit = async () => {
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const r = mode === 'approve' ? await approveHeld(held.actionId, cleanReason(reason), useSafe) : await denyHeld(held.actionId, cleanReason(reason));
      onDone(r);
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };

  const what = `${held.system} ${held.verb}`.trim();
  return (
    <Modal
      title={mode === 'approve' ? `Approve ${what} by ${held.agentId}?` : `Deny ${what} by ${held.agentId}?`}
      description={
        <>
          Held by {held.ruleId || 'policy'}
          {held.reason && <>: {held.reason}</>}
        </>
      }
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className={`btn ${mode === 'deny' ? 'danger' : 'primary'}`} onClick={() => void submit()} disabled={!canSubmit}>
            {busy && <span className="spinner" />} {mode === 'approve' ? (useSafe ? 'Approve safe form' : 'Approve') : 'Deny'}
          </button>
        </>
      }
    >
      {mode === 'approve' && notUndoable(held) && !useSafe && (
        <div className="alert error" role="alert">
          <IconAlert size={14} /> NOT UNDOABLE — Fortik cannot reverse this action once it runs.
        </div>
      )}
      {mode === 'approve' && hasSafe && (
        <div className="field">
          <label className="check" htmlFor={safeId}>
            <input id={safeId} type="checkbox" checked={useSafe} onChange={(e) => setUseSafe(e.target.checked)} /> Run the safe form instead
          </label>
          <span className="help">
            Fortik runs <code>{held.safeForm}</code> itself and records an undo handle first. The original action never runs.
          </span>
        </div>
      )}
      {blockedRed && (
        <div className="alert warn" role="status">
          Red actions are never run unchanged.{' '}
          {hasSafe ? 'Tick “Run the safe form instead” to approve, or deny the action.' : 'This action has no safe form, so it can only be denied.'}
        </div>
      )}
      {mode === 'approve' && !red && (
        <p className="help" style={{ marginTop: 0 }}>
          Approving issues a one-time grant: the agent may retry exactly this action once before the grant expires.
          {required > 1 ? ` ${required} approvals from different people are required.` : ''}
        </p>
      )}
      {mode === 'approve' && required > 1 && (
        <div className="alert info" role="status" data-testid="approval-progress">
          {approvals} of {required} approvals so far.{' '}
          {approvals + 1 >= required ? 'Your approval completes it.' : 'Your vote is recorded; another approver must also approve before anything runs.'}
        </div>
      )}
      {held.expiresAt && <p className="muted small">The hold expires {fmtTime(held.expiresAt)}.</p>}
      <ReasonField value={reason} onChange={setReason} placeholder="Why? It is recorded in the Diary." />
      <ErrorBox error={error} />
    </Modal>
  );
}

/** Toast text for an approval result. */
export function approvalToast(mode: 'approve' | 'deny', h: HeldAction, r: ApprovalResult): { tone: 'green' | 'amber' | 'info'; title: string; body?: string } {
  if (mode === 'deny') return { tone: 'amber', title: `Denied ${h.system} ${h.verb} by ${h.agentId}` };
  if (r.outcome === 'pending') return { tone: 'info', title: `Vote recorded (${r.approvals} of ${r.approvalsRequired})`, body: 'More approvals are needed.' };
  if (r.safeFormTrashTable) return { tone: 'green', title: 'Safe form executed', body: `Moved aside as ${r.safeFormTrashTable}; undo is available.` };
  return {
    tone: 'green',
    title: `Approved ${h.system} ${h.verb} by ${h.agentId}`,
    body: r.grantExpiresAt ? `The agent may retry it once until ${fmtTime(r.grantExpiresAt)}.` : undefined,
  };
}
