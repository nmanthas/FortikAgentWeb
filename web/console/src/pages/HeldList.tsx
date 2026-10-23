// Held actions with Approve / Deny, shared by the agent's Held tab and the
// global Approvals page.

import { useState } from 'react';
import type { HeldAction } from '../api/types';
import { useMe } from '../App';
import { ApprovalDialog, approvalToast, notUndoable } from '../components/ApprovalDialog';
import { ClassChip } from '../components/Chips';
import { IconAlert, SystemIcon } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { fmtAgo, fmtTime } from '../lib/format';
import { hasRole } from '../lib/permissions';
import { useNow } from '../lib/useNow';

/** Diary events after which held lists refresh. */
export function isHeldEvent(eventType: string): boolean {
  return (
    eventType === 'action.held' ||
    eventType === 'action.approved' ||
    eventType === 'action.denied' ||
    eventType === 'action.approval_vote' ||
    eventType === 'action.hold_expired' ||
    eventType === 'safe_form.executed'
  );
}

/** A pending hold past its expiry can no longer be decided (the expiry sweep will mark it). */
export function holdExpired(h: HeldAction, now: number): boolean {
  if (!h.expiresAt) return false;
  const t = Date.parse(h.expiresAt);
  return Number.isFinite(t) && t <= now;
}

export function HeldList({ held, showAgent, onChanged }: { held: HeldAction[]; showAgent?: boolean; onChanged: () => void }) {
  const me = useMe();
  const toast = useToast();
  const canDecide = hasRole(me, 'security');
  const [open, setOpen] = useState<{ h: HeldAction; mode: 'approve' | 'deny' } | null>(null);
  const now = useNow(15_000);

  return (
    <>
      {!canDecide && held.some((h) => h.outcome === 'pending' || h.outcome === '') && (
        <div className="alert info" style={{ margin: '12px 20px 0' }}>
          Approving and denying held actions requires the security role.
        </div>
      )}
      <div className="timeline" style={{ padding: '0 20px' }}>
        {held.map((h) => {
          const pending = h.outcome === 'pending' || h.outcome === '';
          const expired = pending && holdExpired(h, now);
          return (
            <div key={h.actionId} className="tl-item" data-testid="held-item">
              <div className="tl-time" title={fmtTime(h.createdAt)}>
                {fmtAgo(h.createdAt)}
              </div>
              <div className="tl-main">
                <div className="tl-line">
                  <ClassChip cls={h.class} label={h.class} />
                  <span className="sys-icon" title={h.system}>
                    <SystemIcon system={h.system} />
                  </span>
                  {showAgent && <strong>{h.agentId}</strong>}
                  <strong>
                    {h.system} {h.verb}
                  </strong>
                  {h.ruleId && <span className="rule">{h.ruleId}</span>}
                  <span className={`chip ${expired ? 'gray' : pending ? 'amber' : h.outcome === 'approved' ? 'green' : 'gray'}`}>{expired ? 'expired' : h.outcome || 'pending'}</span>
                  {notUndoable(h) && (
                    <span className="chip red" title="Fortik cannot undo this action once it runs">
                      <IconAlert size={12} /> NOT UNDOABLE
                    </span>
                  )}
                </div>
                {h.reason && <div className="tl-reason">{h.reason}</div>}
                {h.safeForm && (
                  <div className="tl-reason">
                    Safe form offered: <code>{h.safeForm}</code>
                  </div>
                )}
                <div className="muted small">
                  {h.approverRole && `approver: ${h.approverRole}`}
                  {h.approvalsRequired ? ` · ${h.approvalsRequired} approval(s)` : ''}
                  {h.expiresAt && ` · expires ${fmtTime(h.expiresAt)}`}
                  {h.levelAtDecision && ` · level at decision ${h.levelAtDecision}`}
                </div>
                {pending && !expired && (
                  <div className="btn-row" style={{ marginTop: 8 }}>
                    <button className="btn small primary" disabled={!canDecide} onClick={() => setOpen({ h, mode: 'approve' })} aria-label={`Approve ${h.system} ${h.verb} by ${h.agentId}`}>
                      Approve
                    </button>
                    <button className="btn small danger" disabled={!canDecide} onClick={() => setOpen({ h, mode: 'deny' })} aria-label={`Deny ${h.system} ${h.verb} by ${h.agentId}`}>
                      Deny
                    </button>
                  </div>
                )}
              </div>
            </div>
          );
        })}
      </div>
      {open && (
        <ApprovalDialog
          held={open.h}
          mode={open.mode}
          onDone={(r) => {
            toast(approvalToast(open.mode, open.h, r));
            onChanged();
          }}
          onClose={() => setOpen(null)}
        />
      )}
    </>
  );
}
