// Approval queue (docs/PHASE5_DESIGN.md §5, §6; Phase 3 §6): every held
// action with filters (status, agent, swarm, rule, class, assigned to),
// sorting, pagination, assignment, bulk deny with a reason, grouping of
// swarm-held calls and the "1 of 2 approvals" progress of two-approver holds.
//
// Uses GET /v1/approvals/queue; on a server without it, the Phase 3
// /v1/held list is filtered the same way in the browser.

import { useEffect, useId, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { assignHeld, bulkDeny, listAgents, listSwarms, loadQueue } from '../api/endpoints';
import type { ActionClass, Agent, BulkDenyOutcome, Me, QueueItem, QueueQuery, QueueResult, QueueSort, Swarm } from '../api/types';
import { useMe } from '../App';
import { ApprovalDialog, approvalToast, notUndoable } from '../components/ApprovalDialog';
import { ClassChip } from '../components/Chips';
import { IconAlert, IconRefresh, SystemIcon } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, Modal, ReasonField } from '../components/ui';
import { fmtAgo, fmtCountdown, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { hasRole, queuePermissions } from '../lib/permissions';
import { cleanReason, reasonOk } from '../lib/reason';
import { useAsync } from '../lib/useAsync';
import { useNow } from '../lib/useNow';
import { holdExpired, isHeldEvent } from './HeldList';
import { ApprovalBar } from './Swarms';

export const PAGE_SIZE = 25;
const CLASS_RANK: Record<ActionClass, number> = { red: 3, yellow: 2, blue: 1, green: 0 };

export interface QueueFilters {
  status: string;
  agentId: string;
  swarmId: string;
  ruleId: string;
  class: string;
  /** '' any, 'me', 'unassigned', or an email. */
  assigned: string;
  sort: QueueSort;
}

export const DEFAULT_FILTERS: QueueFilters = { status: 'pending', agentId: '', swarmId: '', ruleId: '', class: '', assigned: '', sort: 'severity' };

const isPending = (h: QueueItem) => h.outcome === 'pending' || h.outcome === '';

/** What the server is asked for (assigned "me" becomes the user's email). */
export function toQuery(f: QueueFilters, me: Me): QueueQuery {
  const assignedTo = f.assigned === 'me' ? me.email : f.assigned === 'unassigned' ? '' : f.assigned;
  return { status: f.status, agentId: f.agentId, swarmId: f.swarmId, ruleId: f.ruleId.trim(), class: f.class, assignedTo, sort: f.sort };
}

/** The same filters applied in the browser (needed on the /v1/held fallback; harmless on the queue). */
export function filterQueue(items: QueueItem[], f: QueueFilters, me: Me): QueueItem[] {
  const mine = me.email.toLowerCase();
  const rule = f.ruleId.trim().toLowerCase();
  return items.filter((h) => {
    if (f.status === 'pending' && !isPending(h)) return false;
    if (f.status && f.status !== 'pending' && f.status !== 'all' && h.outcome !== f.status) return false;
    if (f.agentId && h.agentId !== f.agentId) return false;
    if (f.swarmId && h.swarmId !== f.swarmId) return false;
    if (rule && !h.ruleId.toLowerCase().includes(rule)) return false;
    if (f.class && h.class !== f.class) return false;
    const a = (h.assignedTo ?? '').replace(/^user:/, '').toLowerCase();
    if (f.assigned === 'me' && a !== mine) return false;
    if (f.assigned === 'unassigned' && a !== '') return false;
    if (f.assigned && f.assigned !== 'me' && f.assigned !== 'unassigned' && a !== f.assigned.toLowerCase()) return false;
    return true;
  });
}

export function sortQueue(items: QueueItem[], sort: QueueSort): QueueItem[] {
  const l = [...items];
  const exp = (h: QueueItem) => (h.expiresAt ? Date.parse(h.expiresAt) : Number.POSITIVE_INFINITY);
  if (sort === 'newest') l.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  else if (sort === 'oldest') l.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  else if (sort === 'expires') l.sort((a, b) => exp(a) - exp(b) || b.createdAt.localeCompare(a.createdAt));
  else l.sort((a, b) => CLASS_RANK[b.class] - CLASS_RANK[a.class] || b.createdAt.localeCompare(a.createdAt));
  return l;
}

export function ApprovalsPage() {
  const me = useMe();
  const toast = useToast();
  const [f, setF] = useState<QueueFilters>(DEFAULT_FILTERS);
  const [page, setPage] = useState(0);
  const [group, setGroup] = useState(true);
  const [sel, setSel] = useState<Set<string>>(new Set());
  const [dialog, setDialog] = useState<{ kind: 'approve' | 'deny' | 'assign'; h: QueueItem } | { kind: 'bulk' } | null>(null);
  const q = toQuery(f, me);
  const queue = useAsync<QueueResult>((s) => loadQueue(q, s), [q.status, q.agentId, q.swarmId, q.ruleId, q.class, q.assignedTo, q.sort]);
  const agents = useAsync<Agent[]>((s) => listAgents(s).catch(() => []), []);
  const swarms = useAsync<Swarm[] | null>((s) => listSwarms('', s).catch(() => null), []);
  useLiveRefresh((e) => isHeldEvent(e.eventType) || e.eventType === 'action.assigned' || e.eventType.startsWith('held.'), queue.reload, 800);
  const now = useNow(15_000);
  const security = hasRole(me, 'security');

  const all = useMemo(() => sortQueue(filterQueue(queue.data?.items ?? [], f, me), f.sort), [queue.data, f, me]);
  const pages = Math.max(1, Math.ceil(all.length / PAGE_SIZE));
  const cur = Math.min(page, pages - 1);
  const shown = all.slice(cur * PAGE_SIZE, (cur + 1) * PAGE_SIZE);
  useEffect(() => setPage(0), [f]);
  // Drop selections that are no longer pending in the list.
  useEffect(() => {
    const ok = new Set(all.filter(isPending).map((h) => h.actionId));
    setSel((s) => new Set([...s].filter((id) => ok.has(id))));
  }, [all]);

  const set = <K extends keyof QueueFilters>(k: K, v: QueueFilters[K]) => setF((x) => ({ ...x, [k]: v }));
  const toggle = (id: string) =>
    setSel((s) => {
      const n = new Set(s);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });
  const selectable = shown.filter((h) => isPending(h) && !holdExpired(h, now));
  const allSelected = selectable.length > 0 && selectable.every((h) => sel.has(h.actionId));

  const groups = useMemo(() => {
    if (!group) return [{ key: '', title: '', items: shown }];
    const by = new Map<string, QueueItem[]>();
    for (const h of shown) {
      const k = h.swarmId ?? '';
      if (!by.has(k)) by.set(k, []);
      by.get(k)!.push(h);
    }
    return [...by.entries()].sort(([a], [b]) => (a === '' ? 1 : b === '' ? -1 : a.localeCompare(b))).map(([key, items]) => ({ key, title: key, items }));
  }, [shown, group]);

  const pendingCount = (queue.data?.items ?? []).filter(isPending).length;

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Approval queue</h2>
            <div className="sub">Actions held for a human decision across all agents. Swarm-held calls are grouped and need two different approvers.</div>
          </div>
          <div className="spacer" />
          <span className="chip amber">{queue.data ? `${pendingCount} pending` : '…'}</span>
          <button className="btn" onClick={queue.reload} aria-label="Refresh" title="Refresh">
            <IconRefresh size={16} />
          </button>
        </div>
        <div className="toolbar queue-filters" data-testid="queue-filters">
          <Select label="Status" value={f.status} onChange={(v) => set('status', v)} options={[['pending', 'Pending'], ['approved', 'Approved'], ['denied', 'Denied'], ['expired', 'Expired'], ['all', 'All']]} />
          <Select label="Agent" value={f.agentId} onChange={(v) => set('agentId', v)} options={[['', 'All agents'], ...(agents.data ?? []).map((a): [string, string] => [a.agentId, a.agentId])]} />
          {swarms.data ? (
            <Select label="Swarm" value={f.swarmId} onChange={(v) => set('swarmId', v)} options={[['', 'All swarms'], ...swarms.data.map((s): [string, string] => [s.swarmId, s.swarmId])]} />
          ) : (
            <TextFilter label="Swarm" value={f.swarmId} onChange={(v) => set('swarmId', v)} placeholder="swarm id" />
          )}
          <TextFilter label="Rule" value={f.ruleId} onChange={(v) => set('ruleId', v)} placeholder="POL-651" />
          <Select label="Class" value={f.class} onChange={(v) => set('class', v)} options={[['', 'All classes'], ['red', 'Dangerous (red)'], ['yellow', 'Risky (yellow)'], ['green', 'Normal (green)']]} />
          <Select label="Assigned to" value={f.assigned} onChange={(v) => set('assigned', v)} options={[['', 'Anyone'], ['me', 'Me'], ['unassigned', 'Unassigned']]} />
          <Select label="Sort" value={f.sort} onChange={(v) => set('sort', v as QueueSort)} options={[['severity', 'Most dangerous first'], ['newest', 'Newest first'], ['oldest', 'Oldest first'], ['expires', 'Expiring soonest']]} />
          <label className="check small">
            <input type="checkbox" checked={group} onChange={(e) => setGroup(e.target.checked)} /> Group by swarm
          </label>
        </div>
        {queue.data?.source === 'held' && (
          <div className="alert info" style={{ margin: '12px 20px 0' }}>
            This server has no approval queue yet (Phase 5). Showing held actions from /v1/held; assignment and bulk deny may be unavailable.
          </div>
        )}
        {!security && <div className="alert info" style={{ margin: '12px 20px 0' }}>Approving, denying and assigning held actions requires the security role.</div>}
        <div className="toolbar">
          <label className="check small">
            <input
              type="checkbox"
              checked={allSelected}
              disabled={!security || selectable.length === 0}
              aria-label="Select every pending action on this page"
              onChange={() =>
                setSel((s) => {
                  const n = new Set(s);
                  for (const h of selectable) {
                    if (allSelected) n.delete(h.actionId);
                    else n.add(h.actionId);
                  }
                  return n;
                })
              }
            />
            Select page
          </label>
          <button className="btn small danger" disabled={!security || sel.size === 0} onClick={() => setDialog({ kind: 'bulk' })} title={security ? undefined : 'Requires the security role.'}>
            Deny selected ({sel.size})
          </button>
          <div className="spacer" />
          <span className="muted small">
            {all.length} matching · page {cur + 1} of {pages}
          </span>
          <button className="btn small" disabled={cur === 0} onClick={() => setPage(cur - 1)}>
            Previous
          </button>
          <button className="btn small" disabled={cur >= pages - 1} onClick={() => setPage(cur + 1)}>
            Next
          </button>
        </div>
        {queue.error && (
          <div className="card-pad">
            <ErrorBox error={queue.error} onRetry={queue.reload} />
          </div>
        )}
        {queue.loading && !queue.data && <Loading />}
        {queue.data && all.length === 0 && <div className="empty">{f.status === 'pending' ? 'Nothing is waiting for approval.' : 'No held actions match these filters.'}</div>}
        {groups.map((g) => (
          <div key={g.key || 'none'} className="queue-group" data-testid={g.key ? 'swarm-group' : undefined}>
            {group && (g.key || groups.length > 1) && (
              <div className="queue-group-head">
                {g.key ? (
                  <>
                    <span className="chip red">swarm</span>
                    <Link to={`/swarms/${encodeURIComponent(g.key)}`} className="mono">
                      {g.key}
                    </Link>
                    <span className="muted small">{g.items.length} held on this page</span>
                  </>
                ) : (
                  <span className="muted small">Not in a swarm · {g.items.length}</span>
                )}
              </div>
            )}
            <div className="timeline" style={{ padding: '0 20px' }}>
              {g.items.map((h) => (
                <QueueRow key={h.actionId} h={h} me={me} now={now} selected={sel.has(h.actionId)} onToggle={() => toggle(h.actionId)} onOpen={(kind) => setDialog({ kind, h })} />
              ))}
            </div>
          </div>
        ))}
      </section>
      {dialog && (dialog.kind === 'approve' || dialog.kind === 'deny') && (
        <ApprovalDialog
          held={dialog.h}
          mode={dialog.kind}
          onDone={(r) => {
            toast(approvalToast(dialog.kind as 'approve' | 'deny', dialog.h, r));
            queue.reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === 'assign' && (
        <AssignDialog
          h={dialog.h}
          me={me}
          onDone={(who) => {
            toast({ tone: 'green', title: `Assigned to ${who}`, body: `${dialog.h.system} ${dialog.h.verb} by ${dialog.h.agentId}` });
            queue.reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === 'bulk' && (
        <BulkDenyDialog
          ids={[...sel]}
          onDone={(r) => {
            const ok = r.filter((x) => x.ok).length;
            toast({ tone: ok === r.length ? 'amber' : 'red', title: `Denied ${ok} of ${r.length}`, body: ok === r.length ? undefined : 'Some could not be denied; see the result.' });
            setSel(new Set());
            queue.reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}

function Select({ label, value, onChange, options }: { label: string; value: string; onChange: (v: string) => void; options: [string, string][] }) {
  const id = useId();
  return (
    <span className="filter">
      <label htmlFor={id} className="filter-label">
        {label}
      </label>
      <select id={id} className="select" value={value} onChange={(e) => onChange(e.target.value)}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
    </span>
  );
}

function TextFilter({ label, value, onChange, placeholder }: { label: string; value: string; onChange: (v: string) => void; placeholder?: string }) {
  const id = useId();
  const [draft, setDraft] = useState(value);
  useEffect(() => setDraft(value), [value]);
  useEffect(() => {
    if (draft === value) return;
    const t = setTimeout(() => onChange(draft), 400);
    return () => clearTimeout(t);
  }, [draft, value, onChange]);
  return (
    <span className="filter">
      <label htmlFor={id} className="filter-label">
        {label}
      </label>
      <input id={id} className="input" style={{ width: 130 }} value={draft} placeholder={placeholder} onChange={(e) => setDraft(e.target.value)} />
    </span>
  );
}

function QueueRow({ h, me, now, selected, onToggle, onOpen }: { h: QueueItem; me: Me; now: number; selected: boolean; onToggle: () => void; onOpen: (k: 'approve' | 'deny' | 'assign') => void }) {
  const pending = isPending(h);
  const expired = pending && holdExpired(h, now);
  const perm = queuePermissions(me, h);
  const required = h.approvalsRequired ?? 1;
  const what = `${h.system} ${h.verb} by ${h.agentId}`;
  return (
    <div className={`tl-item queue-item${selected ? ' selected' : ''}`} data-testid="held-item">
      <div className="tl-time">
        {pending && !expired && (
          <input type="checkbox" checked={selected} disabled={!perm.deny.ok} onChange={onToggle} aria-label={`Select ${what}`} style={{ marginRight: 6 }} />
        )}
        <span title={fmtTime(h.createdAt)}>{fmtAgo(h.createdAt)}</span>
      </div>
      <div className="tl-main">
        <div className="tl-line">
          <ClassChip cls={h.class} label={h.class} />
          <span className="sys-icon" title={h.system}>
            <SystemIcon system={h.system} />
          </span>
          <Link to={`/agents/${encodeURIComponent(h.agentId)}`}>
            <strong>{h.agentId}</strong>
          </Link>
          <strong>
            {h.system} {h.verb}
          </strong>
          {h.ruleId && <span className="rule">{h.ruleId}</span>}
          <span className={`chip ${expired ? 'gray' : pending ? 'amber' : h.outcome === 'approved' ? 'green' : 'gray'}`}>{expired ? 'expired' : h.outcome || 'pending'}</span>
          {h.swarmId && (
            <Link to={`/swarms/${encodeURIComponent(h.swarmId)}`} className="chip red">
              swarm {h.swarmId}
            </Link>
          )}
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
        <div className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
          {required > 1 || h.votes.length > 0 ? <ApprovalBar n={h.approvals} of={required} /> : null}
          {h.votes.map((v, i) => (
            <span key={i} className="muted small" data-testid="vote">
              {v.approver} {v.decision === 'deny' || v.decision === 'denied' ? 'denied' : 'approved'} {fmtAgo(v.at)}
            </span>
          ))}
          <span className="muted small">
            {h.assignedTo ? (
              <>
                assigned to <strong>{h.assignedTo}</strong>
              </>
            ) : (
              'unassigned'
            )}
            {h.expiresAt && pending && !expired && ` · expires in ${fmtCountdown(h.expiresAt, now)}`}
            {h.approverRole && ` · approver: ${h.approverRole}`}
          </span>
        </div>
        {pending && !expired && (
          <div className="btn-row" style={{ marginTop: 6 }}>
            <button className="btn small primary" disabled={!perm.approve.ok} title={perm.approve.why} onClick={() => onOpen('approve')} aria-label={`Approve ${what}`}>
              Approve
            </button>
            <button className="btn small danger" disabled={!perm.deny.ok} title={perm.deny.why} onClick={() => onOpen('deny')} aria-label={`Deny ${what}`}>
              Deny
            </button>
            <button className="btn small" disabled={!perm.assign.ok} title={perm.assign.why} onClick={() => onOpen('assign')} aria-label={`Assign ${what}`}>
              Assign
            </button>
            {perm.deny.ok && !perm.approve.ok && <span className="muted small">{perm.approve.why}</span>}
          </div>
        )}
      </div>
    </div>
  );
}

function AssignDialog({ h, me, onDone, onClose }: { h: QueueItem; me: Me; onDone: (who: string) => void; onClose: () => void }) {
  const [who, setWho] = useState(h.assignedTo?.replace(/^user:/, '') || me.email);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const id = useId();
  const ok = /^[^\s@]+@[^\s@]+$/.test(who.trim());
  const submit = async () => {
    if (!ok) return;
    setBusy(true);
    setError(null);
    try {
      await assignHeld(h.actionId, who.trim());
      onDone(who.trim());
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Assign ${h.system} ${h.verb} by ${h.agentId}`}
      description="The assignee is shown in the queue and can filter on “Assigned to: me”."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => void submit()} disabled={busy || !ok}>
            {busy && <span className="spinner" />} Assign
          </button>
        </>
      }
    >
      <div className="field">
        <label htmlFor={id}>
          Assignee email<span className="req">*</span>
        </label>
        <input id={id} className="input" value={who} autoFocus onChange={(e) => setWho(e.target.value)} aria-invalid={who !== '' && !ok} />
      </div>
      <div className="btn-row">
        <button className="btn small ghost" onClick={() => setWho(me.email)}>
          Assign to me
        </button>
      </div>
      <ErrorBox error={error} />
    </Modal>
  );
}

function BulkDenyDialog({ ids, onDone, onClose }: { ids: string[]; onDone: (r: BulkDenyOutcome[]) => void; onClose: () => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<BulkDenyOutcome[] | null>(null);
  const submit = async () => {
    if (!reasonOk(reason)) return;
    setBusy(true);
    setError(null);
    try {
      const r = await bulkDeny(ids, cleanReason(reason));
      setResult(r);
      onDone(r);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  if (result) {
    const failed = result.filter((r) => !r.ok);
    return (
      <Modal title="Bulk deny — result" onClose={onClose} footer={<button className="btn primary" onClick={onClose}>Close</button>}>
        <div data-testid="bulk-result">
          <p style={{ margin: 0 }}>
            {result.length - failed.length} of {result.length} denied. Each was decided and recorded on its own.
          </p>
          {failed.length > 0 && (
            <ul className="why-list">
              {failed.map((r) => (
                <li key={r.actionId}>
                  <span className="mono">{r.actionId}</span>: {r.error || r.outcome || 'not denied'}
                </li>
              ))}
            </ul>
          )}
        </div>
      </Modal>
    );
  }
  return (
    <Modal
      title={`Deny ${ids.length} held action${ids.length === 1 ? '' : 's'}?`}
      description="Each action is denied and recorded on its own with this reason. The agents get a denial; nothing runs."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn danger" onClick={() => void submit()} disabled={busy || !reasonOk(reason)}>
            {busy && <span className="spinner" />} Deny {ids.length}
          </button>
        </>
      }
    >
      <ReasonField value={reason} onChange={setReason} />
      <ErrorBox error={error} />
    </Modal>
  );
}
