// Agent detail, Phase 4 tabs (docs/PHASE4_DESIGN.md §6): Containment
// (buttons with reason dialogs and per-step results), Memory (access mode,
// staged items with Flag/Drop, snapshots with Restore) and History (the
// containment operations that touched this agent, its team or the fleet).

import { useState } from 'react';
import {
  dropMemoryItem,
  flagMemoryItem,
  getAgentMemory,
  listContainment,
  listSnapshots,
  listStagedItems,
  memoryItemAddressable,
  memoryNamespaces,
  restoreSnapshot,
  runUndo,
} from '../api/endpoints';
import type { Agent, ContainmentOp, MemoryAccess, MemoryFlagResult, MemoryItem, MemoryMode, MemoryRestoreResult, MemorySnapshot } from '../api/types';
import { useMe } from '../App';
import { ContainmentHistory, ContainmentResultView } from '../components/Containment';
import { IconBrain, IconRefresh } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, ReasonDialog } from '../components/ui';
import { fmtAgo, fmtCountdown, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { containmentPermissions, undoPermit } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';
import { AgentControls, DETAIL_CONTROLS } from './AgentControls';

const isContainmentEvent = (t: string) => t.startsWith('containment.') || t === 'agent.suspended' || t === 'agent.resumed';

// --- Containment ---------------------------------------------------------------------

export function ContainmentTab({ agent, onChanged }: { agent: Agent; onChanged: () => void }) {
  const [last, setLast] = useState<ContainmentOp | null>(null);
  return (
    <>
      <div className="card card-pad">
        <div className="section-title">Containment</div>
        <dl className="kv" style={{ marginBottom: 14 }}>
          <dt>Suspended</dt>
          <dd data-testid="suspended-state" style={{ whiteSpace: 'pre-wrap' }}>
            {agent.suspended === undefined
              ? 'not reported by this server'
              : agent.suspended
                ? `yes${agent.suspendedAt ? `, ${fmtAgo(agent.suspendedAt)}` : ''}${agent.suspendedBy ? ` by ${agent.suspendedBy}` : ''}${agent.suspendedReason ? ` — ${agent.suspendedReason}` : ''}`
                : 'no'}
          </dd>
          <dt>Level</dt>
          <dd>{agent.level.replace('_', ' ')}</dd>
        </dl>
        <AgentControls
          key={agent.agentId}
          agent={agent}
          controls={DETAIL_CONTROLS}
          onChanged={(op) => {
            if (op) setLast(op);
            onChanged();
          }}
        />
        <p className="help">
          Suspend is reversible and keeps memory and state. Isolate steps the level down to ISOLATED. Kill and Cancel queue are not reversible from here:
          re-enabling a killed agent goes through the Level tab (security role), and cancelled jobs must be resubmitted.
        </p>
      </div>
      {last && (
        <div className="card card-pad">
          <div className="section-title">Last result</div>
          <ContainmentResultView op={last} />
        </div>
      )}
    </>
  );
}

// --- History -------------------------------------------------------------------------

async function agentHistory(agent: Agent, signal: AbortSignal): Promise<ContainmentOp[]> {
  const queries = [listContainment({ targetType: 'agent', targetId: agent.agentId, limit: 100 }, signal), listContainment({ targetType: 'fleet', limit: 50 }, signal)];
  if (agent.businessUnit) queries.push(listContainment({ targetType: 'team', targetId: agent.businessUnit, limit: 50 }, signal));
  const lists = await Promise.all(queries);
  const byId = new Map<string, ContainmentOp>();
  for (const op of lists.flat()) byId.set(op.opId, op);
  return [...byId.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export function ContainmentHistoryTab({ agent }: { agent: Agent }) {
  const ops = useAsync<ContainmentOp[]>((s) => agentHistory(agent, s), [agent.agentId, agent.businessUnit]);
  useLiveRefresh((e) => isContainmentEvent(e.eventType), ops.reload, 800);
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h2>Containment history</h2>
          <div className="sub">Operations on this agent{agent.businessUnit ? `, its team (${agent.businessUnit})` : ''} and the fleet, with every step.</div>
        </div>
        <div className="spacer" />
        <button className="btn small" onClick={ops.reload} aria-label="Refresh history">
          <IconRefresh size={14} />
        </button>
      </div>
      <div className="card-pad">
        {ops.error && <ErrorBox error={ops.error} onRetry={ops.reload} />}
        {!ops.data && ops.loading && <Loading />}
        {ops.data && <ContainmentHistory ops={ops.data} />}
      </div>
    </div>
  );
}

// --- Memory ----------------------------------------------------------------------------

const MODE_TEXT: Record<MemoryMode, { label: string; chip: string; help: string }> = {
  full: { label: 'Full', chip: 'green', help: 'Reads and writes allowed; writes are staged and promoted after the delay unless flagged.' },
  staging_only: { label: 'Staging only', chip: 'amber', help: 'Reads allowed; new writes stay staged and are never promoted while in this mode.' },
  none: { label: 'None', chip: 'red', help: 'No memory reads or writes. Existing memory is frozen, not deleted.' },
};

interface MemoryData {
  access: MemoryAccess | null;
  staged: MemoryItem[] | null;
  storeErrors: Record<string, string>;
  snapshots: MemorySnapshot[];
  /** No namespace of this agent is known: the snapshots of every namespace are listed. */
  allNamespaces: boolean;
  snapshotsError?: string;
}

async function loadMemory(agentId: string, signal: AbortSignal): Promise<MemoryData> {
  const view = await getAgentMemory(agentId, signal);
  // Older servers list staged items separately; the agent view includes them.
  const staged = view?.staged ?? (await listStagedItems(agentId, signal));
  const namespaces = [...new Set([...memoryNamespaces(view), ...(staged ?? []).map((i) => i.namespace).filter(Boolean)])];
  let snapshots: MemorySnapshot[] = [];
  let snapshotsError: string | undefined;
  try {
    const lists = namespaces.length ? await Promise.all(namespaces.map((n) => listSnapshots(n, signal))) : [await listSnapshots(undefined, signal)];
    const byId = new Map<string, MemorySnapshot>();
    for (const s of lists.flat()) byId.set(s.snapshotId, s);
    snapshots = [...byId.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  } catch (e) {
    if (signal.aborted) throw e;
    snapshotsError = e instanceof Error ? e.message : String(e);
  }
  return { access: view?.access ?? null, staged, storeErrors: view?.storeErrors ?? {}, snapshots, allNamespaces: namespaces.length === 0, snapshotsError };
}

const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** What a snapshot restore did, as the server reported it (memory.RestoreResult). */
export function restoreSummary(r: MemoryRestoreResult): string {
  const parts = [`${plural(r.restored, 'item')} restored.`];
  if (r.skippedRemovedItems.length) parts.push(`${plural(r.skippedRemovedItems.length, 'item')} removed on purpose since the snapshot (undo, drop or delete) not brought back.`);
  if (r.heldForReview.length) parts.push(`${plural(r.heldForReview.length, 'staged item')} held for review: not promoted until a new review window opens.`);
  if (r.undoHandlesClosed.length) parts.push(`${plural(r.undoHandlesClosed.length, 'undo handle')} of removed writes closed.`);
  parts.push(
    r.preRestoreSnapshotId
      ? `The previous state was kept as ${r.preRestoreSnapshotId} (never clean); restore it to undo this.`
      : 'A pre-restore snapshot was taken first, so this can be undone.',
  );
  return parts.join(' ');
}

/** What flagging did (memory.FlagResult); a failed snapshot check is reported, not hidden. */
export function flagToast(r: MemoryFlagResult): { tone: 'amber' | 'red'; title: string; body: string } {
  const parts = [r.alreadyPromoted ? 'It was already promoted; agents stop seeing it.' : 'It will not be promoted.'];
  if (r.snapshotsMarkedUnclean.length) parts.push(`${plural(r.snapshotsMarkedUnclean.length, 'snapshot')} marked not clean.`);
  if (r.snapshotCheckError) {
    parts.push(`The snapshots holding it could not be determined (${r.snapshotCheckError}), so every candidate snapshot was marked not clean.`);
    return { tone: 'red', title: 'Memory item flagged; snapshot check failed', body: parts.join(' ') };
  }
  return { tone: 'amber', title: 'Memory item flagged', body: parts.join(' ') };
}

type Pending = { kind: 'flag'; item: MemoryItem } | { kind: 'drop'; item: MemoryItem } | { kind: 'restore'; snap: MemorySnapshot };

export function MemoryTab({ agent }: { agent: Agent }) {
  const me = useMe();
  const toast = useToast();
  const perms = containmentPermissions(me, agent);
  const undo = undoPermit(me);
  const mem = useAsync<MemoryData>((s) => loadMemory(agent.agentId, s), [agent.agentId]);
  const [pending, setPending] = useState<Pending | null>(null);
  useLiveRefresh((e) => e.eventType.startsWith('memory.') || (e.agentId === agent.agentId && isContainmentEvent(e.eventType)), mem.reload, 800);

  if (mem.error) return <ErrorBox error={mem.error} onRetry={mem.reload} />;
  if (!mem.data) return <Loading />;
  const { access, staged, storeErrors, snapshots, allNamespaces, snapshotsError } = mem.data;
  const mode = access ? MODE_TEXT[access.mode] : null;

  const confirm = async (reason: string) => {
    if (!pending) return;
    if (pending.kind === 'flag') {
      const r = await flagMemoryItem(pending.item, reason);
      toast(flagToast(r));
    } else if (pending.kind === 'drop') {
      if (memoryItemAddressable(pending.item)) await dropMemoryItem(pending.item, reason);
      else if (pending.item.actionId) await runUndo(pending.item.actionId, reason);
      else throw new Error('This staged item does not say where it is stored.');
      toast({ tone: 'amber', title: 'Staged memory item dropped' });
    } else {
      const r = await restoreSnapshot(pending.snap.snapshotId, reason);
      toast({ tone: 'amber', title: `Namespace ${pending.snap.namespace} restored`, body: restoreSummary(r) });
    }
    mem.reload();
  };

  return (
    <>
      <div className="card card-pad">
        <div className="section-title">
          <IconBrain size={16} /> Memory access
        </div>
        {access && mode ? (
          <>
            <div className="row" style={{ flexWrap: 'wrap' }}>
              <span className={`chip ${mode.chip}`} data-testid="memory-mode">
                <span className="dot" />
                {mode.label}
              </span>
              {access.changedAt && (
                <span className="muted small">
                  changed {fmtAgo(access.changedAt)}
                  {access.changedBy && ` by ${access.changedBy}`}
                  {access.reason && ` — ${access.reason}`}
                </span>
              )}
            </div>
            <p className="help">{mode.help} Use Remove memory / Restore memory on the Containment tab to change it.</p>
            {access.namespaces.length > 0 && <div className="muted small">Namespaces: {access.namespaces.join(', ')}</div>}
          </>
        ) : (
          <div className="muted">This server does not report memory access per agent.</div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <div>
            <h2>Staged items</h2>
            <div className="sub">Writes wait in staging before promotion. Flag one to stop its promotion, or Drop it (undo of the write).</div>
          </div>
        </div>
        {Object.keys(storeErrors).length > 0 && (
          <div className="card-pad" style={{ paddingBottom: 0 }}>
            <div className="alert warn" role="alert" data-testid="store-errors">
              <div>
                Some memory stores could not be read, so their staged items are not listed:
                <ul style={{ margin: '4px 0 0', paddingLeft: 18 }}>
                  {Object.entries(storeErrors)
                    .sort(([a], [b]) => a.localeCompare(b))
                    .map(([store, msg]) => (
                      <li key={store}>
                        <span className="mono">{store === '*' ? 'all stores' : store}</span>: {msg}
                      </li>
                    ))}
                </ul>
              </div>
            </div>
          </div>
        )}
        {staged === null && <div className="empty">This server does not list staged memory items.</div>}
        {staged && staged.length === 0 && <div className="empty">No staged items for this agent.</div>}
        {staged && staged.length > 0 && (
          <div className="table-wrap">
            <table className="table" aria-label="Staged memory items">
              <thead>
                <tr>
                  <th>Item</th>
                  <th>Namespace</th>
                  <th>Promotion</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {staged.map((it) => (
                  <tr key={it.id}>
                    <td style={{ maxWidth: 320 }}>
                      <div className="mem-preview">{it.contentPreview || <span className="muted">(empty)</span>}</div>
                      <div className="muted small mono">
                        {it.storeKey ? `${it.storeKey} · ` : ''}
                        {it.id}
                      </div>
                      {it.labels.length > 0 && (
                        <div className="row" style={{ gap: 4, flexWrap: 'wrap', marginTop: 4 }}>
                          {it.labels.map((l) => (
                            <span key={l} className="chip amber">
                              {l}
                            </span>
                          ))}
                        </div>
                      )}
                    </td>
                    <td className="mono">{it.namespace}</td>
                    <td>
                      {it.flagged ? (
                        <span className="chip red">flagged: not promoted</span>
                      ) : it.promoteAt ? (
                        <span title={fmtTime(it.promoteAt)}>in {fmtCountdown(it.promoteAt)}</span>
                      ) : (
                        <span className="chip amber" data-testid="held-for-review" style={{ whiteSpace: 'normal' }}>
                          held for review: {it.holdReason ?? 'not scheduled for promotion'}
                        </span>
                      )}
                    </td>
                    <td>
                      <div className="btn-row" style={{ justifyContent: 'flex-end' }}>
                        <button
                          className="btn small"
                          disabled={!perms.flagItem.ok || it.flagged || !memoryItemAddressable(it)}
                          title={
                            !perms.flagItem.ok
                              ? perms.flagItem.why
                              : it.flagged
                                ? 'Already flagged'
                                : !memoryItemAddressable(it)
                                  ? 'This listing does not say which store and namespace the item is in.'
                                  : undefined
                          }
                          onClick={() => setPending({ kind: 'flag', item: it })}
                        >
                          Flag
                        </button>
                        <button
                          className="btn small"
                          disabled={memoryItemAddressable(it) ? !perms.flagItem.ok : !undo.ok || !it.actionId}
                          title={
                            memoryItemAddressable(it)
                              ? perms.flagItem.ok
                                ? undefined
                                : perms.flagItem.why
                              : !undo.ok
                                ? undo.why
                                : !it.actionId
                                  ? 'This listing does not say where the item is stored: drop it from the Undo page (kind memory_staging).'
                                  : undefined
                          }
                          onClick={() => setPending({ kind: 'drop', item: it })}
                        >
                          Drop
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="card">
        <div className="card-head">
          <div>
            <h2>Snapshots</h2>
            <div className="sub">Pointers to snapshots kept in your memory store. Restoring replaces the namespace with the snapshot&apos;s contents.</div>
          </div>
        </div>
        {snapshotsError && (
          <div className="card-pad">
            <ErrorBox error={new Error(`Snapshots could not be loaded: ${snapshotsError}`)} onRetry={mem.reload} />
          </div>
        )}
        {!snapshotsError && allNamespaces && snapshots.length > 0 && (
          <p className="help" style={{ padding: '10px 20px 0', margin: 0 }} data-testid="all-namespaces">
            The server does not say which namespaces this agent uses, so snapshots of every namespace are listed.
          </p>
        )}
        {!snapshotsError && snapshots.length === 0 && <div className="empty">No snapshots{allNamespaces ? '' : ' for this agent\u2019s namespaces'}.</div>}
        {snapshots.length > 0 && (
          <div className="table-wrap">
            <table className="table" aria-label="Memory snapshots">
              <thead>
                <tr>
                  <th>Namespace</th>
                  <th>Items</th>
                  <th>Taken</th>
                  <th>State</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {snapshots.map((s) => (
                  <tr key={s.snapshotId}>
                    <td className="mono">{s.namespace}</td>
                    <td>{s.itemCount}</td>
                    <td title={fmtTime(s.createdAt)}>
                      {fmtAgo(s.createdAt)}
                      <div className="muted small">{s.createdBy}</div>
                    </td>
                    <td>
                      {s.purgedAt ? <span className="chip gray">purged</span> : s.clean ? <span className="chip green">clean</span> : <span className="chip amber" title="Holds a flagged or not yet reviewed staged item, or is a pre-restore copy: never offered as a rollback target.">not clean</span>}
                    </td>
                    <td>
                      <button
                        className="btn small"
                        disabled={!perms.restoreSnapshot.ok || !!s.purgedAt}
                        title={!perms.restoreSnapshot.ok ? perms.restoreSnapshot.why : s.purgedAt ? 'Purged by retention' : undefined}
                        onClick={() => setPending({ kind: 'restore', snap: s })}
                      >
                        Restore
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {!perms.restoreSnapshot.ok && <p className="help" style={{ padding: '0 20px 14px' }}>{perms.restoreSnapshot.why}</p>}
      </div>

      {pending && (
        <ReasonDialog
          title={pending.kind === 'flag' ? 'Flag this memory item?' : pending.kind === 'drop' ? 'Drop this staged item?' : `Restore ${pending.snap.namespace}?`}
          description={
            pending.kind === 'flag'
              ? 'The item stays staged and will not be promoted; snapshots taken while it is flagged are not clean.'
              : pending.kind === 'drop'
                ? 'Runs the write’s undo: the staged item is deleted before promotion.'
                : `The namespace is replaced by this snapshot (${pending.snap.itemCount} items, ${fmtAgo(pending.snap.createdAt)}). A pre-restore snapshot is taken first.`
          }
          confirmLabel={pending.kind === 'flag' ? 'Flag' : pending.kind === 'drop' ? 'Drop item' : 'Restore snapshot'}
          danger={pending.kind !== 'flag'}
          onConfirm={confirm}
          onClose={() => setPending(null)}
        />
      )}
    </>
  );
}
