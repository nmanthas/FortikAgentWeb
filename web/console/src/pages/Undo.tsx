// Undo page (docs/PHASE4_DESIGN.md §5): every undo handle with what Undo
// will do. The Undo button exists only when the server says the handle is
// undoable; otherwise the row says NOT UNDOABLE and why.

import { useMemo, useState } from 'react';
import { listUndo, runUndo } from '../api/endpoints';
import type { UndoEntry } from '../api/types';
import { useMe } from '../App';
import { IconRefresh } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, ReasonDialog } from '../components/ui';
import { fmtAgo, fmtCountdown, fmtTime, titleCase } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { undoPermit } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

export function UndoPage() {
  const me = useMe();
  const toast = useToast();
  const permit = undoPermit(me);
  const list = useAsync<UndoEntry[]>((s) => listUndo('', s), []);
  const [onlyUndoable, setOnlyUndoable] = useState(false);
  const [query, setQuery] = useState('');
  const [pending, setPending] = useState<UndoEntry | null>(null);
  useLiveRefresh((e) => e.eventType.startsWith('undo.') || e.eventType.startsWith('retention.'), list.reload, 800);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (list.data ?? []).filter((u) => (!onlyUndoable || u.undoable) && (!q || [u.actionId, u.agentId, u.kind].some((f) => f.toLowerCase().includes(q))));
  }, [list.data, onlyUndoable, query]);

  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Undo</h2>
          <div className="sub">Undo handles are prepared before an action runs. Fortik never offers an undo it did not prepare.</div>
        </div>
        <div className="spacer" />
        <button className="btn" onClick={list.reload} aria-label="Refresh" title="Refresh">
          <IconRefresh size={16} />
        </button>
      </div>
      <div className="toolbar">
        <input className="input" style={{ width: 260 }} placeholder="Search action, agent, kind…" aria-label="Search undo handles" value={query} onChange={(e) => setQuery(e.target.value)} />
        <label className="check">
          <input type="checkbox" checked={onlyUndoable} onChange={(e) => setOnlyUndoable(e.target.checked)} /> Undoable only
        </label>
        <div className="spacer" />
        {!permit.ok && <span className="muted small">{permit.why}</span>}
      </div>
      {list.error && (
        <div className="card-pad">
          <ErrorBox error={list.error} onRetry={list.reload} />
        </div>
      )}
      {!list.data && list.loading && <Loading />}
      {list.data && (
        <div className="table-wrap">
          <table className="table" aria-label="Undo handles">
            <thead>
              <tr>
                <th>Action</th>
                <th>Kind</th>
                <th>What Undo does</th>
                <th>Status</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((u) => (
                <tr key={u.actionId} data-testid={`undo-${u.actionId}`}>
                  <td>
                    <div className="mono">{u.actionId}</div>
                    <div className="muted small">
                      {u.agentId || 'unknown agent'} · <span title={fmtTime(u.createdAt)}>{fmtAgo(u.createdAt)}</span>
                    </div>
                  </td>
                  <td>
                    <span className="rule">{u.kind || '—'}</span>
                  </td>
                  <td style={{ maxWidth: 360 }}>
                    {u.description}
                    {u.error && <div className="small" style={{ color: '#b91c1c' }}>Last attempt failed: {u.error}</div>}
                  </td>
                  <td>
                    <span className="chip gray">{titleCase(u.status || 'unknown')}</span>
                    {u.undoable && u.expiresAt && <div className="muted small" title={fmtTime(u.expiresAt)}>expires in {fmtCountdown(u.expiresAt)}</div>}
                    {u.usedBy && <div className="muted small">by {u.usedBy}</div>}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    {u.undoable ? (
                      <button className="btn small primary" disabled={!permit.ok} title={permit.why} onClick={() => setPending(u)}>
                        Undo
                      </button>
                    ) : (
                      <span className="not-undoable" data-testid="not-undoable">
                        NOT UNDOABLE
                        <span className="why">{u.whyNot}</span>
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="empty">{(list.data ?? []).length === 0 ? 'No undo handles yet.' : 'No handles match these filters.'}</div>}
        </div>
      )}
      {pending && (
        <ReasonDialog
          title={`Undo ${pending.actionId}?`}
          description={pending.description}
          confirmLabel="Undo"
          danger
          onConfirm={async (reason) => {
            const r = await runUndo(pending.actionId, reason);
            toast({ tone: 'green', title: `Undo of ${pending.actionId} completed`, body: r.status ? `Handle is now ${r.status}.` : undefined });
            list.reload();
          }}
          onClose={() => setPending(null)}
        />
      )}
    </section>
  );
}
