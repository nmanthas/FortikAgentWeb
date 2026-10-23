// Agent → Instances: running copies against the copy cap
// (docs/PHASE3_DESIGN.md §2.1, §2.6).

import { useEffect, useState } from 'react';
import { listInstances, pauseExtraInstances } from '../api/endpoints';
import type { Agent, Instance, InstancesView } from '../api/types';
import { useMe } from '../App';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, ReasonDialog } from '../components/ui';
import { fmtAgo, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { hasRole, isOwner } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

/** Matches population.heartbeat_interval's default. */
const INSTANCE_POLL_MS = 15_000;

const STATUS_COLOR: Record<string, string> = { live: 'green', paused: 'amber', refused: 'red', stopped: 'gray', stale: 'gray' };

export function InstancesTab({ agent }: { agent: Agent }) {
  const me = useMe();
  const toast = useToast();
  const id = agent.agentId;
  const view = useAsync<InstancesView>((s) => listInstances(id, s), [id]);
  useLiveRefresh((e) => e.agentId === id && (e.eventType.startsWith('instance.') || e.eventType === 'alert.raised'), view.reload, 800);
  // Liveness is heartbeat-based and heartbeats are not Diary events: poll so
  // copies that stop heartbeating drop out of the live count.
  const reload = view.reload;
  useEffect(() => {
    const t = setInterval(reload, INSTANCE_POLL_MS);
    return () => clearInterval(t);
  }, [reload]);
  const [confirm, setConfirm] = useState(false);

  const v = view.data;
  const cap = v?.copyCap ?? agent.copyCap;
  const over = v !== undefined && cap !== null && v.live > cap;
  const extra = v && cap !== null ? Math.max(0, v.live - cap) : 0;
  const canPause = hasRole(me, 'security') || isOwner(me, agent);

  return (
    <>
      <div className="card card-pad">
        <div className="section-title">Running copies</div>
        {view.error && <ErrorBox error={view.error} onRetry={view.reload} />}
        {!v && view.loading && <Loading />}
        {v && (
          <div className="row" style={{ alignItems: 'center', gap: 16 }}>
            <span className={`cap-figure${over ? ' over' : ''}`} data-testid="instance-count">
              {v.live} of {cap ?? '—'}
            </span>
            <span className="muted">live copies vs. copy cap</span>
            <span className="spacer" />
            <button className="btn danger" disabled={!canPause || !over} onClick={() => setConfirm(true)} aria-label={`Pause extra copies of ${id}`}>
              Pause extra
            </button>
          </div>
        )}
        {over && (
          <div className="alert warn" style={{ marginTop: 12 }}>
            More copies are running than allowed. New copies get no credentials (POL-701); Pause extra stops the newest ones above the cap.
          </div>
        )}
        {!canPause && <p className="help">Pausing copies requires the security role or ownership of this agent.</p>}
      </div>
      {v && (
        <div className="card">
          <div className="card-head">
            <h2>Instances</h2>
          </div>
          {v.instances.length === 0 ? (
            <div className="empty">No instances registered.</div>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Instance</th>
                    <th>Host</th>
                    <th>Status</th>
                    <th>Started</th>
                    <th>Last heartbeat</th>
                  </tr>
                </thead>
                <tbody>
                  {v.instances.map((i: Instance) => (
                    <tr key={i.instanceId}>
                      <td>
                        <code>{i.instanceId}</code>
                        {i.parentInstanceId && <div className="muted small">from {i.parentInstanceId}</div>}
                      </td>
                      <td>
                        {i.host || '—'} {i.newHost && <span className="chip amber" title="First time this agent was seen on this host">new host</span>}
                      </td>
                      <td>
                        <span className={`chip ${STATUS_COLOR[i.status] ?? 'gray'}`}>{i.status}</span>
                        {i.reason && <div className="muted small">{i.reason}</div>}
                      </td>
                      <td title={fmtTime(i.startedAt)}>{fmtAgo(i.startedAt)}</td>
                      <td title={fmtTime(i.lastHeartbeat)}>{fmtAgo(i.lastHeartbeat)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {confirm && v && (
        <ReasonDialog
          title={`Pause extra copies of ${id}?`}
          description={`The newest ${extra} live ${extra === 1 ? 'copy' : 'copies'} above the cap of ${cap ?? 0} will be paused: they must stop at their next heartbeat and every action they attempt is refused.`}
          confirmLabel="Pause extra"
          danger
          onConfirm={async (reason) => {
            const r = await pauseExtraInstances(id, reason);
            toast({
              tone: 'amber',
              title: r.paused.length ? `Paused ${r.paused.length} extra ${r.paused.length === 1 ? 'copy' : 'copies'} of ${id}` : `No copies of ${id} were above the cap`,
            });
            view.reload();
          }}
          onClose={() => setConfirm(false)}
        />
      )}
    </>
  );
}
