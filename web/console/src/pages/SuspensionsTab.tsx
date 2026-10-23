// Agent → Suspensions: timed app suspensions (docs/PHASE3_DESIGN.md §5).
// Security, or the agent's owner, may suspend one system (or make it read
// only) for a fixed time or until released. Live credentials for that
// system are revoked on create; the restore worker lifts the suspension at
// expiry unless something happened that blocks it.

import { useId, useState } from 'react';
import { createOverride, extendOverride, listOverrides, makeOverridePermanent, releaseOverride } from '../api/endpoints';
import { isEnforced } from '../api/normalize';
import { OVERRIDE_SYSTEMS, type Agent, type Override, type OverrideMode, type OverrideSystem } from '../api/types';
import { useMe } from '../App';
import { IconClock } from '../components/Icons';
import { SuspensionChip, systemLabel } from '../components/SuspensionChip';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, Modal, ReasonDialog } from '../components/ui';
import { fmtDuration, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { hasRole, isOwner, overridePermissions } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

/** Duration presets; null = until released. */
export const DURATION_PRESETS: { label: string; seconds: number | null }[] = [
  { label: '15m', seconds: 15 * 60 },
  { label: '30m', seconds: 30 * 60 },
  { label: '1h', seconds: 3600 },
  { label: '4h', seconds: 4 * 3600 },
  { label: 'Until released', seconds: null },
];

const EXTEND_PRESETS = DURATION_PRESETS.filter((p): p is { label: string; seconds: number } => p.seconds !== null);

export function SuspensionsTab({ agent }: { agent: Agent }) {
  const me = useMe();
  const id = agent.agentId;
  const list = useAsync<Override[]>((s) => listOverrides(id, '', s), [id]);
  useLiveRefresh((e) => e.eventType.startsWith('override.') && (e.agentId === id || e.agentId === undefined), list.reload, 500);
  const canEdit = hasRole(me, 'security') || isOwner(me, agent);
  const [creating, setCreating] = useState(false);

  const enforced = (list.data ?? []).filter(isEnforced);
  const past = (list.data ?? []).filter((o) => !isEnforced(o));

  return (
    <>
      <div className="card card-pad">
        <div className="row" style={{ justifyContent: 'space-between' }}>
          <div className="section-title" style={{ margin: 0 }}>
            <IconClock size={16} /> App suspensions
          </div>
          <button className="btn primary" disabled={!canEdit} onClick={() => setCreating(true)}>
            Suspend an app
          </button>
        </div>
        <p className="help">
          Cut one app off (or make it read only) for a while without changing the agent&apos;s level. Live credentials for that app are revoked at once;
          access comes back automatically when the timer ends, unless the agent was quarantined or did something dangerous on that app meanwhile.
        </p>
        {!canEdit && <p className="help">Suspending apps requires the security role or ownership of this agent.</p>}
      </div>
      {list.error && <ErrorBox error={list.error} onRetry={list.reload} />}
      {list.loading && !list.data && <Loading />}
      {list.data && (
        <div className="card">
          <div className="card-head">
            <h2>In force</h2>
          </div>
          {enforced.length === 0 && <div className="empty">No app is suspended for this agent.</div>}
          <div className="timeline" style={{ padding: '0 20px' }}>
            {enforced.map((o) => (
              <OverrideRow key={o.overrideId} o={o} agent={agent} onChanged={list.reload} />
            ))}
          </div>
        </div>
      )}
      {past.length > 0 && (
        <div className="card">
          <div className="card-head">
            <h2>History</h2>
          </div>
          <div className="timeline" style={{ padding: '0 20px' }}>
            {past.map((o) => (
              <div key={o.overrideId} className="tl-item">
                <div className="tl-time">{fmtTime(o.startsAt)}</div>
                <div className="tl-main">
                  <div className="tl-line">
                    <strong>
                      {systemLabel(o.system)} {o.mode === 'read_only' ? 'read-only' : 'suspended'}
                    </strong>
                    <span className="chip gray">{o.status}</span>
                  </div>
                  <div className="muted small">
                    by {o.createdBy || 'unknown'} · “{o.reason}”{o.restoredAt && ` · ended ${fmtTime(o.restoredAt)}`}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
      {creating && <CreateDialog agentId={id} onClose={() => setCreating(false)} onCreated={list.reload} />}
    </>
  );
}

function OverrideRow({ o, agent, onChanged }: { o: Override; agent: Agent; onChanged: () => void }) {
  const me = useMe();
  const toast = useToast();
  const perm = overridePermissions(me, agent, o);
  const [act, setAct] = useState<'release' | 'extend' | 'permanent' | null>(null);
  const [extendBy, setExtendBy] = useState<number>(EXTEND_PRESETS[0]!.seconds);
  const label = systemLabel(o.system);
  return (
    <div className="tl-item">
      <div className="tl-time">{fmtTime(o.startsAt)}</div>
      <div className="tl-main">
        <div className="tl-line">
          <SuspensionChip o={o} />
        </div>
        <div className="muted small">
          by {o.createdBy || 'unknown'} · “{o.reason}”
        </div>
        {o.status === 'blocked' && (
          <div className="alert warn" style={{ marginTop: 6 }}>
            Automatic restore was blocked{o.blockedReason ? `: ${o.blockedReason}` : ''}. The suspension stays in force until released.
          </div>
        )}
        {o.scope === 'team' && <div className="muted small">Applies to the whole team {o.scopeId}.</div>}
        {o.revokeResult && Object.keys(o.revokeResult).length > 0 && (
          <div className="muted small">Credentials: {Object.entries(o.revokeResult).map(([k, v]) => `${k}: ${v}`).join('; ')}</div>
        )}
        <div className="btn-row" style={{ marginTop: 8 }}>
          <button className="btn small" disabled={!perm.canRelease} title={perm.releaseWhy} onClick={() => setAct('release')} aria-label={`Release ${label} now`}>
            Release now
          </button>
          <button className="btn small" disabled={!perm.canExtend} title={perm.extendWhy} onClick={() => setAct('extend')} aria-label={`Extend ${label} suspension`}>
            Extend
          </button>
          <button className="btn small" disabled={!perm.canPermanent} title={perm.permanentWhy} onClick={() => setAct('permanent')} aria-label={`Make ${label} suspension permanent`}>
            Make permanent
          </button>
        </div>
      </div>
      {act === 'release' && (
        <ReasonDialog
          title={`Release the ${label} suspension now?`}
          description="Access to the app returns at once, within the agent's access profile."
          confirmLabel="Release now"
          onConfirm={async (reason) => {
            await releaseOverride(o.overrideId, reason);
            toast({ tone: 'green', title: `${label} released` });
            onChanged();
          }}
          onClose={() => setAct(null)}
        />
      )}
      {act === 'permanent' && (
        <ReasonDialog
          title={`Make the ${label} suspension permanent?`}
          description="It stays in force until someone releases it."
          confirmLabel="Make permanent"
          danger
          onConfirm={async (reason) => {
            await makeOverridePermanent(o.overrideId, reason);
            toast({ tone: 'amber', title: `${label} suspended until released` });
            onChanged();
          }}
          onClose={() => setAct(null)}
        />
      )}
      {act === 'extend' && (
        <ReasonDialog
          title={`Extend the ${label} suspension`}
          description={
            <span className="preset-row" role="group" aria-label="Extend by">
              {EXTEND_PRESETS.map((p) => (
                <button key={p.label} type="button" className="btn small" aria-pressed={extendBy === p.seconds} onClick={() => setExtendBy(p.seconds)}>
                  +{p.label}
                </button>
              ))}
            </span>
          }
          confirmLabel={`Extend by ${fmtDuration(extendBy)}`}
          onConfirm={async (reason) => {
            await extendOverride(o.overrideId, extendBy, reason);
            toast({ tone: 'info', title: `${label} suspension extended by ${fmtDuration(extendBy)}` });
            onChanged();
          }}
          onClose={() => setAct(null)}
        />
      )}
    </div>
  );
}

function CreateDialog({ agentId, onClose, onCreated }: { agentId: string; onClose: () => void; onCreated: () => void }) {
  const toast = useToast();
  const [system, setSystem] = useState<OverrideSystem>('github');
  const [mode, setMode] = useState<OverrideMode>('suspended');
  const [preset, setPreset] = useState(2);
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const sysId = useId();
  const modeId = useId();
  const reasonId = useId();
  const p = DURATION_PRESETS[preset]!;

  const submit = async () => {
    const r = reason.trim();
    if (!r) return;
    setBusy(true);
    setError(null);
    try {
      const o = await createOverride({
        scope: 'agent',
        scope_id: agentId,
        system,
        mode,
        ...(p.seconds === null ? { until_released: true } : { duration_seconds: p.seconds }),
        reason: r,
      });
      toast({ tone: 'amber', title: `${systemLabel(system)} ${mode === 'read_only' ? 'made read-only' : 'suspended'} for ${agentId}`, body: o.expiresAt ? `Restores at ${fmtTime(o.expiresAt)}` : 'Until released' });
      onCreated();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };

  return (
    <Modal
      title={`Suspend an app for ${agentId}`}
      description="Live credentials for the app are revoked immediately."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn danger" onClick={() => void submit()} disabled={busy || reason.trim() === ''}>
            {busy && <span className="spinner" />} Suspend
          </button>
        </>
      }
    >
      <div className="form-grid">
        <div className="field">
          <label htmlFor={sysId}>App</label>
          <select id={sysId} className="select" value={system} onChange={(e) => setSystem(e.target.value as OverrideSystem)}>
            {OVERRIDE_SYSTEMS.map((s) => (
              <option key={s} value={s}>
                {systemLabel(s)}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={modeId}>Mode</label>
          <select id={modeId} className="select" value={mode} onChange={(e) => setMode(e.target.value as OverrideMode)}>
            <option value="suspended">Suspended — no access</option>
            <option value="read_only">Read only</option>
          </select>
        </div>
        <div className="field full">
          <span className="label">Duration</span>
          <div className="preset-row" role="group" aria-label="Duration">
            {DURATION_PRESETS.map((d, i) => (
              <button key={d.label} type="button" className="btn small" aria-pressed={preset === i} onClick={() => setPreset(i)}>
                {d.label}
              </button>
            ))}
          </div>
        </div>
        <div className="field full">
          <label htmlFor={reasonId}>
            Reason<span className="req">*</span>
          </label>
          <textarea id={reasonId} className="input" rows={3} maxLength={1000} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Recorded in the Diary and shown in refusals." />
        </div>
      </div>
      <ErrorBox error={error} />
    </Modal>
  );
}
