// Swarms (docs/PHASE5_DESIGN.md §1, §6): the list of detected swarms and one
// swarm's detail (members, root, signal, spawn tree, breakers, held calls),
// with Trip breaker / Suspend / Isolate / Kill swarm / Release and the sealed
// bundle export. Kill swarm shows its 7 steps ticking off across the members
// exactly as the server reported them; Release shows "1 of 2 approvals".

import { useEffect, useId, useMemo, useState, type ReactNode } from 'react';
import { Link, useNavigate, useParams } from 'react-router-dom';
import { getSwarm, listSwarms, releaseSwarm, swarmBundle, swarmOp } from '../api/endpoints';
import { approverKey, swarmActive } from '../api/normalize';
import type { ContainmentOp, ContainmentStep, StepStatus, Swarm, SwarmDetail, SwarmOp } from '../api/types';
import { useMe } from '../App';
import { LevelChip } from '../components/Chips';
import { ContainmentHistory, ContainmentResultView, OpStatusChip, StepStatusChip, opLabel, stepLabel } from '../components/Containment';
import { IconRefresh } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, Modal, ReasonField } from '../components/ui';
import { fmtAgo, fmtNum, fmtTime, titleCase } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { swarmPermissions, type Permit } from '../lib/permissions';
import { cleanReason, reasonOk } from '../lib/reason';
import { useAsync } from '../lib/useAsync';
import { HeldList } from './HeldList';

export const SIGNAL_LABEL: Record<string, string> = {
  action_hash: 'Identical action (Max-5 breaker)',
  spawn_tree: 'Spawn tree',
  copy_surge: 'Copy surge',
  converging_targets: 'Converging targets',
};
export const signalLabel = (k: string) => SIGNAL_LABEL[k] ?? titleCase(k || 'unknown');

const STATE_CHIP: Record<string, string> = { active: 'red', detected: 'red', tripped: 'red', frozen: 'orange', suspended: 'orange', isolated: 'orange', killed: 'black', released: 'green' };
export function SwarmStateChip({ state }: { state: string }) {
  return (
    <span className={`chip ${STATE_CHIP[state] ?? 'amber'}`} data-testid="swarm-state">
      <span className="dot" />
      {state}
    </span>
  );
}

const isSwarmEvent = (t: string) => t.startsWith('swarm.') || t.startsWith('containment.') || t === 'action.held';

/** The kill-swarm steps in plan order (docs/PHASE5_DESIGN.md §1), shown while the request runs. */
export const KILL_STEPS = [
  'Freeze spawning',
  'Hold every pending matching call',
  'Revoke live credentials',
  'Cancel queued jobs and retries',
  'Remove memory access',
  'Stop all copies',
  'Seal the Diary bundle',
];

/** Reveal delay per step when showing a kill result (tests set it to 0). */
export const swarmTiming = { tickMs: 220 };

// --- list ---------------------------------------------------------------------------------

export function SwarmsPage() {
  const { swarmId } = useParams();
  if (swarmId) return <SwarmDetailPage id={swarmId} />;
  return <SwarmList />;
}

function SwarmList() {
  const [state, setState] = useState('');
  const swarms = useAsync<Swarm[]>((s) => listSwarms(state, s), [state]);
  const navigate = useNavigate();
  useLiveRefresh((e) => e.eventType.startsWith('swarm.'), swarms.reload, 1000);
  const list = swarms.data ?? [];
  const active = list.filter((s) => swarmActive(s.state)).length;
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Swarms</h2>
          <div className="sub">Groups of agents or copies acting together: identical actions past the breaker, spawn trees, copy surges and converging targets.</div>
        </div>
        <div className="spacer" />
        {swarms.data && <span className="chip red">{active} active</span>}
        <button className="btn" onClick={swarms.reload} aria-label="Refresh" title="Refresh">
          <IconRefresh size={16} />
        </button>
      </div>
      <div className="toolbar">
        <label className="sr-only" htmlFor="swarm-state">
          State
        </label>
        <select id="swarm-state" className="select" style={{ width: 200 }} value={state} onChange={(e) => setState(e.target.value)}>
          <option value="">All states</option>
          <option value="active">Active</option>
          <option value="detected">Detected</option>
          <option value="breaker_tripped">Breaker tripped</option>
          <option value="suspended">Suspended</option>
          <option value="isolated">Isolated</option>
          <option value="killed">Killed</option>
          <option value="released">Released</option>
        </select>
      </div>
      {swarms.error && (
        <div className="card-pad">
          <ErrorBox error={swarms.error} onRetry={swarms.reload} />
        </div>
      )}
      {swarms.loading && !swarms.data && <Loading />}
      {swarms.data && list.length === 0 && <div className="empty">No swarms{state ? ` in state ${state}` : ''}.</div>}
      {list.length > 0 && (
        <div className="table-wrap">
          <table className="table" aria-label="Swarms">
            <thead>
              <tr>
                <th>Swarm</th>
                <th>State</th>
                <th>Signal</th>
                <th>Root</th>
                <th>Members</th>
                <th>Created</th>
              </tr>
            </thead>
            <tbody>
              {list.map((s) => (
                <tr
                  key={s.swarmId}
                  className="row"
                  tabIndex={0}
                  data-testid="swarm-row"
                  onClick={() => navigate(`/swarms/${encodeURIComponent(s.swarmId)}`)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') navigate(`/swarms/${encodeURIComponent(s.swarmId)}`);
                  }}
                >
                  <td>
                    <Link to={`/swarms/${encodeURIComponent(s.swarmId)}`} className="mono" onClick={(e) => e.stopPropagation()}>
                      {s.swarmId}
                    </Link>
                  </td>
                  <td>
                    <SwarmStateChip state={s.state} />
                  </td>
                  <td>{signalLabel(s.detectedBy)}</td>
                  <td>{s.root ?? <span className="muted">—</span>}</td>
                  <td>{fmtNum(s.memberCount)}</td>
                  <td title={fmtTime(s.createdAt)}>{fmtAgo(s.createdAt)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

// --- detail -------------------------------------------------------------------------------

type Dialog = { kind: 'op'; op: SwarmOp } | { kind: 'release' } | null;

function SwarmDetailPage({ id }: { id: string }) {
  const me = useMe();
  const toast = useToast();
  const swarm = useAsync<SwarmDetail>((s) => getSwarm(id, s), [id]);
  const [dialog, setDialog] = useState<Dialog>(null);
  const [exportErr, setExportErr] = useState<unknown>(null);
  const [exporting, setExporting] = useState(false);
  useLiveRefresh((e) => isSwarmEvent(e.eventType) && (e.data.swarm_id === undefined || e.data.swarm_id === id || e.data.target_id === id), swarm.reload, 1000);

  if (swarm.error && !swarm.data) return <ErrorBox error={swarm.error} onRetry={swarm.reload} />;
  if (!swarm.data) return <Loading label="Loading the swarm…" />;
  const s = swarm.data;
  const perm = swarmPermissions(me, s);
  const approvals = new Set(s.releaseVotes.map((v) => approverKey(v.approver))).size;

  const doExport = async () => {
    setExporting(true);
    setExportErr(null);
    try {
      const b = await swarmBundle(s.swarmId);
      downloadText(`fortik-swarm-${s.swarmId}-bundle.json`, b.text, b.contentType);
      toast({ tone: 'green', title: 'Bundle exported', body: `fortik-swarm-${s.swarmId}-bundle.json` });
    } catch (e) {
      setExportErr(e);
    } finally {
      setExporting(false);
    }
  };

  const btn = (label: string, p: Permit, onClick: () => void, cls = 'btn') => (
    <button className={cls} disabled={!p.ok} title={p.why} onClick={onClick}>
      {label}
    </button>
  );

  return (
    <>
      <div className="row">
        <Link to="/swarms">← All swarms</Link>
      </div>
      {swarm.error && <ErrorBox error={swarm.error} onRetry={swarm.reload} />}
      <section className="card" data-testid="swarm-detail">
        <div className="card-head" style={{ flexWrap: 'wrap' }}>
          <div className="grow">
            <h2 className="mono">{s.swarmId}</h2>
            <div className="sub">
              {signalLabel(s.detectedBy)} · {fmtNum(s.memberCount)} members · created {fmtTime(s.createdAt)}
              {s.root && <> · root {s.root}</>}
            </div>
          </div>
          <SwarmStateChip state={s.state} />
          {s.frozen && <span className="chip orange">Spawning frozen</span>}
        </div>
        <div className="card-pad">
          <div className="btn-row" data-testid="swarm-actions">
            {btn('Trip breaker', perm.trip, () => setDialog({ kind: 'op', op: 'trip' }), 'btn warn')}
            {btn('Suspend', perm.suspend, () => setDialog({ kind: 'op', op: 'suspend' }))}
            {btn('Isolate', perm.isolate, () => setDialog({ kind: 'op', op: 'isolate' }))}
            {btn('Kill swarm', perm.kill, () => setDialog({ kind: 'op', op: 'kill' }), 'btn danger')}
            {btn(`Release (${approvals} of ${s.releaseRequired})`, perm.release, () => setDialog({ kind: 'release' }))}
            <button className="btn" disabled={!perm.bundle.ok || exporting} title={perm.bundle.why} onClick={() => void doExport()}>
              {exporting && <span className="spinner" />} Export bundle
            </button>
          </div>
          <ReleaseProgress s={s} why={perm.release.why} />
          {[perm.trip, perm.kill].find((p) => !p.ok && /security/.test(p.why ?? '')) && <p className="help">Swarm actions require the security role. You can read everything here and export the bundle.</p>}
          <ErrorBox error={exportErr} />
        </div>
      </section>

      <div className="grid-2">
        <section className="card">
          <div className="card-head">
            <h2>Signal</h2>
          </div>
          <div className="card-pad">
            <div className="row" style={{ marginBottom: 8 }}>
              <span className="chip red">{signalLabel(s.signal.kind)}</span>
            </div>
            {s.signal.facts.length === 0 ? (
              <div className="muted small">The server reported no further detail for this signal.</div>
            ) : (
              <dl className="kv" data-testid="signal-facts">
                {s.signal.facts.map(([k, v]) => (
                  <FactRow key={k} k={titleCase(k)} v={v} />
                ))}
              </dl>
            )}
          </div>
        </section>
        <section className="card">
          <div className="card-head">
            <h2>Spawn tree</h2>
          </div>
          <div className="card-pad">
            <SpawnTree s={s} />
          </div>
        </section>
      </div>

      <section className="card">
        <div className="card-head">
          <h2>Members</h2>
          <span className="chip gray">{s.members.length}</span>
        </div>
        {s.members.length === 0 ? (
          <div className="empty">The server did not list the members.</div>
        ) : (
          <div className="table-wrap">
            <table className="table" aria-label="Members">
              <thead>
                <tr>
                  <th>Member</th>
                  <th>Role</th>
                  <th>Level</th>
                  <th>Status</th>
                  <th>Joined</th>
                </tr>
              </thead>
              <tbody>
                {s.members.map((m) => (
                  <tr key={m.id} data-testid="swarm-member">
                    <td>
                      <Link to={`/agents/${encodeURIComponent(m.agentId)}`}>{m.agentId}</Link>
                      {m.instanceId && <span className="muted small mono"> · copy {m.instanceId}</span>}
                    </td>
                    <td>{m.role ?? (m.agentId === s.root ? 'root' : 'member')}</td>
                    <td>{m.level ? <LevelChip level={m.level} /> : <span className="muted">—</span>}</td>
                    <td>{m.status ?? '—'}</td>
                    <td>{m.joinedAt ? fmtAgo(m.joinedAt) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <h2>Breakers</h2>
        </div>
        {s.breakers.length === 0 ? (
          <div className="empty">No breakers on this swarm.</div>
        ) : (
          <div className="table-wrap">
            <table className="table" aria-label="Breakers">
              <thead>
                <tr>
                  <th>Action hash</th>
                  <th>State</th>
                  <th>Tripped</th>
                  <th>By</th>
                  <th>Held</th>
                </tr>
              </thead>
              <tbody>
                {s.breakers.map((b, i) => (
                  <tr key={b.breakerId || i}>
                    <td className="mono small" title={b.actionHash}>
                      {b.actionHash.length > 20 ? `${b.actionHash.slice(0, 20)}…` : b.actionHash || '—'}
                    </td>
                    <td>
                      <span className={`chip ${b.state === 'tripped' ? 'red' : 'gray'}`}>{b.state}</span>
                    </td>
                    <td>{b.trippedAt ? fmtTime(b.trippedAt) : '—'}</td>
                    <td>{b.trippedBy ?? '—'}</td>
                    <td>{b.matched !== undefined ? fmtNum(b.matched) : '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="card">
        <div className="card-head">
          <div>
            <h2>Held calls</h2>
            <div className="sub">Calls the breaker or the kill held. Each needs two different security approvers.</div>
          </div>
          <span className="chip amber">{s.held.length}</span>
        </div>
        {s.held.length === 0 ? <div className="empty">No held calls.</div> : <HeldList held={s.held} showAgent onChanged={swarm.reload} />}
      </section>

      {s.ops.length > 0 && (
        <section className="card">
          <div className="card-head">
            <h2>Containment history</h2>
          </div>
          <div className="card-pad">
            <ContainmentHistory ops={s.ops} showTarget={false} />
          </div>
        </section>
      )}

      {dialog?.kind === 'op' && <SwarmOpDialog swarm={s} op={dialog.op} onDone={swarm.reload} onClose={() => setDialog(null)} />}
      {dialog?.kind === 'release' && (
        <ReleaseDialog
          swarm={s}
          onDone={(released, votes, required) => {
            toast(
              released
                ? { tone: 'green', title: `Swarm ${s.swarmId} released`, body: 'Breakers released, freeze lifted, members resumed. Killed members stay KILLED.' }
                : { tone: 'info', title: `Vote recorded (${votes} of ${required} approvals)`, body: 'A different security approver must give the second approval.' },
            );
            swarm.reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}

function FactRow({ k, v }: { k: string; v: string }) {
  return (
    <>
      <dt>{k}</dt>
      <dd className="mono small">{v}</dd>
    </>
  );
}

/** Two-approver progress for a swarm release. */
export function ReleaseProgress({ s, why }: { s: SwarmDetail; why?: string }) {
  const n = new Set(s.releaseVotes.map((v) => approverKey(v.approver))).size;
  return (
    <div className="release-box" data-testid="release-progress">
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <strong>Release</strong>
        <ApprovalBar n={n} of={s.releaseRequired} />
        {s.releaseVotes.map((v, i) => (
          <span key={i} className="muted small">
            {v.approver} voted {fmtAgo(v.at)}
          </span>
        ))}
      </div>
      <p className="help" style={{ margin: '4px 0 0' }}>
        {why && n > 0 ? `${why} ` : ''}Release needs {s.releaseRequired} different security approvers. The first vote is recorded; the second releases the breakers, lifts the freeze and resumes members.
        It never un-kills: killed members stay KILLED until security re-enables each one from its Level tab.
      </p>
    </div>
  );
}

export function ApprovalBar({ n, of }: { n: number; of: number }) {
  const pct = Math.min(100, Math.round((n / Math.max(1, of)) * 100));
  return (
    <span className="approval-bar" role="progressbar" aria-valuemin={0} aria-valuemax={of} aria-valuenow={n} aria-label={`${n} of ${of} approvals`}>
      <span className="track">
        <span className="fill" style={{ width: `${pct}%` }} />
      </span>
      <span className="txt">
        {n} of {of} approvals
      </span>
    </span>
  );
}

function SpawnTree({ s }: { s: SwarmDetail }) {
  const { roots, children } = useMemo(() => {
    const children = new Map<string, string[]>();
    const hasParent = new Set<string>();
    for (const e of s.spawnTree) {
      if (!children.has(e.parent)) children.set(e.parent, []);
      const l = children.get(e.parent)!;
      if (!l.includes(e.child)) l.push(e.child);
      hasParent.add(e.child);
    }
    const all = new Set([...children.keys(), ...hasParent]);
    let roots = [...all].filter((x) => !hasParent.has(x));
    if (s.root && all.has(s.root)) roots = [s.root, ...roots.filter((r) => r !== s.root)];
    return { roots, children };
  }, [s]);
  if (s.spawnTree.length === 0) return <div className="muted small">{s.root ? `Root ${s.root}; the server reported no spawn tree.` : 'No spawn tree reported for this swarm.'}</div>;
  const seen = new Set<string>();
  const render = (id: string, depth: number): ReactNode => {
    if (seen.has(id) || depth > 12) return null;
    seen.add(id);
    const kids = children.get(id) ?? [];
    return (
      <li key={`${id}-${depth}`}>
        <span className={`chain-node${id === s.root ? ' current' : ''}`}>{id}</span>
        {kids.length > 0 && <ul className="tree">{kids.map((k) => render(k, depth + 1))}</ul>}
      </li>
    );
  };
  return (
    <ul className="tree root" data-testid="spawn-tree" aria-label="Spawn tree">
      {roots.map((r) => render(r, 0))}
    </ul>
  );
}

// --- ops ------------------------------------------------------------------------------------

const OP_TEXT: Record<SwarmOp, { title: string; confirm: string; desc: string; danger?: boolean }> = {
  trip: { title: 'Trip breaker', confirm: 'Trip breaker', desc: "Holds every call matching the swarm's action hash (two approvers each). Nothing else changes." },
  suspend: { title: 'Suspend swarm', confirm: 'Suspend all members', desc: 'Runs suspend on every member: actions refused, live credentials revoked, queued jobs paused, copies told to pause. Reversible.' },
  isolate: { title: 'Isolate swarm', confirm: 'Isolate all members', desc: 'Steps every member down to ISOLATED: no external calls, no access to business systems.' },
  kill: {
    title: 'Kill swarm',
    confirm: 'Kill swarm',
    desc: 'Runs the 7 kill-swarm steps in order, each in parallel across members. Killed members stay KILLED; Release never un-kills.',
    danger: true,
  },
};

function SwarmOpDialog({ swarm, op, onDone, onClose }: { swarm: SwarmDetail; op: SwarmOp; onDone: () => void; onClose: () => void }) {
  const t = OP_TEXT[op];
  const [reason, setReason] = useState('');
  const [keepRoot, setKeepRoot] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<ContainmentOp | null>(null);
  const keepId = useId();

  const submit = async () => {
    if (!reasonOk(reason)) return;
    setBusy(true);
    setError(null);
    try {
      const r = await swarmOp(swarm.swarmId, op, cleanReason(reason), op === 'kill' ? keepRoot : undefined);
      setResult(r);
      onDone();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <Modal
        title={`${t.title} — result`}
        onClose={onClose}
        footer={
          <button className="btn primary" onClick={onClose}>
            Close
          </button>
        }
      >
        <SwarmOpResult op={result} />
      </Modal>
    );
  }
  return (
    <Modal
      title={`${t.title}: ${swarm.swarmId}?`}
      description={t.desc}
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className={`btn ${t.danger ? 'danger' : 'primary'}`} onClick={() => void submit()} disabled={busy || !reasonOk(reason)}>
            {busy && <span className="spinner" />} {t.confirm}
          </button>
        </>
      }
    >
      {op === 'kill' && (
        <>
          <ol className="steps" aria-label="Kill-swarm steps">
            {KILL_STEPS.map((name, i) => (
              <li key={name} className="step-row">
                <span className="step-n">{i + 1}</span>
                <span className="step-name">{name}</span>
                {busy && <span className="spinner" style={{ marginLeft: 'auto' }} />}
              </li>
            ))}
          </ol>
          <label className="check" htmlFor={keepId}>
            <input id={keepId} type="checkbox" checked={keepRoot} onChange={(e) => setKeepRoot(e.target.checked)} /> Keep the root at READ_ONLY instead of KILLED
          </label>
        </>
      )}
      <div className="muted small">{fmtNum(swarm.memberCount)} members.</div>
      <ReasonField value={reason} onChange={setReason} />
      <ErrorBox error={error} />
    </Modal>
  );
}

interface StepGroup {
  name: string;
  steps: ContainmentStep[];
  status: StepStatus;
  counts: Record<StepStatus, number>;
}

/** Groups per-member steps by name, in the order the server ran them. */
export function groupSteps(op: ContainmentOp): StepGroup[] {
  const order: string[] = [];
  const by = new Map<string, ContainmentStep[]>();
  for (const s of op.steps) {
    if (!by.has(s.name)) {
      by.set(s.name, []);
      order.push(s.name);
    }
    by.get(s.name)!.push(s);
  }
  return order.map((name) => {
    const steps = by.get(name)!;
    const counts: Record<StepStatus, number> = { done: 0, skipped: 0, failed: 0, unknown: 0 };
    for (const s of steps) counts[s.status]++;
    const status: StepStatus = counts.failed ? 'failed' : counts.unknown ? 'unknown' : counts.done ? 'done' : 'skipped';
    return { name, steps, status, counts };
  });
}

/** A swarm op's result: each step with a tick per member, revealed in order. */
export function SwarmOpResult({ op }: { op: ContainmentOp }) {
  const groups = useMemo(() => groupSteps(op), [op]);
  const [shown, setShown] = useState(swarmTiming.tickMs <= 0 ? groups.length : 0);
  const [raw, setRaw] = useState(false);
  useEffect(() => {
    if (shown >= groups.length) return;
    const t = setTimeout(() => setShown((n) => n + 1), swarmTiming.tickMs);
    return () => clearTimeout(t);
  }, [shown, groups.length]);
  const failed = groups.some((g) => g.status === 'failed' || g.status === 'unknown');
  return (
    <div className="op-result" data-testid="swarm-op-result">
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <strong>
          {opLabel(op.op)} · swarm {op.targetId}
        </strong>
        <OpStatusChip status={op.status} />
        {shown < groups.length && (
          <button className="btn small ghost" onClick={() => setShown(groups.length)}>
            Show all
          </button>
        )}
      </div>
      {op.httpError && (
        <div className="alert warn" role="alert">
          The server reported a problem: {op.httpError}
        </div>
      )}
      {(failed || (op.status !== 'done' && op.status !== 'running')) && (
        <p className="help" style={{ margin: 0 }}>
          Not every step succeeded on every member. Only the ticks marked done took effect; hover a tick for its detail.
        </p>
      )}
      {groups.length === 0 && <div className="muted small">The server did not report any steps for this operation.</div>}
      <ol className="steps" aria-label="Steps">
        {groups.map((g, i) => {
          const visible = i < shown;
          return (
            <li key={g.name} className={`step-row ${visible ? g.status : ''}`} data-testid="swarm-step" data-status={visible ? g.status : 'pending'}>
              <span className="step-n">{i + 1}</span>
              <div className="grow" style={{ minWidth: 0 }}>
                <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
                  <span className="step-name">{stepLabel(g.name)}</span>
                  {visible ? <StepStatusChip status={g.status} /> : <span className="spinner" aria-label="pending" />}
                  {visible && (
                    <span className="muted small" data-testid="swarm-step-counts">
                      {(['done', 'skipped', 'failed', 'unknown'] as StepStatus[])
                        .filter((k) => g.counts[k] > 0)
                        .map((k) => `${g.counts[k]} ${k}`)
                        .join(' · ')}
                    </span>
                  )}
                </div>
                {visible && (
                  <div className="member-ticks" aria-label={`${stepLabel(g.name)} per member`}>
                    {g.steps.map((s, j) => (
                      <span key={j} className={`tick ${s.status}`} title={`${s.agentId ?? 'swarm'}: ${s.status}${s.detail ? ` — ${s.detail}` : ''}`}>
                        <span className="sr-only">
                          {s.agentId ?? 'swarm'} {s.status}
                        </span>
                      </span>
                    ))}
                  </div>
                )}
                {visible &&
                  g.steps
                    .filter((s) => (s.status === 'failed' || s.status === 'unknown') && s.detail)
                    .slice(0, 5)
                    .map((s, j) => (
                      <div key={j} className="step-detail">
                        {s.agentId ? `${s.agentId}: ` : ''}
                        {s.detail}
                      </div>
                    ))}
                {visible && g.steps.length === 1 && g.steps[0]!.detail && g.steps[0]!.status !== 'failed' && <div className="step-detail">{g.steps[0]!.detail}</div>}
              </div>
            </li>
          );
        })}
      </ol>
      {groups.length > 0 && (
        <button className="btn small ghost" aria-expanded={raw} onClick={() => setRaw(!raw)}>
          {raw ? 'Hide every step' : 'Every step, per member'}
        </button>
      )}
      {raw && <ContainmentResultView op={op} />}
    </div>
  );
}

function ReleaseDialog({ swarm, onDone, onClose }: { swarm: SwarmDetail; onDone: (released: boolean, votes: number, required: number) => void; onClose: () => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [op, setOp] = useState<ContainmentOp | null>(null);
  const n = new Set(swarm.releaseVotes.map((v) => approverKey(v.approver))).size;
  const submit = async () => {
    if (!reasonOk(reason)) return;
    setBusy(true);
    setError(null);
    try {
      const r = await releaseSwarm(swarm.swarmId, cleanReason(reason));
      onDone(r.released, r.votes, r.required);
      if (r.op) setOp(r.op);
      else onClose();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  if (op)
    return (
      <Modal title="Release — result" onClose={onClose} footer={<button className="btn primary" onClick={onClose}>Close</button>}>
        <SwarmOpResult op={op} />
      </Modal>
    );
  return (
    <Modal
      title={`Release swarm ${swarm.swarmId}?`}
      description={
        n === 0
          ? `Your vote is the first of ${swarm.releaseRequired}. A different security approver must give the second before anything is released.`
          : `${n} of ${swarm.releaseRequired} approvals so far. Your vote releases the breakers, lifts the freeze and resumes members.`
      }
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => void submit()} disabled={busy || !reasonOk(reason)}>
            {busy && <span className="spinner" />} {n + 1 >= swarm.releaseRequired ? 'Release swarm' : 'Vote to release'}
          </button>
        </>
      }
    >
      <ApprovalBar n={n} of={swarm.releaseRequired} />
      <p className="help" style={{ margin: 0 }}>
        Killed members stay KILLED: re-enable each one from its Level tab (security).
      </p>
      <ReasonField value={reason} onChange={setReason} />
      <ErrorBox error={error} />
    </Modal>
  );
}

/** Saves text as a file (the bundle is kept byte-for-byte: it is signed). */
export function downloadText(filename: string, text: string, contentType = 'application/json') {
  if (typeof URL.createObjectURL !== 'function') throw new Error('This browser cannot save files.');
  const url = URL.createObjectURL(new Blob([text], { type: contentType.split(';')[0] || 'application/json' }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
