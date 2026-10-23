// Right-side agent detail panel: Overview, Baseline, Containment, Memory, Access, Level,
// Held, Suspensions, Instances, Delegations, Tokens, History.

import { useState } from 'react';
import { getAgent, getAgentStats, issueToken, listActions, listHeld, revokeTokens, setLevel } from '../api/endpoints';
import { LEVELS } from '../api/normalize';
import type { ActionClass, ActionRow, AgentDetail, AgentStats, HeldAction, Level } from '../api/types';
import { useMe } from '../App';
import { DonutLegend } from './DonutLegend';
import { BarChart, Donut, MIX_COLORS } from '../components/Charts';
import { ClassChip, CLASS_COLOR, classLabel, DecisionChip, LEVEL_SOLID, LevelChip } from '../components/Chips';
import { IconArrowDown, IconArrowUp, IconBot, IconCopy, IconKey, IconSkull, IconX, SystemIcon } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, Modal, ReasonDialog } from '../components/ui';
import { fmtAgo, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { hasRole, levelPermissions } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';
import { AccessTab } from './AccessTab';
import { BaselineTab } from './BaselineTab';
import { ContainmentHistoryTab, ContainmentTab, MemoryTab } from './ContainmentTab';
import { DelegationsTab } from './DelegationsTab';
import { HeldList, isHeldEvent } from './HeldList';
import { InstancesTab } from './InstancesTab';
import { SuspensionsTab } from './SuspensionsTab';

type Tab = 'overview' | 'baseline' | 'containment' | 'memory' | 'access' | 'level' | 'held' | 'suspensions' | 'instances' | 'delegations' | 'tokens' | 'history';

export function AgentPanel({ agentId, onClose, onChanged }: { agentId: string; onClose: () => void; onChanged: () => void }) {
  const detail = useAsync<AgentDetail>((s) => getAgent(agentId, s), [agentId]);
  const [tab, setTab] = useState<Tab>('overview');

  useLiveRefresh((e) => e.agentId === agentId, detail.reload, 800);

  const a = detail.data?.agent;
  const pending = detail.data?.held.length ?? 0;
  const changed = () => {
    detail.reload();
    onChanged();
  };

  return (
    <>
      <div className="overlay" onClick={onClose} />
      <aside className="panel" role="dialog" aria-modal="true" aria-label={`Agent ${agentId}`}>
        <div className="panel-head">
          <div className="panel-title">
            <span className="agent-avatar" style={{ width: 40, height: 40 }}>
              <IconBot />
            </span>
            <div className="grow">
              <h2>{agentId}</h2>
              <div className="meta">
                {a ? [a.name, a.type, a.platform, a.sponsor && `owner ${a.sponsor}`].filter(Boolean).join(' · ') || 'no details' : '…'}
              </div>
            </div>
            {a?.suspended && <span className="chip orange">Suspended</span>}
            {a && <LevelChip level={a.level} />}
            <button className="icon-btn" onClick={onClose} aria-label="Close panel">
              <IconX />
            </button>
          </div>
          <div className="tabs" role="tablist">
            {(
              [
                ['overview', 'Overview'],
                ['baseline', 'Baseline'],
                ['containment', 'Containment'],
                ['memory', 'Memory'],
                ['access', 'Access'],
                ['level', 'Level'],
                ['held', 'Held'],
                ['suspensions', 'Suspensions'],
                ['instances', 'Instances'],
                ['delegations', 'Delegations'],
                ['tokens', 'Tokens'],
                ['history', 'History'],
              ] as [Tab, string][]
            ).map(([k, label]) => (
              <button key={k} role="tab" aria-selected={tab === k} className={`tab${tab === k ? ' active' : ''}`} onClick={() => setTab(k)}>
                {label}
                {k === 'held' && pending > 0 && <span className="count">{pending}</span>}
              </button>
            ))}
          </div>
        </div>
        <div className="panel-body">
          {detail.error && <ErrorBox error={detail.error} onRetry={detail.reload} />}
          {!detail.data && detail.loading && <Loading />}
          {detail.data && (
            <>
              {tab === 'overview' && <OverviewTab d={detail.data} />}
              {tab === 'baseline' && <BaselineTab agentId={agentId} />}
              {tab === 'containment' && <ContainmentTab agent={detail.data.agent} onChanged={changed} />}
              {tab === 'memory' && <MemoryTab agent={detail.data.agent} />}
              {tab === 'access' && <AccessTab agent={detail.data.agent} />}
              {tab === 'level' && <LevelTab d={detail.data} onChanged={changed} />}
              {tab === 'held' && <HeldTab agentId={agentId} />}
              {tab === 'suspensions' && <SuspensionsTab agent={detail.data.agent} />}
              {tab === 'instances' && <InstancesTab agent={detail.data.agent} />}
              {tab === 'delegations' && <DelegationsTab agentId={agentId} />}
              {tab === 'tokens' && <TokensTab d={detail.data} onChanged={changed} />}
              {tab === 'history' && <ContainmentHistoryTab agent={detail.data.agent} />}
            </>
          )}
        </div>
      </aside>
    </>
  );
}

// --- Overview ---------------------------------------------------------------------

function hourLabel(iso: string | undefined, i: number, hours: number): string {
  if (iso) {
    const t = Date.parse(iso);
    if (Number.isFinite(t)) return new Date(t).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }
  return `-${hours - i}h`;
}

function OverviewTab({ d }: { d: AgentDetail }) {
  const id = d.agent.agentId;
  const stats = useAsync<AgentStats>((s) => getAgentStats(id, 24, s), [id]);
  const actions = useAsync<ActionRow[]>((s) => listActions(id, 25, s), [id]);
  useLiveRefresh(
    (e) => e.agentId === id && e.eventType.startsWith('action.'),
    () => {
      stats.reload();
      actions.reload();
    },
    800,
  );

  const s = stats.data;
  const verbs = s ? Object.entries(s.byVerb).sort((x, y) => y[1] - x[1]) : [];
  const top = verbs.slice(0, 7);
  const rest = verbs.slice(7).reduce((acc, [, n]) => acc + n, 0);
  const slices = [...top.map(([label, value], i) => ({ label, value, color: MIX_COLORS[i % MIX_COLORS.length]! })), ...(rest ? [{ label: 'OTHER', value: rest, color: '#cbd5e1' }] : [])];
  const classes: ActionClass[] = ['green', 'blue', 'yellow', 'red'];
  const counts = s?.byClass ?? d.counts24h;

  return (
    <>
      <div className="grid-2">
        <div className="card card-pad">
          <div className="section-title">Action mix (24h)</div>
          {stats.error && <ErrorBox error={stats.error} onRetry={stats.reload} />}
          {s && (
            <div className="row" style={{ gap: 16, alignItems: 'center' }}>
              <Donut slices={slices} center={String(s.total)} />
              <DonutLegend slices={slices} />
            </div>
          )}
          {!s && stats.loading && <Loading />}
        </div>
        <div className="card card-pad">
          <div className="section-title">Classes (24h)</div>
          <div className="stat-list">
            {classes.map((c) => (
              <div key={c} className="stat-row">
                <span className="legend-dot" style={{ background: CLASS_COLOR[c] }} />
                {classLabel(c)} <span className="muted small">({c})</span>
                <span className="n">{counts[c]}</span>
              </div>
            ))}
          </div>
          <dl className="kv" style={{ marginTop: 14 }}>
            <dt>Workspace user</dt>
            <dd>{d.agent.workspaceUser || '—'}</dd>
            <dt>Level changed</dt>
            <dd>{d.agent.levelChangedAt ? fmtAgo(d.agent.levelChangedAt) : '—'}</dd>
            <dt>Business unit</dt>
            <dd>{d.agent.businessUnit || '—'}</dd>
          </dl>
        </div>
      </div>
      <div className="card card-pad">
        <div className="section-title">Actions per hour (24h, coloured by worst class)</div>
        {s && (
          <BarChart
            bars={s.hourly.map((v, i) => {
              const w = s.hourlyWorst[i] ?? null;
              return { value: v, color: w ? CLASS_COLOR[w] : '#cbd5e1', label: hourLabel(s.hourStarts[i], i, s.hours) };
            })}
          />
        )}
      </div>
      <div className="card card-pad">
        <div className="section-title">Recent activity</div>
        {actions.error && <ErrorBox error={actions.error} onRetry={actions.reload} />}
        {actions.data && actions.data.length === 0 && <div className="muted">No actions recorded for this agent yet.</div>}
        <div className="timeline">
          {(actions.data ?? []).map((x) => (
            <div key={x.actionId} className="tl-item">
              <div className="tl-time" title={fmtTime(x.ts)}>
                {fmtAgo(x.ts)}
              </div>
              <div className="tl-main">
                <div className="tl-line">
                  <ClassChip cls={x.class} label={x.class} />
                  <span className="sys-icon" title={x.system}>
                    <SystemIcon system={x.system} />
                  </span>
                  <strong>
                    {x.system} {x.verb}
                  </strong>
                  <DecisionChip decision={x.decision} />
                  {x.ruleId && <span className="rule">{x.ruleId}</span>}
                  {x.failClosed && <span className="chip red">fail-closed</span>}
                </div>
                {x.reason && <div className="tl-reason">{x.reason}</div>}
              </div>
            </div>
          ))}
        </div>
      </div>
    </>
  );
}

// --- Level ------------------------------------------------------------------------

type LevelAction = { kind: 'down' | 'up' | 'kill'; target: Level };

function LevelTab({ d, onChanged }: { d: AgentDetail; onChanged: () => void }) {
  const me = useMe();
  const toast = useToast();
  const agent = d.agent;
  const perms = levelPermissions(me, agent);
  const [picked, setDownTarget] = useState<Level | ''>('');
  const [pending, setPending] = useState<LevelAction | null>(null);
  // The choice resets when the level changes and it is no longer below it.
  const downTarget: Level | '' = picked && perms.stepDownTargets.includes(picked) ? picked : (perms.stepDownTargets[0] ?? '');

  const run = async (target: Level, reason: string) => {
    const r = (await setLevel(agent.agentId, target, reason)) as { revocation?: Record<string, string>; revocation_error?: string } | null;
    toast({ tone: target === 'KILLED' ? 'red' : 'info', title: `${agent.agentId} set to ${target.replace('_', ' ')}` });
    if (r?.revocation_error) toast({ tone: 'amber', title: 'Credential revocation incomplete', body: r.revocation_error });
    onChanged();
  };

  return (
    <>
      <div className="card card-pad">
        <div className="section-title">Control ladder</div>
        <div className="ladder" aria-label="Control levels">
          {LEVELS.map((l) => (
            <div
              key={l}
              className={`step${l === agent.level ? ' current' : ''}`}
              style={l === agent.level ? { background: LEVEL_SOLID[l], borderColor: LEVEL_SOLID[l] } : undefined}
              aria-current={l === agent.level ? 'step' : undefined}
            >
              {l.replace('_', ' ')}
            </div>
          ))}
        </div>
        <p className="help" style={{ marginTop: 10 }}>
          Stricter levels restrict what policy allows. Owners and the security role may step down and step up one level at a time; only the security role
          may kill an agent or bring it back from KILLED. Every change needs a reason and is written to the Diary. Moving to QUARANTINED or KILLED
          also revokes the agent&apos;s live credentials.
        </p>
      </div>

      <div className="card card-pad">
        <div className="section-title">
          <IconArrowDown size={16} /> Step down
        </div>
        <div className="row">
          <select
            className="select"
            style={{ width: 220 }}
            aria-label="Step down to"
            value={downTarget}
            disabled={!perms.canStepDown}
            onChange={(e) => setDownTarget(e.target.value as Level)}
          >
            {perms.stepDownTargets.map((l) => (
              <option key={l} value={l}>
                {l.replace('_', ' ')}
              </option>
            ))}
          </select>
          <button className="btn" disabled={!perms.canStepDown || !downTarget} onClick={() => downTarget && setPending({ kind: 'down', target: downTarget })}>
            Step down
          </button>
        </div>
        {perms.stepDownWhy && <p className="help">{perms.stepDownWhy}</p>}
      </div>

      <div className="card card-pad">
        <div className="section-title">
          <IconArrowUp size={16} /> Step up one level
        </div>
        <button className="btn" disabled={!perms.canStepUp} onClick={() => perms.stepUpTarget && setPending({ kind: 'up', target: perms.stepUpTarget })}>
          {perms.stepUpTarget ? `Step up to ${perms.stepUpTarget.replace('_', ' ')}` : 'Step up'}
        </button>
        {perms.stepUpWhy && <p className="help">{perms.stepUpWhy}</p>}
      </div>

      <div className="card card-pad" style={{ borderColor: '#fecaca' }}>
        <div className="section-title" style={{ color: '#b91c1c' }}>
          <IconSkull size={16} /> Kill
        </div>
        <p className="help" style={{ marginTop: 0 }}>
          KILLED denies every action and revokes credentials. Only the security role can undo it.
        </p>
        <button className="btn danger" disabled={!perms.canKill} onClick={() => setPending({ kind: 'kill', target: 'KILLED' })}>
          Kill agent
        </button>
        {perms.killWhy && <p className="help">{perms.killWhy}</p>}
      </div>

      {pending && (
        <ReasonDialog
          title={pending.kind === 'kill' ? `Kill ${agent.agentId}?` : `Set ${agent.agentId} to ${pending.target.replace('_', ' ')}?`}
          description={
            pending.kind === 'kill'
              ? 'Every action will be denied and live credentials revoked (AWS sessions cannot be recalled: Fortik attaches a deny-by-issue-time policy).'
              : `From ${agent.level.replace('_', ' ')} to ${pending.target.replace('_', ' ')}.`
          }
          confirmLabel={pending.kind === 'kill' ? 'Kill agent' : 'Change level'}
          danger={pending.kind === 'kill' || pending.target === 'QUARANTINED'}
          onConfirm={(reason) => run(pending.target, reason)}
          onClose={() => setPending(null)}
        />
      )}
    </>
  );
}

// --- Held -------------------------------------------------------------------------

function HeldTab({ agentId }: { agentId: string }) {
  // The held API has no agent filter: every pending hold, plus recent
  // decided ones (newest 1000 across agents), filtered to this agent.
  const held = useAsync<HeldAction[]>(
    async (s) => {
      const [pending, all] = await Promise.all([listHeld('pending', s), listHeld('all', s)]);
      const byId = new Map<string, HeldAction>();
      for (const h of [...pending, ...all]) if (h.agentId === agentId && !byId.has(h.actionId)) byId.set(h.actionId, h);
      return [...byId.values()].sort((a, b) => Number(b.outcome === 'pending') - Number(a.outcome === 'pending') || b.createdAt.localeCompare(a.createdAt));
    },
    [agentId],
  );
  useLiveRefresh((e) => e.agentId === agentId && isHeldEvent(e.eventType), held.reload, 800);
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h2>Held actions</h2>
          <div className="sub">Approve or deny each hold with a reason. Dangerous actions are only ever approved in their safe form.</div>
        </div>
      </div>
      {held.error && (
        <div className="card-pad">
          <ErrorBox error={held.error} onRetry={held.reload} />
        </div>
      )}
      {held.loading && !held.data && <Loading />}
      {held.data && held.data.length === 0 && <div className="empty">No held actions for this agent.</div>}
      {held.data && <HeldList held={held.data} onChanged={held.reload} />}
    </div>
  );
}

// --- Tokens -----------------------------------------------------------------------

function TokensTab({ d, onChanged }: { d: AgentDetail; onChanged: () => void }) {
  const me = useMe();
  const toast = useToast();
  const security = hasRole(me, 'security');
  const id = d.agent.agentId;
  const [token, setToken] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [confirmRevoke, setConfirmRevoke] = useState(false);
  const [copied, setCopied] = useState(false);

  const issue = async () => {
    setBusy(true);
    setError(null);
    try {
      setToken(await issueToken(id));
      setCopied(false);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const revoke = async () => {
    setBusy(true);
    setError(null);
    try {
      await revokeTokens(id);
      toast({ tone: 'amber', title: `All tokens of ${id} revoked` });
      setConfirmRevoke(false);
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };
  const copy = async () => {
    if (!token) return;
    try {
      await navigator.clipboard.writeText(token);
      setCopied(true);
    } catch {
      setError(new Error('Copy failed: select the token and copy it manually.'));
    }
  };

  return (
    <>
      <div className="card card-pad">
        <div className="section-title">
          <IconKey size={16} /> Agent tokens
        </div>
        <p className="help" style={{ marginTop: 0 }}>
          An agent authenticates to the Fortik gateway, the credentials endpoint and pgproxy with a bearer token. Fortik stores only its SHA-256, so a
          token can be shown exactly once. Issuing a new token does not revoke earlier ones; use Revoke all for that.
        </p>
        <dl className="kv">
          <dt>Token on file</dt>
          <dd>{d.tokenIssued === null ? 'unknown (secret store unavailable)' : d.tokenIssued ? 'yes' : 'no'}</dd>
        </dl>
        <div className="btn-row" style={{ marginTop: 14 }}>
          <button className="btn primary" disabled={!security || busy} onClick={() => void issue()}>
            {busy && !confirmRevoke && <span className="spinner" />} Issue token
          </button>
          <button className="btn danger" disabled={!security || busy} onClick={() => setConfirmRevoke(true)}>
            Revoke all tokens
          </button>
        </div>
        {!security && <p className="help">Issuing and revoking tokens requires the security role.</p>}
        <div style={{ marginTop: 12 }}>
          <ErrorBox error={error} />
        </div>
      </div>
      {token && (
        <Modal
          title="New agent token"
          description="Copy it now and hand it to the agent's runtime. It will not be shown again; if it is lost, issue a new one and revoke the old ones."
          onClose={() => setToken(null)}
          footer={
            <button className="btn primary" onClick={() => setToken(null)}>
              I have stored it
            </button>
          }
        >
          <div className="alert warn">
            Treat this like a password: anyone holding it can act as <strong>{id}</strong> within its access profile.
          </div>
          <div className="token-box">
            <code data-testid="token-value">{token}</code>
            <button className="btn" onClick={() => void copy()} aria-label="Copy token">
              <IconCopy size={16} /> {copied ? 'Copied' : 'Copy'}
            </button>
          </div>
        </Modal>
      )}
      {confirmRevoke && (
        <Modal
          title={`Revoke all tokens of ${id}?`}
          description="The agent loses access to the gateway, credential issuance and pgproxy until a new token is issued."
          onClose={() => setConfirmRevoke(false)}
          footer={
            <>
              <button className="btn" onClick={() => setConfirmRevoke(false)} disabled={busy}>
                Cancel
              </button>
              <button className="btn danger" onClick={() => void revoke()} disabled={busy}>
                {busy && <span className="spinner" />} Revoke all
              </button>
            </>
          }
        />
      )}
    </>
  );
}
