// Command Center (docs/PHASE4_DESIGN.md §6, the v2 screen): KPI tiles, the
// Agent Radar, the live incident with its action chain, the Action Control
// panel for the selected agent (with Fleet E-Stop and Release), the live
// Agent Diary feed and the architecture panel.

import { useEffect, useMemo, useRef, useState } from 'react';
import { Link } from 'react-router-dom';
import { fleetRelease, loadCommandCenter, loadIncident, recentDiary, type CommandCenterData, type Incident } from '../api/endpoints';
import type { Agent, DiaryEvent } from '../api/types';
import { useMe } from '../App';
import { ClassChip, DecisionChip, LevelChip } from '../components/Chips';
import { EStopDialog, OpDialog } from '../components/Containment';
import { IconAlert, IconBan, IconBot, IconBrain, IconEye, IconPause, IconShield, IconSwarm, SystemIcon } from '../components/Icons';
import { ErrorBox, Loading } from '../components/ui';
import { dangerousVerbs, isHighRisk, pickSelected } from '../lib/commandCenter';
import { fmtAgo, fmtClock, fmtNum, fmtTime } from '../lib/format';
import { useLive, useLiveRefresh, type LiveListener } from '../lib/live';
import { fleetPermit } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';
import { AgentControls, COMMAND_CONTROLS } from './AgentControls';

const REFRESH_EVENTS = /^(action\.|agent\.|access\.|containment\.|held\.|approval\.|memory\.)/;

export function CommandCenterPage() {
  const page = useAsync<CommandCenterData>((s) => loadCommandCenter(s), []);
  const incident = useAsync<Incident | null>((s) => loadIncident(s), []);
  const [picked, setPicked] = useState<string | null>(null);

  useLiveRefresh((e) => REFRESH_EVENTS.test(e.eventType), page.reload, 1500);
  useLiveRefresh((e) => e.eventType.startsWith('action.'), incident.reload, 1500);

  const reloadAll = () => {
    page.reload();
    incident.reload();
  };

  if (page.error && !page.data) return <ErrorBox error={page.error} onRetry={page.reload} />;
  if (!page.data) return <Loading label="Loading the Command Center…" />;
  const d = page.data;
  // Until the user picks a row, the panel follows the live incident. Opening
  // any control dialog pins the selection (onPin), so a newer red decision
  // cannot move the panel, or the dialog's target, to another agent (F23).
  const selected = pickSelected(d.agents, picked, incident.data?.latest.agentId ?? null);

  return (
    <>
      {page.error && <ErrorBox error={page.error} onRetry={page.reload} />}
      <CommandKpis d={d} />
      <div className="cc-grid">
        <div className="cc-main">
          <AgentRadar d={d} selectedId={selected?.agentId ?? null} onSelect={setPicked} />
          <IncidentPanel incident={incident.data} loading={incident.loading} error={incident.error} onRetry={incident.reload} onSelect={setPicked} />
          <ArchitecturePanel />
        </div>
        <div className="cc-side">
          <ActionControlPanel agent={selected} onChanged={reloadAll} onPin={setPicked} />
          <DiaryFeed />
        </div>
      </div>
    </>
  );
}

// --- KPI tiles ----------------------------------------------------------------------

export function CommandKpis({ d }: { d: CommandCenterData }) {
  const discovered = d.agents.filter((a) => a.discovered).length;
  const highRisk = d.agents.filter(isHighRisk).length;
  const tiles = [
    { key: 'agents', label: 'Agents discovered', value: fmtNum(d.agents.length), icon: <IconBot />, tint: '#eef2ff', color: '#4f46e5', foot: `${discovered} found automatically` },
    { key: 'risk', label: 'High-risk agents', value: fmtNum(highRisk), icon: <IconAlert />, tint: '#fef2f2', color: '#dc2626', foot: 'dangerous action in 24h' },
    {
      key: 'blocked',
      label: 'Blocked actions today',
      value: `${fmtNum(d.blockedToday)}${d.blockedCapped ? '+' : ''}`,
      icon: <IconBan />,
      tint: '#fff7ed',
      color: '#ea580c',
      foot: 'denied since 00:00 UTC',
    },
    { key: 'approvals', label: 'Pending approvals', value: fmtNum(d.pendingApprovals), icon: <IconPause />, tint: '#fffbeb', color: '#d97706', foot: <Link to="/approvals">review holds</Link> },
    {
      key: 'memory',
      label: 'Active memory quarantines',
      value: d.memoryQuarantined ? fmtNum(d.memoryQuarantined.size) : '—',
      icon: <IconBrain />,
      tint: '#f5f3ff',
      color: '#7c3aed',
      foot: d.memoryQuarantined ? 'memory access cut' : 'containment history unavailable',
    },
    {
      key: 'swarms',
      label: 'Active swarms',
      value: d.activeSwarms ? fmtNum(d.activeSwarms.length) : '—',
      icon: <IconSwarm />,
      tint: '#fef2f2',
      color: '#b91c1c',
      foot: d.activeSwarms ? (
        <Link to="/swarms">{d.activeSwarms.length ? `${fmtNum(d.activeSwarms.reduce((n, s) => n + s.memberCount, 0))} members` : 'view swarms'}</Link>
      ) : (
        'swarms unavailable'
      ),
    },
    {
      key: 'discovered',
      label: 'Discovered agents',
      value: fmtNum(discovered),
      icon: <IconEye />,
      tint: '#fff7ed',
      color: '#c2410c',
      foot:
        d.shadowFlagged === null ? (
          'shadow scan unavailable'
        ) : (
          <Link to="/shadow">{d.shadowFlagged ? `${fmtNum(d.shadowFlagged)} flagged for revocation` : 'review findings'}</Link>
        ),
    },
  ];
  return (
    <div className="kpis kpis-auto" data-testid="cc-kpis">
      {tiles.map((t) => (
        <div key={t.key} className="card kpi" data-testid={`kpi-${t.key}`}>
          <div className="kpi-top">
            {t.label}
            <span className="kpi-icon" style={{ background: t.tint, color: t.color }}>
              {t.icon}
            </span>
          </div>
          <div className="kpi-value">{t.value}</div>
          <div className="kpi-foot">{t.foot}</div>
        </div>
      ))}
    </div>
  );
}

// --- Agent Radar ----------------------------------------------------------------------

function AgentRadar({ d, selectedId, onSelect }: { d: CommandCenterData; selectedId: string | null; onSelect: (id: string) => void }) {
  const verbs = useMemo(() => dangerousVerbs(d.redActions), [d.redActions]);
  const rows = useMemo(() => {
    const rank = (a: Agent) => (isHighRisk(a) ? 0 : a.worstClass24h === 'yellow' ? 1 : a.worstClass24h ? 2 : 3);
    return [...d.agents].sort((a, b) => rank(a) - rank(b) || (b.actionsToday ?? 0) - (a.actionsToday ?? 0) || a.agentId.localeCompare(b.agentId));
  }, [d.agents]);
  return (
    <section className="card">
      <div className="card-head">
        <div>
          <h2>Agent Radar</h2>
          <div className="sub">Every agent, who owns it, the tools it used and the dangerous verbs it tried in the last 24 hours. Select one to act on it.</div>
        </div>
      </div>
      <div className="table-wrap">
        <table className="table" aria-label="Agent Radar">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Owner</th>
              <th>Tools (24h)</th>
              <th>Dangerous verbs</th>
              <th>Risk</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const v = verbs.get(a.agentId) ?? [];
              return (
                <tr
                  key={a.agentId}
                  className={`row${a.agentId === selectedId ? ' selected' : ''}`}
                  tabIndex={0}
                  aria-selected={a.agentId === selectedId}
                  onClick={() => onSelect(a.agentId)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault();
                      onSelect(a.agentId);
                    }
                  }}
                >
                  <td>
                    <div className="agent-cell">
                      <span className="agent-avatar">
                        <IconBot size={16} />
                      </span>
                      <div>
                        <div className="id">{a.agentId}</div>
                        <div className="type">
                          {[a.type, a.platform].filter(Boolean).join(' · ') || '—'}
                          {a.discovered && ' · discovered'}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td>{a.sponsor || <span className="muted">unassigned</span>}</td>
                  <td>
                    <div className="sys-icons">
                      {(a.systems24h ?? []).length === 0 && <span className="muted">—</span>}
                      {(a.systems24h ?? []).map((s) => (
                        <span key={s} className="sys-icon" title={s}>
                          <SystemIcon system={s} />
                        </span>
                      ))}
                    </div>
                  </td>
                  <td>
                    {v.length === 0 ? (
                      <span className="muted">—</span>
                    ) : (
                      <div className="verb-list">
                        {v.slice(0, 3).map((x) => (
                          <span key={x} className="chip red">
                            {x}
                          </span>
                        ))}
                        {v.length > 3 && <span className="muted small">+{v.length - 3}</span>}
                      </div>
                    )}
                  </td>
                  <td>
                    <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                      <ClassChip cls={a.worstClass24h ?? null} />
                      {a.level !== 'FULL' && <LevelChip level={a.level} />}
                      {a.suspended && <span className="chip orange">Suspended</span>}
                      {d.memoryQuarantined?.has(a.agentId) && <span className="chip purple">Memory cut</span>}
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <div className="empty">No agents yet. Register one, or let pgproxy and the gateway discover them.</div>}
      </div>
    </section>
  );
}

// --- Live incident ---------------------------------------------------------------------

function IncidentPanel({
  incident,
  loading,
  error,
  onRetry,
  onSelect,
}: {
  incident: Incident | null | undefined;
  loading: boolean;
  error: Error | undefined;
  onRetry: () => void;
  onSelect: (id: string) => void;
}) {
  return (
    <section className="card" data-testid="incident">
      <div className="card-head">
        <div>
          <h2>Live incident · action chain</h2>
          <div className="sub">The latest dangerous (red) decision and what the same agent did just before it.</div>
        </div>
        <div className="spacer" />
        {incident && (
          <button className="btn small" onClick={() => onSelect(incident.latest.agentId)}>
            Act on {incident.latest.agentId}
          </button>
        )}
      </div>
      <div className="card-pad">
        {error && <ErrorBox error={error} onRetry={onRetry} />}
        {incident === undefined && loading && <Loading />}
        {incident === null && <div className="muted">No dangerous decision recorded yet.</div>}
        {incident && (
          <>
            <div className="row" style={{ flexWrap: 'wrap', marginBottom: 12 }}>
              <span className="chip red">
                <span className="dot" />
                {incident.latest.ruleId || 'red decision'}
              </span>
              <strong>{incident.latest.agentId}</strong>
              <span className="muted">
                {incident.latest.system} {incident.latest.verb} · {fmtAgo(incident.latest.ts)}
              </span>
            </div>
            {incident.latest.reason && <p className="tl-reason" style={{ marginTop: 0 }}>{incident.latest.reason}</p>}
            <ol className="action-chain" aria-label="Action chain">
              {incident.chain.map((a, i) => {
                const last = i === incident.chain.length - 1;
                return (
                  <li key={a.actionId || i} className={`chain-step${last ? ' incident' : ''}`} data-testid="chain-step">
                    <div className="chain-time" title={fmtTime(a.ts)}>
                      {fmtClock(a.ts)}
                    </div>
                    <div className="chain-card">
                      <div className="tl-line">
                        <span className="sys-icon" title={a.system}>
                          <SystemIcon system={a.system} />
                        </span>
                        <strong>
                          {a.system} {a.verb}
                        </strong>
                        <ClassChip cls={a.class} label={a.class} />
                        <DecisionChip decision={a.decision} />
                        {a.ruleId && <span className="rule">{a.ruleId}</span>}
                      </div>
                    </div>
                  </li>
                );
              })}
            </ol>
          </>
        )}
      </div>
    </section>
  );
}

// --- Action Control ----------------------------------------------------------------------

function ActionControlPanel({ agent, onChanged, onPin }: { agent: Agent | null; onChanged: () => void; onPin: (agentId: string) => void }) {
  const me = useMe();
  const fleet = fleetPermit(me);
  const [estop, setEstop] = useState(false);
  const [release, setRelease] = useState(false);
  return (
    <section className="card" data-testid="action-control">
      <div className="card-head">
        <div>
          <h2>Action Control</h2>
          <div className="sub">{agent ? 'Contain the selected agent. Every action needs a reason and is written to the Diary.' : 'Select an agent in the radar.'}</div>
        </div>
      </div>
      <div className="card-pad">
        {agent && (
          <>
            <div className="row" style={{ marginBottom: 12, flexWrap: 'wrap' }}>
              <span className="agent-avatar">
                <IconBot size={16} />
              </span>
              <div className="grow">
                <Link to={`/agents/${encodeURIComponent(agent.agentId)}`} className="id" style={{ fontWeight: 650 }}>
                  {agent.agentId}
                </Link>
                <div className="muted small">{agent.sponsor ? `owner ${agent.sponsor}` : 'no owner'}</div>
              </div>
              <LevelChip level={agent.level} />
              {agent.suspended && <span className="chip orange">Suspended</span>}
            </div>
            <AgentControls
              key={agent.agentId}
              agent={agent}
              controls={COMMAND_CONTROLS}
              labels={{ suspend: 'Freeze agent', resume: 'Unfreeze agent', memory_remove: 'Quarantine memory' }}
              onChanged={onChanged}
              onOpen={onPin}
            />
          </>
        )}
        <div className="estop-box">
          <div className="section-title" style={{ marginBottom: 6 }}>
            <IconShield size={16} /> Fleet
          </div>
          <div className="btn-row">
            <button className="btn estop" disabled={!fleet.ok} title={fleet.why} onClick={() => setEstop(true)}>
              Fleet E-Stop
            </button>
            <button className="btn" disabled={!fleet.ok} title={fleet.why} onClick={() => setRelease(true)}>
              Release
            </button>
          </div>
          <p className="help" style={{ marginBottom: 0 }}>
            {fleet.ok ? 'E-Stop suspends every registered agent; Release resumes only the agents the e-stop suspended.' : fleet.why}
          </p>
        </div>
      </div>
      {estop && <EStopDialog onDone={onChanged} onClose={() => setEstop(false)} />}
      {release && (
        <OpDialog
          title="Release the fleet e-stop"
          description="Resumes only the agents the last e-stop suspended. Agents suspended for other reasons stay suspended."
          confirmLabel="Release"
          run={(reason) => fleetRelease(reason)}
          onDone={onChanged}
          onClose={() => setRelease(false)}
        />
      )}
    </section>
  );
}

// --- Agent Diary feed (live) ---------------------------------------------------------------

const FEED_MAX = 40;

/** A short, data-free summary of a Diary entry (no raw payloads). */
export function diarySummary(e: DiaryEvent): string {
  const d = e.data;
  const s = (k: string) => (typeof d[k] === 'string' && d[k] !== '' ? (d[k] as string) : '');
  const parts = [
    [s('system'), s('verb')].filter(Boolean).join(' '),
    s('decision'),
    s('rule_id'),
    s('op') && s('target_id') ? `${s('op')} ${s('target_id')}` : s('op'),
    s('status'),
  ].filter(Boolean);
  const reason = s('reason');
  const text = parts.join(' · ');
  const r = reason.length > 120 ? `${reason.slice(0, 120)}…` : reason;
  return [text, r].filter(Boolean).join(' — ');
}

/** Plain-language titles for Diary event types whose name alone is not obvious (shown on hover). */
export const EVENT_TITLE: Record<string, string> = {
  'memory.item_deleted': 'A memory item was deleted from the store',
  'memory.review_window_opened': 'Held memory items got a review window: they are promoted when it ends unless flagged',
  'memory.snapshot_marked_unclean': 'A memory snapshot was marked not clean (it holds a flagged or unreviewed item)',
};

export function eventTone(t: string): string {
  if (/^(containment\.|agent\.suspended|agent\.killed|fleet\.)/.test(t)) return 'red';
  if (t === 'memory.item_deleted' || t === 'memory.snapshot_marked_unclean') return 'amber';
  if (t === 'memory.review_window_opened') return 'blue';
  if (/(denied|blocked|refused|failed)/.test(t)) return 'amber';
  if (t.startsWith('action.')) return 'blue';
  return 'gray';
}

function DiaryFeed() {
  const { connected, subscribe } = useLive();
  const [live, setLive] = useState<DiaryEvent[]>([]);
  const initial = useAsync<DiaryEvent[]>((s) => recentDiary(30, FEED_MAX, s), []);
  // A reconnect (null) reloads the recent history, since events may have been missed.
  useSubscription(subscribe, (e) => {
    if (e === null) {
      setLive([]);
      initial.reload();
      return;
    }
    setLive((l) => [e, ...l].slice(0, FEED_MAX));
  });

  const seen = new Set<number>();
  const events = [...live, ...(initial.data ?? [])]
    .filter((e) => {
      if (e.seq && seen.has(e.seq)) return false;
      if (e.seq) seen.add(e.seq);
      return true;
    })
    .slice(0, FEED_MAX);

  return (
    <section className="card" data-testid="diary-feed">
      <div className="card-head">
        <div>
          <h2>Agent Diary</h2>
          <div className="sub">Committed Diary entries as they happen.</div>
        </div>
        <div className="spacer" />
        <span className={`live${connected ? ' on' : ''}`}>
          <span className="dot" />
          {connected ? 'Live' : 'Offline'}
        </span>
      </div>
      <div className="feed">
        {initial.error && events.length === 0 && (
          <div className="card-pad muted small">
            Recent history unavailable ({initial.error.message}); new entries appear here as they are committed.
          </div>
        )}
        {events.length === 0 && !initial.error && <div className="empty">{initial.loading ? 'Loading…' : 'No Diary entries in the last 30 minutes.'}</div>}
        {events.map((e, i) => (
          <div key={e.seq || `l${i}`} className="feed-item">
            <span className="feed-time" title={fmtTime(e.ts)}>
              {fmtClock(e.ts)}
            </span>
            <div className="grow" style={{ minWidth: 0 }}>
              <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                <span className={`chip ${eventTone(e.eventType)}`} title={EVENT_TITLE[e.eventType]}>
                  {e.eventType}
                </span>
                {e.agentId && <span className="feed-agent">{e.agentId}</span>}
              </div>
              {diarySummary(e) && <div className="feed-sum">{diarySummary(e)}</div>}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}

// --- Architecture ---------------------------------------------------------------------

function ArchitecturePanel() {
  return (
    <section className="card" data-testid="architecture">
      <div className="card-head">
        <div>
          <h2>Architecture</h2>
          <div className="sub">Agents never hold the real credentials: every path to a business system goes through a Fortik decision.</div>
        </div>
      </div>
      <div className="card-pad">
        <div className="arch">
          <div className="arch-col">
            <div className="arch-head">AI agents</div>
            <div className="arch-node">Claude Code (hook)</div>
            <div className="arch-node">MCP clients &amp; A2A agents</div>
            <div className="arch-node">Workers &amp; queued jobs</div>
            <div className="arch-node">SQL clients</div>
          </div>
          <div className="arch-arrow" aria-hidden="true">
            →
          </div>
          <div className="arch-col fortik">
            <div className="arch-head">Fortik</div>
            <div className="arch-node strong">Decide · OPA policy · hash-chained Diary</div>
            <div className="arch-node">Gateway /gw (Gmail, Drive, GitHub, memory)</div>
            <div className="arch-node">pgproxy :6432</div>
            <div className="arch-node">agentgateway callout (MCP, A2A, HTTP)</div>
            <div className="arch-node">Authority broker (short-lived credentials)</div>
            <div className="arch-node contain">Containment: suspend · isolate · memory cut · kill · e-stop</div>
          </div>
          <div className="arch-arrow" aria-hidden="true">
            →
          </div>
          <div className="arch-col">
            <div className="arch-head">Your systems</div>
            <div className="arch-node">Gmail &amp; Drive</div>
            <div className="arch-node">GitHub</div>
            <div className="arch-node">AWS</div>
            <div className="arch-node">PostgreSQL</div>
            <div className="arch-node">Vector memory</div>
            <div className="arch-node">Temporal / Celery queues</div>
          </div>
        </div>
      </div>
    </section>
  );
}

// --- helpers ----------------------------------------------------------------------------

function useSubscription(subscribe: (fn: LiveListener) => () => void, fn: LiveListener) {
  const ref = useRef(fn);
  ref.current = fn;
  useEffect(() => subscribe((e) => ref.current(e)), [subscribe]);
}
