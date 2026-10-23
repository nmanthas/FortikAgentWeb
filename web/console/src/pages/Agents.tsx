// Agents screen: KPI row, searchable/filterable agent table, register
// dialog, and the right-side detail panel for /agents/:agentId.

import { useCallback, useMemo, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { loadAgentsPage, type AgentsPage as PageData } from '../api/endpoints';
import { deriveStatus, LEVELS } from '../api/normalize';
import type { ActionClass, Agent, Level, Summary } from '../api/types';
import { useMe } from '../App';
import { AgentStatusChip, ClassChip, CLASS_COLOR, LevelChip } from '../components/Chips';
import { IconActivity, IconAlert, IconBot, IconPause, IconPlus, IconRefresh, IconSearch, IconShield, SystemIcon } from '../components/Icons';
import { ErrorBox, Loading } from '../components/ui';
import { fmtNum } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { hasRole } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';
import { AgentPanel } from './AgentPanel';
import { RegisterAgentDialog } from './RegisterAgentDialog';

type RiskFilter = 'all' | ActionClass | 'none';

const REFRESH_EVENTS = /^(action\.|agent\.|access\.|undo\.)/;

export function AgentsPage() {
  const me = useMe();
  const { agentId } = useParams();
  const navigate = useNavigate();
  const page = useAsync<PageData>((signal) => loadAgentsPage(signal), []);
  const [query, setQuery] = useState('');
  const [level, setLevel] = useState<'all' | Level>('all');
  const [risk, setRisk] = useState<RiskFilter>('all');
  const [registering, setRegistering] = useState(false);

  useLiveRefresh((e) => REFRESH_EVENTS.test(e.eventType), page.reload, 1000);

  const rows = useMemo(() => {
    const agents = page.data?.agents ?? [];
    const q = query.trim().toLowerCase();
    return agents.filter((a) => {
      if (level !== 'all' && a.level !== level) return false;
      if (risk !== 'all') {
        const w = a.worstClass24h ?? null;
        if (risk === 'none' ? w !== null : w !== risk) return false;
      }
      if (!q) return true;
      return [a.agentId, a.name, a.type, a.sponsor, a.platform, a.businessUnit].some((f) => f.toLowerCase().includes(q));
    });
  }, [page.data, query, level, risk]);

  const pendingFor = useCallback((a: Agent) => a.heldPending ?? page.data?.heldByAgent.get(a.agentId) ?? 0, [page.data]);
  const canRegister = hasRole(me, 'security');

  return (
    <>
      {page.data && <Kpis s={page.data.summary} />}
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Agents</h2>
            <div className="sub">Every registered or discovered agent, its control level and the riskiest thing it did in the last 24 hours.</div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={page.reload} aria-label="Refresh" title="Refresh">
            <IconRefresh size={16} />
          </button>
          <button
            className="btn primary"
            onClick={() => setRegistering(true)}
            disabled={!canRegister}
            title={canRegister ? 'Register an agent' : 'Registering agents requires the security role'}
          >
            <IconPlus size={16} /> Register agent
          </button>
        </div>
        <div className="toolbar">
          <div className="search">
            <IconSearch size={15} />
            <input
              className="input"
              placeholder="Search agent, owner, type…"
              aria-label="Search agents"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
            />
          </div>
          <select className="select" aria-label="Filter by level" value={level} onChange={(e) => setLevel(e.target.value as 'all' | Level)}>
            <option value="all">All levels</option>
            {LEVELS.map((l) => (
              <option key={l} value={l}>
                {l.replace('_', ' ')}
              </option>
            ))}
          </select>
          <select className="select" aria-label="Filter by risk" value={risk} onChange={(e) => setRisk(e.target.value as RiskFilter)}>
            <option value="all">All risk</option>
            <option value="red">Dangerous (red)</option>
            <option value="yellow">Risky (yellow)</option>
            <option value="blue">Above normal (blue)</option>
            <option value="green">Normal (green)</option>
            <option value="none">No activity</option>
          </select>
          <div className="spacer" />
          {page.data && (
            <span className="muted small">
              {rows.length} of {page.data.agents.length} agents
            </span>
          )}
        </div>
        {page.error && (
          <div className="card-pad">
            <ErrorBox error={page.error} onRetry={page.reload} />
          </div>
        )}
        {page.loading && !page.data && <Loading />}
        {page.data && (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Agent</th>
                  <th>Owner</th>
                  <th>Actions today</th>
                  <th>Level</th>
                  <th>Systems (24h)</th>
                  <th>Risk (24h)</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => (
                  <tr
                    key={a.agentId}
                    className={`row${a.agentId === agentId ? ' selected' : ''}`}
                    onClick={() => navigate(`/agents/${encodeURIComponent(a.agentId)}`)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') navigate(`/agents/${encodeURIComponent(a.agentId)}`);
                    }}
                    tabIndex={0}
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
                    <td>{fmtNum(a.actionsToday ?? 0)}</td>
                    <td>
                      <LevelChip level={a.level} />
                    </td>
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
                      <ClassChip cls={a.worstClass24h ?? null} />
                    </td>
                    <td>
                      <AgentStatusChip status={deriveStatus(a, pendingFor(a))} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length === 0 && (
              <div className="empty">
                {page.data.agents.length === 0
                  ? 'No agents yet. Register one, or let pgproxy and the gateway discover them.'
                  : 'No agents match these filters.'}
              </div>
            )}
          </div>
        )}
      </section>
      {agentId && <AgentPanel key={agentId} agentId={agentId} onClose={() => navigate('/agents')} onChanged={page.reload} />}
      {registering && (
        <RegisterAgentDialog
          onClose={() => setRegistering(false)}
          onCreated={(id) => {
            setRegistering(false);
            page.reload();
            navigate(`/agents/${encodeURIComponent(id)}`);
          }}
        />
      )}
    </>
  );
}

function ClassBar({ counts }: { counts: Record<ActionClass, number> }) {
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  if (total === 0) return <span className="muted">no actions yet</span>;
  return (
    <svg width="96" height="8" role="img" aria-label={Object.entries(counts).map(([k, v]) => `${k}: ${v}`).join(', ')}>
      {(() => {
        let x = 0;
        return (['green', 'blue', 'yellow', 'red'] as ActionClass[]).map((c) => {
          const w = (counts[c] / total) * 96;
          const el = <rect key={c} x={x} y={0} width={w} height={8} fill={CLASS_COLOR[c]} />;
          x += w;
          return el;
        });
      })()}
    </svg>
  );
}

function Kpis({ s }: { s: Summary }) {
  const tiles = [
    { label: 'Total agents', value: s.totalAgents, icon: <IconBot />, tint: '#eef2ff', color: '#4f46e5', foot: 'registered and discovered' },
    {
      label: 'Actions today',
      value: s.actionsToday,
      icon: <IconActivity />,
      tint: '#ecfdf3',
      color: '#16a34a',
      foot: s.byClassToday ? <ClassBar counts={s.byClassToday} /> : 'since 00:00 UTC',
    },
    { label: 'Held / pending', value: s.heldPending, icon: <IconPause />, tint: '#fffbeb', color: '#d97706', foot: 'awaiting a human decision' },
    { label: 'Dangerous today', value: s.redToday, icon: <IconAlert />, tint: '#fef2f2', color: '#dc2626', foot: 'red-class actions' },
    { label: 'Not at FULL', value: s.agentsNotFull, icon: <IconShield />, tint: '#f5f3ff', color: '#7c3aed', foot: 'supervised or stricter' },
  ];
  return (
    <div className="kpis" data-testid="kpis">
      {tiles.map((t) => (
        <div key={t.label} className="card kpi">
          <div className="kpi-top">
            {t.label}
            <span className="kpi-icon" style={{ background: t.tint, color: t.color }}>
              {t.icon}
            </span>
          </div>
          <div className="kpi-value">{fmtNum(t.value)}</div>
          <div className="kpi-foot">{t.foot}</div>
        </div>
      ))}
    </div>
  );
}
