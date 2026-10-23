// Teams (docs/PHASE4_DESIGN.md §6): agents grouped by business unit, with
// Suspend team / Resume team (security only). Each run shows its per-step
// result; agents without a business unit are listed but cannot be targeted.

import { useMemo, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { listAgents, teamOp, type TeamOp } from '../api/endpoints';
import type { Agent } from '../api/types';
import { useMe } from '../App';
import { LevelChip } from '../components/Chips';
import { OpDialog } from '../components/Containment';
import { IconPause, IconRefresh, IconUsers } from '../components/Icons';
import { ErrorBox, Loading } from '../components/ui';
import { useLiveRefresh } from '../lib/live';
import { fleetPermit } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

export interface Team {
  name: string;
  agents: Agent[];
}

/** Groups agents by business unit (teams sorted by name; agents without one last, under ""). */
export function groupTeams(agents: Agent[]): Team[] {
  const m = new Map<string, Agent[]>();
  for (const a of agents) {
    const k = a.businessUnit.trim();
    const l = m.get(k) ?? [];
    l.push(a);
    m.set(k, l);
  }
  return [...m.entries()]
    .map(([name, list]) => ({ name, agents: list.sort((x, y) => x.agentId.localeCompare(y.agentId)) }))
    .sort((a, b) => (a.name === '' ? 1 : b.name === '' ? -1 : a.name.localeCompare(b.name)));
}

export function TeamsPage() {
  const me = useMe();
  const navigate = useNavigate();
  const permit = fleetPermit(me);
  const agents = useAsync<Agent[]>((s) => listAgents(s), []);
  const [pending, setPending] = useState<{ team: string; op: TeamOp } | null>(null);
  useLiveRefresh((e) => /^(agent\.|containment\.)/.test(e.eventType), agents.reload, 1000);
  const teams = useMemo(() => groupTeams(agents.data ?? []), [agents.data]);

  if (agents.error) return <ErrorBox error={agents.error} onRetry={agents.reload} />;
  if (!agents.data) return <Loading />;

  return (
    <>
      <div className="card card-pad">
        <div className="row">
          <IconUsers />
          <h2 style={{ fontSize: 15 }}>Teams</h2>
        </div>
        <p className="help" style={{ marginBottom: 0 }}>
          A team is every agent with the same business unit. Suspending a team suspends each of its agents (actions refused, credentials revoked, queued
          jobs paused, copies told to pause); Resume team lifts it. {!permit.ok && <strong>{permit.why}</strong>}
        </p>
      </div>
      {teams.length === 0 && <div className="card empty">No agents yet.</div>}
      <div className="team-grid">
        {teams.map((t) => {
          const suspended = t.agents.filter((a) => a.suspended).length;
          return (
            <section key={t.name || '(none)'} className="card" data-testid={`team-${t.name || 'none'}`}>
              <div className="card-head">
                <div className="grow">
                  <h2>{t.name || 'No business unit'}</h2>
                  <div className="sub">
                    {t.agents.length} agent{t.agents.length === 1 ? '' : 's'}
                    {suspended > 0 && ` · ${suspended} suspended`}
                  </div>
                </div>
                {t.name && (
                  <div className="btn-row">
                    <button className="btn small warn" disabled={!permit.ok} title={permit.why} onClick={() => setPending({ team: t.name, op: 'suspend' })}>
                      <IconPause size={14} /> Suspend team
                    </button>
                    <button className="btn small" disabled={!permit.ok} title={permit.why} onClick={() => setPending({ team: t.name, op: 'resume' })}>
                      <IconRefresh size={14} /> Resume team
                    </button>
                  </div>
                )}
              </div>
              {!t.name && <p className="help" style={{ padding: '10px 20px 0', margin: 0 }}>Set a business unit on these agents to manage them as a team.</p>}
              <ul className="team-list">
                {t.agents.map((a) => (
                  <li key={a.agentId}>
                    <button className="link-btn" onClick={() => navigate(`/agents/${encodeURIComponent(a.agentId)}`)}>
                      {a.agentId}
                    </button>
                    <span className="spacer" />
                    {a.suspended && <span className="chip orange">Suspended</span>}
                    <LevelChip level={a.level} />
                  </li>
                ))}
              </ul>
            </section>
          );
        })}
      </div>
      {pending && (
        <OpDialog
          title={`${pending.op === 'suspend' ? 'Suspend' : 'Resume'} team ${pending.team}`}
          description={
            pending.op === 'suspend'
              ? `Suspends every agent in ${pending.team}. Memory and state are kept; Resume team continues where they stopped.`
              : `Clears the suspension of every agent in ${pending.team} and resumes their paused queued jobs.`
          }
          confirmLabel={pending.op === 'suspend' ? 'Suspend team' : 'Resume team'}
          danger={pending.op === 'suspend'}
          run={(reason) => teamOp(pending.team, pending.op, reason)}
          onDone={agents.reload}
          onClose={() => setPending(null)}
        />
      )}
    </>
  );
}
