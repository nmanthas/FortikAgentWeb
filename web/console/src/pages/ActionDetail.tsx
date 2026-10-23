// One action and the Diary entries that name it (the "Diary" link target of
// the map's sample actions, path-trace hops and swarm held calls).

import { Link, useParams } from 'react-router-dom';
import { getActionDetail, type ActionDetail } from '../api/endpoints';
import { ClassChip, DecisionChip } from '../components/Chips';
import { ErrorBox, Loading } from '../components/ui';
import { fmtTime } from '../lib/format';
import { useAsync } from '../lib/useAsync';
import { diarySummary, eventTone } from './CommandCenter';

export function ActionDetailPage() {
  const { actionId = '' } = useParams();
  const d = useAsync<ActionDetail>((s) => getActionDetail(actionId, s), [actionId]);
  if (d.error && !d.data) return <ErrorBox error={d.error} onRetry={d.reload} />;
  if (!d.data) return <Loading />;
  const a = d.data.action;
  return (
    <>
      <section className="card" data-testid="action-detail">
        <div className="card-head">
          <div className="grow">
            <h2 className="mono">{a.actionId}</h2>
            <div className="sub">{fmtTime(a.ts)}</div>
          </div>
          <ClassChip cls={a.class} label={a.class} />
          <DecisionChip decision={a.decision} />
        </div>
        <div className="card-pad">
          <dl className="kv">
            <dt>Agent</dt>
            <dd>{a.agentId ? <Link to={`/agents/${encodeURIComponent(a.agentId)}`}>{a.agentId}</Link> : '—'}</dd>
            <dt>Action</dt>
            <dd>
              {a.system} {a.verb}
            </dd>
            <dt>Rule</dt>
            <dd>{a.ruleId || '—'}</dd>
            <dt>Reason</dt>
            <dd>{a.reason || '—'}</dd>
            <dt>Source</dt>
            <dd>{a.source || '—'}</dd>
          </dl>
        </div>
      </section>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Diary</h2>
            <div className="sub">Committed, hash-chained Diary entries that name this action.</div>
          </div>
        </div>
        {d.data.diary === null && <div className="card-pad muted small">Reading the Diary requires the auditor role.</div>}
        {d.data.diary && d.data.diary.length === 0 && <div className="empty">No Diary entries name this action in the day after it.</div>}
        {d.data.diary && d.data.diary.length > 0 && (
          <div className="feed" style={{ maxHeight: 'none' }}>
            {d.data.diary.map((e) => (
              <div key={e.seq} className="feed-item" data-testid="diary-entry">
                <span className="feed-time mono">#{e.seq}</span>
                <div className="grow" style={{ minWidth: 0 }}>
                  <div className="row" style={{ gap: 6, flexWrap: 'wrap' }}>
                    <span className={`chip ${eventTone(e.eventType)}`}>{e.eventType}</span>
                    <span className="muted small">{fmtTime(e.ts)}</span>
                  </div>
                  {diarySummary(e) && <div className="feed-sum">{diarySummary(e)}</div>}
                </div>
              </div>
            ))}
          </div>
        )}
      </section>
    </>
  );
}
