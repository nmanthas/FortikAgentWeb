// Agent Baseline tab (docs/PHASE5_DESIGN.md §4): the agent's own hourly
// counts for a verb over up to 14 days, with the above-normal threshold
// (mean + 3σ, or 5× the median with less than 3 days of history). An
// above-normal action that would be green is held as yellow (POL-660).

import { useId, useState } from 'react';
import { getBaseline } from '../api/endpoints';
import type { Baseline, BaselinePoint } from '../api/types';
import { ErrorBox, Loading } from '../components/ui';
import { fmtNum, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { useAsync } from '../lib/useAsync';

const NORMAL = '#2563eb';
const ABOVE = '#d97706';
const THRESHOLD = '#dc2626';
const MEAN = '#64748b';

const fmtStat = (n: number | null, digits = 1) => (n === null ? '—' : Number.isInteger(n) ? fmtNum(n) : n.toFixed(digits));

export function BaselineTab({ agentId }: { agentId: string }) {
  const [verb, setVerb] = useState('');
  const b = useAsync<Baseline | null>((s) => getBaseline(agentId, verb, s), [agentId, verb]);
  useLiveRefresh((e) => e.agentId === agentId && e.eventType.startsWith('action.'), b.reload, 5000);
  const id = useId();
  const d = b.data;
  const verbs = d ? [...new Set([...(d.verbs ?? []), ...(verb ? [verb] : [])])].sort() : [];
  return (
    <div className="stat-list" data-testid="baseline-tab">
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <label className="label" htmlFor={id}>
          Verb
        </label>
        <select id={id} className="select" style={{ width: 200 }} value={verb} onChange={(e) => setVerb(e.target.value)}>
          <option value="">{d?.verb && !verb ? `${d.verb} (default)` : 'All verbs'}</option>
          {verbs.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
        {d && (d.aboveNormal ? <span className="chip amber">Above normal now</span> : <span className="chip green">Within normal</span>)}
      </div>
      {b.error && <ErrorBox error={b.error} onRetry={b.reload} />}
      {b.loading && b.data === undefined && <Loading />}
      {b.data === null && <div className="empty">This server does not compute behaviour baselines yet.</div>}
      {d && (
        <>
          <BaselineChart series={d.series} threshold={d.threshold} mean={d.mean} />
          <div className="legend-row muted small">
            <span>
              <span className="legend-dot" style={{ background: NORMAL }} /> hourly count
            </span>
            <span>
              <span className="legend-dot" style={{ background: ABOVE }} /> above the threshold
            </span>
            <span>
              <svg width={22} height={8} aria-hidden="true">
                <line x1={0} x2={22} y1={4} y2={4} stroke={THRESHOLD} strokeWidth={2} strokeDasharray="5 3" />
              </svg>{' '}
              threshold
            </span>
            <span>
              <svg width={22} height={8} aria-hidden="true">
                <line x1={0} x2={22} y1={4} y2={4} stroke={MEAN} strokeWidth={1.5} strokeDasharray="2 3" />
              </svg>{' '}
              mean
            </span>
          </div>
          <dl className="kv" data-testid="baseline-stats">
            <dt>This hour</dt>
            <dd>{fmtStat(d.current, 0)}</dd>
            <dt>Threshold</dt>
            <dd>
              {fmtStat(d.threshold)}
              {d.method && <span className="muted small"> · {d.method}</span>}
            </dd>
            <dt>Mean ± σ</dt>
            <dd>
              {fmtStat(d.mean)} ± {fmtStat(d.stddev)}
            </dd>
            <dt>Median</dt>
            <dd>{fmtStat(d.median)}</dd>
            <dt>History</dt>
            <dd>{d.historyDays === null ? '—' : `${fmtStat(d.historyDays)} days`}</dd>
            {d.minCount !== undefined && (
              <>
                <dt>Minimum</dt>
                <dd>never below {fmtNum(d.minCount)} per hour</dd>
              </>
            )}
          </dl>
          <p className="help" style={{ margin: 0 }}>
            {d.historyDays !== null && d.historyDays < 3
              ? 'Less than 3 days of history: above normal means more than 5× the median hourly count.'
              : 'Above normal means more than the mean plus 3 standard deviations of this agent’s own hourly counts over 14 days.'}{' '}
            An above-normal action that would otherwise be green is held as yellow for one approver (POL-660).
          </p>
        </>
      )}
    </div>
  );
}

/** Hourly bars with the threshold and mean as horizontal lines (one y-axis, counts). */
export function BaselineChart({ series, threshold, mean, height = 170 }: { series: BaselinePoint[]; threshold: number | null; mean: number | null; height?: number }) {
  if (series.length === 0) return <div className="empty">No hourly counts yet.</div>;
  const w = 640;
  const left = 34;
  const chartH = height - 22;
  const max = Math.max(1, threshold ?? 0, ...series.map((p) => p.count)) * 1.08;
  const slot = (w - left) / series.length;
  const bw = Math.max(1, slot - (slot > 4 ? 1.5 : 0.5));
  const y = (v: number) => chartH - (v / max) * (chartH - 8);
  const above = threshold === null ? 0 : series.filter((p) => p.count > threshold).length;
  const ticks = [0, Math.round(max / 2), Math.round(max)];
  // Day labels at local midnight.
  const days = series
    .map((p, i) => ({ i, t: Date.parse(p.hour) }))
    .filter(({ t }) => Number.isFinite(t) && new Date(t).getHours() === 0);
  return (
    <svg
      width="100%"
      viewBox={`0 0 ${w} ${height}`}
      role="img"
      data-testid="baseline-chart"
      aria-label={`Hourly counts over ${series.length} hours; threshold ${threshold ?? 'unknown'}; ${above} hour${above === 1 ? '' : 's'} above it.`}
    >
      {ticks.map((t) => (
        <g key={t}>
          <line x1={left} x2={w} y1={y(t)} y2={y(t)} stroke="#eef1f6" />
          <text x={left - 6} y={y(t) + 3} fontSize={10} textAnchor="end" fill="#8a94a6">
            {t}
          </text>
        </g>
      ))}
      {series.map((p, i) => {
        const h = p.count === 0 ? 0 : Math.max(1.5, chartH - y(p.count));
        const hot = threshold !== null && p.count > threshold;
        return (
          <rect key={i} x={left + i * slot} y={chartH - h} width={bw} height={h} rx={Math.min(2, bw / 2)} fill={hot ? ABOVE : NORMAL} opacity={hot ? 1 : 0.75} data-testid={hot ? 'bar-above' : 'bar'}>
            <title>{`${p.hour ? fmtTime(p.hour) : `hour ${i + 1}`}: ${p.count}${hot ? ' (above normal)' : ''}`}</title>
          </rect>
        );
      })}
      {mean !== null && <line x1={left} x2={w} y1={y(mean)} y2={y(mean)} stroke={MEAN} strokeWidth={1.2} strokeDasharray="2 3" />}
      {threshold !== null && (
        <g data-testid="baseline-threshold">
          <line x1={left} x2={w} y1={y(threshold)} y2={y(threshold)} stroke={THRESHOLD} strokeWidth={1.8} strokeDasharray="6 4" />
          <text x={w - 4} y={y(threshold) - 4} fontSize={10.5} textAnchor="end" fill={THRESHOLD} fontWeight={600}>
            threshold {Number.isInteger(threshold) ? threshold : threshold.toFixed(1)}
          </text>
        </g>
      )}
      {days.map(({ i, t }) => (
        <text key={i} x={left + i * slot} y={height - 6} fontSize={10} fill="#8a94a6">
          {new Date(t).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
        </text>
      ))}
      <line x1={left} x2={w} y1={chartH} y2={chartH} stroke="#d5dae4" />
    </svg>
  );
}
