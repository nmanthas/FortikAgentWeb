// Design-partner success metrics (plan; Phase 6 GET /v1/metrics/pilot): the
// five targets, measured on this deployment's own records, last 30 days.
import { fmtMetric, getPilotMetrics, type PilotMetrics } from '../api/phase6';
import { fmtNum } from '../lib/format';
import { useAsync } from '../lib/useAsync';
import { ErrorBox } from './ui';

export function PilotMetricsCard() {
  const m = useAsync<PilotMetrics | null>((s) => getPilotMetrics(s), []);
  if (m.data === null || (m.loading && !m.data)) return null;
  return (
    <section className="card" data-testid="pilot-metrics">
      <div className="card-head">
        <div>
          <h2>Pilot success metrics</h2>
          <div className="sub">
            The plan's targets, measured on this deployment's records (last 30 days, {fmtNum(m.data?.decisions ?? 0)} decisions
            {m.data && m.data.observedDecisions > 0 ? `, ${fmtNum(m.data.observedDecisions)} recorded in observe mode` : ''}).
          </div>
        </div>
      </div>
      {m.error && <ErrorBox error={m.error} onRetry={m.reload} />}
      {m.data && (
        <div className="metric-grid">
          {m.data.metrics.map((x) => (
            <div key={x.key} className="metric" data-testid="pilot-metric" title={x.basis}>
              <div className="t">{x.label}</div>
              <div className="v">{fmtMetric(x)}</div>
              <div className="row" style={{ gap: 6 }}>
                <span className="t">target {x.target}</span>
                {x.met === true && <span className="chip green">met</span>}
                {x.met === false && <span className="chip red">not met</span>}
                {x.met === null && <span className="chip gray">no data</span>}
              </div>
              <div className="t">n = {fmtNum(x.n)}</div>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
