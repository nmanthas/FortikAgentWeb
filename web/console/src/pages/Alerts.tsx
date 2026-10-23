// Alerts (docs/PHASE3_DESIGN.md §2.9): open alerts grouped by severity with
// Acknowledge and Resolve. New alerts also arrive as live toasts.

import { useState } from 'react';
import { Link } from 'react-router-dom';
import { ackAlert, listAlerts, resolveAlert } from '../api/endpoints';
import { SEVERITY_RANK } from '../api/normalize';
import type { Alert, AlertStatus, Severity } from '../api/types';
import { useMe } from '../App';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading } from '../components/ui';
import { useAlertCount } from '../lib/alertCount';
import { fmtAgo, fmtTime, titleCase } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { hasRole } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

export const SEVERITY_COLOR: Record<Severity, string> = { critical: 'black', high: 'red', warning: 'amber', info: 'blue' };
const ORDER: Severity[] = ['critical', 'high', 'warning', 'info'];

export function AlertsPage() {
  const me = useMe();
  const toast = useToast();
  const counts = useAlertCount();
  const [status, setStatus] = useState<AlertStatus>('open');
  const alerts = useAsync<Alert[]>((s) => listAlerts(status, s), [status]);
  useLiveRefresh((e) => e.eventType.startsWith('alert.'), alerts.reload, 800);
  const canChange = hasRole(me, 'security');
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const change = async (a: Alert, op: 'ack' | 'resolve') => {
    setBusy(a.alertId);
    setError(null);
    try {
      await (op === 'ack' ? ackAlert(a.alertId) : resolveAlert(a.alertId));
      toast({ tone: 'green', title: op === 'ack' ? 'Alert acknowledged' : 'Alert resolved', body: a.summary });
      alerts.reload();
      counts.refresh();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  const list = (alerts.data ?? []).slice().sort((x, y) => SEVERITY_RANK[y.severity] - SEVERITY_RANK[x.severity] || y.updatedAt.localeCompare(x.updatedAt));

  return (
    <>
      <div className="toolbar" style={{ marginBottom: 12 }}>
        <label className="sr-only" htmlFor="alert-status">
          Alert status
        </label>
        <select id="alert-status" className="select" style={{ width: 200 }} value={status} onChange={(e) => setStatus(e.target.value as AlertStatus)}>
          <option value="open">Open</option>
          <option value="acknowledged">Acknowledged</option>
          <option value="resolved">Resolved</option>
        </select>
        {!canChange && <span className="muted small">Acknowledging and resolving alerts requires the security role.</span>}
      </div>
      <ErrorBox error={error} />
      {alerts.error && <ErrorBox error={alerts.error} onRetry={alerts.reload} />}
      {alerts.loading && !alerts.data && <Loading />}
      {alerts.data && list.length === 0 && (
        <div className="card">
          <div className="empty">No {status} alerts.</div>
        </div>
      )}
      {ORDER.map((sev) => {
        const group = list.filter((a) => a.severity === sev);
        if (group.length === 0) return null;
        return (
          <div key={sev} className="card sev-group" data-testid={`severity-${sev}`}>
            <div className="card-head">
              <h2>
                <span className={`chip ${SEVERITY_COLOR[sev]}`}>{titleCase(sev)}</span> {group.length}
              </h2>
            </div>
            <div className="timeline" style={{ padding: '0 20px' }}>
              {group.map((a) => (
                <div key={a.alertId} className="tl-item" data-testid="alert-item">
                  <div className="tl-time" title={fmtTime(a.createdAt)}>
                    {fmtAgo(a.updatedAt || a.createdAt)}
                  </div>
                  <div className="tl-main">
                    <div className="tl-line">
                      <strong>{titleCase(a.kind)}</strong>
                      {a.agentId && <Link to={`/agents/${encodeURIComponent(a.agentId)}`}>{a.agentId}</Link>}
                      {a.agentType && <span className="muted small">type {a.agentType}</span>}
                      {a.count > 1 && <span className="chip gray">×{a.count}</span>}
                      {a.status !== 'open' && <span className="chip gray">{a.status}</span>}
                    </div>
                    <div className="tl-reason">{a.summary}</div>
                    {a.ackedBy && <div className="muted small">acknowledged by {a.ackedBy}</div>}
                    {a.status !== 'resolved' && (
                      <div className="btn-row" style={{ marginTop: 8 }}>
                        {a.status === 'open' && (
                          <button className="btn small" disabled={!canChange || busy !== null} onClick={() => void change(a, 'ack')} aria-label={`Acknowledge ${a.summary}`}>
                            Acknowledge
                          </button>
                        )}
                        <button className="btn small" disabled={!canChange || busy !== null} onClick={() => void change(a, 'resolve')} aria-label={`Resolve ${a.summary}`}>
                          Resolve
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        );
      })}
    </>
  );
}
