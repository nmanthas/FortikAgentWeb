// A NetSuite MCP connection's details on its Integrations card (QuickStart
// with a personal access token, or a full account's AI Connector Service
// with OAuth): the state of the last live check (never "Connected" from
// saved settings alone), the authorization, the discovered tools, and what
// Fortik does and does not enforce for this server today.

import { useState } from 'react';
import {
  getQuickStart,
  PERMISSION_LABEL,
  quickStartTone,
  refreshQuickStart,
  startOAuth,
  type QuickStartActivity,
  type QuickStartStatus,
  type QuickStartTool,
} from '../api/quickstart';
import { fmtAgo, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { useAsync } from '../lib/useAsync';
import { useToast } from './Toasts';
import { errText, Modal } from './ui';

const DOC_LABEL: Record<string, string> = {
  read_only_token: 'documented: read-only tokens',
  read_write_token: 'documented: read-write tokens only',
  undocumented: 'not in Oracle’s documented lists',
};

/** The display name of a NetSuite MCP connection type. */
export const mcpLabel = (integration: string) => (integration === 'netsuite_mcp' ? 'NetSuite MCP' : 'QuickStart');

export function QuickStartPanel({
  canRefresh,
  onChanged,
  connectionKey = 'netsuite_quickstart',
}: {
  canRefresh: boolean;
  onChanged: () => void;
  connectionKey?: string;
}) {
  const toast = useToast();
  const st = useAsync<QuickStartStatus | null>((signal) => getQuickStart(signal, connectionKey), [connectionKey]);
  const [busy, setBusy] = useState(false);
  const [authorizing, setAuthorizing] = useState(false);
  const [showTools, setShowTools] = useState(false);
  useLiveRefresh((e) => e.eventType.startsWith('integration.') || e.eventType.startsWith('mcp.'), st.reload, 500);

  const fallback = connectionKey.startsWith('netsuite_mcp') ? 'NetSuite MCP' : 'QuickStart';
  if (st.error) return <div className="muted small err">{fallback} status unavailable: {errText(st.error)}</div>;
  if (st.data === undefined) return <div className="muted small">Loading {fallback} status…</div>;
  if (st.data === null) return null; // older server without NetSuite MCP
  const q = st.data;
  const label = mcpLabel(q.integration);
  const oauth = q.oauth;

  const refresh = async () => {
    setBusy(true);
    try {
      const r = await refreshQuickStart(connectionKey);
      toast(
        r.ok
          ? { tone: 'green', title: `${label}: connected`, body: `${r.status.tools.length} tools discovered` }
          : { tone: 'red', title: `${label}: ${r.status.stateLabel}`, body: r.error },
      );
    } catch (e) {
      toast({ tone: 'red', title: `${label}: check could not run`, body: errText(e) });
    } finally {
      setBusy(false);
      st.reload();
      onChanged();
    }
  };

  // Opens NetSuite's consent screen; NetSuite returns to Fortik's callback,
  // which stores the tokens, runs a check and comes back to Integrations.
  const authorize = async () => {
    setAuthorizing(true);
    try {
      const url = await startOAuth(connectionKey);
      if (!url) throw new Error('the server returned no authorization URL');
      window.location.assign(url);
    } catch (e) {
      toast({ tone: 'red', title: `${label}: authorization could not start`, body: errText(e) });
      setAuthorizing(false);
    }
  };

  return (
    <div className="qs-panel" data-testid="quickstart-panel" style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 13 }}>
      <div className="row" style={{ gap: 8, flexWrap: 'wrap' }}>
        <span className={`chip ${quickStartTone(q.state)}`} data-testid="quickstart-state">
          <span className="dot" />
          {q.stateLabel}
        </span>
        {q.configured && (
          <span className="muted small">
            transport mcp · system netsuite{q.integrationId && ` · ${q.integrationId}`}
          </span>
        )}
      </div>
      {q.detail && <div className="muted small">{q.detail}</div>}
      <div
        className="banner small"
        data-testid="quickstart-enforcement"
        style={{ padding: '6px 8px', borderRadius: 6, background: q.enforcement.agentCallsRouted ? '#f0fdf4' : '#fffbeb', color: q.enforcement.agentCallsRouted ? '#166534' : '#92400e' }}
      >
        <strong>Agent calls routed through Fortik: {q.enforcement.agentCallsRouted ? 'yes' : 'no'}.</strong> {q.enforcement.note}
      </div>
      {q.agentEndpoint && (
        <div className="small">
          Agents connect to <span className="mono" data-testid="quickstart-agent-endpoint">{q.agentEndpoint}</span> with their Fortik agent token (never the{' '}
          {oauth ? 'NetSuite OAuth token' : 'QuickStart token'}).
        </div>
      )}
      {oauth && q.configured && (
        <div className="small" data-testid="mcp-oauth">
          {oauth.authorized ? (
            <>
              Authorized{oauth.authorizedBy && ` by ${oauth.authorizedBy}`}
              {oauth.authorizedAt && <span title={fmtTime(oauth.authorizedAt)}> {fmtAgo(oauth.authorizedAt)}</span>}
              {oauth.scope && <> · scope <span className="mono">{oauth.scope}</span></>}
              {oauth.refreshedAt && <> · token refreshed {fmtAgo(oauth.refreshedAt)}</>}
            </>
          ) : (
            <span className="err">
              {oauth.stale
                ? 'The stored authorization was issued for another account or client ID: authorize again.'
                : 'No NetSuite user has authorized Fortik for this connection yet.'}
            </span>
          )}
          {q.mappedTools === 0 && (
            <div className="muted">
              No tool of this server is mapped in Fortik yet: every tool call is refused and none is offered to agents until it is mapped (policies/fortik/netsuite_mcp/data.json).
            </div>
          )}
        </div>
      )}
      {q.activity && <ActivitySummary a={q.activity} />}
      {q.configured && (
        <div className="facts" style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {q.tenantLabel && <span>Tenant: {q.tenantLabel}</span>}
          <span className="mono small">{q.endpoint}</span>
          {!q.endpointPermitted && q.endpointRefusal && <span className="err">Endpoint not permitted: {q.endpointRefusal}</span>}
          {!oauth && (
            <span>
              Token: {q.token.set ? 'stored in Fortik’s secret store' : 'not set'}
              {q.token.expiresOn && ` · expires ${q.token.expiresOn}`}
              {q.token.daysLeft !== null && q.token.daysLeft >= 0 && ` (${q.token.daysLeft} days left)`}
            </span>
          )}
          {q.token.warning && <span className="err">{q.token.warning}</span>}
          {q.server && (
            <span>
              Server: {q.server.name || 'unnamed'} {q.server.version} · MCP {q.server.protocolVersion}
            </span>
          )}
          {oauth ? (
            <span>Permissions: the authorizing NetSuite user&apos;s role (Fortik cannot read or narrow it)</span>
          ) : (
            <span title={q.permissionBasis}>Token scope: {PERMISSION_LABEL[q.permissionMode] ?? q.permissionMode}</span>
          )}
          <span>
            Last successful check: <span title={fmtTime(q.lastSuccessAt || undefined)}>{q.lastSuccessAt ? fmtAgo(q.lastSuccessAt) : 'never'}</span>
            {' · '}tools synchronized: {q.lastToolsSyncAt ? fmtAgo(q.lastToolsSyncAt) : 'never'}
          </span>
          {q.tools.length > 0 && !q.toolsCurrent && <span className="err">The tool list is from an earlier check, not the current settings or token.</span>}
          {q.rejected.length > 0 && <span className="err">{q.rejected.length} malformed tool definition(s) excluded.</span>}
        </div>
      )}
      <div className="row" style={{ gap: 6 }}>
        {oauth && (
          <button
            className="btn small primary"
            disabled={!canRefresh || !q.configured || authorizing}
            title={!q.configured ? 'Configure it first' : !canRefresh ? 'Requires the security role' : 'Opens NetSuite to sign in and approve Fortik'}
            onClick={() => void authorize()}
            data-testid="mcp-authorize"
          >
            {authorizing && <span className="spinner" />} {oauth.authorized ? 'Authorize again' : 'Authorize'}
          </button>
        )}
        <button className="btn small" disabled={q.tools.length === 0 && q.rejected.length === 0} onClick={() => setShowTools(true)} data-testid="quickstart-view-tools">
          View tools ({q.tools.length})
        </button>
        <button
          className="btn small"
          disabled={!canRefresh || !q.configured || busy}
          title={!q.configured ? 'Configure it first' : !canRefresh ? 'Requires the security role' : 'Runs initialize and tools/list against the server now'}
          onClick={() => void refresh()}
          data-testid="quickstart-refresh"
        >
          {busy && <span className="spinner" />} Refresh tools
        </button>
      </div>
      {q.configured && <div className="muted small">{q.revokeInstructions}</div>}
      {q.coverage.length > 0 && (
        <details className="small" data-testid="quickstart-coverage">
          <summary>Coverage ({q.coverage.filter((c) => c.status === 'verified_live').length} of {q.coverage.length} verified live)</summary>
          <table className="table small" style={{ marginTop: 4 }}>
            <tbody>
              {q.coverage.map((c) => (
                <tr key={c.dimension} title={[c.gap, c.fix].filter(Boolean).join(' — ')}>
                  <td>{c.dimension.replace(/_/g, ' ')}</td>
                  <td>
                    <span className={`chip ${COVERAGE_TONE[c.status] ?? 'gray'}`}>{c.status.replace(/_/g, ' ')}</span>
                  </td>
                  <td className="muted">{c.gap}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
      {q.knownGaps.length > 0 && (
        <details className="small" data-testid="quickstart-gaps">
          <summary>Known gaps ({q.knownGaps.length})</summary>
          <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
            {q.knownGaps.map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
        </details>
      )}
      {showTools && <ToolsDialog q={q} onClose={() => setShowTools(false)} />}
    </div>
  );
}

const COVERAGE_TONE: Record<string, string> = {
  verified_live: 'green',
  verified_test: 'blue',
  implemented: 'amber',
  unsupported: 'gray',
  not_built: 'red',
};

const OUTCOME_LABEL: Record<string, string> = {
  executed: 'executed',
  failed: 'failed',
  not_executed: 'not executed',
  unknown: 'outcome unknown',
};

function ActivitySummary({ a }: { a: QuickStartActivity }) {
  return (
    <div className="small" data-testid="quickstart-activity">
      <div>
        Last {a.windowHours}h: <strong>{a.allowed}</strong> allowed · <strong>{a.held}</strong> held · <strong>{a.denied}</strong> denied ·{' '}
        <strong>{a.executed}</strong> executed{a.failed > 0 && <> · <span className="err">{a.failed} failed</span></>}
      </div>
      <div className="muted">
        {a.pendingApprovals} pending approval{a.pendingApprovals === 1 ? '' : 's'} · {a.activeSuspensions} active NetSuite suspension
        {a.activeSuspensions === 1 ? '' : 's'} · {a.undoAvailable} undo{a.undoAvailable === 1 ? '' : 's'} available
      </div>
      {a.recent.length > 0 && (
        <details>
          <summary>Recent decisions ({a.recent.length})</summary>
          <table className="table small" style={{ marginTop: 4 }}>
            <thead>
              <tr>
                <th>When</th>
                <th>Agent</th>
                <th>Tool</th>
                <th>Decision</th>
                <th>Rule</th>
                <th>Result</th>
              </tr>
            </thead>
            <tbody>
              {a.recent.map((r) => (
                <tr key={r.actionId} title={r.reason}>
                  <td>{r.ts ? fmtAgo(r.ts) : ''}</td>
                  <td className="mono">{r.agentId}</td>
                  <td className="mono">{r.tool}</td>
                  <td>{r.decision.replace('_', ' ')}</td>
                  <td className="mono">{r.ruleId}</td>
                  <td>
                    {OUTCOME_LABEL[r.outcome] ?? (r.decision === 'hold' ? 'waiting for approval' : r.decision === 'deny' ? 'not executed' : '')}
                    {r.undo === 'active' && ' · undo available'}
                    {r.undo === 'used' && ' · undone'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </details>
      )}
    </div>
  );
}

function ToolsDialog({ q, onClose }: { q: QuickStartStatus; onClose: () => void }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Modal
      title={`${mcpLabel(q.integration)} tools (${q.tools.length})`}
      description={`As returned by the server's tools/list${q.lastToolsSyncAt ? ` at ${fmtTime(q.lastToolsSyncAt)}` : ''}. Descriptions and schemas are the server's own text.${
        q.oauth ? ' Unmapped tools are refused and not offered to agents.' : ` Token scope: ${PERMISSION_LABEL[q.permissionMode] ?? q.permissionMode} — ${q.permissionBasis}`
      }`}
      onClose={onClose}
      footer={
        <button className="btn" onClick={onClose}>
          Close
        </button>
      }
    >
      <div style={{ maxHeight: 420, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 6 }} data-testid="quickstart-tools">
        {q.tools.map((t: QuickStartTool) => (
          <div key={t.name} className="card card-pad" style={{ padding: 8 }}>
            <button className="btn ghost small" onClick={() => setOpen(open === t.name ? null : t.name)} style={{ padding: 0 }}>
              <span className="mono">{t.name}</span>
            </button>{' '}
            {q.oauth ? (
              <span className={`chip ${t.mapped ? 'green' : 'gray'}`}>{t.mapped ? 'mapped' : 'not mapped: refused'}</span>
            ) : (
              <span className={`chip ${t.documentedAccess === 'read_write_token' ? 'amber' : t.documentedAccess === 'undocumented' ? 'gray' : 'green'}`}>
                {DOC_LABEL[t.documentedAccess] ?? t.documentedAccess}
              </span>
            )}
            {t.description && <div className="muted small">{t.description}</div>}
            {open === t.name && <pre className="mono small" style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{JSON.stringify(t.inputSchema, null, 2)}</pre>}
          </div>
        ))}
        {q.rejected.map((r, i) => (
          <div key={`rej-${i}`} className="err small">
            Excluded {r.name ? <span className="mono">{r.name}</span> : 'an entry'}: {r.reason}
          </div>
        ))}
      </div>
    </Modal>
  );
}
