// One integration card per provider tenant (NetSuite, Salesforce, ServiceNow,
// SAP) with a "Connection method" dropdown: REST API or MCP Server. The
// dropdown decides which method's form is shown, saved and tested; each
// method keeps its own saved configuration, credentials and status, and
// switching never changes or disconnects the other one. A method is shown
// as connected only when its own connection passed a live test; a method the
// provider environment does not offer is shown unavailable, with the reason.

import { useState, type ReactNode } from 'react';
import {
  createApp,
  getAppActivity,
  getRestCheck,
  HEALTH,
  TRANSPORT_LABEL,
  type AppActivity,
  type AppIntegration,
  type ProviderInfo,
  type RestCheck,
  type TransportView,
} from '../api/apps';
import { deleteIntegration, saveIntegration, testIntegration } from '../api/endpoints';
import type { Integration, IntegrationSchema } from '../api/types';
import { fmtAgo, fmtTime } from '../lib/format';
import { buildPayload, formProblems, initialForm, INSTANCE_NAME, type IntegrationFormState, type SecretState } from '../lib/integrationForm';
import { useLiveRefresh } from '../lib/live';
import { useAsync } from '../lib/useAsync';
import { ConnectionFields } from './ConnectionFields';
import { IconCloud, IconDatabase, IconGlobe, IconPlug } from './Icons';
import { QuickStartPanel } from './QuickStartPanel';
import { useToast } from './Toasts';
import { errText, ErrorBox, Modal } from './ui';

const LOGOS: Record<string, { icon: ReactNode; bg: string; fg: string }> = {
  netsuite: { icon: <IconDatabase size={22} />, bg: '#f0fdf4', fg: '#15803d' },
  salesforce: { icon: <IconCloud size={22} />, bg: '#eff6ff', fg: '#0284c7' },
  servicenow: { icon: <IconPlug size={22} />, bg: '#ecfdf5', fg: '#047857' },
  sap: { icon: <IconGlobe size={22} />, bg: '#eff6ff', fg: '#1d4ed8' },
};

const VERIFIED: Record<string, { label: string; tone: string; title: string }> = {
  live: { label: 'verified live', tone: 'green', title: 'Exercised against a real account' },
  test: { label: 'tested against fakes only', tone: 'blue', title: 'Exercised only against local fakes; not yet against a real account' },
};

const LIVE_TEST = {
  label: 'live test passed',
  tone: 'green',
  title: "The last Test connection of this method succeeded against this tenant (not a local fake). Fortik's other handling of this provider (decisions, holds, approvals) may still be verified only against local fakes: see Known gaps.",
};

/** Whether a connection's last successful test reached a real host (not a loopback fake). */
export function testedLive(current: Integration | undefined): boolean {
  if (current?.status !== 'ok') return false;
  for (const k of ['endpoint_url', 'instance_url', 'api_base_url', 'api_base']) {
    const v = current.config[k];
    if (typeof v !== 'string' || v === '') continue;
    try {
      const h = new URL(v).hostname.replace(/^\[|\]$/g, '');
      return !(h === 'localhost' || h === '::1' || h.startsWith('127.'));
    } catch {
      return false;
    }
  }
  return true; // the provider's default endpoint (e.g. NetSuite's, derived from the account)
}

/** What a method's saved connection says (never "connected" from saved settings alone). */
export function methodStatus(t: TransportView, current: Integration | undefined): { label: string; tone: string } {
  if (!t.available) return { label: 'Unavailable', tone: 'gray' };
  if (!current) return { label: 'Not configured', tone: 'gray' };
  switch (current.status) {
    case 'ok':
      return { label: 'Connected', tone: 'green' };
    case 'error':
      return { label: 'Connection test failed', tone: 'red' };
    case 'configured':
      return { label: 'Saved, not tested yet', tone: 'amber' };
  }
  return { label: 'Not configured', tone: 'gray' };
}

export interface ProviderCardProps {
  app: AppIntegration;
  schemas: Map<string, IntegrationSchema>;
  canEdit: boolean;
  onChanged: () => void;
  /** Opens the "add tenant" dialog (optionally for one environment). */
  onAddTenant?: (environment?: string) => void;
}

export function ProviderCard({ app, schemas, canEdit, onChanged, onAddTenant }: ProviderCardProps) {
  const initial = app.transports.find((t) => t.configured) ?? app.transports.find((t) => t.available) ?? app.transports[0];
  const [method, setMethod] = useState(initial?.transport ?? '');
  // Unsaved edits per method survive switching back and forth.
  const [forms, setForms] = useState<Record<string, IntegrationFormState | undefined>>({});
  const t = app.transports.find((x) => x.transport === method) ?? initial;
  const current = t ? app.connections.find((c) => c.key === t.connectionKey) : undefined;
  const health = HEALTH[app.health] ?? { label: app.health, tone: 'gray' };
  const logo = LOGOS[app.provider] ?? LOGOS.netsuite!;
  const env = app.environment === 'quickstart' ? 'QuickStart' : '';
  // The tenant's own name, when it says more than the provider's.
  const tenantName = !app.virtual && app.displayName && app.displayName !== app.providerTitle ? app.displayName : '';
  const status = t ? methodStatus(t, current) : null;
  const verified = !t?.available ? undefined : testedLive(current) && t.verified !== 'live' ? LIVE_TEST : VERIFIED[t.verified];
  return (
    <div className="card int-card provider-card" data-testid={`provider-card-${app.integrationId}`}>
      <div className="top">
        <span className="int-logo" style={{ background: logo.bg, color: logo.fg }}>
          {logo.icon}
        </span>
        <div className="grow">
          <div className="pc-title">
            <h3>{app.providerTitle}</h3>
            {env && <span className="chip gray">{env}</span>}
          </div>
          <div className="pc-meta">
            {app.virtual ? (
              <span>Not connected yet. Choose a connection method below.</span>
            ) : (
              <>
                {tenantName && <span>{tenantName}</span>}
                {tenantName && <span>·</span>}
                <span className="mono">{app.integrationId}</span>
                {app.tenantRef && app.tenantRef !== tenantName && (
                  <>
                    <span>·</span>
                    <span>{app.tenantRef}</span>
                  </>
                )}
              </>
            )}
          </div>
        </div>
        <span className={`chip ${health.tone}`} data-testid="provider-health" title="All connection methods of this integration">
          <span className="dot" />
          {health.label}
        </span>
      </div>
      <div className="pc-toolbar">
        <div className="field">
          <label htmlFor={`method-${app.integrationId}`}>Connection method</label>
          <select
            id={`method-${app.integrationId}`}
            className="select"
            value={t?.transport ?? ''}
            onChange={(e) => setMethod(e.target.value)}
            data-testid="connection-method"
          >
            {app.transports.map((o) => (
              <option key={o.transport} value={o.transport}>
                {o.title}
                {!o.available ? ' — unavailable' : ''}
              </option>
            ))}
          </select>
        </div>
        {t && status && (
          <div className="pc-status">
            <span className={`chip ${status.tone}`} data-testid="method-status">
              <span className="dot" />
              {TRANSPORT_LABEL[t.transport] ?? t.transport} — {status.label}
            </span>
            {verified && (
              <span className={`chip ${verified.tone}`} title={verified.title}>
                {verified.label}
              </span>
            )}
            {current?.lastTestedAt && (
              <span className="muted small" title={fmtTime(current.lastTestedAt)}>
                last tested {fmtAgo(current.lastTestedAt)}
              </span>
            )}
          </div>
        )}
      </div>
      {t && (
        <MethodPanel
          key={t.connectionKey || t.transport}
          app={app}
          t={t}
          schema={t.system ? schemas.get(t.system) : undefined}
          current={current}
          canEdit={canEdit}
          form={forms[t.transport]}
          setForm={(f) => setForms((m) => ({ ...m, [t.transport]: f }))}
          onChanged={onChanged}
          onAddTenant={onAddTenant}
        />
      )}
      {((!app.virtual && app.connections.length > 0) || (onAddTenant && !app.virtual)) && (
        <div className="pc-foot">
          {!app.virtual && app.connections.length > 0 && <ActivityLine id={app.integrationId} />}
          <div className="spacer" />
          {onAddTenant && !app.virtual && (
            <button className="btn ghost small" disabled={!canEdit} onClick={() => onAddTenant()} data-testid="add-tenant">
              + Add another {app.providerTitle} tenant
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function MethodPanel({
  app,
  t,
  schema,
  current,
  canEdit,
  form,
  setForm,
  onChanged,
  onAddTenant,
}: {
  app: AppIntegration;
  t: TransportView;
  schema: IntegrationSchema | undefined;
  current: Integration | undefined;
  canEdit: boolean;
  form: IntegrationFormState | undefined;
  setForm: (f: IntegrationFormState | undefined) => void;
  onChanged: () => void;
  onAddTenant?: (environment?: string) => void;
}) {
  const toast = useToast();
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [disconnecting, setDisconnecting] = useState(false);
  const label = TRANSPORT_LABEL[t.transport] ?? t.transport;

  if (!t.available || !schema) {
    const quickstartREST = app.provider === 'netsuite' && app.environment === 'quickstart' && t.transport === 'rest_api';
    return (
      <div className="pc-body single">
        <div className="alert warn" data-testid="method-unavailable">
          <div>
            <strong>
              {t.title} is unavailable{app.environment === 'quickstart' ? ' for this QuickStart account' : ''}.
            </strong>{' '}
            {t.reason || 'This build has no connection type for this method.'}
            {quickstartREST && onAddTenant && (
              <div style={{ marginTop: 8 }}>
                <button className="btn small" disabled={!canEdit} onClick={() => onAddTenant('full')} data-testid="add-full-account">
                  Connect a full NetSuite account with SuiteTalk REST
                </button>
              </div>
            )}
          </div>
        </div>
      </div>
    );
  }

  const st = form ?? initialForm(schema, current);
  const touched = form !== undefined;
  const problems = formProblems(schema, st, current);
  const setValue = (k: string, v: string | boolean) => setForm({ ...st, values: { ...st.values, [k]: v } });
  const setSecret = (k: string, v: SecretState) => setForm({ ...st, secrets: { ...st.secrets, [k]: v } });

  const save = async () => {
    setBusy('save');
    setError(null);
    setTestMsg(null);
    try {
      const { config, secrets } = buildPayload(schema, st);
      await saveIntegration(t.connectionKey, config, secrets);
      setForm(undefined); // typed secrets are dropped from memory once stored
      toast({ tone: 'green', title: `${app.providerTitle} ${label} saved`, body: 'Run Test connection to check it.' });
      onChanged();
    } catch (e) {
      setError(e);
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy('test');
    setError(null);
    setTestMsg(null);
    try {
      const r = await testIntegration(t.connectionKey);
      setTestMsg(r.ok ? { ok: true, text: `${label}: connection OK${r.durationMs !== undefined ? ` (${r.durationMs} ms)` : ''}.` } : { ok: false, text: r.error ?? 'Connection failed.' });
    } catch (e) {
      setTestMsg({ ok: false, text: errText(e) });
    } finally {
      setBusy(null);
      onChanged();
    }
  };

  return (
    <>
      <div className="pc-body" data-testid={`method-${t.transport}`}>
        <section className="pc-section">
          <h4>{t.title}: settings</h4>
          {!canEdit && <div className="alert info small">Read-only: changing integrations requires the security role.</div>}
          <ConnectionFields schema={schema} st={st} saved={current} canEdit={canEdit} setValue={setValue} setSecret={setSecret} idPrefix={`${t.connectionKey}-`} />
          {touched && problems.length > 0 && (
            <div className="alert warn" data-testid="form-problems">
              <div>
                Before saving:
                <ul>
                  {problems.map((p) => (
                    <li key={p}>{p}</li>
                  ))}
                </ul>
              </div>
            </div>
          )}
          <ErrorBox error={error} />
          {testMsg && (
            <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`} role="status" data-testid="test-result">
              {testMsg.text}
            </div>
          )}
        </section>
        <aside className="pc-section pc-details">
          <h4>{current ? 'Connection' : 'Before you connect'}</h4>
          {current?.lastError && !testMsg && <div className="alert error small">Last error: {current.lastError}</div>}
          {!current && <div className="muted">{t.reason}</div>}
          {current && t.transport === 'mcp' && <QuickStartPanel connectionKey={t.connectionKey} canRefresh={canEdit} onChanged={onChanged} />}
          {current && t.transport === 'rest_api' && app.provider !== 'netsuite' && <RestCheckPanel connectionKey={t.connectionKey} />}
          {current && t.transport === 'rest_api' && app.provider === 'netsuite' && (
            <div className="muted">
              Agents call <span className="mono">/gw/netsuite/services/rest/...</span> on the gateway with their Fortik token
              {!app.virtual && (
                <>
                  ; with several NetSuite accounts they name this one with <span className="mono">X-Fortik-Integration: {app.integrationId}</span>
                </>
              )}
              .
            </div>
          )}
        </aside>
      </div>
      <div className="actions">
        <button className="btn primary small" disabled={!canEdit || busy !== null || problems.length > 0 || (!touched && !!current)} onClick={() => void save()} data-testid="save">
          {busy === 'save' && <span className="spinner" />} Save
        </button>
        <button
          className="btn small"
          disabled={!canEdit || !current || touched || busy !== null || current.testAvailable === false}
          title={!current ? 'Save it first' : touched ? 'Save your changes first' : undefined}
          onClick={() => void test()}
          data-testid="test-connection"
        >
          {busy === 'test' && <span className="spinner" />} Test connection
        </button>
        {touched && <span className="muted small">Unsaved changes</span>}
        <div className="spacer" />
        {touched && (
          <button className="btn ghost small" onClick={() => setForm(undefined)}>
            Discard changes
          </button>
        )}
        {current && (
          <button className="btn ghost small" style={{ color: '#b91c1c' }} disabled={!canEdit} onClick={() => setDisconnecting(true)} data-testid="disconnect">
            Disconnect {label}
          </button>
        )}
      </div>
      {disconnecting && (
        <DisconnectDialog
          what={`${app.providerTitle} ${label}`}
          connectionKey={t.connectionKey}
          onClose={() => setDisconnecting(false)}
          onDone={(notes) => {
            setDisconnecting(false);
            toast({ tone: 'amber', title: `${app.providerTitle} ${label} disconnected`, body: ['Its credentials were removed from the secret store.', ...notes].join(' ') });
            onChanged();
          }}
        />
      )}
    </>
  );
}

function DisconnectDialog({ what, connectionKey, onClose, onDone }: { what: string; connectionKey: string; onClose: () => void; onDone: (notes: string[]) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  return (
    <Modal
      title={`Disconnect ${what}?`}
      description="Its settings and stored credentials are deleted and agent calls over this method are refused until it is configured again. The other connection method of this integration is not affected."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button
            className="btn danger"
            disabled={busy}
            data-testid="confirm-disconnect"
            onClick={() => {
              setBusy(true);
              setError(null);
              deleteIntegration(connectionKey).then(onDone, (e: unknown) => {
                setError(e);
                setBusy(false);
              });
            }}
          >
            {busy && <span className="spinner" />} Disconnect
          </button>
        </>
      }
    >
      <ErrorBox error={error} />
    </Modal>
  );
}

const CHECK_TONE: Record<string, string> = { connected: 'green', saved_not_tested: 'amber', not_configured: 'gray' };

function capabilityText(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return String(v);
  if (Array.isArray(v)) return v.map(capabilityText).join(', ');
  return Object.entries(v as Record<string, unknown>)
    .map(([k, x]) => `${k}: ${typeof x === 'object' && x !== null && !Array.isArray(x) ? `{${capabilityText(x)}}` : capabilityText(x)}`)
    .join('; ');
}

/** The last live check of a Salesforce, ServiceNow or SAP REST connection. */
function RestCheckPanel({ connectionKey }: { connectionKey: string }) {
  const chk = useAsync<RestCheck>((signal) => getRestCheck(connectionKey, signal), [connectionKey]);
  useLiveRefresh((e) => e.eventType.startsWith('integration.'), chk.reload, 500);
  if (chk.error) return <div className="muted small err">Status unavailable: {errText(chk.error)}</div>;
  if (!chk.data) return null;
  const c = chk.data;
  return (
    <div className="small" data-testid="rest-check" style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div className="row" style={{ gap: 8 }}>
        <span className={`chip ${CHECK_TONE[c.state] ?? 'red'}`} data-testid="rest-check-state">
          {c.stateLabel}
        </span>
        {c.detail && <span className="muted">{c.detail}</span>}
      </div>
      {!c.endpointPermitted && c.endpointRefusal && <div className="err">Endpoint not permitted: {c.endpointRefusal}</div>}
      {Object.keys(c.identity).length > 0 && <div>Acts as: {capabilityText(c.identity)}</div>}
      {Object.keys(c.capabilities).length > 0 && (
        <div data-testid="rest-capabilities">
          Capabilities{c.capabilitiesCurrent ? '' : ' (from an earlier check)'}: {capabilityText(c.capabilities)}
        </div>
      )}
      {c.agentEndpoint && (
        <div>
          Agents call <span className="mono">{c.agentEndpoint}…</span> with their Fortik token (never these credentials).
        </div>
      )}
      {c.knownGaps.length > 0 && (
        <details>
          <summary>Known gaps ({c.knownGaps.length})</summary>
          <ul style={{ margin: '4px 0 0 16px', padding: 0 }}>
            {c.knownGaps.map((g) => (
              <li key={g}>{g}</li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

const DECISIONS = ['allow', 'allow_reduced', 'hold', 'deny'];

function ActivityLine({ id }: { id: string }) {
  const act = useAsync<AppActivity>((signal) => getAppActivity(id, signal), [id]);
  if (!act.data) return null;
  const a = act.data;
  const transports = Object.keys(a.byTransport).sort();
  return (
    <div className="small muted" data-testid="provider-activity">
      Last {a.windowHours}h, all methods:{' '}
      {transports.length === 0
        ? 'no agent calls'
        : transports.map((t, i) => (
            <span key={t}>
              {i > 0 && ' · '}
              <strong>{TRANSPORT_LABEL[t] ?? (t || 'other')}</strong>{' '}
              {DECISIONS.filter((d) => a.byTransport[t]?.[d])
                .map((d) => `${a.byTransport[t]?.[d] ?? 0} ${d.replace('_', ' ')}`)
                .join(', ')}
            </span>
          ))}
      {' '}· {a.pendingApprovals} pending approval{a.pendingApprovals === 1 ? '' : 's'}
    </div>
  );
}

const TENANT_PATTERN: Record<string, RegExp> = {
  full: /^[A-Za-z0-9]{1,20}(_[A-Za-z0-9]{1,10})?$/,
};

/** Adds a tenant of a provider (another account, org, instance or system) before its connections. */
export function AddTenantDialog({
  provider,
  existing,
  environment,
  onClose,
  onCreated,
}: {
  provider: ProviderInfo;
  existing: string[];
  environment?: string;
  onClose: () => void;
  onCreated: () => void;
}) {
  const [env, setEnv] = useState(environment ?? provider.environments[0]?.environment ?? '');
  const [name, setName] = useState('');
  const [display, setDisplay] = useState('');
  const [tenant, setTenant] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const envInfo = provider.environments.find((e) => e.environment === env);
  const n = name.trim();
  const dup = existing.includes(`${provider.provider}:${n}`);
  const needsTenant = env === 'full';
  const tenantOK = tenant.trim() === '' ? !needsTenant : (TENANT_PATTERN[env]?.test(tenant.trim()) ?? true);
  const ok = INSTANCE_NAME.test(n) && !dup && display.trim() !== '' && tenantOK;
  const create = async () => {
    setBusy(true);
    setError(null);
    try {
      await createApp({ provider: provider.provider, environment: env, name: n, tenant_ref: tenant.trim(), display_name: display.trim() });
      onCreated();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Add a ${provider.title} tenant`}
      description="A tenant is one account, org, instance or system. Choose its connection method on its card afterwards; each method keeps its own credentials."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" disabled={!ok || busy} onClick={() => void create()}>
            {busy && <span className="spinner" />} Add
          </button>
        </>
      }
    >
      <ErrorBox error={error} />
      {provider.environments.length > 1 && (
        <div className="field">
          <label htmlFor="tenant-env">Environment</label>
          <select id="tenant-env" className="select" value={env} onChange={(e) => setEnv(e.target.value)}>
            {provider.environments.map((e) => (
              <option key={e.environment} value={e.environment}>
                {e.title}
              </option>
            ))}
          </select>
          <span className="help">
            {envInfo?.transports.map((t) => `${TRANSPORT_LABEL[t.transport] ?? t.transport}: ${t.available ? 'available' : 'not available'}`).join(' · ')}
          </span>
        </div>
      )}
      <div className="field">
        <label htmlFor="tenant-name">Name</label>
        <input id="tenant-name" className="input" value={name} placeholder="acme" onChange={(e) => setName(e.target.value)} aria-invalid={n !== '' && (!INSTANCE_NAME.test(n) || dup)} />
        <span className="help">
          {dup ? `A ${provider.title} tenant with this name already exists.` : `The integration id becomes ${provider.provider}:${n || '<name>'}; access profiles restrict agents by it.`}
        </span>
      </div>
      <div className="field">
        <label htmlFor="tenant-display">Display name</label>
        <input id="tenant-display" className="input" value={display} placeholder="Acme production" onChange={(e) => setDisplay(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="tenant-ref">{envInfo?.tenantLabel || 'Tenant'}</label>
        <input id="tenant-ref" className="input" value={tenant} onChange={(e) => setTenant(e.target.value)} />
        <span className="help">
          {needsTenant
            ? 'Required. Every connection of this tenant must name this account; an account belongs to one tenant only.'
            : env === 'quickstart'
              ? 'Optional label; QuickStart connections are told apart by their token, not by this label.'
              : 'Optional now; set by its first connection otherwise. Every connection of the tenant must reach the same one.'}
        </span>
      </div>
    </Modal>
  );
}
