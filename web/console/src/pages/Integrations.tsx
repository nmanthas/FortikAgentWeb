// Integrations screen. NetSuite, Salesforce, ServiceNow and SAP have one card
// per tenant with a "Connection method" dropdown (REST API or MCP Server)
// that decides which method's form is shown, saved and tested
// (GET /v1/app-integrations; components/ProviderCard). Every other system has
// a card per system (Google Workspace, GitHub, AWS, the Phase 4 queue
// systems) or per instance (Postgres upstreams, memory stores), configured in
// a drawer rendered from GET /v1/integrations/schema.

import { useEffect, useState, type ReactNode } from 'react';
import { listApps, tenantsOf, UNIFIED_PROVIDERS, type AppIntegrations, type ProviderInfo } from '../api/apps';
import { deleteIntegration, getIntegrationSchemas, listIntegrations, testIntegration } from '../api/endpoints';
import type { Integration, IntegrationSchema } from '../api/types';
import { useMe } from '../App';
import { IntegrationStatusChip } from '../components/Chips';
import { AddTenantDialog, ProviderCard } from '../components/ProviderCard';
import { QuickStartPanel } from '../components/QuickStartPanel';
import { IconBell, IconBolt, IconBrain, IconClock, IconCloud, IconDatabase, IconGit, IconGlobe, IconMail, IconPlus, IconPlug } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { errText, ErrorBox, Loading, Modal } from '../components/ui';
import { fmtAgo, fmtTime } from '../lib/format';
import { INSTANCE_NAME, integrationTitle, MULTI_TITLE, SYSTEM_BLURB, SYSTEM_ORDER } from '../lib/integrationForm';
import { useLiveRefresh } from '../lib/live';
import { hasRole } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';
import { IntegrationDrawer } from './IntegrationDrawer';

interface PageData {
  schemas: IntegrationSchema[];
  integrations: Integration[];
  /** null on a server without logical integrations (NetSuite then shows as plain cards). */
  apps: AppIntegrations | null;
}

async function load(signal: AbortSignal): Promise<PageData> {
  const [schemas, integrations, apps] = await Promise.all([getIntegrationSchemas(signal), listIntegrations(signal), listApps(signal)]);
  schemas.sort((a, b) => order(a.system) - order(b.system));
  return { schemas, integrations, apps };
}

/** Reads (and removes) the result the OAuth callback appends to /integrations. */
function takeOAuthResult(): { key: string; ok: boolean; error: string } | null {
  const q = new URLSearchParams(window.location.search);
  if (!q.has('oauth_ok') && !q.has('oauth_error')) return null;
  const out = { key: q.get('oauth') ?? '', ok: q.get('oauth_ok') === '1', error: q.get('oauth_error') ?? '' };
  for (const k of ['oauth', 'oauth_ok', 'oauth_error']) q.delete(k);
  const rest = q.toString();
  window.history.replaceState(null, '', window.location.pathname + (rest ? `?${rest}` : '') + window.location.hash);
  return out;
}

const LOGO: Record<string, { icon: ReactNode; bg: string; fg: string }> = {
  google_workspace: { icon: <IconMail size={22} />, bg: '#eff6ff', fg: '#2563eb' },
  github: { icon: <IconGit size={22} />, bg: '#f1f5f9', fg: '#0f172a' },
  aws: { icon: <IconCloud size={22} />, bg: '#fff7ed', fg: '#ea580c' },
  postgres: { icon: <IconDatabase size={22} />, bg: '#eef2ff', fg: '#4f46e5' },
  memory: { icon: <IconBrain size={22} />, bg: '#f5f3ff', fg: '#7c3aed' },
  temporal: { icon: <IconClock size={22} />, bg: '#f1f5f9', fg: '#0f172a' },
  celery: { icon: <IconBolt size={22} />, bg: '#ecfdf3', fg: '#16a34a' },
  queue_webhook: { icon: <IconGlobe size={22} />, bg: '#eff6ff', fg: '#2563eb' },
  notify_slack: { icon: <IconBell size={22} />, bg: '#fdf2f8', fg: '#db2777' },
  netsuite: { icon: <IconDatabase size={22} />, bg: '#f0fdf4', fg: '#15803d' },
  netsuite_quickstart: { icon: <IconPlug size={22} />, bg: '#f0fdf4', fg: '#15803d' },
};

const FALLBACK_LOGO = { icon: <IconPlug size={22} />, bg: '#f1f5f9', fg: '#475569' };

/** Systems the server lists but this console does not know sort last, in the server's order. */
const order = (system: string) => {
  const i = SYSTEM_ORDER.indexOf(system);
  return i < 0 ? SYSTEM_ORDER.length : i;
};

export function IntegrationsPage() {
  const me = useMe();
  const toast = useToast();
  const page = useAsync<PageData>(load, []);
  const [editing, setEditing] = useState<{ key: string; schema: IntegrationSchema; isNew: boolean } | null>(null);
  const [adding, setAdding] = useState<IntegrationSchema | null>(null);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [testing, setTesting] = useState<Record<string, boolean>>({});
  const [addingTenant, setAddingTenant] = useState<{ provider: ProviderInfo; environment?: string } | null>(null);
  const security = hasRole(me, 'security');

  useEffect(() => {
    const r = takeOAuthResult();
    if (!r) return;
    toast(
      r.ok
        ? { tone: 'green', title: `${r.key || 'NetSuite'}: authorized`, body: 'NetSuite issued tokens to Fortik; a connection check ran.' }
        : { tone: 'red', title: `${r.key || 'NetSuite'}: authorization failed`, body: r.error },
    );
  }, [toast]);

  useLiveRefresh((e) => e.eventType.startsWith('integration.'), page.reload, 500);

  const runTest = async (key: string) => {
    setTesting((t) => ({ ...t, [key]: true }));
    try {
      const r = await testIntegration(key);
      toast(r.ok ? { tone: 'green', title: `${key}: connection OK`, body: r.durationMs !== undefined ? `${r.durationMs} ms` : undefined } : { tone: 'red', title: `${key}: connection failed`, body: r.error });
    } catch (e) {
      toast({ tone: 'red', title: `${key}: test could not run`, body: errText(e) });
    } finally {
      setTesting((t) => ({ ...t, [key]: false }));
      page.reload();
    }
  };

  if (page.error) return <ErrorBox error={page.error} onRetry={page.reload} />;
  if (!page.data) return <Loading />;
  const { schemas, integrations, apps } = page.data;
  const byKey = new Map(integrations.map((i) => [i.key, i]));
  const schemaMap = new Map(schemas.map((s) => [s.system, s]));
  // Providers with one card per tenant and a connection method dropdown. On
  // a server without logical integrations they fall back to plain cards.
  const unified = (apps?.providers ?? []).filter((p) => UNIFIED_PROVIDERS.includes(p.provider));
  const unifiedSystems = new Set(unified.flatMap((p) => p.environments.flatMap((e) => e.transports.map((t) => t.system))).filter(Boolean));
  // The console never offers a connection type the server did not list.
  const plainSchemas = schemas.filter((s) => !unifiedSystems.has(s.system) && s.system !== 'netsuite_mcp');
  const multiSchemas = plainSchemas.filter((s) => s.multi);

  const cards: { key: string; schema: IntegrationSchema; title: string; current?: Integration }[] = [];
  for (const s of plainSchemas) {
    if (s.multi) {
      for (const i of integrations.filter((x) => x.system === s.system).sort((a, b) => a.key.localeCompare(b.key)))
        cards.push({ key: i.key, schema: s, title: integrationTitle(s, i.key), current: i });
    } else {
      cards.push({ key: s.system, schema: s, title: s.title, current: byKey.get(s.system) });
    }
  }

  return (
    <>
      <div className="card card-pad">
        <div className="row">
          <IconPlug />
          <h2 style={{ fontSize: 15 }}>Connections Fortik brokers</h2>
        </div>
        <p className="help" style={{ marginBottom: 0 }}>
          Enter credentials for each system here — use test accounts first. Secrets go only to Fortik&apos;s secret store: they are never saved in the database,
          never shown again, and never handed to agents. Until a system is configured, every agent action on it is refused with “integration not
          configured”. {!security && <strong>You can view these settings; changing them requires the security role.</strong>}
        </p>
      </div>
      <div className="int-grid">
        {apps &&
          unified.flatMap((p) =>
            tenantsOf(apps, p.provider).map((a) => (
              <ProviderCard
                key={a.integrationId}
                app={a}
                schemas={schemaMap}
                canEdit={security}
                onChanged={page.reload}
                onAddTenant={p.multiTenant ? (environment) => setAddingTenant({ provider: p, environment }) : undefined}
              />
            )),
          )}
        {cards.map(({ key, schema, title, current }) => {
          const logo = LOGO[schema.system] ?? FALLBACK_LOGO;
          const status = current?.status ?? 'unconfigured';
          return (
            <div key={key} className="card int-card" data-testid={`integration-${key}`}>
              <div className="top">
                <span className="int-logo" style={{ background: logo.bg, color: logo.fg }}>
                  {logo.icon}
                </span>
                <div className="grow">
                  <h3 style={{ fontSize: 15 }}>{title}</h3>
                  <div className="muted small mono">{key}</div>
                </div>
                <IntegrationStatusChip status={status} />
              </div>
              <div className="desc">{SYSTEM_BLURB[schema.system] ?? ''}</div>
              <div className="facts">
                <span>
                  Last tested: <span title={fmtTime(current?.lastTestedAt)}>{current?.lastTestedAt ? fmtAgo(current.lastTestedAt) : 'never'}</span>
                </span>
                {current?.updatedAt && (
                  <span>
                    Updated {fmtAgo(current.updatedAt)}
                    {current.updatedBy && ` by ${current.updatedBy}`}
                  </span>
                )}
                {current?.lastError && <span className="err">Last error: {current.lastError}</span>}
              </div>
              {schema.system === 'netsuite_quickstart' && <QuickStartPanel canRefresh={security} onChanged={page.reload} />}
              <div className="actions">
                <button className="btn primary small" onClick={() => setEditing({ key, schema, isNew: !current })}>
                  {current ? (security ? 'Configure' : 'View') : 'Set up'}
                </button>
                <button
                  className="btn small"
                  disabled={!security || !current || testing[key] || current.testAvailable === false}
                  title={!current ? 'Configure it first' : current.testAvailable === false ? 'No live test in this build' : undefined}
                  onClick={() => void runTest(key)}
                >
                  {testing[key] && <span className="spinner" />} Test connection
                </button>
                <div className="spacer" />
                {current && (
                  <button className="btn ghost small" style={{ color: '#b91c1c' }} disabled={!security} onClick={() => setDeleting(key)}>
                    Delete
                  </button>
                )}
              </div>
            </div>
          );
        })}
        {multiSchemas.map((ms) => {
          const noun = MULTI_TITLE[ms.system]?.noun ?? ms.title;
          return (
            <button
              key={`add-${ms.system}`}
              className="card int-card"
              style={{ borderStyle: 'dashed', cursor: security ? 'pointer' : 'not-allowed', minHeight: 180, alignItems: 'center', justifyContent: 'center', gap: 8, color: '#475569' }}
              disabled={!security}
              onClick={() => setAdding(ms)}
            >
              <IconPlus size={22} />
              <strong>Add {noun}</strong>
              <span className="muted small" style={{ maxWidth: 260, textAlign: 'center' }}>
                {ms.system === 'postgres' ? 'Each database agents may reach through pgproxy gets its own upstream.' : `Each ${noun} gets its own name.`}
              </span>
            </button>
          );
        })}
      </div>

      {editing && (
        <IntegrationDrawer
          integrationKey={editing.key}
          schema={editing.schema}
          current={byKey.get(editing.key)}
          canEdit={security}
          onClose={() => setEditing(null)}
          onSaved={() => page.reload()}
        />
      )}
      {adding && (
        <AddInstanceDialog
          schema={adding}
          existing={integrations.map((i) => i.key)}
          onClose={() => setAdding(null)}
          onPick={(name) => {
            const schema = adding;
            setAdding(null);
            setEditing({ key: `${schema.system}:${name}`, schema, isNew: true });
          }}
        />
      )}
      {deleting && (
        <DeleteDialog
          integrationKey={deleting}
          onClose={() => setDeleting(null)}
          onDeleted={(notes) => {
            toast({ tone: 'amber', title: `${deleting} deleted`, body: ['Its secrets were removed from the secret store.', ...notes].join(' ') });
            setDeleting(null);
            page.reload();
          }}
        />
      )}
      {addingTenant && (
        <AddTenantDialog
          provider={addingTenant.provider}
          environment={addingTenant.environment}
          existing={apps?.integrations.map((a) => a.integrationId) ?? []}
          onClose={() => setAddingTenant(null)}
          onCreated={() => {
            setAddingTenant(null);
            page.reload();
          }}
        />
      )}
    </>
  );
}

function AddInstanceDialog({
  schema,
  existing,
  onClose,
  onPick,
}: {
  schema: IntegrationSchema;
  existing: string[];
  onClose: () => void;
  onPick: (name: string) => void;
}) {
  const [name, setName] = useState('');
  const meta = MULTI_TITLE[schema.system];
  const noun = meta?.noun ?? schema.title;
  const n = name.trim();
  const valid = INSTANCE_NAME.test(n);
  const dup = existing.includes(`${schema.system}:${n}`);
  return (
    <Modal
      title={`Add ${noun}`}
      description={meta?.help}
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Cancel
          </button>
          <button className="btn primary" disabled={!valid || dup} onClick={() => onPick(n)}>
            Continue
          </button>
        </>
      }
    >
      <div className="field">
        <label htmlFor="instance-name">{schema.system === 'postgres' ? 'Upstream name' : 'Name'}</label>
        <input
          id="instance-name"
          className="input"
          value={name}
          autoFocus
          placeholder={meta?.placeholder ?? 'name'}
          aria-invalid={n !== '' && (!valid || dup)}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter' && valid && !dup) onPick(n);
          }}
        />
        <span className="help">
          {dup ? `A ${noun} with this name already exists.` : 'Lowercase letters, digits and underscores, starting with a letter (e.g. acme_prod).'}
        </span>
      </div>
    </Modal>
  );
}

function DeleteDialog({ integrationKey, onClose, onDeleted }: { integrationKey: string; onClose: () => void; onDeleted: (notes: string[]) => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const del = async () => {
    setBusy(true);
    setError(null);
    try {
      onDeleted(await deleteIntegration(integrationKey));
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Delete ${integrationKey}?`}
      description={
        integrationKey.startsWith('netsuite_mcp')
          ? 'Fortik asks NetSuite to revoke its OAuth grant, then deletes the settings and tokens. Agent calls over this transport are refused until it is configured again; other transports of the tenant are not affected.'
          : 'Its settings and stored secrets are deleted. Every agent action on this connection will be refused until it is configured again.'
      }
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn danger" onClick={() => void del()} disabled={busy}>
            {busy && <span className="spinner" />} Delete
          </button>
        </>
      }
    >
      <ErrorBox error={error} />
    </Modal>
  );
}
