// Integrations screen: a card per system (Google Workspace, GitHub, AWS, the
// Phase 4 queue systems) and per instance of a multi-instance system (Postgres
// upstreams, memory stores), with status, last test and last error; the
// Configure drawer is rendered from GET /v1/integrations/schema.

import { useState, type ReactNode } from 'react';
import { deleteIntegration, getIntegrationSchemas, listIntegrations, testIntegration } from '../api/endpoints';
import type { Integration, IntegrationSchema } from '../api/types';
import { useMe } from '../App';
import { IntegrationStatusChip } from '../components/Chips';
import { IconBolt, IconBrain, IconClock, IconCloud, IconDatabase, IconGit, IconGlobe, IconMail, IconPlus, IconPlug } from '../components/Icons';
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
}

async function load(signal: AbortSignal): Promise<PageData> {
  const [schemas, integrations] = await Promise.all([getIntegrationSchemas(signal), listIntegrations(signal)]);
  schemas.sort((a, b) => order(a.system) - order(b.system));
  return { schemas, integrations };
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
  const security = hasRole(me, 'security');

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
  const { schemas, integrations } = page.data;
  const byKey = new Map(integrations.map((i) => [i.key, i]));
  const multiSchemas = schemas.filter((s) => s.multi);

  const cards: { key: string; schema: IntegrationSchema; title: string; current?: Integration }[] = [];
  for (const s of schemas) {
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
          onDeleted={() => {
            toast({ tone: 'amber', title: `${deleting} deleted`, body: 'Its secrets were removed from the secret store.' });
            setDeleting(null);
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

function DeleteDialog({ integrationKey, onClose, onDeleted }: { integrationKey: string; onClose: () => void; onDeleted: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const del = async () => {
    setBusy(true);
    setError(null);
    try {
      await deleteIntegration(integrationKey);
      onDeleted();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`Delete ${integrationKey}?`}
      description="Its settings and stored secrets are deleted. Every agent action on this system will be refused until it is configured again."
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
