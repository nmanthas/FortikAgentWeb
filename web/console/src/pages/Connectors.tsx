// SaaS copilot connectors (Phase 6, docs/PHASE6_DESIGN.md §6): a copilot's
// Workspace / GitHub connector uses a Fortik-issued OAuth client. Fortik
// decides every token it hands the copilot; disabling a connector, or
// killing its agent, revokes the upstream grant at once. The client secret is
// shown once, at registration; Fortik stores only its hash.
import { useState } from 'react';
import { Link } from 'react-router-dom';
import { disableConnector, listConnectors, registerConnector, type ConnectorList, type RegisteredConnector } from '../api/phase6';
import { useMe } from '../App';
import { IconRefresh } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, Modal } from '../components/ui';
import { fmtAgo, fmtTime } from '../lib/format';
import { hasRole } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

const UPSTREAMS: [string, string][] = [
  ['google_workspace', 'Google Workspace'],
  ['github', 'GitHub'],
];

export function ConnectorsPage() {
  const me = useMe();
  const toast = useToast();
  const list = useAsync<ConnectorList | null>((s) => listConnectors(s), []);
  const [registering, setRegistering] = useState(false);
  const [created, setCreated] = useState<RegisteredConnector | null>(null);
  const [disabling, setDisabling] = useState<string | null>(null);
  const canWrite = hasRole(me, 'security');

  if (list.error && !list.data) return <ErrorBox error={list.error} onRetry={list.reload} />;
  if (list.loading && list.data === undefined) return <Loading />;
  if (list.data === null) {
    return (
      <section className="card">
        <div className="card-pad" data-testid="connectors-off">
          The SaaS copilot connector broker is not enabled on this server (config <span className="mono">connectors.enabled</span>, see
          docs/DEPLOYMENT.md).
        </div>
      </section>
    );
  }
  const cs = list.data?.connectors ?? [];
  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Copilot connectors</h2>
            <div className="sub">
              Copilots (ChatGPT, Microsoft Copilot, Gemini, Agentforce…) reach Google Workspace or GitHub only through a Fortik-issued OAuth
              client. Every token is a Fortik decision; a kill or a disable revokes the grant upstream.
            </div>
          </div>
          <div className="spacer" />
          <button className="btn" onClick={list.reload} aria-label="Refresh" title="Refresh">
            <IconRefresh size={16} />
          </button>
          <button className="btn primary" disabled={!canWrite} title={canWrite ? undefined : 'Requires the security role.'} onClick={() => setRegistering(true)}>
            Register connector
          </button>
        </div>
        {list.data?.callbackUrl && (
          <div className="toolbar">
            <span className="muted small">
              Register this redirect URI on Fortik's OAuth clients at Google and GitHub: <span className="mono">{list.data.callbackUrl}</span>
            </span>
          </div>
        )}
        {cs.length === 0 ? (
          <div className="empty">No connectors registered.</div>
        ) : (
          <div className="table-wrap">
            <table className="table" aria-label="Copilot connectors">
              <thead>
                <tr>
                  <th>Copilot agent</th>
                  <th>Vendor</th>
                  <th>Upstream</th>
                  <th>Client id</th>
                  <th>Scopes</th>
                  <th>Active grants</th>
                  <th>Status</th>
                  <th>Registered</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {cs.map((c) => (
                  <tr key={c.connectorId} data-testid="connector-row">
                    <td>
                      <Link to={`/agents/${encodeURIComponent(c.agentId)}`}>{c.agentId}</Link>
                    </td>
                    <td>{c.vendor}</td>
                    <td>{UPSTREAMS.find(([k]) => k === c.upstream)?.[1] ?? c.upstream}</td>
                    <td className="mono small">{c.clientId}</td>
                    <td className="small" style={{ maxWidth: 260, overflowWrap: 'anywhere' }}>
                      {c.scopes.length ? c.scopes.join(' ') : <span className="muted">from the GitHub App</span>}
                    </td>
                    <td>{c.activeGrants}</td>
                    <td>
                      <span className={`chip ${c.status === 'active' ? 'green' : 'gray'}`} title={c.disabledReason || undefined}>
                        {c.status}
                      </span>
                    </td>
                    <td title={fmtTime(c.createdAt)}>{fmtAgo(c.createdAt)}</td>
                    <td>
                      <button
                        className="btn small danger"
                        disabled={!canWrite || c.status !== 'active'}
                        aria-label={`Disable ${c.agentId}`}
                        onClick={() => setDisabling(c.connectorId)}
                      >
                        Disable
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {registering && (
        <RegisterConnector
          onClose={() => setRegistering(false)}
          onDone={(r) => {
            setRegistering(false);
            setCreated(r);
            list.reload();
          }}
        />
      )}
      {created && <CreatedConnector r={created} onClose={() => setCreated(null)} />}
      {disabling && (
        <DisableConnector
          id={disabling}
          onClose={() => setDisabling(null)}
          onDone={(n, errors) => {
            setDisabling(null);
            toast({
              tone: errors ? 'red' : 'amber',
              title: 'Connector disabled',
              body: errors ? `${n} grant(s) revoked; upstream errors: ${errors}` : `${n} grant(s) revoked upstream`,
            });
            list.reload();
          }}
        />
      )}
    </>
  );
}

function RegisterConnector({ onClose, onDone }: { onClose: () => void; onDone: (r: RegisteredConnector) => void }) {
  const [f, setF] = useState({ agentId: '', name: '', sponsor: '', team: '', vendor: 'chatgpt', upstream: 'google_workspace', redirect: '', scopes: '', reason: '' });
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const set = (k: keyof typeof f) => (e: { target: { value: string } }) => setF({ ...f, [k]: e.target.value });
  const ok = f.agentId && f.sponsor && f.redirect && f.reason && (f.upstream === 'github' || f.scopes.trim());
  const submit = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(
        await registerConnector({
          agentId: f.agentId.trim(),
          name: f.name.trim(),
          sponsor: f.sponsor.trim(),
          team: f.team.trim(),
          vendor: f.vendor.trim(),
          upstream: f.upstream,
          redirectUris: f.redirect.split(/\s+/).filter(Boolean),
          scopes: f.scopes.split(/\s+/).filter(Boolean),
          reason: f.reason.trim(),
        }),
      );
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const field = (id: keyof typeof f, label: string, hint?: string) => (
    <label className="field">
      <span>{label}</span>
      <input className="input" value={f[id]} onChange={set(id)} aria-label={label} placeholder={hint} />
    </label>
  );
  return (
    <Modal
      title="Register a copilot connector"
      description="Creates the copilot as a Fortik agent and an OAuth client for its vendor's connector. Scopes are the most the copilot can ever get."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" disabled={!ok || busy} onClick={() => void submit()}>
            {busy && <span className="spinner" />} Register
          </button>
        </>
      }
    >
      {field('agentId', 'Agent id', 'copilot_chatgpt_finance')}
      {field('name', 'Name')}
      {field('sponsor', 'Sponsor (owner email)')}
      {field('team', 'Team')}
      {field('vendor', 'Vendor', 'chatgpt | copilot | gemini | agentforce')}
      <label className="field">
        <span>Upstream</span>
        <select className="select" value={f.upstream} onChange={set('upstream')} aria-label="Upstream">
          {UPSTREAMS.map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </select>
      </label>
      {field('redirect', "Vendor's redirect URI(s)", 'https://… (space-separated)')}
      {field('scopes', 'Scopes', 'https://www.googleapis.com/auth/gmail.readonly …')}
      {field('reason', 'Reason')}
      <ErrorBox error={error} />
    </Modal>
  );
}

function CreatedConnector({ r, onClose }: { r: RegisteredConnector; onClose: () => void }) {
  return (
    <Modal
      title="Connector registered"
      description="Give these to the vendor's connector settings. The client secret is shown only now; Fortik keeps only its hash."
      onClose={onClose}
      footer={
        <button className="btn primary" onClick={onClose}>
          Done
        </button>
      }
    >
      <dl className="kv" data-testid="connector-created">
        <dt>Client id</dt>
        <dd className="mono">{r.connector.clientId}</dd>
        <dt>Client secret</dt>
        <dd className="mono" data-testid="connector-secret">
          {r.clientSecret}
        </dd>
        <dt>Authorization URL</dt>
        <dd className="mono">{r.authorizeUrl}</dd>
        <dt>Token URL</dt>
        <dd className="mono">{r.tokenUrl}</dd>
      </dl>
    </Modal>
  );
}

function DisableConnector({ id, onClose, onDone }: { id: string; onClose: () => void; onDone: (n: number, errors: string) => void }) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const run = async () => {
    setBusy(true);
    try {
      const r = await disableConnector(id, reason.trim());
      onDone(Object.keys(r.grants).length, r.errors);
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Disable this connector?"
      description="No more tokens are issued, and every grant is revoked at the upstream now: the copilot loses access immediately."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn danger" disabled={!reason.trim() || busy} onClick={() => void run()}>
            {busy && <span className="spinner" />} Disable
          </button>
        </>
      }
    >
      <label className="field">
        <span>Reason</span>
        <input className="input" value={reason} onChange={(e) => setReason(e.target.value)} aria-label="Reason" />
      </label>
      <ErrorBox error={error} />
    </Modal>
  );
}
