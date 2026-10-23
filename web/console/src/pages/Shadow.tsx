// Shadow agents (docs/PHASE5_DESIGN.md §3, §6): standing credentials used by
// software that Fortik does not govern, and calls from unknown agents, hosts
// or OAuth clients. A software-used finding registers a discovered agent at
// ISOLATED; security can revoke the credential (where Fortik can), dismiss
// the finding, or register the agent properly with an owner. Only
// credential identifiers are ever shown: the server never stores secrets.

import { useId, useState } from 'react';
import { Link } from 'react-router-dom';
import { listShadow, registerShadow, scanShadow, shadowAction, type ShadowAction, type ShadowActionResult } from '../api/endpoints';
import { factsOf } from '../api/normalize';
import type { ShadowFinding } from '../api/types';
import { useMe } from '../App';
import { IconRefresh, IconSearch, SystemIcon } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, Modal } from '../components/ui';
import { fmtAgo, fmtTime, titleCase } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { shadowPermit } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

const STATUS_CHIP: Record<string, string> = {
  open: 'amber',
  new: 'amber',
  flagged_for_revocation: 'red',
  revoked: 'gray',
  dismissed: 'gray',
  registered: 'green',
};

/** Statuses after which nothing is left to do on a finding. */
const CLOSED = ['revoked', 'dismissed', 'registered'];

export function ShadowPage() {
  const me = useMe();
  const toast = useToast();
  const [status, setStatus] = useState('');
  const findings = useAsync<ShadowFinding[]>((s) => listShadow(status, s), [status]);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [dialog, setDialog] = useState<{ kind: ShadowAction | 'register'; f: ShadowFinding } | null>(null);
  const [open, setOpen] = useState<string | null>(null);
  useLiveRefresh((e) => e.eventType.startsWith('shadow.') || (e.eventType.startsWith('agent.') && e.data.discovered === true), findings.reload, 1000);
  const permit = shadowPermit(me);

  const scan = async () => {
    setScanning(true);
    setError(null);
    try {
      const r = await scanShadow();
      const facts = scanSummary(r);
      toast({ tone: 'green', title: 'Scan finished', body: facts || 'The server reported no summary; the list is refreshed.' });
      findings.reload();
    } catch (e) {
      setError(e);
    } finally {
      setScanning(false);
    }
  };

  const list = findings.data ?? [];
  const flagged = list.filter((f) => f.status === 'flagged_for_revocation').length;

  return (
    <>
      <section className="card">
        <div className="card-head">
          <div>
            <h2>Shadow agents</h2>
            <div className="sub">Standing credentials used by software, and calls from unknown agents, hosts or OAuth clients. A discovered agent starts ISOLATED.</div>
          </div>
          <div className="spacer" />
          {findings.data && <span className="chip red">{flagged} flagged for revocation</span>}
          <button className="btn" onClick={findings.reload} aria-label="Refresh" title="Refresh">
            <IconRefresh size={16} />
          </button>
          <button className="btn primary" disabled={!permit.ok || scanning} title={permit.why} onClick={() => void scan()}>
            {scanning ? <span className="spinner" /> : <IconSearch size={15} />} Scan now
          </button>
        </div>
        <div className="toolbar">
          <label className="sr-only" htmlFor="shadow-status">
            Status
          </label>
          <select id="shadow-status" className="select" style={{ width: 240 }} value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All findings</option>
            <option value="open">Open</option>
            <option value="flagged_for_revocation">Flagged for revocation</option>
            <option value="revoked">Revoked</option>
            <option value="dismissed">Dismissed</option>
            <option value="registered">Registered</option>
          </select>
          {!permit.ok && <span className="muted small">{permit.why} You can read every finding.</span>}
        </div>
        {(error || findings.error) && (
          <div className="card-pad">
            <ErrorBox error={error} />
            {findings.error && <ErrorBox error={findings.error} onRetry={findings.reload} />}
          </div>
        )}
        {findings.loading && !findings.data && <Loading />}
        {findings.data && list.length === 0 && <div className="empty">No shadow-agent findings{status ? ` with status ${status.replace(/_/g, ' ')}` : ''}.</div>}
        {list.length > 0 && (
          <div className="table-wrap">
            <table className="table" aria-label="Shadow-agent findings">
              <thead>
                <tr>
                  <th>System</th>
                  <th>Kind</th>
                  <th>Credential</th>
                  <th>Holder</th>
                  <th>Used by software</th>
                  <th>Status</th>
                  <th>Discovered agent</th>
                  <th>Found</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {list.map((f) => {
                  const closed = CLOSED.includes(f.status);
                  const expanded = open === f.findingId;
                  return [
                    <tr key={f.findingId} data-testid="shadow-row">
                      <td>
                        <span className="row" style={{ gap: 6 }}>
                          <span className="sys-icon">
                            <SystemIcon system={f.system} />
                          </span>
                          {f.system || '—'}
                        </span>
                      </td>
                      <td>{f.kind ? titleCase(f.kind) : '—'}</td>
                      <td className="mono small" style={{ overflowWrap: 'anywhere', maxWidth: 220 }}>
                        {f.credentialId || '—'}
                      </td>
                      <td style={{ overflowWrap: 'anywhere', maxWidth: 200 }}>{f.holder || '—'}</td>
                      <td>{f.usedBySoftware ? <span className="chip red">software</span> : <span className="chip gray">person</span>}</td>
                      <td>
                        <span className={`chip ${STATUS_CHIP[f.status] ?? 'amber'}`} data-testid="shadow-status">
                          {f.status.replace(/_/g, ' ')}
                        </span>
                      </td>
                      <td>{f.discoveredAgentId ? <Link to={`/agents/${encodeURIComponent(f.discoveredAgentId)}`}>{f.discoveredAgentId}</Link> : <span className="muted">—</span>}</td>
                      <td title={fmtTime(f.createdAt)}>{fmtAgo(f.createdAt)}</td>
                      <td>
                        <div className="btn-row" style={{ flexWrap: 'nowrap' }}>
                          <button className="btn small ghost" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : f.findingId)}>
                            Evidence
                          </button>
                          <button className="btn small danger" disabled={!permit.ok || closed} title={permit.why ?? (closed ? `Already ${f.status}.` : undefined)} onClick={() => setDialog({ kind: 'revoke', f })} aria-label={`Revoke ${f.credentialId || f.findingId}`}>
                            Revoke
                          </button>
                          <button className="btn small" disabled={!permit.ok || closed} title={permit.why ?? (closed ? `Already ${f.status}.` : undefined)} onClick={() => setDialog({ kind: 'dismiss', f })} aria-label={`Dismiss ${f.credentialId || f.findingId}`}>
                            Dismiss
                          </button>
                          <button className="btn small primary" disabled={!permit.ok || closed} title={permit.why ?? (closed ? `Already ${f.status}.` : undefined)} onClick={() => setDialog({ kind: 'register', f })} aria-label={`Register ${f.credentialId || f.findingId}`}>
                            Register
                          </button>
                        </div>
                      </td>
                    </tr>,
                    expanded && (
                      <tr key={`${f.findingId}-ev`}>
                        <td colSpan={9} style={{ background: '#fafbfd' }}>
                          {f.evidence.length === 0 ? (
                            <span className="muted small">No evidence reported.</span>
                          ) : (
                            <dl className="kv" data-testid="shadow-evidence">
                              {f.evidence.map(([k, v]) => [
                                <dt key={`${k}-k`}>{titleCase(k)}</dt>,
                                <dd key={`${k}-v`} className="mono small">
                                  {v}
                                </dd>,
                              ])}
                            </dl>
                          )}
                        </td>
                      </tr>
                    ),
                  ];
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>
      {dialog && dialog.kind !== 'register' && (
        <ConfirmAction
          f={dialog.f}
          action={dialog.kind}
          onDone={(r) => {
            const id = dialog.f.credentialId || dialog.f.findingId;
            if (dialog.kind !== 'revoke') toast({ tone: 'info', title: 'Finding dismissed', body: id });
            else if (r.revoked) toast({ tone: 'amber', title: 'Credential revoked', body: id });
            else
              toast({
                tone: 'red',
                title: r.outcome === 'manual_required' ? 'NOT revoked: manual action required' : 'NOT revoked',
                body: `${id}: ${r.detail || 'the server did not confirm the revoke'} (still flagged for revocation)`,
              });
            findings.reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
      {dialog?.kind === 'register' && (
        <RegisterDialog
          f={dialog.f}
          onDone={() => {
            toast({ tone: 'green', title: 'Agent registered', body: 'It now has an owner. Its level stays ISOLATED until someone raises it.' });
            findings.reload();
          }}
          onClose={() => setDialog(null)}
        />
      )}
    </>
  );
}

function ConfirmAction({ f, action, onDone, onClose }: { f: ShadowFinding; action: ShadowAction; onDone: (r: ShadowActionResult) => void; onClose: () => void }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      onDone(await shadowAction(f.findingId, action));
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  const revoke = action === 'revoke';
  return (
    <Modal
      title={revoke ? `Revoke ${f.credentialId || 'this credential'}?` : 'Dismiss this finding?'}
      description={
        revoke
          ? `Fortik revokes the credential on ${f.system || 'the system'} where it can (for example ALTER ROLE … NOLOGIN on Postgres). Software still using it stops working. If Fortik cannot revoke it on this system, you are told so with what to do instead, and the finding stays flagged for revocation.`
          : 'The finding is closed as not a shadow agent. A discovered agent it created is kept as is.'
      }
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className={`btn ${revoke ? 'danger' : 'primary'}`} onClick={() => void run()} disabled={busy}>
            {busy && <span className="spinner" />} {revoke ? 'Revoke' : 'Dismiss'}
          </button>
        </>
      }
    >
      <dl className="kv">
        <dt>System</dt>
        <dd>{f.system || '—'}</dd>
        <dt>Holder</dt>
        <dd>{f.holder || '—'}</dd>
      </dl>
      <ErrorBox error={error} />
    </Modal>
  );
}

function RegisterDialog({ f, onDone, onClose }: { f: ShadowFinding; onDone: () => void; onClose: () => void }) {
  const [sponsor, setSponsor] = useState('');
  const [name, setName] = useState(f.discoveredAgentId ?? '');
  const [team, setTeam] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const id = useId();
  const sponsorOk = /^[^\s@]+@[^\s@]+$/.test(sponsor.trim());
  const ok = sponsorOk && name.trim() !== '' && team.trim() !== '';
  const submit = async () => {
    if (!ok) return;
    setBusy(true);
    setError(null);
    try {
      await registerShadow(f.findingId, { sponsor: sponsor.trim(), name: name.trim(), team: team.trim() });
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title="Register this agent"
      description="Gives the discovered agent an owner (sponsor), a name and a team. It stays ISOLATED until its owner or security raises its level."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => void submit()} disabled={busy || !ok}>
            {busy && <span className="spinner" />} Register
          </button>
        </>
      }
    >
      <div className="field">
        <label htmlFor={`${id}-s`}>
          Sponsor (owner email)<span className="req">*</span>
        </label>
        <input id={`${id}-s`} className="input" value={sponsor} autoFocus aria-invalid={sponsor !== '' && !sponsorOk} onChange={(e) => setSponsor(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor={`${id}-n`}>
          Name<span className="req">*</span>
        </label>
        <input id={`${id}-n`} className="input" value={name} maxLength={200} onChange={(e) => setName(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor={`${id}-t`}>
          Team<span className="req">*</span>
        </label>
        <input id={`${id}-t`} className="input" value={team} maxLength={200} onChange={(e) => setTeam(e.target.value)} />
      </div>
      <ErrorBox error={error} />
    </Modal>
  );
}

/** The scan counts worth showing (the server's report starts with ids and times). */
export function scanSummary(r: Record<string, unknown>): string {
  const parts: string[] = [];
  const n = (k: string) => (typeof r[k] === 'number' ? (r[k] as number) : null);
  const add = (k: string, label: string) => {
    const v = n(k);
    if (v !== null) parts.push(`${label}: ${v}`);
  };
  add('credentials', 'Credentials');
  add('used_by_software', 'Used by software');
  add('new_findings', 'New findings');
  add('newly_flagged', 'Newly flagged');
  const ns = Array.isArray(r.not_scanned) ? (r.not_scanned as unknown[]).filter((x) => typeof x === 'string') : [];
  if (ns.length) parts.push(`Not scanned: ${ns.join(', ')}`);
  if (!parts.length)
    return factsOf(r)
      .filter(([k]) => !['scan_id', 'actor', 'reason', 'started_at', 'finished_at'].includes(k))
      .map(([k, v]) => `${titleCase(k)}: ${v}`)
      .slice(0, 4)
      .join(' · ');
  return parts.join(' · ');
}
