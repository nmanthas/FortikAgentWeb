// Access tab: one editor per system (gmail, drive, github, aws, postgres,
// and from Phase 3 a2a, http, mcp) for the profile shapes in
// docs/PHASE2_DESIGN.md §5 and docs/PHASE3_DESIGN.md §1.5, with version history
// and revert. Every save and revert requires a reason. The server validates
// again (and enforces narrow-only edits for owners); its errors are shown.

import { useEffect, useMemo, useState } from 'react';
import { getAccess, getAccessHistory, listIntegrations, putAccess, revertAccess } from '../api/endpoints';
import type { AccessSystem, Agent, ProfileView } from '../api/types';
import { ACCESS_SYSTEMS } from '../api/types';
import { useMe } from '../App';
import { IconPlus, IconX, SystemIcon } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Loading, ReasonDialog } from '../components/ui';
import { fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { accessEditMode } from '../lib/permissions';
import {
  fromForm,
  summarize,
  SYSTEM_LABELS,
  toForm,
  validateForm,
  MAX_DELEGATION_DEPTH,
  type A2AForm,
  type AnyForm,
  type AWSForm,
  type External,
  type HTTPForm,
  type MCPForm,
  type DriveForm,
  type GitHubForm,
  type GmailForm,
  type Mode,
  type Perm,
  type PostgresForm,
  type Send,
} from '../lib/profiles';
import { useAsync } from '../lib/useAsync';

export function AccessTab({ agent }: { agent: Agent }) {
  const me = useMe();
  const id = agent.agentId;
  const profiles = useAsync<ProfileView[]>((s) => getAccess(id, s), [id]);
  const [system, setSystem] = useState<AccessSystem>('gmail');
  useLiveRefresh((e) => e.agentId === id && e.eventType === 'access.changed', profiles.reload, 500);

  const mode = accessEditMode(me, agent);
  const current = profiles.data?.find((p) => p.system === system) ?? { system, version: 0, profile: null };

  return (
    <>
      <div className="card card-pad">
        <div className="section-title">Access profiles</div>
        <p className="help" style={{ marginTop: 0 }}>
          A profile is the most an agent may ever do on a system; policy then decides each action within it. No profile means no access (rule POL-020).
          Changes apply to the next credential Fortik issues.
        </p>
        <div className="sys-tabs" role="tablist" aria-label="System">
          {ACCESS_SYSTEMS.map((s) => {
            const p = profiles.data?.find((x) => x.system === s);
            return (
              <button key={s} role="tab" aria-selected={system === s} className={`sys-tab${system === s ? ' active' : ''}`} onClick={() => setSystem(s)}>
                <SystemIcon system={s} /> {SYSTEM_LABELS[s]}
                <span className="muted small">{p && p.version > 0 ? `v${p.version}` : 'none'}</span>
              </button>
            );
          })}
        </div>
        {mode === 'narrow' && (
          <div className="alert info" style={{ marginTop: 12 }}>
            You own this agent, so you may narrow its access. Widening it requires the security role.
          </div>
        )}
        {mode === 'none' && (
          <div className="alert warn" style={{ marginTop: 12 }}>
            Read-only: editing access requires the security role or ownership of this agent.
          </div>
        )}
      </div>
      {profiles.error && <ErrorBox error={profiles.error} onRetry={profiles.reload} />}
      {profiles.loading && !profiles.data && <Loading />}
      {profiles.data && (
        <SystemEditor key={`${system}:${current.version}`} agentId={id} system={system} current={current} editable={mode !== 'none'} onSaved={profiles.reload} />
      )}
    </>
  );
}

function SystemEditor({
  agentId,
  system,
  current,
  editable,
  onSaved,
}: {
  agentId: string;
  system: AccessSystem;
  current: ProfileView;
  editable: boolean;
  onSaved: () => void;
}) {
  const toast = useToast();
  const initial = useMemo(() => toForm(system, current.profile), [system, current.profile]);
  const [form, setForm] = useState<AnyForm>(initial);
  const [confirm, setConfirm] = useState(false);
  const [revertTo, setRevertTo] = useState<ProfileView | null>(null);
  const history = useAsync<ProfileView[]>((s) => getAccessHistory(agentId, system, s), [agentId, system, current.version]);

  const problems = validateForm(system, form);
  const next = fromForm(system, form);
  // A system without a profile can always be saved (even as "none"); otherwise only real changes.
  const dirty = current.profile === null || JSON.stringify(next) !== JSON.stringify(fromForm(system, initial));

  return (
    <>
      <div className="card card-pad">
        <div className="row" style={{ marginBottom: 12 }}>
          <div className="section-title" style={{ margin: 0 }}>
            {SYSTEM_LABELS[system]}
          </div>
          <span className="muted small">
            {current.version > 0 ? `version ${current.version} · ${current.changedBy ?? ''} · ${fmtTime(current.changedAt)}` : 'no profile yet: all access denied'}
          </span>
        </div>
        <fieldset disabled={!editable} style={{ border: 0, padding: 0, margin: 0 }}>
          {system === 'gmail' && <GmailEditor f={form as GmailForm} set={setForm} />}
          {system === 'drive' && <DriveEditor f={form as DriveForm} set={setForm} />}
          {system === 'github' && <GitHubEditor f={form as GitHubForm} set={setForm} />}
          {system === 'aws' && <AWSEditor f={form as AWSForm} set={setForm} />}
          {system === 'postgres' && <PostgresEditor f={form as PostgresForm} set={setForm} />}
          {system === 'a2a' && <A2AEditor f={form as A2AForm} set={setForm} />}
          {system === 'http' && <HTTPEditor f={form as HTTPForm} set={setForm} />}
          {system === 'mcp' && <MCPEditor f={form as MCPForm} set={setForm} />}
        </fieldset>
        {problems.length > 0 && (
          <div className="alert error" style={{ marginTop: 12 }} role="alert">
            <div>
              Fix before saving:
              <ul>
                {problems.map((p) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
            </div>
          </div>
        )}
        <div className="btn-row" style={{ marginTop: 14 }}>
          <button className="btn primary" disabled={!editable || problems.length > 0 || !dirty} onClick={() => setConfirm(true)}>
            Save new version
          </button>
          <button className="btn" disabled={!editable} onClick={() => setForm(initial)}>
            Reset
          </button>
          <span className="muted small">Result: {summarize(system, next)}</span>
        </div>
      </div>

      <div className="card card-pad">
        <div className="section-title">History</div>
        {history.error && <ErrorBox error={history.error} onRetry={history.reload} />}
        {history.data && history.data.length === 0 && <div className="muted">No versions yet.</div>}
        <div className="history">
          {(history.data ?? []).map((h) => (
            <div key={h.version} className="history-item">
              <span className="v">v{h.version}</span>
              <div className="body">
                <div>{summarize(system, h.profile)}</div>
                <div className="by">
                  {h.changedBy ?? 'unknown'} · {fmtTime(h.changedAt)}
                  {h.reason && <> · “{h.reason}”</>}
                </div>
              </div>
              {h.version !== current.version && (
                <button className="btn small" disabled={!editable} onClick={() => setRevertTo(h)}>
                  Revert to v{h.version}
                </button>
              )}
              {h.version === current.version && <span className="chip green">current</span>}
            </div>
          ))}
        </div>
      </div>

      {confirm && (
        <ReasonDialog
          title={`Save ${SYSTEM_LABELS[system]} access for ${agentId}`}
          description={<>New profile: {summarize(system, next)}</>}
          confirmLabel="Save"
          onConfirm={async (reason) => {
            await putAccess(agentId, system, next, reason);
            toast({ tone: 'green', title: `${SYSTEM_LABELS[system]} access saved`, body: summarize(system, next) });
            onSaved();
          }}
          onClose={() => setConfirm(false)}
        />
      )}
      {revertTo && (
        <ReasonDialog
          title={`Revert ${SYSTEM_LABELS[system]} access to v${revertTo.version}?`}
          description={<>A new version is written with: {summarize(system, revertTo.profile)}</>}
          confirmLabel="Revert"
          onConfirm={async (reason) => {
            await revertAccess(agentId, system, revertTo.version, reason);
            toast({ tone: 'green', title: `${SYSTEM_LABELS[system]} access reverted to v${revertTo.version}` });
            onSaved();
          }}
          onClose={() => setRevertTo(null)}
        />
      )}
    </>
  );
}

// --- per-system editors ---------------------------------------------------------------

type SetForm = (f: AnyForm) => void;

function Select<T extends string>({
  id,
  label,
  value,
  options,
  onChange,
  help,
}: {
  id: string;
  label: string;
  value: T;
  options: [T, string][];
  onChange: (v: T) => void;
  help?: string;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <select id={id} className="select" value={value} onChange={(e) => onChange(e.target.value as T)}>
        {options.map(([v, l]) => (
          <option key={v} value={v}>
            {l}
          </option>
        ))}
      </select>
      {help && <span className="help">{help}</span>}
    </div>
  );
}

const MODE_OPTS: [Mode, string][] = [
  ['none', 'None — no access'],
  ['read_only', 'Read only'],
  ['read_write', 'Read and write'],
];
const SEND_OPTS: [Send, string][] = [
  ['none', 'None'],
  ['internal_only', 'Internal only'],
  ['any', 'Anyone'],
];
const PERM_OPTS: [Perm, string][] = [
  ['none', 'None'],
  ['read', 'Read'],
  ['write', 'Write'],
];

function GmailEditor({ f, set }: { f: GmailForm; set: SetForm }) {
  return (
    <div className="form-grid">
      <Select
        id="gmail-send"
        label="Send mail"
        value={f.send}
        options={SEND_OPTS}
        onChange={(send) => set({ ...f, send })}
        help="Internal only = recipients in the Workspace's internal domains (POL-022)."
      />
      <div className="field">
        <label htmlFor="gmail-max">Max recipients per message</label>
        <input
          id="gmail-max"
          className="input"
          type="number"
          min={0}
          max={10000}
          step={1}
          value={f.maxRecipients}
          onChange={(e) => set({ ...f, maxRecipients: e.target.value === '' ? 0 : Number(e.target.value) })}
        />
        <span className="help">Messages with more recipients are denied (POL-027).</span>
      </div>
      <label className="check full">
        <input type="checkbox" checked={f.read} onChange={(e) => set({ ...f, read: e.target.checked })} /> May read the mailbox
      </label>
    </div>
  );
}

function DriveEditor({ f, set }: { f: DriveForm; set: SetForm }) {
  return (
    <div className="form-grid">
      <Select id="drive-mode" label="Files" value={f.mode} options={MODE_OPTS} onChange={(mode) => set({ ...f, mode })} help="Read only denies writes (POL-021)." />
      <Select
        id="drive-share"
        label="Sharing"
        value={f.share}
        options={SEND_OPTS}
        onChange={(share) => set({ ...f, share })}
        help="Internal only refuses external and anyone-with-link shares (POL-023)."
      />
    </div>
  );
}

function ListEditor({ id, label, values, onChange, placeholder, help }: { id: string; label: string; values: string[]; onChange: (v: string[]) => void; placeholder: string; help?: string }) {
  return (
    <div className="field full">
      <label htmlFor={`${id}-0`}>{label}</label>
      <div className="list-editor">
        {values.map((v, i) => (
          <div key={i} className="item">
            <input
              id={`${id}-${i}`}
              className="input"
              aria-label={`${label} ${i + 1}`}
              value={v}
              placeholder={placeholder}
              onChange={(e) => onChange(values.map((x, j) => (j === i ? e.target.value : x)))}
            />
            <button type="button" className="icon-btn" aria-label={`Remove ${v || 'entry'}`} onClick={() => onChange(values.filter((_, j) => j !== i))}>
              <IconX size={14} />
            </button>
          </div>
        ))}
        <div>
          <button type="button" className="btn small" aria-label={`Add to ${label}`} onClick={() => onChange([...values, ''])}>
            <IconPlus size={14} /> Add
          </button>
        </div>
      </div>
      {help && <span className="help">{help}</span>}
    </div>
  );
}

function GitHubEditor({ f, set }: { f: GitHubForm; set: SetForm }) {
  return (
    <div className="form-grid">
      <ListEditor
        id="gh-repos"
        label="Repositories"
        values={f.repos}
        placeholder="org/repo"
        onChange={(repos) => set({ ...f, repos })}
        help="Only these repositories, as owner/name (POL-024). Tokens are scoped to them."
      />
      <Select id="gh-contents" label="Contents" value={f.contents} options={PERM_OPTS} onChange={(contents) => set({ ...f, contents })} help="Write is needed to push and move refs." />
      <Select id="gh-prs" label="Pull requests" value={f.pullRequests} options={PERM_OPTS} onChange={(pullRequests) => set({ ...f, pullRequests })} help="Write is needed to open, merge or close PRs." />
      <Select id="gh-issues" label="Issues" value={f.issues} options={PERM_OPTS} onChange={(issues) => set({ ...f, issues })} />
      <Select
        id="gh-metadata"
        label="Metadata"
        value={f.metadata}
        options={[
          ['none', 'None'],
          ['read', 'Read'],
        ]}
        onChange={(metadata) => set({ ...f, metadata })}
      />
      <label className="check full">
        <input type="checkbox" checked={f.allowDirectToken} onChange={(e) => set({ ...f, allowDirectToken: e.target.checked })} /> Allow a direct
        installation token via /v1/credentials/issue (otherwise only the gateway proxy)
      </label>
    </div>
  );
}

function AWSEditor({ f, set }: { f: AWSForm; set: SetForm }) {
  return (
    <div className="form-grid">
      <Select id="aws-mode" label="Mode" value={f.mode} options={MODE_OPTS} onChange={(mode) => set({ ...f, mode })} help="Read only allows only read verbs (POL-021)." />
      <div />
      <ListEditor
        id="aws-services"
        label="Services"
        values={f.services}
        placeholder="s3"
        onChange={(services) => set({ ...f, services })}
        help="IAM service prefixes the agent may use, e.g. s3, ec2, dynamodb (POL-025)."
      />
      <ListEditor
        id="aws-denied"
        label="Denied actions"
        values={f.deniedActions}
        placeholder="iam:*"
        onChange={(deniedActions) => set({ ...f, deniedActions })}
        help="Always refused, even inside allowed services. Wildcards * and ? are allowed, e.g. iam:*, s3:Delete*."
      />
    </div>
  );
}

function PostgresEditor({ f, set }: { f: PostgresForm; set: SetForm }) {
  const [known, setKnown] = useState<string[]>([]);
  useEffect(() => {
    const ac = new AbortController();
    listIntegrations(ac.signal).then(
      (ins) => setKnown(ins.filter((i) => i.system === 'postgres').map((i) => i.key.replace(/^postgres:/, ''))),
      () => setKnown([]), // owners without the auditor role cannot list integrations: names are typed by hand
    );
    return () => ac.abort();
  }, []);
  const update = (i: number, patch: Partial<{ name: string; mode: Mode }>) =>
    set({ upstreams: f.upstreams.map((u, j) => (j === i ? { ...u, ...patch } : u)) });
  return (
    <div className="field">
      <span className="label">Upstreams</span>
      <span className="help">Databases the agent may reach through pgproxy and how (POL-026). Unlisted upstreams are denied.</span>
      <datalist id="pg-upstreams">
        {known.map((k) => (
          <option key={k} value={k} />
        ))}
      </datalist>
      <div className="list-editor" style={{ marginTop: 6 }}>
        {f.upstreams.map((u, i) => (
          <div key={i} className="item">
            <input className="input" list="pg-upstreams" aria-label="Upstream name" placeholder="acme_prod" value={u.name} onChange={(e) => update(i, { name: e.target.value })} />
            <select className="select" aria-label={`Access to ${u.name || 'upstream'}`} style={{ width: 200 }} value={u.mode} onChange={(e) => update(i, { mode: e.target.value as Mode })}>
              {MODE_OPTS.map(([v, l]) => (
                <option key={v} value={v}>
                  {l}
                </option>
              ))}
            </select>
            <button type="button" className="icon-btn" aria-label={`Remove ${u.name || 'upstream'}`} onClick={() => set({ upstreams: f.upstreams.filter((_, j) => j !== i) })}>
              <IconX size={14} />
            </button>
          </div>
        ))}
        <div>
          <button type="button" className="btn small" onClick={() => set({ upstreams: [...f.upstreams, { name: known.find((k) => !f.upstreams.some((u) => u.name === k)) ?? '', mode: 'read_only' }] })}>
            <IconPlus size={14} /> Add upstream
          </button>
        </div>
      </div>
    </div>
  );
}

function A2AEditor({ f, set }: { f: A2AForm; set: SetForm }) {
  return (
    <div className="form-grid">
      <div className="field">
        <label htmlFor="a2a-depth">Max delegation depth</label>
        <input
          id="a2a-depth"
          className="input"
          type="number"
          min={1}
          max={MAX_DELEGATION_DEPTH}
          step={1}
          value={f.maxDepth}
          onChange={(e) => set({ ...f, maxDepth: e.target.value === '' ? 0 : Number(e.target.value) })}
        />
        <span className="help">The longest chain (A → B → C is depth 2) this agent may start or extend (POL-603).</span>
      </div>
      <div />
      <label className="check full">
        <input type="checkbox" checked={f.anyAgent} onChange={(e) => set({ ...f, anyAgent: e.target.checked })} /> May delegate to any agent
      </label>
      {!f.anyAgent && (
        <ListEditor
          id="a2a-to"
          label="May delegate to"
          values={f.mayDelegateTo}
          placeholder="agent_b"
          onChange={(mayDelegateTo) => set({ ...f, mayDelegateTo })}
          help="Agent ids this agent may hand tasks to. An empty list means it may not delegate. Whatever the delegatee does is still checked against this agent's own permissions (POL-601)."
        />
      )}
    </div>
  );
}

const EXTERNAL_OPTS: [External, string][] = [
  ['none', 'None — internal only'],
  ['allowlist', 'Only listed domains'],
  ['any', 'Any external domain'],
];

function HTTPEditor({ f, set }: { f: HTTPForm; set: SetForm }) {
  return (
    <div className="form-grid">
      <Select
        id="http-external"
        label="External web access"
        value={f.external}
        options={EXTERNAL_OPTS}
        onChange={(external) => set({ ...f, external })}
        help="Browsing and calls outside the company (POL-028). Uploads are held separately (POL-505)."
      />
      <div />
      {f.external === 'allowlist' && (
        <ListEditor
          id="http-domains"
          label="Allowed domains"
          values={f.allowedDomains}
          placeholder="api.example.com"
          onChange={(allowedDomains) => set({ ...f, allowedDomains })}
          help="Exact hosts, or *.example.org for any subdomain."
        />
      )}
    </div>
  );
}

function MCPEditor({ f, set }: { f: MCPForm; set: SetForm }) {
  const update = (i: number, patch: Partial<MCPForm['servers'][number]>) => set({ servers: f.servers.map((s, j) => (j === i ? { ...s, ...patch } : s)) });
  return (
    <div className="field">
      <span className="label">MCP servers</span>
      <span className="help">Servers (as named in the agentgateway config) and the tools the agent may call on each (POL-029). Unlisted servers and tools are denied.</span>
      <div className="list-editor" style={{ marginTop: 6 }}>
        {f.servers.map((sv, i) => (
          <div key={i} className="card card-pad" style={{ margin: 0 }}>
            <div className="item">
              <input className="input" aria-label="MCP server name" placeholder="github-mcp" value={sv.name} onChange={(e) => update(i, { name: e.target.value })} />
              <label className="check">
                <input type="checkbox" aria-label={`All tools on ${sv.name || 'this server'}`} checked={sv.allTools} onChange={(e) => update(i, { allTools: e.target.checked })} /> All tools
              </label>
              <button type="button" className="icon-btn" aria-label={`Remove ${sv.name || 'server'}`} onClick={() => set({ servers: f.servers.filter((_, j) => j !== i) })}>
                <IconX size={14} />
              </button>
            </div>
            {!sv.allTools && (
              <ListEditor
                id={`mcp-tools-${i}`}
                label={`Tools on ${sv.name || 'this server'}`}
                values={sv.tools}
                placeholder="read_graph"
                onChange={(tools) => update(i, { tools })}
              />
            )}
          </div>
        ))}
        <div>
          <button type="button" className="btn small" onClick={() => set({ servers: [...f.servers, { name: '', allTools: false, tools: [] }] })}>
            <IconPlus size={14} /> Add server
          </button>
        </div>
      </div>
    </div>
  );
}
