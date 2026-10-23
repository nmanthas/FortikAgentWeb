// Register agent dialog (POST /v1/agents, security role).

import { useState, type FormEvent } from 'react';
import { createAgent } from '../api/endpoints';
import type { NewAgent } from '../api/types';
import { ErrorBox, Modal } from '../components/ui';

const AGENT_ID = /^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,127}$/;

const EMPTY: NewAgent = {
  agent_id: '',
  name: '',
  type: '',
  platform: '',
  sponsor: '',
  business_unit: '',
  workspace_user: '',
  copy_cap: 1,
};

export function RegisterAgentDialog({ onClose, onCreated }: { onClose: () => void; onCreated: (agentId: string) => void }) {
  const [f, setF] = useState<NewAgent>(EMPTY);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const set = <K extends keyof NewAgent>(k: K, v: NewAgent[K]) => setF((x) => ({ ...x, [k]: v }));

  const idOk = AGENT_ID.test(f.agent_id.trim());
  const capOk = Number.isInteger(f.copy_cap) && f.copy_cap >= 0 && f.copy_cap <= 10000;

  const submit = async (e?: FormEvent) => {
    e?.preventDefault();
    if (!idOk || !capOk) return;
    setBusy(true);
    setError(null);
    const body: NewAgent = {
      ...f,
      agent_id: f.agent_id.trim(),
      name: f.name.trim(),
      type: f.type.trim(),
      platform: f.platform.trim(),
      sponsor: f.sponsor.trim(),
      business_unit: f.business_unit.trim(),
      workspace_user: f.workspace_user.trim(),
    };
    try {
      const a = await createAgent(body);
      onCreated(a.agentId || body.agent_id);
    } catch (err) {
      setError(err);
      setBusy(false);
    }
  };

  const text = (k: keyof NewAgent, label: string, help: string, placeholder = '', required = false) => (
    <div className="field">
      <label htmlFor={`reg-${k}`}>
        {label}
        {required && <span className="req">*</span>}
      </label>
      <input
        id={`reg-${k}`}
        className="input"
        value={String(f[k])}
        placeholder={placeholder}
        onChange={(e) => set(k, e.target.value as never)}
        aria-invalid={k === 'agent_id' && f.agent_id !== '' && !idOk}
      />
      <span className="help">{help}</span>
    </div>
  );

  return (
    <Modal
      title="Register agent"
      description="New agents start at the level your policy assigns and have no access to any system until you grant an access profile."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn primary" onClick={() => void submit()} disabled={busy || !idOk || !capOk}>
            {busy && <span className="spinner" />} Register
          </button>
        </>
      }
    >
      <form onSubmit={submit} className="form-grid">
        <div className="full">{text('agent_id', 'Agent ID', 'Letters, digits and _ . : @ - ; cannot be changed later.', 'billing-bot', true)}</div>
        {text('name', 'Display name', 'Shown in the console.', 'Billing assistant')}
        {text('type', 'Type', 'What kind of agent this is.', 'support, coding, ops…')}
        {text('platform', 'Platform', 'Framework or vendor.', 'langgraph, openai…')}
        {text('business_unit', 'Business unit', 'Team responsible for it.', 'Finance')}
        {text('sponsor', 'Owner email', 'The owner may step this agent down, up one level, and narrow its access.', 'owner@example.com')}
        {text('workspace_user', 'Workspace user', 'Google Workspace user the agent acts as for Gmail and Drive.', 'agent-bot@example.com')}
        <div className="field">
          <label htmlFor="reg-copy_cap">Copy cap</label>
          <input
            id="reg-copy_cap"
            className="input"
            type="number"
            min={0}
            step={1}
            value={f.copy_cap}
            aria-invalid={!capOk}
            onChange={(e) => set('copy_cap', e.target.value === '' ? 0 : Number(e.target.value))}
          />
          <span className="help">How many instances (copies) of this agent may run at once (0–10000).</span>
        </div>
        <button type="submit" hidden />
      </form>
      <ErrorBox error={error} />
    </Modal>
  );
}
