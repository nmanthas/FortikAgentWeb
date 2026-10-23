// Configure drawer for one integration, rendered from its schema. Secret
// fields are write-only: a stored secret shows as "••• set" with Replace
// (and Remove for optional ones); its value is never fetched or prefilled.

import { useState, type CSSProperties } from 'react';
import { saveIntegration, testIntegration } from '../api/endpoints';
import type { Integration, IntegrationSchema, SchemaField } from '../api/types';
import { IntegrationStatusChip } from '../components/Chips';
import { useToast } from '../components/Toasts';
import { Drawer, errText, ErrorBox } from '../components/ui';
import { fmtAgo } from '../lib/format';
import { buildPayload, formProblems, initialForm, integrationTitle, isSecretSet, SYSTEM_STEPS, type IntegrationFormState, type SecretState } from '../lib/integrationForm';

export function IntegrationDrawer({
  integrationKey,
  schema,
  current,
  canEdit,
  onClose,
  onSaved,
}: {
  integrationKey: string;
  schema: IntegrationSchema;
  current: Integration | undefined;
  canEdit: boolean;
  onClose: () => void;
  onSaved: (i: Integration) => void;
}) {
  const toast = useToast();
  const [st, setSt] = useState<IntegrationFormState>(() => initialForm(schema, current));
  const [saved, setSaved] = useState<Integration | undefined>(current);
  const [busy, setBusy] = useState<'save' | 'test' | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [testMsg, setTestMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [touched, setTouched] = useState(false);

  const problems = formProblems(schema, st, saved);
  const setValue = (k: string, v: string | boolean) => {
    setTouched(true);
    setSt((s) => ({ ...s, values: { ...s.values, [k]: v } }));
  };
  const setSecret = (k: string, v: SecretState) => {
    setTouched(true);
    setSt((s) => ({ ...s, secrets: { ...s.secrets, [k]: v } }));
  };

  const save = async (): Promise<Integration | null> => {
    setBusy('save');
    setError(null);
    setTestMsg(null);
    try {
      const { config, secrets } = buildPayload(schema, st);
      const res = await saveIntegration(integrationKey, config, secrets);
      setSaved(res);
      // Typed secrets are dropped from memory as soon as they are stored.
      setSt(initialForm(schema, res));
      setTouched(false);
      onSaved(res);
      toast({ tone: 'green', title: `${integrationKey} saved`, body: 'Run Test connection to check the credentials.' });
      return res;
    } catch (e) {
      setError(e);
      return null;
    } finally {
      setBusy(null);
    }
  };

  const test = async () => {
    setBusy('test');
    setError(null);
    setTestMsg(null);
    try {
      const r = await testIntegration(integrationKey);
      if (r.integration) {
        setSaved(r.integration);
        onSaved(r.integration);
      }
      setTestMsg(r.ok ? { ok: true, text: `Connection OK${r.durationMs !== undefined ? ` (${r.durationMs} ms)` : ''}.` } : { ok: false, text: r.error ?? 'Connection failed.' });
    } catch (e) {
      setTestMsg({ ok: false, text: errText(e) });
    } finally {
      setBusy(null);
    }
  };

  const status = saved?.status ?? 'unconfigured';
  return (
    <Drawer
      title={integrationTitle(schema, integrationKey)}
      subtitle={
        <span className="row">
          <IntegrationStatusChip status={status} />
          {saved?.lastTestedAt ? `last tested ${fmtAgo(saved.lastTestedAt)}` : 'never tested'}
        </span>
      }
      onClose={onClose}
      footer={
        <>
          <button className="btn" onClick={onClose}>
            Close
          </button>
          <button className="btn" disabled={!canEdit || !saved || touched || busy !== null || saved.testAvailable === false} onClick={() => void test()} title={touched ? 'Save your changes first' : undefined}>
            {busy === 'test' && <span className="spinner" />} Test connection
          </button>
          <button className="btn primary" disabled={!canEdit || busy !== null || problems.length > 0 || (!touched && !!saved)} onClick={() => void save()}>
            {busy === 'save' && <span className="spinner" />} Save
          </button>
        </>
      }
    >
      {SYSTEM_STEPS[schema.system] && (
        <div className="alert info">
          <div>
            <strong>How to set this up</strong>
            <ol style={{ margin: '6px 0 0', paddingLeft: 18 }}>
              {SYSTEM_STEPS[schema.system]!.map((s) => (
                <li key={s}>{s}</li>
              ))}
            </ol>
          </div>
        </div>
      )}
      {!canEdit && <div className="alert warn">Read-only: changing integrations requires the security role.</div>}
      {saved?.lastError && <div className="alert error">Last error: {saved.lastError}</div>}
      <fieldset disabled={!canEdit} style={{ border: 0, padding: 0, margin: 0, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {schema.fields.map((f) =>
          f.secret ? (
            <SecretField key={f.key} f={f} isSet={isSecretSet(saved, f.key)} state={st.secrets[f.key] ?? { mode: 'keep' }} onChange={(v) => setSecret(f.key, v)} />
          ) : (
            <ConfigField key={f.key} f={f} value={st.values[f.key] ?? ''} onChange={(v) => setValue(f.key, v)} />
          ),
        )}
      </fieldset>
      {touched && problems.length > 0 && (
        <div className="alert warn">
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
        <div className={`alert ${testMsg.ok ? 'ok' : 'error'}`} role="status">
          {testMsg.text}
        </div>
      )}
    </Drawer>
  );
}

function Label({ f, htmlFor }: { f: SchemaField; htmlFor: string }) {
  return (
    <label htmlFor={htmlFor}>
      {f.label}
      {f.required && <span className="req">*</span>}
      {f.secret && <span className="chip gray" style={{ marginLeft: 8, height: 18 }}>secret · write-only</span>}
    </label>
  );
}

function ConfigField({ f, value, onChange }: { f: SchemaField; value: string | boolean; onChange: (v: string | boolean) => void }) {
  const id = `int-${f.key}`;
  const text = typeof value === 'string' ? value : '';
  let input;
  switch (f.type) {
    case 'bool':
      return (
        <div className="field">
          <label className="check">
            <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} /> {f.label}
          </label>
          {f.help && <span className="help">{f.help}</span>}
        </div>
      );
    case 'select':
      input = (
        <select id={id} className="select" value={text} onChange={(e) => onChange(e.target.value)}>
          {!f.required && <option value="">—</option>}
          {f.required && text === '' && <option value="">Choose…</option>}
          {(f.options ?? []).map((o) => (
            <option key={o} value={o}>
              {o}
            </option>
          ))}
        </select>
      );
      break;
    case 'textarea':
      input = <textarea id={id} className="textarea" value={text} onChange={(e) => onChange(e.target.value)} />;
      break;
    case 'list':
      input = <textarea id={id} className="textarea" style={{ minHeight: 70 }} value={text} placeholder="One entry per line" onChange={(e) => onChange(e.target.value)} />;
      break;
    case 'number':
      input = <input id={id} className="input" type="number" step={1} value={text} onChange={(e) => onChange(e.target.value)} />;
      break;
    default:
      input = <input id={id} className="input" value={text} autoComplete="off" spellCheck={false} onChange={(e) => onChange(e.target.value)} />;
  }
  return (
    <div className="field">
      <Label f={f} htmlFor={id} />
      {input}
      {f.help && <span className="help">{f.help}</span>}
    </div>
  );
}

function SecretField({ f, isSet, state, onChange }: { f: SchemaField; isSet: boolean; state: SecretState; onChange: (v: SecretState) => void }) {
  const id = `int-${f.key}`;
  if (state.mode === 'keep' && isSet) {
    return (
      <div className="field">
        <Label f={f} htmlFor={id} />
        <div className="secret-set" data-testid={`secret-set-${f.key}`}>
          <span className="dots">•••</span> set
          <div className="spacer" />
          <button type="button" className="btn small" onClick={() => onChange({ mode: 'replace', value: '' })}>
            Replace
          </button>
          {!f.required && (
            <button type="button" className="btn small ghost" style={{ color: '#b91c1c' }} onClick={() => onChange({ mode: 'remove' })}>
              Remove
            </button>
          )}
        </div>
        {f.help && <span className="help">{f.help}</span>}
      </div>
    );
  }
  if (state.mode === 'remove') {
    return (
      <div className="field">
        <Label f={f} htmlFor={id} />
        <div className="secret-set">
          <span className="muted">Will be removed on save.</span>
          <div className="spacer" />
          <button type="button" className="btn small" onClick={() => onChange({ mode: 'keep' })}>
            Keep it
          </button>
        </div>
      </div>
    );
  }
  const value = state.mode === 'replace' ? state.value : '';
  const common = {
    id,
    value,
    autoComplete: 'off',
    spellCheck: false,
    placeholder: isSet ? 'Enter the new value' : f.type === 'textarea' ? 'Paste here' : '',
    onChange: (e: { target: { value: string } }) => onChange({ mode: 'replace', value: e.target.value }),
  };
  return (
    <div className="field">
      <Label f={f} htmlFor={id} />
      {f.type === 'textarea' ? (
        <textarea className="textarea" style={{ WebkitTextSecurity: 'disc' } as CSSProperties} {...common} data-testid={`secret-input-${f.key}`} />
      ) : (
        <input className="input" type="password" {...common} data-testid={`secret-input-${f.key}`} />
      )}
      {isSet && (
        <div>
          <button type="button" className="btn small ghost" onClick={() => onChange({ mode: 'keep' })}>
            Cancel — keep the stored value
          </button>
        </div>
      )}
      {f.help && <span className="help">{f.help}</span>}
    </div>
  );
}
