// Configure drawer for one integration, rendered from its schema. Secret
// fields are write-only: a stored secret shows as "••• set" with Replace
// (and Remove for optional ones); its value is never fetched or prefilled.

import { useState } from 'react';
import { saveIntegration, testIntegration } from '../api/endpoints';
import type { Integration, IntegrationSchema } from '../api/types';
import { IntegrationStatusChip } from '../components/Chips';
import { ConfigField, SecretField } from '../components/ConnectionFields';
import { useToast } from '../components/Toasts';
import { Drawer, errText, ErrorBox } from '../components/ui';
import { fmtAgo } from '../lib/format';
import { buildPayload, fieldVisible, formProblems, initialForm, integrationTitle, isSecretSet, SYSTEM_STEPS, type IntegrationFormState, type SecretState } from '../lib/integrationForm';

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
        {schema.fields.filter((f) => fieldVisible(f, st.values)).map((f) =>
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
