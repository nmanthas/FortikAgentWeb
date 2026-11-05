// Form fields of one connection, rendered from its schema (the Configure
// drawer and the integration cards). Secret fields are write-only: a stored
// secret shows as "••• set" with Replace (and Remove for optional ones); its
// value is never fetched or prefilled.

import { useState, type CSSProperties } from 'react';
import type { Integration, IntegrationSchema, SchemaField } from '../api/types';
import { fieldVisible, isSecretSet, optionLabel, type IntegrationFormState, type SecretState } from '../lib/integrationForm';

/** A field's help: long help shows its first sentence, with More for the rest. */
export function Help({ text }: { text?: string }) {
  const [open, setOpen] = useState(false);
  if (!text) return null;
  if (text.length <= 160) return <span className="help">{text}</span>;
  // The first sentence when it is a useful length, else the first words.
  const end = text.search(/\.\s(?=[A-Z])/); // not "e.g. https"
  const short = end >= 40 && end <= 180 ? text.slice(0, end + 1) : `${text.slice(0, text.lastIndexOf(' ', 140))}…`;
  return (
    <span className="help">
      {open ? text : short}{' '}
      <button type="button" className="help-more" onClick={() => setOpen(!open)}>
        {open ? 'Less' : 'More'}
      </button>
    </span>
  );
}

export function Label({ f, htmlFor }: { f: SchemaField; htmlFor: string }) {
  return (
    <label htmlFor={htmlFor}>
      {f.label}
      {f.required && <span className="req">*</span>}
      {f.secret && <span className="chip gray" style={{ marginLeft: 8, height: 18 }}>secret · write-only</span>}
    </label>
  );
}

export function ConfigField({
  f,
  value,
  onChange,
  idPrefix = 'int-',
  className = '',
}: {
  f: SchemaField;
  value: string | boolean;
  onChange: (v: string | boolean) => void;
  idPrefix?: string;
  className?: string;
}) {
  const id = `${idPrefix}${f.key}`;
  const text = typeof value === 'string' ? value : '';
  let input;
  switch (f.type) {
    case 'bool':
      return (
        <div className={`field ${className}`.trim()}>
          <label className="check">
            <input type="checkbox" checked={value === true} onChange={(e) => onChange(e.target.checked)} /> {f.label}
          </label>
          <Help text={f.help} />
        </div>
      );
    case 'select':
      // A choice of one is shown as a fixed value, not a dropdown.
      if ((f.options ?? []).length === 1 && (text === '' || text === f.options![0])) {
        input = <input id={id} className="input" value={optionLabel(f.options![0]!)} readOnly aria-readonly="true" style={{ background: '#fafbfd' }} />;
        break;
      }
      input = (
        <select id={id} className="select" value={text} onChange={(e) => onChange(e.target.value)}>
          {!f.required && <option value="">—</option>}
          {f.required && text === '' && <option value="">Choose…</option>}
          {(f.options ?? []).map((o) => (
            <option key={o} value={o}>
              {optionLabel(o)}
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
    <div className={`field ${className}`.trim()}>
      <Label f={f} htmlFor={id} />
      {input}
      <Help text={f.help} />
    </div>
  );
}

export function SecretField({
  f,
  isSet,
  state,
  onChange,
  idPrefix = 'int-',
  className = '',
}: {
  f: SchemaField;
  isSet: boolean;
  state: SecretState;
  onChange: (v: SecretState) => void;
  idPrefix?: string;
  className?: string;
}) {
  const id = `${idPrefix}${f.key}`;
  if (state.mode === 'keep' && isSet) {
    return (
      <div className={`field ${className}`.trim()}>
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
        <Help text={f.help} />
      </div>
    );
  }
  if (state.mode === 'remove') {
    return (
      <div className={`field ${className}`.trim()}>
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
    <div className={`field ${className}`.trim()}>
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
      <Help text={f.help} />
    </div>
  );
}

/** Every field of a connection that applies to the current form values. */
/** Multi-line and on/off fields take a full row of the two-column grid. */
const wide = (f: SchemaField) => f.type === 'textarea' || f.type === 'list' || f.type === 'bool';

export function ConnectionFields({
  schema,
  st,
  saved,
  canEdit,
  setValue,
  setSecret,
  idPrefix,
}: {
  schema: IntegrationSchema;
  st: IntegrationFormState;
  saved: Integration | undefined;
  canEdit: boolean;
  setValue: (k: string, v: string | boolean) => void;
  setSecret: (k: string, v: SecretState) => void;
  idPrefix: string;
}) {
  return (
    <fieldset disabled={!canEdit} className="pc-fields" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }}>
      {schema.fields
        .filter((f) => fieldVisible(f, st.values))
        .map((f) =>
          f.secret ? (
            <SecretField
              key={f.key}
              f={f}
              idPrefix={idPrefix}
              className={wide(f) ? 'full' : ''}
              isSet={isSecretSet(saved, f.key)}
              state={st.secrets[f.key] ?? { mode: 'keep' }}
              onChange={(v) => setSecret(f.key, v)}
            />
          ) : (
            <ConfigField key={f.key} f={f} idPrefix={idPrefix} className={wide(f) ? 'full' : ''} value={st.values[f.key] ?? ''} onChange={(v) => setValue(f.key, v)} />
          ),
        )}
    </fieldset>
  );
}
