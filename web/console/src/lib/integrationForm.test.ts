import { describe, expect, it } from 'vitest';
import type { Integration, IntegrationSchema } from '../api/types';
import { buildPayload, formProblems, initialForm } from './integrationForm';

const schema: IntegrationSchema = {
  system: 'aws',
  title: 'AWS',
  multi: false,
  fields: [
    { key: 'region', label: 'Region', type: 'text', secret: false, required: true },
    { key: 'domains', label: 'Domains', type: 'list', secret: false, required: false },
    { key: 'port', label: 'Port', type: 'number', secret: false, required: false, default: 5432 },
    { key: 'sslmode', label: 'TLS', type: 'select', secret: false, required: false, options: ['disable', 'require'], default: 'require' },
    { key: 'access_key_id', label: 'Access key', type: 'password', secret: true, required: true },
    { key: 'external_id', label: 'External ID', type: 'password', secret: true, required: false },
  ],
};

const stored: Integration = {
  key: 'aws',
  system: 'aws',
  config: { region: 'us-east-1', domains: ['a.com', 'b.com'], port: 6543, sslmode: 'disable' },
  secretFields: ['access_key_id', 'external_id'],
  secrets: { access_key_id: { set: true }, external_id: { set: true } },
  status: 'ok',
  testAvailable: true,
};

describe('integration form', () => {
  it('never prefills secrets and keeps stored ones by default', () => {
    const st = initialForm(schema, stored);
    expect(st.secrets.access_key_id).toEqual({ mode: 'keep' });
    expect(st.values).toEqual({ region: 'us-east-1', domains: 'a.com\nb.com', port: '6543', sslmode: 'disable' });
    const p = buildPayload(schema, st);
    expect(p.secrets).toEqual({});
    expect(p.config).toEqual({ region: 'us-east-1', domains: ['a.com', 'b.com'], port: 6543, sslmode: 'disable' });
  });

  it('uses schema defaults for a new integration and requires secrets', () => {
    const st = initialForm(schema, undefined);
    expect(st.values.port).toBe('5432');
    expect(st.secrets.access_key_id).toEqual({ mode: 'replace', value: '' });
    expect(formProblems(schema, st, undefined)).toEqual(['Region is required.', 'Access key is required.']);
  });

  it('sends replaced secrets, null for removed optional ones, and never empty strings', () => {
    const st = initialForm(schema, stored);
    st.secrets.access_key_id = { mode: 'replace', value: 'AKIANEWVALUE' };
    st.secrets.external_id = { mode: 'remove' };
    expect(buildPayload(schema, st).secrets).toEqual({ access_key_id: 'AKIANEWVALUE', external_id: null });

    st.secrets.access_key_id = { mode: 'replace', value: '   ' };
    expect(buildPayload(schema, st).secrets).toEqual({ external_id: null });
    expect(formProblems(schema, st, stored)).toContain('Access key is required.');
  });

  it('omits empty optional values and checks numbers', () => {
    const st = initialForm(schema, stored);
    st.values.port = '';
    st.values.domains = ' x.com, y.com\n\nx.com ';
    expect(buildPayload(schema, st).config).toEqual({ region: 'us-east-1', domains: ['x.com', 'y.com'], sslmode: 'disable' });
    st.values.port = '12a';
    expect(formProblems(schema, st, stored)).toEqual(['Port must be a whole number.']);
  });
});
