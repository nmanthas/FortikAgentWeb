import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { normApps, tenantsOf, type AppIntegration } from '../api/apps';
import { normSchemas } from '../api/normalize';
import type { IntegrationSchema } from '../api/types';
import { installFakeApi } from '../test/fakeApi';
import { renderWithApp } from '../test/render';
import { AddTenantDialog, ProviderCard, testedLive } from './ProviderCard';

afterEach(() => {
  vi.unstubAllGlobals();
});

// Schemas as the server sends them (subset of fields; show_when included).
const schemas = new Map<string, IntegrationSchema>(
  normSchemas({
    schemas: [
      {
        system: 'netsuite',
        title: 'NetSuite REST API (SuiteTalk)',
        fields: [
          { key: 'account_id', label: 'Account ID', type: 'text', required: true },
          { key: 'client_id', label: 'Client ID', type: 'text', required: true },
          { key: 'certificate_id', label: 'Certificate ID', type: 'text', required: true },
          { key: 'algorithm', label: 'Signing algorithm', type: 'select', options: ['PS256', 'ES256'], default: 'PS256' },
          { key: 'private_key_pem', label: 'Private key (PEM)', type: 'textarea', secret: true, required: true },
        ],
      },
      {
        system: 'netsuite_quickstart',
        title: 'NetSuite QuickStart MCP server',
        fields: [
          { key: 'tenant_label', label: 'QuickStart account / tenant label', type: 'text', required: true },
          { key: 'endpoint_url', label: 'MCP endpoint URL', type: 'text', default: 'https://my.quickstartapi.netsuite.com/mcp' },
          { key: 'transport', label: 'Transport', type: 'select', options: ['streamable_http'], default: 'streamable_http' },
          { key: 'personal_access_token', label: 'Personal access token', type: 'password', secret: true, required: true },
        ],
      },
      {
        system: 'salesforce',
        title: 'Salesforce REST API',
        fields: [
          { key: 'instance_url', label: 'My Domain URL', type: 'text', required: true },
          { key: 'auth_flow', label: 'OAuth flow', type: 'select', options: ['client_credentials', 'jwt_bearer'], default: 'client_credentials' },
          { key: 'client_id', label: 'Consumer key (client ID)', type: 'text', required: true },
          { key: 'username', label: 'Username', type: 'text', show_when: { auth_flow: ['jwt_bearer'] } },
          { key: 'client_secret', label: 'Consumer secret', type: 'password', secret: true, show_when: { auth_flow: ['client_credentials'] } },
          { key: 'private_key_pem', label: 'Private key (PEM)', type: 'textarea', secret: true, show_when: { auth_flow: ['jwt_bearer'] } },
        ],
      },
      {
        system: 'salesforce_mcp',
        title: 'Salesforce MCP server',
        fields: [
          { key: 'endpoint_url', label: 'MCP server URL', type: 'text', required: true },
          { key: 'auth_type', label: 'Authentication', type: 'select', options: ['oauth_authorization_code', 'bearer_token'], default: 'oauth_authorization_code' },
          { key: 'client_id', label: 'OAuth client ID', type: 'text', show_when: { auth_type: ['oauth_authorization_code'] } },
          { key: 'access_token', label: 'Bearer token', type: 'password', secret: true, show_when: { auth_type: ['bearer_token'] } },
          { key: 'oauth_tokens', label: 'OAuth tokens', type: 'password', secret: true, managed: true },
        ],
      },
      { system: 'servicenow', title: 'ServiceNow REST API', fields: [{ key: 'instance_url', label: 'Instance URL', type: 'text', required: true }] },
      { system: 'servicenow_mcp', title: 'ServiceNow MCP server', fields: [{ key: 'endpoint_url', label: 'MCP server URL', type: 'text', required: true }] },
      { system: 'sap', title: 'SAP OData API', fields: [{ key: 'api_base_url', label: 'API base URL', type: 'text', required: true }] },
      { system: 'sap_mcp', title: 'SAP MCP server', fields: [{ key: 'endpoint_url', label: 'MCP server URL', type: 'text', required: true }] },
    ],
  }).map((s) => [s.system, s]),
);

const tr = (transport: string, system: string, title: string, extra: Record<string, unknown> = {}) => ({
  transport,
  system,
  title,
  available: true,
  verified: 'test',
  reason: `needs ${title}`,
  ...extra,
});

const providers = [
  {
    provider: 'netsuite',
    title: 'NetSuite',
    multi_tenant: true,
    environments: [
      {
        environment: 'full',
        title: 'NetSuite account (SuiteTalk)',
        tenant_label: 'NetSuite account ID',
        transports: [tr('rest_api', 'netsuite', 'REST API (SuiteTalk)'), tr('mcp', 'netsuite_mcp', 'MCP Server (AI Connector Service)')],
      },
      {
        environment: 'quickstart',
        title: 'NetSuite QuickStart',
        tenant_label: 'QuickStart company (label)',
        transports: [
          { transport: 'rest_api', title: 'REST API (SuiteTalk)', available: false, verified: 'none', reason: "SuiteTalk REST is not part of QuickStart's documented setup." },
          tr('mcp', 'netsuite_quickstart', 'MCP Server (QuickStart)', { verified: 'live' }),
        ],
      },
    ],
  },
  ...(['salesforce', 'servicenow', 'sap'] as const).map((p) => ({
    provider: p,
    title: { salesforce: 'Salesforce', servicenow: 'ServiceNow', sap: 'SAP' }[p],
    multi_tenant: true,
    environments: [{ environment: '', title: p, tenant_label: 'host', transports: [tr('rest_api', p, 'REST API'), tr('mcp', `${p}_mcp`, 'MCP Server')] }],
  })),
];

const restConn = { key: 'salesforce', system: 'salesforce', status: 'ok', last_tested_at: '2026-10-28T10:00:00Z', config: { instance_url: 'https://acme.my.salesforce.com', auth_flow: 'client_credentials', client_id: 'cid' }, secret_fields: ['client_secret'] };

function salesforceApp(conns: unknown[] = [restConn]): AppIntegration {
  return normApps({
    integrations: [
      {
        integration_id: 'salesforce:default',
        provider: 'salesforce',
        environment: '',
        tenant_ref: 'acme.my.salesforce.com',
        display_name: 'Salesforce',
        provider_title: 'Salesforce',
        health: 'healthy',
        connections: conns,
        transports: [
          { ...tr('rest_api', 'salesforce', 'REST API'), connection_key: 'salesforce', configured: conns.length > 0, status: 'ok' },
          { ...tr('mcp', 'salesforce_mcp', 'MCP Server'), connection_key: 'salesforce_mcp', configured: false },
        ],
      },
    ],
    providers,
  }).integrations[0]!;
}

const fieldLabels = () => Array.from(document.querySelectorAll('fieldset label')).map((l) => l.textContent ?? '');

describe('ProviderCard', () => {
  it('is one component with a working REST / MCP dropdown, each showing only its own fields and status', async () => {
    installFakeApi({ 'GET /v1/integrations/salesforce/check': { state: 'connected', state_label: 'Connected', capabilities: { objects_visible: 3 } } });
    renderWithApp(<ProviderCard app={salesforceApp()} schemas={schemas} canEdit onChanged={() => undefined} />);
    expect(screen.getAllByTestId(/^provider-card-/)).toHaveLength(1);
    const select = screen.getByTestId('connection-method') as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(['REST API', 'MCP Server']);
    // REST is configured, so it is selected first: REST fields only.
    expect(select.value).toBe('rest_api');
    expect(screen.getByTestId('method-status').textContent).toBe('REST API — Connected');
    expect(fieldLabels().join('|')).toContain('My Domain URL');
    expect(fieldLabels().join('|')).not.toContain('MCP server URL');
    expect((await screen.findByTestId('rest-capabilities')).textContent).toContain('objects_visible: 3');
    // The saved secret is never shown, only that it is set.
    expect(screen.getByTestId('secret-set-client_secret').textContent).toContain('set');
    expect(document.body.innerHTML).not.toContain('sf-secret');

    fireEvent.change(select, { target: { value: 'mcp' } });
    expect(screen.getByTestId('method-status').textContent).toBe('MCP Server — Not configured');
    expect(fieldLabels().join('|')).toContain('MCP server URL');
    expect(fieldLabels().join('|')).not.toContain('My Domain URL');
    // The Fortik-managed OAuth tokens field is never in a form.
    expect(fieldLabels().join('|')).not.toContain('OAuth tokens');
  });

  it('keeps unsaved edits of each method when switching, and saves only the selected one', async () => {
    const { calls } = installFakeApi({
      'GET /v1/integrations/salesforce/check': { state: 'connected', state_label: 'Connected' },
      'PUT /v1/integrations/salesforce_mcp': { key: 'salesforce_mcp', system: 'salesforce_mcp', status: 'configured' },
    });
    const onChanged = vi.fn();
    renderWithApp(<ProviderCard app={salesforceApp()} schemas={schemas} canEdit onChanged={onChanged} />);
    const select = screen.getByTestId('connection-method');
    fireEvent.change(select, { target: { value: 'mcp' } });
    fireEvent.change(screen.getByLabelText(/MCP server URL/), { target: { value: 'https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads' } });
    fireEvent.change(select, { target: { value: 'rest_api' } });
    expect((screen.getByLabelText(/My Domain URL/) as HTMLInputElement).value).toBe('https://acme.my.salesforce.com');
    fireEvent.change(select, { target: { value: 'mcp' } });
    expect((screen.getByLabelText(/MCP server URL/) as HTMLInputElement).value).toBe('https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads');
    fireEvent.change(screen.getByLabelText(/OAuth client ID/), { target: { value: 'eca-client' } });
    fireEvent.click(screen.getByTestId('save'));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    const put = calls.filter((c) => c.method === 'PUT');
    expect(put).toHaveLength(1);
    expect(put[0]!.path).toBe('/v1/integrations/salesforce_mcp');
    expect((put[0]!.body as { config: Record<string, unknown> }).config).toMatchObject({ endpoint_url: 'https://api.salesforce.com/platform/mcp/v1/platform/sobject-reads', client_id: 'eca-client' });
    // The REST method was neither saved nor disconnected.
    expect(calls.some((c) => c.path === '/v1/integrations/salesforce' && c.method !== 'GET')).toBe(false);
  });

  it('Test connection tests the selected method; Disconnect removes only it', async () => {
    const { calls } = installFakeApi({
      'GET /v1/integrations/salesforce/check': { state: 'auth_failed', state_label: 'Authentication failed', detail: 'invalid_client' },
      'POST /v1/integrations/salesforce/test': { ok: false, error: 'Authentication failed: token request refused: invalid_client' },
      'DELETE /v1/integrations/salesforce': { deleted: 'salesforce', notes: [] },
    });
    const onChanged = vi.fn();
    renderWithApp(<ProviderCard app={salesforceApp()} schemas={schemas} canEdit onChanged={onChanged} />);
    expect((await screen.findByTestId('rest-check-state')).textContent).toBe('Authentication failed');
    fireEvent.click(screen.getByTestId('test-connection'));
    expect((await screen.findByTestId('test-result')).textContent).toContain('invalid_client');
    expect(calls.filter((c) => c.method === 'POST').map((c) => c.path)).toEqual(['/v1/integrations/salesforce/test']);
    fireEvent.click(screen.getByTestId('disconnect'));
    fireEvent.click(await screen.findByTestId('confirm-disconnect'));
    await waitFor(() => expect(calls.some((c) => c.method === 'DELETE')).toBe(true));
    expect(calls.filter((c) => c.method === 'DELETE').map((c) => c.path)).toEqual(['/v1/integrations/salesforce']);
  });

  it('shows only the fields of the selected authentication and reports validation errors', () => {
    installFakeApi({});
    renderWithApp(<ProviderCard app={salesforceApp([])} schemas={schemas} canEdit onChanged={() => undefined} />);
    expect(screen.getByTestId('method-status').textContent).toBe('REST API — Not configured');
    expect(fieldLabels().join('|')).toContain('Consumer secret');
    expect(fieldLabels().join('|')).not.toContain('Private key');
    fireEvent.change(screen.getByLabelText(/OAuth flow/), { target: { value: 'jwt_bearer' } });
    expect(fieldLabels().join('|')).toContain('Private key');
    expect(fieldLabels().join('|')).not.toContain('Consumer secret');
    expect(screen.getByTestId('form-problems').textContent).toContain('My Domain URL is required');
    expect((screen.getByTestId('save') as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByTestId('test-connection') as HTMLButtonElement).disabled).toBe(true);
  });

  it('NetSuite: one card per QuickStart account; REST explained as unavailable, MCP keeps its connection', () => {
    installFakeApi({});
    const qs = normApps({
      integrations: [
        {
          integration_id: 'netsuite:quickstart',
          provider: 'netsuite',
          environment: 'quickstart',
          environment_title: 'NetSuite QuickStart',
          display_name: 'Acme QuickStart',
          provider_title: 'NetSuite',
          health: 'healthy',
          connections: [{ key: 'netsuite_quickstart', system: 'netsuite_quickstart', status: 'ok', config: { tenant_label: 'Acme' }, secret_fields: ['personal_access_token'] }],
          transports: [
            { transport: 'rest_api', title: 'REST API (SuiteTalk)', available: false, verified: 'none', reason: "SuiteTalk REST is not part of QuickStart's documented setup." },
            { ...tr('mcp', 'netsuite_quickstart', 'MCP Server (QuickStart)', { verified: 'live' }), connection_key: 'netsuite_quickstart', configured: true, status: 'ok' },
          ],
        },
      ],
      providers,
    });
    const onAdd = vi.fn();
    renderWithApp(<ProviderCard app={qs.integrations[0]!} schemas={schemas} canEdit onChanged={() => undefined} onAddTenant={onAdd} />);
    const select = screen.getByTestId('connection-method') as HTMLSelectElement;
    expect(select.value).toBe('mcp');
    expect(screen.getByTestId('method-status').textContent).toBe('MCP Server — Connected');
    expect(fieldLabels().join('|')).toContain('Personal access token');
    expect(fieldLabels().join('|')).not.toContain('Certificate ID');
    fireEvent.change(select, { target: { value: 'rest_api' } });
    const why = screen.getByTestId('method-unavailable');
    expect(why.textContent).toContain('unavailable for this QuickStart account');
    expect(why.textContent).toContain('not part of QuickStart');
    expect(document.querySelector('fieldset')).toBeNull();
    fireEvent.click(within(why).getByTestId('add-full-account'));
    expect(onAdd).toHaveBeenCalledWith('full');
  });

  it('NetSuite with nothing connected: one placeholder offering SuiteTalk REST and the QuickStart MCP form', () => {
    installFakeApi({});
    const apps = normApps({ integrations: [], providers });
    const tenants = tenantsOf(apps, 'netsuite');
    expect(tenants).toHaveLength(1);
    renderWithApp(<ProviderCard app={tenants[0]!} schemas={schemas} canEdit onChanged={() => undefined} />);
    const select = screen.getByTestId('connection-method') as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.textContent)).toEqual(['REST API (SuiteTalk)', 'MCP Server (QuickStart)']);
    expect(fieldLabels().join('|')).toContain('Certificate ID');
    expect(fieldLabels().join('|')).toContain('Private key');
    fireEvent.change(select, { target: { value: 'mcp' } });
    expect(fieldLabels().join('|')).toContain('MCP endpoint URL');
    expect(fieldLabels().join('|')).not.toContain('Certificate ID');
    expect((screen.getByLabelText(/MCP endpoint URL/) as HTMLInputElement).value).toBe('https://my.quickstartapi.netsuite.com/mcp');
  });

  it.each(['salesforce', 'servicenow', 'sap'])('%s: one placeholder card with REST API and MCP Server forms', (p) => {
    installFakeApi({});
    const tenants = tenantsOf(normApps({ integrations: [], providers }), p);
    expect(tenants).toHaveLength(1);
    renderWithApp(<ProviderCard app={tenants[0]!} schemas={schemas} canEdit onChanged={() => undefined} />);
    const select = screen.getByTestId('connection-method') as HTMLSelectElement;
    expect(Array.from(select.options).map((o) => o.value)).toEqual(['rest_api', 'mcp']);
    const restFields = fieldLabels().join('|');
    fireEvent.change(select, { target: { value: 'mcp' } });
    const mcpFields = fieldLabels().join('|');
    expect(restFields).not.toEqual(mcpFields);
    expect(mcpFields).toContain('MCP server URL');
    expect(screen.getByTestId('method-status').textContent).toBe('MCP Server — Not configured');
  });
});

describe('field presentation', () => {
  it('shows a fixed value for a one-option choice, readable option names, and long help folded behind More', () => {
    installFakeApi({});
    const tenants = tenantsOf(normApps({ integrations: [], providers }), 'netsuite');
    renderWithApp(<ProviderCard app={tenants[0]!} schemas={schemas} canEdit onChanged={() => undefined} />);
    fireEvent.change(screen.getByTestId('connection-method'), { target: { value: 'mcp' } });
    const transport = screen.getByLabelText(/Transport/) as HTMLInputElement;
    expect(transport.tagName).toBe('INPUT');
    expect(transport.readOnly).toBe(true);
    expect(transport.value).toBe('Streamable HTTP');
  });

  it('folds long help to its first sentence', async () => {
    const { Help } = await import('./ConnectionFields');
    const long = 'First sentence of the help, long enough to be a real summary. ' + 'Then a lot more detail follows, e.g. https://example.com and more words. '.repeat(3);
    renderWithApp(<Help text={long} />);
    expect(screen.getByText(/First sentence of the help/).textContent).not.toContain('Then a lot more');
    fireEvent.click(screen.getByRole('button', { name: 'More' }));
    expect(screen.getByText(/First sentence of the help/).textContent).toContain('Then a lot more');
  });
});

describe('evidence chip', () => {
  it('says the live test passed only for a successful test of a real host', async () => {
    installFakeApi({ 'GET /v1/integrations/salesforce/check': { state: 'connected', state_label: 'Connected' } });
    renderWithApp(<ProviderCard app={salesforceApp()} schemas={schemas} canEdit onChanged={() => undefined} />);
    expect(screen.getByText('live test passed')).toBeTruthy();
    expect(screen.queryByText('tested against fakes only')).toBeNull();
    const base = { key: 'salesforce', system: 'salesforce', config: {}, secretFields: [], secrets: {}, testAvailable: true };
    expect(testedLive({ ...base, status: 'ok', config: { instance_url: 'https://acme.my.salesforce.com' } })).toBe(true);
    expect(testedLive({ ...base, status: 'ok', config: { instance_url: 'http://127.0.0.1:18501' } })).toBe(false);
    expect(testedLive({ ...base, status: 'error', config: { instance_url: 'https://acme.my.salesforce.com' } })).toBe(false);
    expect(testedLive({ ...base, status: 'configured', config: {} })).toBe(false);
  });
});

describe('AddTenantDialog', () => {
  it('creates a tenant of any provider', async () => {
    const { calls } = installFakeApi({ 'POST /v1/app-integrations': { status: 201, body: { integration_id: 'servicenow:eu' } } });
    const onCreated = vi.fn();
    const p = normApps({ providers }).providers.find((x) => x.provider === 'servicenow')!;
    renderWithApp(<AddTenantDialog provider={p} existing={['servicenow:default']} onClose={() => undefined} onCreated={onCreated} />);
    fireEvent.change(screen.getByLabelText('Name'), { target: { value: 'eu' } });
    fireEvent.change(screen.getByLabelText('Display name'), { target: { value: 'ServiceNow EU' } });
    fireEvent.change(screen.getByLabelText('host'), { target: { value: 'https://acme-eu.service-now.com' } });
    fireEvent.click(screen.getByRole('button', { name: /Add/ }));
    await waitFor(() => expect(onCreated).toHaveBeenCalled());
    expect(calls.find((c) => c.method === 'POST')?.body).toEqual({ provider: 'servicenow', environment: '', name: 'eu', tenant_ref: 'https://acme-eu.service-now.com', display_name: 'ServiceNow EU' });
  });
});
