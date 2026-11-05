import { describe, expect, it } from 'vitest';
import { connectionKeyFor, normActivity, normApps, virtualApp } from './apps';
import { normSchemas } from './normalize';

const provider = {
  provider: 'netsuite',
  title: 'NetSuite',
  multi_tenant: true,
  environments: [
    {
      environment: 'full',
      title: 'NetSuite account (SuiteTalk)',
      tenant_label: 'NetSuite account ID',
      transports: [
        { transport: 'rest_api', system: 'netsuite', title: 'REST API', available: true, verified: 'test', reason: 'needs an integration record' },
        { transport: 'mcp', system: 'netsuite_mcp', title: 'MCP server (AI Connector)', available: true, verified: 'test', reason: 'needs OAuth' },
      ],
    },
    {
      environment: 'quickstart',
      title: 'NetSuite QuickStart',
      tenant_label: 'QuickStart company (label)',
      transports: [
        { transport: 'rest_api', title: 'REST API', available: false, verified: 'none', reason: 'not part of QuickStart' },
        { transport: 'mcp', system: 'netsuite_quickstart', title: 'MCP server (QuickStart)', available: true, verified: 'live', reason: 'needs a PAT' },
      ],
    },
  ],
};

describe('normApps', () => {
  it('keeps each transport separate: MCP working is not REST configured', () => {
    const r = normApps({
      integrations: [
        {
          integration_id: 'netsuite:quickstart',
          provider: 'netsuite',
          environment: 'quickstart',
          tenant_ref: 'Acme QS',
          health: 'healthy',
          connections: [{ key: 'netsuite_quickstart', system: 'netsuite_quickstart', status: 'ok', transport: 'mcp' }],
          transports: [
            { transport: 'rest_api', available: false, reason: 'not part of QuickStart', configured: false },
            { transport: 'mcp', system: 'netsuite_quickstart', available: true, configured: true, status: 'ok', connection_key: 'netsuite_quickstart' },
          ],
        },
      ],
      providers: [provider],
    });
    const qs = r.integrations[0]!;
    const rest = qs.transports.find((t) => t.transport === 'rest_api')!;
    const mcp = qs.transports.find((t) => t.transport === 'mcp')!;
    expect(rest.configured).toBe(false);
    expect(rest.available).toBe(false);
    expect(rest.status).toBe('');
    expect(rest.reason).toContain('QuickStart');
    expect(mcp.configured).toBe(true);
    expect(mcp.status).toBe('ok');
    expect(r.providers[0]!.environments).toHaveLength(2);
  });

  it('never invents a connection or health from an empty reply', () => {
    const r = normApps({ integrations: [{ integration_id: 'netsuite:x', transports: [{ transport: 'mcp', status: 'ok' }] }] });
    expect(r.integrations[0]!.health).toBe('not_connected');
    expect(r.integrations[0]!.transports[0]!.configured).toBe(false);
    expect(r.integrations[0]!.transports[0]!.status).toBe('');
    expect(normApps(null)).toEqual({ integrations: [], providers: [] });
  });
});

describe('connection keys', () => {
  it('matches the server rule, legacy keys included', () => {
    expect(connectionKeyFor('netsuite', 'netsuite:default')).toBe('netsuite');
    expect(connectionKeyFor('netsuite', 'netsuite:acme')).toBe('netsuite:acme');
    expect(connectionKeyFor('netsuite_mcp', 'netsuite:acme')).toBe('netsuite_mcp:acme');
    expect(connectionKeyFor('netsuite_quickstart', 'netsuite:quickstart')).toBe('netsuite_quickstart');
    expect(connectionKeyFor('netsuite_mcp', 'netsuite:default')).toBe('netsuite_mcp:default');
    expect(connectionKeyFor('salesforce', 'salesforce:default')).toBe('salesforce');
    expect(connectionKeyFor('servicenow_mcp', 'servicenow:default')).toBe('servicenow_mcp');
    expect(connectionKeyFor('sap', 'sap:eu')).toBe('sap:eu');
  });

  it('a placeholder tenant has nothing configured', () => {
    const p = normApps({ providers: [provider] }).providers[0]!;
    const v = virtualApp(p, p.environments[0]!, 'netsuite:default');
    expect(v.virtual).toBe(true);
    expect(v.transports.map((t) => [t.transport, t.connectionKey, t.configured])).toEqual([
      ['rest_api', 'netsuite', false],
      ['mcp', 'netsuite_mcp:default', false],
    ]);
  });
});

describe('normActivity', () => {
  it('counts per transport and decision', () => {
    const a = normActivity({ window_hours: 24, by_transport: { rest_api: { allow: 3 }, mcp: { deny: 1, hold: 'x' } }, pending_approvals: 2, recent: [{ action_id: 'a1' }] });
    expect(a.byTransport).toEqual({ rest_api: { allow: 3 }, mcp: { deny: 1, hold: 0 } });
    expect(a.pendingApprovals).toBe(2);
    expect(a.recent[0]!.actionId).toBe('a1');
  });
});

describe('normSchemas', () => {
  it('never offers a managed field (OAuth tokens Fortik obtains) in a form', () => {
    const [s] = normSchemas({
      schemas: [
        {
          system: 'netsuite_mcp',
          title: 'NetSuite MCP server (AI Connector Service)',
          fields: [
            { key: 'account_id', label: 'Account ID', type: 'text', required: true },
            { key: 'oauth_tokens', label: 'OAuth tokens', type: 'password', secret: true, managed: true },
          ],
        },
      ],
    });
    expect(s!.fields.map((f) => f.key)).toEqual(['account_id']);
  });
});
