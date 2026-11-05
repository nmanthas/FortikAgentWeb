import { describe, expect, it } from 'vitest';
import type { AccessSystem } from '../api/types';
import { fromForm, summarize, toForm, validateForm, type GitHubForm, type PostgresForm } from './profiles';

describe('access profile forms', () => {
  const samples: Record<AccessSystem, unknown> = {
    gmail: { send: 'internal_only', read: true, max_recipients: 25 },
    drive: { mode: 'read_only', share: 'none' },
    github: { repos: ['org/repo'], permissions: { contents: 'write', pull_requests: 'read', metadata: 'read' }, allow_direct_token: false },
    aws: { mode: 'read_only', services: ['s3', 'ec2'], denied_actions: ['iam:*'] },
    postgres: { upstreams: { acme_prod: 'read_only', acme_staging: 'read_write' } },
    a2a: { may_delegate_to: ['agent_b', 'agent_c'], max_depth: 3 },
    http: { external: 'allowlist', allowed_domains: ['api.example.com', '*.example.org'] },
    mcp: { servers: { 'github-mcp': ['*'], memory: ['read_graph', 'search_nodes'] } },
    netsuite: { mode: 'read_only', record_types: ['customer', 'vendorbill'], suiteql: false, quickstart_tools: ['list_records', 'read_record'] },
    salesforce: { mode: 'read_write', objects: ['account', 'contact'], integrations: ['salesforce:default'] },
    servicenow: { mode: 'read_only', objects: ['*'], mcp_tools: ['get_incident'] },
    sap: { mode: 'read_only', objects: ['api_business_partner/a_businesspartner'] },
  };

  it('round-trips every documented profile shape', () => {
    for (const [sys, p] of Object.entries(samples) as [AccessSystem, unknown][]) {
      expect(fromForm(sys, toForm(sys, p))).toEqual(p);
      expect(validateForm(sys, toForm(sys, p))).toEqual([]);
    }
  });

  it('starts a missing profile at the most restrictive values', () => {
    expect(fromForm('gmail', toForm('gmail', null))).toEqual({ send: 'none', read: false, max_recipients: 0 });
    expect(fromForm('drive', toForm('drive', null))).toEqual({ mode: 'none', share: 'none' });
    expect(fromForm('aws', toForm('aws', null))).toEqual({ mode: 'none', services: [], denied_actions: [] });
    expect(summarize('github', null)).toMatch(/POL-020/);
  });

  it('maps unknown enum values to none (fail closed)', () => {
    expect(toForm('drive', { mode: 'superuser', share: 'everyone' })).toEqual({ mode: 'none', share: 'none' });
  });

  it('validates repos, AWS patterns and upstream names', () => {
    const gh = toForm('github', samples.github) as GitHubForm;
    expect(validateForm('github', { ...gh, repos: ['not a repo'] })).toHaveLength(1);
    expect(validateForm('aws', { mode: 'read_only', services: ['S3'], deniedActions: ['iam'] })).toHaveLength(2);
    const pg: PostgresForm = { upstreams: [{ name: 'a', mode: 'read_only' }, { name: 'a', mode: 'none' }, { name: '9bad', mode: 'none' }] };
    expect(validateForm('postgres', pg).length).toBe(2);
    expect(validateForm('gmail', { send: 'any', read: true, maxRecipients: -1 })).toHaveLength(1);
  });

  it('handles the Phase 3 systems (a2a, http, mcp)', () => {
    expect(fromForm('a2a', toForm('a2a', null))).toEqual({ may_delegate_to: [], max_depth: 1 });
    expect(fromForm('http', toForm('http', null))).toEqual({ external: 'none' });
    expect(fromForm('mcp', toForm('mcp', null))).toEqual({ servers: {} });
    expect(fromForm('a2a', toForm('a2a', { may_delegate_to: ['*'], max_depth: 2 }))).toEqual({ may_delegate_to: ['*'], max_depth: 2 });
    expect(toForm('http', { external: 'everything' })).toEqual({ external: 'none', allowedDomains: [] });
    // allowed_domains is only sent with an allowlist (the server refuses it otherwise).
    expect(fromForm('http', { external: 'any', allowedDomains: ['x.com'] })).toEqual({ external: 'any' });
    expect(validateForm('http', { external: 'allowlist', allowedDomains: [] })).toHaveLength(1);
    expect(validateForm('http', { external: 'allowlist', allowedDomains: ['bad domain', '*'] })).toHaveLength(2);
    expect(validateForm('a2a', { anyAgent: false, mayDelegateTo: ['ok-agent', 'bad agent'], maxDepth: 0 })).toHaveLength(2);
    expect(validateForm('mcp', { servers: [{ name: 'm', allTools: false, tools: ['ok', 'bad tool'] }, { name: 'm', allTools: true, tools: [] }] })).toHaveLength(2);
    expect(summarize('a2a', { may_delegate_to: [], max_depth: 1 })).toBe('may delegate to nobody, max depth 1');
  });

  it('drops blank and duplicate list entries', () => {
    const gh = toForm('github', samples.github) as GitHubForm;
    expect(fromForm('github', { ...gh, repos: ['org/repo', ' ', 'org/repo', ' org/two '] })).toMatchObject({ repos: ['org/repo', 'org/two'] });
  });

  it('netsuite: record types, SuiteQL and the QuickStart tool allowlist round-trip', () => {
    expect(fromForm('netsuite', toForm('netsuite', null))).toEqual({ mode: 'none', record_types: [], suiteql: false });
    const all = { mode: 'read_write', record_types: ['*'], suiteql: true };
    expect(fromForm('netsuite', toForm('netsuite', all))).toEqual(all);
    const narrow = { mode: 'read_only', record_types: ['customer', 'term'], suiteql: false, quickstart_tools: ['read_record'] };
    expect(fromForm('netsuite', toForm('netsuite', narrow))).toEqual(narrow);
    expect(summarize('netsuite', narrow)).toContain('QuickStart tools: read_record');
    expect(
      validateForm('netsuite', { mode: 'read_only', allTypes: false, recordTypes: ['Vendor Bill'], suiteql: false, allTools: false, quickstartTools: ['Read Record'], allTenants: true, tenants: [] }),
    ).toHaveLength(2);
  });

  it('netsuite: the tenant restriction (integrations) round-trips and is validated', () => {
    const tenants = { mode: 'read_only', record_types: ['*'], suiteql: false, integrations: ['netsuite:acme', 'netsuite:quickstart'] };
    expect(fromForm('netsuite', toForm('netsuite', tenants))).toEqual(tenants);
    expect(summarize('netsuite', tenants)).toContain('tenants: netsuite:acme, netsuite:quickstart');
    // ["*"] and absent both mean every tenant; the form writes nothing then.
    expect(fromForm('netsuite', toForm('netsuite', { mode: 'read_only', record_types: ['*'], suiteql: false, integrations: ['*'] }))).not.toHaveProperty('integrations');
    expect(summarize('netsuite', { mode: 'read_only', record_types: ['*'], suiteql: false })).toContain('every NetSuite tenant');
    expect(
      validateForm('netsuite', { mode: 'read_only', allTypes: true, recordTypes: [], suiteql: false, allTools: true, quickstartTools: [], allTenants: false, tenants: ['acme', 'netsuite:Acme'] }),
    ).toHaveLength(1);
  });

  it('salesforce / servicenow / sap: one profile for REST and MCP, restrictive by default', () => {
    expect(fromForm('salesforce', toForm('salesforce', null))).toEqual({ mode: 'none', objects: [] });
    expect(summarize('servicenow', { mode: 'read_only', objects: ['*'] })).toContain('every object, every tenant, every MCP tool the mode allows');
    expect(
      validateForm('sap', { mode: 'read_only', allObjects: true, objects: [], allTenants: false, tenants: ['salesforce:x'], allTools: false, tools: ['bad tool'], allAgents: false, agents: [], agentMessages: 'approval' }),
    ).toHaveLength(2);
  });

  it('salesforce: Agentforce agents and message handling round-trip; none by default', () => {
    const p = { mode: 'read_write', objects: ['*'], agentforce_agents: ['0Xxg70000020uCOCAY'], agentforce_messages: 'allow' };
    expect(fromForm('salesforce', toForm('salesforce', p))).toEqual(p);
    expect(fromForm('salesforce', toForm('salesforce', { mode: 'read_write', objects: ['*'], agentforce_agents: ['*'] }))).toEqual({
      mode: 'read_write',
      objects: ['*'],
      agentforce_agents: ['*'],
    });
    // no agents: neither key is written (none allowed), and other systems never get them
    expect(fromForm('salesforce', toForm('salesforce', { mode: 'read_write', objects: ['*'], agentforce_messages: 'allow' }))).toEqual({ mode: 'read_write', objects: ['*'] });
    expect(fromForm('servicenow', { ...toForm('servicenow', { mode: 'read_only', objects: ['*'] }), allAgents: true } as never)).not.toHaveProperty('agentforce_agents');
    expect(summarize('salesforce', p)).toContain('Agentforce agents: 0Xxg70000020uCOCAY (messages allowed)');
    expect(summarize('salesforce', { mode: 'read_only', objects: ['*'] })).toContain('no Agentforce agents');
    expect(
      validateForm('salesforce', { mode: 'read_write', allObjects: true, objects: [], allTenants: true, tenants: [], allTools: true, tools: [], allAgents: false, agents: ['Fortik Kill Switch'], agentMessages: 'approval' }),
    ).toHaveLength(1);
  });
});
