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
});
