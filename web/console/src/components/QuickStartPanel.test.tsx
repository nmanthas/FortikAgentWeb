import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { normQuickStart, quickStartTone } from '../api/quickstart';
import { installFakeApi } from '../test/fakeApi';
import { QuickStartPanel } from './QuickStartPanel';

afterEach(() => {
  vi.unstubAllGlobals();
});

const connected = (extra: Record<string, unknown> = {}) => ({
  integration: 'netsuite_quickstart',
  system: 'netsuite',
  transport: 'mcp',
  configured: true,
  state: 'connected',
  state_label: 'Connected',
  detail: 'initialized (protocol 2025-06-18) and listed 2 tools',
  tenant_label: 'Acme test company',
  endpoint: 'https://my.quickstartapi.netsuite.com/mcp',
  endpoint_permitted: true,
  token: { set: true, expires_on: '2026-11-20', days_left: 26 },
  server: { name: 'QuickStart MCP', version: '1', protocol_version: '2025-06-18', capabilities: { tools: {} } },
  tools: [
    { name: 'read_record', description: 'Reads a record', input_schema: { type: 'object' }, documented_access: 'read_only_token' },
    { name: 'list_records', input_schema: { type: 'object' }, documented_access: 'read_only_token' },
  ],
  rejected_tools: [],
  tool_count: 2,
  tools_from_current_settings: true,
  permission_mode: 'read_only',
  permission_basis: 'every exposed tool is in the documented read-only list',
  last_success_at: '2026-10-25T06:00:00Z',
  last_tools_sync_at: '2026-10-25T06:00:00Z',
  enforcement: { agent_calls_routed: true, pre_execution: 'enforced', post_execution: 'unsupported', note: 'Agents that use Fortik’s QuickStart endpoint are decided before each tool call.' },
  agent_endpoint: 'http://127.0.0.1:8090/mcp/netsuite_quickstart',
  activity: {
    window_hours: 24, allowed: 5, held: 2, denied: 1, executed: 5, failed: 0, pending_approvals: 1, active_netsuite_suspensions: 0, undo_available: 1,
    recent: [
      { action_id: 'act_1', agent_id: 'erp-bot', tool: 'update_record', decision: 'allow', rule_id: 'POL-1120', reason: 'approved', ts: '2026-10-25T06:00:00Z', outcome: 'executed', undo: 'active' },
      { action_id: 'act_2', agent_id: 'erp-bot', tool: 'delete_record', decision: 'hold', rule_id: 'POL-1002', reason: 'red', ts: '2026-10-25T06:00:00Z', outcome: '', undo: '' },
    ],
  },
  known_gaps: ['Only agents that connect to Fortik’s endpoint are governed.'],
  coverage: { capabilities: [{ dimension: 'pre_execution_enforcement', status: 'not_built' }] },
  revoke_instructions: 'Disconnecting removes the token from Fortik only; it does not revoke it in QuickStart.',
  ...extra,
});

describe('normQuickStart', () => {
  it('never assumes enforcement or a connection that the server did not report', () => {
    const q = normQuickStart({});
    expect(q.configured).toBe(false);
    expect(q.enforcement.agentCallsRouted).toBe(false);
    expect(q.state).toBe('unknown');
    expect(q.tools).toEqual([]);
    expect(quickStartTone(q.state)).toBe('red');
  });

  it('keeps tools, scope and the token expiry, and has no token value field', () => {
    const q = normQuickStart(connected());
    expect(q.tools.map((t) => t.name)).toEqual(['read_record', 'list_records']);
    expect(q.permissionMode).toBe('read_only');
    expect(q.token).toEqual({ set: true, expiresOn: '2026-11-20', daysLeft: 26, warning: '' });
    expect(JSON.stringify(q)).not.toMatch(/"value"/);
    expect(quickStartTone('saved_not_tested')).toBe('amber');
    expect(quickStartTone('token_expired')).toBe('red');
  });
});

describe('QuickStartPanel', () => {
  it('shows the live state, the tools and that agent calls are not routed yet', async () => {
    installFakeApi({ 'GET /v1/integrations/netsuite_quickstart/mcp': connected() });
    render(<QuickStartPanel canRefresh onChanged={() => undefined} />);
    expect((await screen.findByTestId('quickstart-state')).textContent).toContain('Connected');
    expect(screen.getByTestId('quickstart-enforcement').textContent).toContain('Agent calls routed through Fortik: yes');
    expect(screen.getByTestId('quickstart-agent-endpoint').textContent).toBe('http://127.0.0.1:8090/mcp/netsuite_quickstart');
    const act = screen.getByTestId('quickstart-activity').textContent ?? '';
    expect(act).toContain('5 allowed');
    expect(act).toContain('2 held');
    expect(act).toContain('undo available');
    expect(act).toContain('waiting for approval');
    expect(screen.getByTestId('quickstart-gaps').textContent).toContain('Known gaps (1)');
    expect(screen.getByTestId('quickstart-coverage').textContent).toContain('pre execution enforcement');
    expect(screen.getByText(/Read-only \(inferred\)/)).toBeTruthy();
    fireEvent.click(screen.getByTestId('quickstart-view-tools'));
    expect((await screen.findByTestId('quickstart-tools')).textContent).toContain('read_record');
  });

  it('saved settings are not shown as connected', async () => {
    installFakeApi({ 'GET /v1/integrations/netsuite_quickstart/mcp': connected({ state: 'saved_not_tested', state_label: 'Configuration saved but not tested', tools: [], server: null }) });
    render(<QuickStartPanel canRefresh onChanged={() => undefined} />);
    const chip = await screen.findByTestId('quickstart-state');
    expect(chip.textContent).toContain('saved but not tested');
    expect(chip.className).toContain('amber');
  });

  it('Refresh tools runs a live check and reports a failure state', async () => {
    const onChanged = vi.fn();
    const { calls } = installFakeApi({
      'GET /v1/integrations/netsuite_quickstart/mcp': connected(),
      'POST /v1/integrations/netsuite_quickstart/mcp/refresh': {
        ok: false,
        error: 'Authentication failed: initialize: the server rejected the token',
        status: connected({ state: 'auth_failed', state_label: 'Authentication failed' }),
      },
    });
    render(<QuickStartPanel canRefresh onChanged={onChanged} />);
    fireEvent.click(await screen.findByTestId('quickstart-refresh'));
    await waitFor(() => expect(onChanged).toHaveBeenCalled());
    expect(calls.some((c) => c.method === 'POST' && c.path === '/v1/integrations/netsuite_quickstart/mcp/refresh')).toBe(true);
  });

  it('refresh needs the security role', async () => {
    installFakeApi({ 'GET /v1/integrations/netsuite_quickstart/mcp': connected() });
    render(<QuickStartPanel canRefresh={false} onChanged={() => undefined} />);
    expect(((await screen.findByTestId('quickstart-refresh')) as HTMLButtonElement).disabled).toBe(true);
  });

  it('renders nothing on a server without the QuickStart integration', async () => {
    const { calls } = installFakeApi({});
    const { container } = render(<QuickStartPanel canRefresh onChanged={() => undefined} />);
    await waitFor(() => expect(calls).toHaveLength(1));
    await waitFor(() => expect(container.textContent).toBe(''));
  });

  it('an AI Connector (OAuth) connection shows its authorization and an Authorize button, never a token', async () => {
    const assign = vi.fn();
    vi.stubGlobal('location', { ...window.location, assign });
    const { calls } = installFakeApi({
      'GET /v1/integrations/netsuite_mcp%3Aacme/mcp': connected({
        integration: 'netsuite_mcp',
        key: 'netsuite_mcp:acme',
        integration_id: 'netsuite:acme',
        auth_type: 'oauth_authorization_code',
        state: 'authorization_required',
        state_label: 'Authorization required',
        oauth: { authorized: false },
        token: { set: false },
        tools: [],
        mapped_tools: 0,
        permission_mode: 'unknown',
      }),
      'POST /v1/integrations/netsuite_mcp%3Aacme/oauth/start': { authorize_url: 'https://1234567.app.netsuite.com/app/login/oauth2/authorize.nl?state=x', expires_in: 600 },
    });
    render(<QuickStartPanel connectionKey="netsuite_mcp:acme" canRefresh onChanged={() => undefined} />);
    const chip = await screen.findByTestId('quickstart-state');
    expect(chip.textContent).toContain('Authorization required');
    expect(chip.className).toContain('amber');
    const oauth = screen.getByTestId('mcp-oauth').textContent ?? '';
    expect(oauth).toContain('No NetSuite user has authorized Fortik');
    expect(oauth).toContain('every tool call is refused');
    expect(screen.queryByText(/Token: /)).toBeNull();
    fireEvent.click(screen.getByTestId('mcp-authorize'));
    await waitFor(() => expect(assign).toHaveBeenCalledWith('https://1234567.app.netsuite.com/app/login/oauth2/authorize.nl?state=x'));
    expect(calls.some((c) => c.method === 'POST' && c.path === '/v1/integrations/netsuite_mcp%3Aacme/oauth/start')).toBe(true);
  });

  it('a stale authorization is not shown as authorized', async () => {
    installFakeApi({
      'GET /v1/integrations/netsuite_mcp%3Aacme/mcp': connected({ integration: 'netsuite_mcp', key: 'netsuite_mcp:acme', oauth: { authorized: false, stale: true } }),
    });
    render(<QuickStartPanel connectionKey="netsuite_mcp:acme" canRefresh={false} onChanged={() => undefined} />);
    expect((await screen.findByTestId('mcp-oauth')).textContent).toContain('authorize again');
    expect((screen.getByTestId('mcp-authorize') as HTMLButtonElement).disabled).toBe(true);
  });
});
