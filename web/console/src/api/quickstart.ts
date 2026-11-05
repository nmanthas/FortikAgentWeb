// NetSuite MCP connections: QuickStart (personal access token) and a full
// account's AI Connector Service (OAuth). GET /v1/integrations/{key}/mcp,
// POST .../mcp/refresh and .../oauth/start. The normaliser is defensive and
// never invents a value; no token is ever part of a reply.

import { api, ApiError } from './client';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

export interface QuickStartTool {
  name: string;
  title: string;
  description: string;
  inputSchema: unknown;
  annotations: unknown;
  /** Oracle's documented list the name is in: read_only_token | read_write_token | undocumented. */
  documentedAccess: string;
  /** In Fortik's tool mapping: an unmapped tool is refused and not offered to agents. */
  mapped: boolean;
}

export interface QuickStartRejected {
  name: string;
  reason: string;
}

export interface QuickStartCapability {
  dimension: string;
  status: string;
  gap: string;
  fix: string;
}

export interface QuickStartRecent {
  actionId: string;
  agentId: string;
  tool: string;
  decision: string;
  ruleId: string;
  reason: string;
  ts: string;
  /** executed | failed | not_executed | unknown; "" when the call was not allowed. */
  outcome: string;
  /** Undo handle status (active, used, failed...) when one exists. */
  undo: string;
}

export interface QuickStartActivity {
  windowHours: number;
  allowed: number;
  held: number;
  denied: number;
  executed: number;
  failed: number;
  pendingApprovals: number;
  activeSuspensions: number;
  undoAvailable: number;
  recent: QuickStartRecent[];
}

export interface OAuthState {
  authorized: boolean;
  authorizedAt: string;
  authorizedBy: string;
  accessExpiresAt: string;
  refreshedAt: string;
  /** Tokens were issued for another account or client: authorize again. */
  stale: boolean;
  scope: string;
}

export interface QuickStartStatus {
  /** The connection type: netsuite_quickstart | netsuite_mcp. */
  integration: string;
  /** The connection key, e.g. netsuite_quickstart or netsuite_mcp:acme. */
  key: string;
  /** The logical integration (tenant), e.g. netsuite:acme. */
  integrationId: string;
  authType: string;
  /** OAuth connections only. */
  oauth: OAuthState | null;
  mappedTools: number;
  configured: boolean;
  state: string;
  stateLabel: string;
  detail: string;
  lastCheckedState: string;
  name: string;
  tenantLabel: string;
  endpoint: string;
  endpointPermitted: boolean;
  endpointRefusal: string;
  token: { set: boolean; expiresOn: string; daysLeft: number | null; warning: string };
  server: { name: string; version: string; protocolVersion: string } | null;
  tools: QuickStartTool[];
  rejected: QuickStartRejected[];
  toolsCurrent: boolean;
  permissionMode: string;
  permissionBasis: string;
  lastAttemptAt: string;
  lastSuccessAt: string;
  lastToolsSyncAt: string;
  enforcement: { agentCallsRouted: boolean; preExecution: string; postExecution: string; note: string };
  coverage: QuickStartCapability[];
  revokeInstructions: string;
  agentEndpoint: string;
  activity: QuickStartActivity | null;
  knownGaps: string[];
}

const n0 = (v: unknown) => num(v) ?? 0;

function normActivity(raw: unknown): QuickStartActivity | null {
  if (!isObj(raw)) return null;
  return {
    windowHours: n0(raw.window_hours),
    allowed: n0(raw.allowed),
    held: n0(raw.held),
    denied: n0(raw.denied),
    executed: n0(raw.executed),
    failed: n0(raw.failed),
    pendingApprovals: n0(raw.pending_approvals),
    activeSuspensions: n0(raw.active_netsuite_suspensions),
    undoAvailable: n0(raw.undo_available),
    recent: (Array.isArray(raw.recent) ? raw.recent : []).filter(isObj).map((r) => ({
      actionId: str(r.action_id),
      agentId: str(r.agent_id),
      tool: str(r.tool),
      decision: str(r.decision),
      ruleId: str(r.rule_id),
      reason: str(r.reason),
      ts: str(r.ts),
      outcome: str(r.outcome),
      undo: str(r.undo),
    })),
  };
}

export function normQuickStart(raw: unknown): QuickStartStatus {
  const o = isObj(raw) ? raw : {};
  const tok = isObj(o.token) ? o.token : {};
  const srv = isObj(o.server) ? o.server : null;
  const enf = isObj(o.enforcement) ? o.enforcement : {};
  const cov = isObj(o.coverage) && Array.isArray(o.coverage.capabilities) ? o.coverage.capabilities : [];
  const oa = isObj(o.oauth) ? o.oauth : null;
  return {
    integration: str(o.integration, 'netsuite_quickstart'),
    key: str(o.key, str(o.integration, 'netsuite_quickstart')),
    integrationId: str(o.integration_id),
    authType: str(o.auth_type),
    oauth: oa
      ? {
          authorized: oa.authorized === true,
          authorizedAt: str(oa.authorized_at),
          authorizedBy: str(oa.authorized_by),
          accessExpiresAt: str(oa.access_expires_at),
          refreshedAt: str(oa.refreshed_at),
          stale: oa.stale === true,
          scope: str(oa.scope),
        }
      : null,
    mappedTools: n0(o.mapped_tools),
    configured: o.configured === true,
    state: str(o.state, 'unknown'),
    stateLabel: str(o.state_label, str(o.state, 'Unknown')),
    detail: str(o.detail),
    lastCheckedState: str(o.last_checked_state),
    name: str(o.name),
    tenantLabel: str(o.tenant_label),
    endpoint: str(o.endpoint),
    endpointPermitted: o.endpoint_permitted === true,
    endpointRefusal: str(o.endpoint_refusal),
    token: { set: tok.set === true, expiresOn: str(tok.expires_on), daysLeft: num(tok.days_left), warning: str(tok.warning) },
    server: srv ? { name: str(srv.name), version: str(srv.version), protocolVersion: str(srv.protocol_version) } : null,
    tools: (Array.isArray(o.tools) ? o.tools : []).filter(isObj).map((t) => ({
      name: str(t.name),
      title: str(t.title),
      description: str(t.description),
      inputSchema: t.input_schema ?? null,
      annotations: t.annotations ?? null,
      documentedAccess: str(t.documented_access, 'undocumented'),
      mapped: t.mapped === true,
    })),
    rejected: (Array.isArray(o.rejected_tools) ? o.rejected_tools : []).filter(isObj).map((r) => ({ name: str(r.name), reason: str(r.reason) })),
    toolsCurrent: o.tools_from_current_settings === true,
    permissionMode: str(o.permission_mode, 'unknown'),
    permissionBasis: str(o.permission_basis),
    lastAttemptAt: str(o.last_attempt_at),
    lastSuccessAt: str(o.last_success_at),
    lastToolsSyncAt: str(o.last_tools_sync_at),
    // Absent means not routed: never assume enforcement.
    enforcement: {
      agentCallsRouted: enf.agent_calls_routed === true,
      preExecution: str(enf.pre_execution, 'unknown'),
      postExecution: str(enf.post_execution, 'unknown'),
      note: str(enf.note),
    },
    coverage: cov.filter(isObj).map((c) => ({ dimension: str(c.dimension), status: str(c.status), gap: str(c.gap), fix: str(c.fix) })),
    revokeInstructions: str(o.revoke_instructions),
    agentEndpoint: str(o.agent_endpoint),
    activity: normActivity(o.activity),
    knownGaps: (Array.isArray(o.known_gaps) ? o.known_gaps : []).filter((x): x is string => typeof x === 'string'),
  };
}

const seg = encodeURIComponent;

/** GET /v1/integrations/{key}/mcp; null on a server without NetSuite MCP. */
export async function getQuickStart(signal?: AbortSignal, key = 'netsuite_quickstart'): Promise<QuickStartStatus | null> {
  try {
    return normQuickStart(await api.get(`/v1/integrations/${seg(key)}/mcp`, signal));
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return null;
    throw e;
  }
}

/** POST /v1/integrations/{key}/oauth/start (security): the NetSuite consent URL to open. */
export async function startOAuth(key: string): Promise<string> {
  const r = await api.post<unknown>(`/v1/integrations/${seg(key)}/oauth/start`, {});
  return isObj(r) ? str(r.authorize_url) : '';
}

export interface QuickStartRefresh {
  ok: boolean;
  error: string;
  status: QuickStartStatus;
}

/** POST /v1/integrations/{key}/mcp/refresh (security): a live check and tool rediscovery. */
export async function refreshQuickStart(key = 'netsuite_quickstart'): Promise<QuickStartRefresh> {
  const r = await api.post<unknown>(`/v1/integrations/${seg(key)}/mcp/refresh`, {});
  const o = isObj(r) ? r : {};
  return { ok: o.ok === true, error: str(o.error), status: normQuickStart(o.status) };
}

/** Chip tone for a connection state. */
export function quickStartTone(state: string): 'green' | 'amber' | 'red' | 'gray' {
  switch (state) {
    case 'connected':
      return 'green';
    case 'connected_limited':
    case 'saved_not_tested':
    case 'authorization_required':
    case 'unavailable':
      return 'amber';
    case 'not_configured':
      return 'gray';
    default:
      return 'red';
  }
}

export const PERMISSION_LABEL: Record<string, string> = {
  read_only: 'Read-only (inferred)',
  read_write: 'Read and write (inferred)',
  unverified: 'Not established',
  unknown: 'Unknown',
};
