// Logical integrations (integration platform Milestone 1): one card per
// provider tenant, e.g. netsuite:acme, with its transport connections (REST
// API, MCP). GET/POST /v1/app-integrations, GET .../{id}/activity. The
// normaliser never invents a connection: a transport is configured only when
// the server says so, and one transport working says nothing about another.

import { api, ApiError } from './client';
import { normIntegration } from './normalize';
import type { Integration } from './types';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d);
const n0 = (v: unknown) => (typeof v === 'number' && Number.isFinite(v) ? v : 0);
const seg = encodeURIComponent;

export interface TransportOption {
  transport: string; // rest_api | mcp | native
  system: string; // the connection type, '' when unavailable
  title: string;
  available: boolean;
  reason: string;
  verified: string; // live | test | none
}

export interface TransportView extends TransportOption {
  connectionKey: string;
  configured: boolean;
  status: string; // configured | ok | error ('' when not configured)
}

export interface EnvironmentInfo {
  environment: string;
  title: string;
  tenantLabel: string;
  transports: TransportOption[];
}

export interface ProviderInfo {
  provider: string;
  title: string;
  multiTenant: boolean;
  environments: EnvironmentInfo[];
}

export interface AppIntegration {
  integrationId: string;
  provider: string;
  environment: string;
  tenantRef: string;
  displayName: string;
  createdExplicitly: boolean;
  providerTitle: string;
  environmentTitle: string;
  health: string; // not_connected | healthy | degraded | unhealthy | untested
  connections: Integration[];
  transports: TransportView[];
  /** true for a placeholder the console shows before anything is configured (not on the server). */
  virtual?: boolean;
}

function normOption(o: Obj): TransportOption {
  return {
    transport: str(o.transport),
    system: str(o.system),
    title: str(o.title, str(o.transport)),
    available: o.available === true,
    reason: str(o.reason),
    verified: str(o.verified, 'none'),
  };
}

function normProvider(p: Obj): ProviderInfo {
  return {
    provider: str(p.provider),
    title: str(p.title, str(p.provider)),
    multiTenant: p.multi_tenant === true,
    environments: (Array.isArray(p.environments) ? p.environments : []).filter(isObj).map((e) => ({
      environment: str(e.environment),
      title: str(e.title, str(e.environment)),
      tenantLabel: str(e.tenant_label),
      transports: (Array.isArray(e.transports) ? e.transports : []).filter(isObj).map(normOption),
    })),
  };
}

export function normApp(a: unknown): AppIntegration {
  const o = isObj(a) ? a : {};
  return {
    integrationId: str(o.integration_id),
    provider: str(o.provider),
    environment: str(o.environment),
    tenantRef: str(o.tenant_ref),
    displayName: str(o.display_name, str(o.integration_id)),
    createdExplicitly: o.created_explicitly === true,
    providerTitle: str(o.provider_title, str(o.provider)),
    environmentTitle: str(o.environment_title),
    health: str(o.health, 'not_connected'),
    connections: (Array.isArray(o.connections) ? o.connections : []).map(normIntegration).filter((c) => c.key !== ''),
    transports: (Array.isArray(o.transports) ? o.transports : []).filter(isObj).map((t) => ({
      ...normOption(t),
      connectionKey: str(t.connection_key),
      configured: t.configured === true,
      status: t.configured === true ? str(t.status, 'configured') : '',
    })),
  };
}

export interface AppIntegrations {
  integrations: AppIntegration[];
  providers: ProviderInfo[];
}

export function normApps(raw: unknown): AppIntegrations {
  const o = isObj(raw) ? raw : {};
  return {
    integrations: (Array.isArray(o.integrations) ? o.integrations : []).map(normApp).filter((a) => a.integrationId !== ''),
    providers: (Array.isArray(o.providers) ? o.providers : []).filter(isObj).map(normProvider),
  };
}

/** GET /v1/app-integrations; null on a server without logical integrations. */
export async function listApps(signal?: AbortSignal): Promise<AppIntegrations | null> {
  try {
    return normApps(await api.get('/v1/app-integrations', signal));
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return null;
    throw e;
  }
}

export interface CreateAppInput {
  provider: string;
  environment: string;
  name: string;
  tenant_ref: string;
  display_name: string;
}

/** POST /v1/app-integrations (security): a tenant before its connections. */
export async function createApp(input: CreateAppInput): Promise<AppIntegration> {
  return normApp(await api.post('/v1/app-integrations', input));
}

/** DELETE /v1/app-integrations/{id} (security): only without connections. */
export async function deleteApp(id: string): Promise<void> {
  await api.del(`/v1/app-integrations/${seg(id)}`);
}

export interface AppActivity {
  windowHours: number;
  byTransport: Record<string, Record<string, number>>;
  pendingApprovals: number;
  activeSuspensions: number;
  recent: { actionId: string; agentId: string; transport: string; operation: string; decision: string; ruleId: string; reason: string; ts: string }[];
}

export function normActivity(raw: unknown): AppActivity {
  const o = isObj(raw) ? raw : {};
  const by: Record<string, Record<string, number>> = {};
  if (isObj(o.by_transport))
    for (const [t, m] of Object.entries(o.by_transport)) {
      if (!isObj(m)) continue;
      by[t] = {};
      for (const [d, n] of Object.entries(m)) by[t][d] = n0(n);
    }
  return {
    windowHours: n0(o.window_hours) || 24,
    byTransport: by,
    pendingApprovals: n0(o.pending_approvals),
    activeSuspensions: n0(o.active_suspensions),
    recent: (Array.isArray(o.recent) ? o.recent : []).filter(isObj).map((r) => ({
      actionId: str(r.action_id),
      agentId: str(r.agent_id),
      transport: str(r.transport),
      operation: str(r.operation),
      decision: str(r.decision),
      ruleId: str(r.rule_id),
      reason: str(r.reason),
      ts: str(r.ts),
    })),
  };
}

/** GET /v1/app-integrations/{id}/activity. */
export async function getAppActivity(id: string, signal?: AbortSignal): Promise<AppActivity> {
  return normActivity(await api.get(`/v1/app-integrations/${seg(id)}/activity`, signal));
}

/**
 * The connection key of a connection type for a logical integration; the
 * same rule as the server's integrations.ConnectionKey (legacy single keys
 * for netsuite:default and netsuite:quickstart).
 */
/** Connection types whose bare key is the provider's default tenant (integrations.bareKeyTypes). */
const BARE_DEFAULT = ['netsuite', 'salesforce', 'salesforce_mcp', 'servicenow', 'servicenow_mcp', 'sap', 'sap_mcp'];

export function connectionKeyFor(system: string, integrationId: string): string {
  const name = integrationId.slice(integrationId.indexOf(':') + 1);
  if (BARE_DEFAULT.includes(system) && name === 'default') return system;
  if (system === 'netsuite_quickstart' && name === 'quickstart') return 'netsuite_quickstart';
  return `${system}:${name}`;
}

/** A placeholder card for an environment with no integration yet (nothing configured). */
export function virtualApp(p: ProviderInfo, env: EnvironmentInfo, integrationId: string): AppIntegration {
  return {
    integrationId,
    provider: p.provider,
    environment: env.environment,
    tenantRef: '',
    displayName: env.title,
    createdExplicitly: false,
    providerTitle: p.title,
    environmentTitle: env.title,
    health: 'not_connected',
    connections: [],
    transports: env.transports.map((t) => ({ ...t, connectionKey: t.system ? connectionKeyFor(t.system, integrationId) : '', configured: false, status: '' })),
    virtual: true,
  };
}

export const TRANSPORT_LABEL: Record<string, string> = { rest_api: 'REST API', mcp: 'MCP Server', native: 'Native' };

export const HEALTH: Record<string, { label: string; tone: string }> = {
  healthy: { label: 'Healthy', tone: 'green' },
  degraded: { label: 'Degraded', tone: 'amber' },
  unhealthy: { label: 'Unhealthy', tone: 'red' },
  untested: { label: 'Not tested', tone: 'amber' },
  not_connected: { label: 'Not connected', tone: 'gray' },
};

export interface RestCheck {
  key: string;
  configured: boolean;
  state: string;
  stateLabel: string;
  detail: string;
  lastCheckedState: string;
  endpoint: string;
  endpointPermitted: boolean;
  endpointRefusal: string;
  auth: string;
  identity: Record<string, unknown>;
  capabilities: Record<string, unknown>;
  capabilitiesCurrent: boolean;
  lastSuccessAt: string;
  agentEndpoint: string;
  knownGaps: string[];
}

export function normRestCheck(raw: unknown): RestCheck {
  const o = isObj(raw) ? raw : {};
  return {
    key: str(o.key),
    configured: o.configured === true,
    state: str(o.state, 'unknown'),
    stateLabel: str(o.state_label, str(o.state, 'Unknown')),
    detail: str(o.detail),
    lastCheckedState: str(o.last_checked_state),
    endpoint: str(o.endpoint),
    endpointPermitted: o.endpoint_permitted === true,
    endpointRefusal: str(o.endpoint_refusal),
    auth: str(o.auth),
    identity: isObj(o.identity) ? o.identity : {},
    capabilities: isObj(o.capabilities) ? o.capabilities : {},
    capabilitiesCurrent: o.capabilities_from_current_settings === true,
    lastSuccessAt: str(o.last_success_at),
    agentEndpoint: str(o.agent_endpoint),
    knownGaps: (Array.isArray(o.known_gaps) ? o.known_gaps : []).filter((x): x is string => typeof x === 'string'),
  };
}

/** GET /v1/integrations/{key}/check: a Salesforce, ServiceNow or SAP REST connection's last live check. */
export async function getRestCheck(key: string, signal?: AbortSignal): Promise<RestCheck> {
  return normRestCheck(await api.get(`/v1/integrations/${seg(key)}/check`, signal));
}

/** Providers shown as one card per tenant with a connection method dropdown. */
export const UNIFIED_PROVIDERS = ['netsuite', 'salesforce', 'servicenow', 'sap'];

/**
 * The tenants to show for a provider: the server's, or one placeholder when
 * it has none. NetSuite's placeholder offers SuiteTalk REST (a full account,
 * netsuite:default) and the QuickStart MCP server (netsuite:quickstart):
 * saving either creates that tenant.
 */
export function tenantsOf(apps: AppIntegrations, provider: string): AppIntegration[] {
  const real = apps.integrations.filter((a) => a.provider === provider).sort((a, b) => a.integrationId.localeCompare(b.integrationId));
  if (real.length > 0) return real;
  const p = apps.providers.find((x) => x.provider === provider);
  if (!p || p.environments.length === 0) return [];
  if (provider === 'netsuite') {
    const full = p.environments.find((e) => e.environment === 'full');
    const qs = p.environments.find((e) => e.environment === 'quickstart');
    const rest = full?.transports.find((t) => t.transport === 'rest_api');
    const mcp = qs?.transports.find((t) => t.transport === 'mcp');
    if (rest && mcp) {
      const v = virtualApp(p, full!, 'netsuite:default');
      v.displayName = 'NetSuite';
      v.environmentTitle = '';
      v.transports = [
        { ...rest, connectionKey: connectionKeyFor(rest.system, 'netsuite:default'), configured: false, status: '' },
        { ...mcp, connectionKey: connectionKeyFor(mcp.system, 'netsuite:quickstart'), configured: false, status: '' },
      ];
      return [v];
    }
  }
  const v = virtualApp(p, p.environments[0]!, `${provider}:default`);
  v.displayName = p.title;
  return [v];
}
