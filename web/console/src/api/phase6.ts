// Phase 6 (docs/PHASE6_DESIGN.md): observe mode, pilot success metrics and
// the SaaS copilot connector broker. Normalisers are defensive: the console
// renders whatever the server reports and never invents a value.

import { api, ApiError, seg } from './client';

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, d = '') => (typeof v === 'string' ? v : d);
const num = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const strs = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

// --- observe mode ------------------------------------------------------------

export type EnforcementMode = 'default' | 'observe' | 'enforce';

export interface Enforcement {
  mode: 'observe' | 'enforce';
  observeAgents: string[];
  enforceAgents: string[];
}

export function normEnforcement(raw: unknown): Enforcement {
  const o = isObj(raw) ? raw : {};
  return {
    mode: str(o.mode) === 'observe' ? 'observe' : 'enforce',
    observeAgents: strs(o.observe_agents),
    enforceAgents: strs(o.enforce_agents),
  };
}

/** GET /v1/enforcement; null on a server without observe mode. */
export async function getEnforcement(signal?: AbortSignal): Promise<Enforcement | null> {
  try {
    return normEnforcement(await api.get('/v1/enforcement', signal));
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return null;
    throw e;
  }
}

/** PUT /v1/agents/{id}/enforcement (security). */
export async function setAgentEnforcement(agentId: string, mode: EnforcementMode, reason: string): Promise<{ effective: string }> {
  const r = await api.put<unknown>(`/v1/agents/${seg(agentId)}/enforcement`, { mode, reason });
  const o = isObj(r) ? r : {};
  return { effective: str(o.effective_enforcement, mode) };
}

/** What an observe-mode decision would have been (decision_json.observed). */
export interface Observed {
  decision: string;
  ruleId: string;
  reason: string;
  ladderTo?: string;
}

export function normObserved(raw: unknown): Observed | null {
  if (!isObj(raw) || !str(raw.decision)) return null;
  const lc = isObj(raw.ladder_change) ? str(raw.ladder_change.to) : '';
  return { decision: str(raw.decision), ruleId: str(raw.rule_id), reason: str(raw.reason), ladderTo: lc || undefined };
}

// --- pilot success metrics ------------------------------------------------------

export interface PilotMetric {
  key: string;
  label: string;
  value: number | null;
  unit: string;
  target: string;
  met: boolean | null;
  basis: string;
  n: number;
}

export interface PilotMetrics {
  from: string;
  to: string;
  metrics: PilotMetric[];
  decisions: number;
  observedDecisions: number;
}

const METRICS: [string, string][] = [
  ['risky_handled_without_kill', 'Risky actions handled without a kill'],
  ['red_false_alarm_rate', 'False alarms on red (overturned)'],
  ['red_to_step_down_p50', 'Red action to step-down (median)'],
  ['undo_success', 'Undo succeeded when requested'],
  ['green_overhead_p95', 'Fortik overhead on green (p95)'],
];

export function normPilotMetrics(raw: unknown): PilotMetrics {
  const o = isObj(raw) ? raw : {};
  return {
    from: str(o.from),
    to: str(o.to),
    decisions: num(o.decisions) ?? 0,
    observedDecisions: num(o.observed_decisions) ?? 0,
    metrics: METRICS.map(([key, label]) => {
      const m = isObj(o[key]) ? (o[key] as Obj) : {};
      return {
        key,
        label,
        value: num(m.value),
        unit: str(m.unit),
        target: str(m.target),
        met: typeof m.met === 'boolean' ? m.met : null,
        basis: str(m.basis),
        n: num(m.n) ?? 0,
      };
    }),
  };
}

/** GET /v1/metrics/pilot (default: the last 30 days); null when not available. */
export async function getPilotMetrics(signal?: AbortSignal): Promise<PilotMetrics | null> {
  try {
    return normPilotMetrics(await api.get('/v1/metrics/pilot', signal));
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return null;
    throw e;
  }
}

export function fmtMetric(m: PilotMetric): string {
  if (m.value === null) return 'no data';
  if (m.unit === '%') return `${m.value >= 99.95 || m.value === 0 ? m.value.toFixed(0) : m.value.toFixed(1)}%`;
  if (m.unit === 'ms') return m.value < 10 ? `${m.value.toFixed(1)} ms` : `${Math.round(m.value)} ms`;
  return `${m.value}`;
}

// --- SaaS copilot connectors ---------------------------------------------------------

export interface Connector {
  connectorId: string;
  agentId: string;
  vendor: string;
  upstream: string;
  clientId: string;
  redirectUris: string[];
  scopes: string[];
  status: string;
  createdBy: string;
  createdAt: string;
  activeGrants: number;
  disabledReason: string;
}

export function normConnector(raw: unknown): Connector {
  const o = isObj(raw) ? raw : {};
  return {
    connectorId: str(o.connector_id),
    agentId: str(o.agent_id),
    vendor: str(o.vendor),
    upstream: str(o.upstream),
    clientId: str(o.client_id),
    redirectUris: strs(o.redirect_uris),
    scopes: strs(o.scopes),
    status: str(o.status, 'unknown'),
    createdBy: str(o.created_by),
    createdAt: str(o.created_at),
    activeGrants: num(o.active_grants) ?? 0,
    disabledReason: str(o.disabled_reason),
  };
}

export interface ConnectorList {
  connectors: Connector[];
  callbackUrl: string;
}

/** GET /v1/connectors; null when the broker is not enabled on this server. */
export async function listConnectors(signal?: AbortSignal): Promise<ConnectorList | null> {
  try {
    const r = await api.get<unknown>('/v1/connectors', signal);
    const o = isObj(r) ? r : {};
    return {
      connectors: (Array.isArray(o.connectors) ? o.connectors : []).map(normConnector).filter((c) => c.connectorId !== ''),
      callbackUrl: str(o.callback_url),
    };
  } catch (e) {
    if (e instanceof ApiError && (e.status === 404 || e.status === 405)) return null;
    throw e;
  }
}

export interface ConnectorRequest {
  agentId: string;
  name: string;
  sponsor: string;
  team: string;
  vendor: string;
  upstream: string;
  redirectUris: string[];
  scopes: string[];
  reason: string;
}

export interface RegisteredConnector {
  connector: Connector;
  clientSecret: string;
  authorizeUrl: string;
  tokenUrl: string;
}

/** POST /v1/connectors (security): the client secret is returned once. */
export async function registerConnector(req: ConnectorRequest): Promise<RegisteredConnector> {
  const r = await api.post<unknown>('/v1/connectors', {
    agent_id: req.agentId,
    name: req.name,
    sponsor: req.sponsor,
    team: req.team,
    vendor: req.vendor,
    upstream: req.upstream,
    redirect_uris: req.redirectUris,
    scopes: req.scopes,
    reason: req.reason,
  });
  const o = isObj(r) ? r : {};
  return {
    connector: normConnector(o.connector),
    clientSecret: str(o.client_secret),
    authorizeUrl: str(o.authorize_url),
    tokenUrl: str(o.token_url),
  };
}

/** POST /v1/connectors/{id}/disable (security): every grant is revoked upstream. */
export async function disableConnector(id: string, reason: string): Promise<{ grants: Record<string, string>; errors: string }> {
  const r = await api.post<unknown>(`/v1/connectors/${seg(id)}/disable`, { reason });
  const o = isObj(r) ? r : {};
  const grants: Record<string, string> = {};
  if (isObj(o.grants)) for (const [k, v] of Object.entries(o.grants)) grants[k] = str(v);
  return { grants, errors: str(o.revoke_errors) };
}
