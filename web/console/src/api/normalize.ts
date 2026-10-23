// Normalisers from raw API JSON into the console's types (api/types.ts), plus
// client-side aggregation used when the server does not (yet) compute a
// figure itself. Unknown or malformed values never throw: they become safe
// defaults ("—" in the UI), and unknown levels/classes are treated as the
// most restrictive/most severe so the UI never understates risk.

import type {
  AgentMemoryView,
  ContainmentOp,
  ContainmentStep,
  MemoryAccess,
  MemoryFlagResult,
  MemoryItem,
  MemoryMode,
  MemoryRestoreResult,
  MemorySnapshot,
  OpStatus,
  StepStatus,
  UndoEntry,
  UndoRunResult,
  Alert,
  AgentType,
  ApprovalResult,
  BlockedDelegation,
  DelegationView,
  Hop,
  Instance,
  InstancesView,
  Override,
  Severity,
  ActionClass,
  ActionRow,
  Agent,
  AgentDetail,
  AgentStats,
  AuthConfig,
  DiaryEvent,
  HeldAction,
  Integration,
  IntegrationSchema,
  IntegrationStatus,
  Level,
  Me,
  ProfileView,
  SchemaField,
  Summary,
  TestResult,
  AccessSystem,
  Baseline,
  BaselinePoint,
  BulkDenyOutcome,
  CommMap,
  EdgeClass,
  MapCluster,
  MapEdge,
  MapNode,
  MapNodeKind,
  PathHop,
  QueueItem,
  ShadowFinding,
  SpawnEdge,
  Swarm,
  SwarmBreaker,
  SwarmDetail,
  SwarmMember,
  SwarmReleaseResult,
  SwarmSignal,
  Vote,
} from './types';
import { ACCESS_SYSTEMS } from './types';

type Obj = Record<string, unknown>;

export const LEVELS: Level[] = ['FULL', 'SUPERVISED', 'READ_ONLY', 'ISOLATED', 'QUARANTINED', 'KILLED'];
const CLASSES: ActionClass[] = ['green', 'blue', 'yellow', 'red'];

export const isObj = (v: unknown): v is Obj => typeof v === 'object' && v !== null && !Array.isArray(v);
const str = (v: unknown, d = ''): string => (typeof v === 'string' ? v : typeof v === 'number' ? String(v) : d);
const num = (v: unknown, d = 0): number => (typeof v === 'number' && Number.isFinite(v) ? v : d);
const optNum = (v: unknown): number | undefined => (typeof v === 'number' && Number.isFinite(v) ? v : undefined);
const bool = (v: unknown): boolean => v === true;
const optStr = (v: unknown): string | undefined => (typeof v === 'string' && v !== '' ? v : undefined);

/** First defined value among keys. */
function pick(o: Obj, ...keys: string[]): unknown {
  for (const k of keys) {
    if (o[k] !== undefined && o[k] !== null) return o[k];
  }
  return undefined;
}

/** Parses a level given as a name ("READ_ONLY", "read-only") or index (0..5). Unknown → KILLED (fail closed). */
export function parseLevel(v: unknown): Level {
  if (typeof v === 'number' && Number.isInteger(v) && v >= 0 && v < LEVELS.length) return LEVELS[v] as Level;
  if (typeof v === 'string') {
    const s = v.trim().toUpperCase().replace(/[- ]/g, '_');
    if ((LEVELS as string[]).includes(s)) return s as Level;
    if (/^\d$/.test(s)) return parseLevel(Number(s));
  }
  return 'KILLED';
}

export function levelIndex(l: Level): number {
  return LEVELS.indexOf(l);
}

/** Parses a class. Unknown non-empty values → red (never understate risk). */
export function parseClass(v: unknown): ActionClass {
  const s = str(v).toLowerCase();
  if ((CLASSES as string[]).includes(s)) return s as ActionClass;
  if (s === 'amber') return 'yellow';
  return 'red';
}

export function parseOptClass(v: unknown): ActionClass | null {
  if (v === null || v === undefined || v === '') return null;
  return parseClass(v);
}

const CLASS_RANK: Record<ActionClass, number> = { green: 0, blue: 1, yellow: 2, red: 3 };

export function worseClass(a: ActionClass | null | undefined, b: ActionClass | null | undefined): ActionClass | null {
  if (!a) return b ?? null;
  if (!b) return a;
  return CLASS_RANK[b] > CLASS_RANK[a] ? b : a;
}

export function normMe(raw: unknown): Me {
  const o = isObj(raw) ? raw : {};
  return {
    kind: str(o.kind, 'user'),
    email: str(o.email),
    name: str(o.name),
    roles: Array.isArray(o.roles) ? o.roles.filter((r): r is string => typeof r === 'string') : [],
    authMethod: str(o.auth_method),
    csrf: str(o.csrf),
    expiresAt: optStr(o.expires_at),
    devLoginEnabled: bool(o.dev_login_enabled),
    oidcEnabled: bool(o.oidc_enabled),
  };
}

export function normAuthConfig(raw: unknown): AuthConfig {
  const o = isObj(raw) ? raw : {};
  const users = Array.isArray(o.dev_users) ? o.dev_users.filter(isObj) : [];
  return {
    oidcEnabled: bool(o.oidc_enabled),
    devLoginEnabled: bool(o.dev_login_enabled),
    devUsers: users.map((u) => ({
      email: str(u.email),
      name: optStr(u.name),
      roles: Array.isArray(u.roles) ? u.roles.filter((r): r is string => typeof r === 'string') : [],
    })),
  };
}

export function normAgent(raw: unknown): Agent {
  let o = isObj(raw) ? raw : {};
  if (isObj(o.agent)) o = { ...o, ...o.agent };
  const systems = pick(o, 'systems_24h', 'systems');
  return {
    agentId: str(o.agent_id),
    name: str(o.name),
    type: str(o.type),
    platform: str(o.platform),
    sponsor: str(o.sponsor),
    businessUnit: str(o.business_unit),
    workspaceUser: str(o.workspace_user),
    copyCap: optNum(o.copy_cap) ?? null,
    level: parseLevel(pick(o, 'level_name', 'level')),
    levelChangedAt: optStr(o.level_changed_at),
    discovered: bool(o.discovered),
    actionsToday: optNum(o.actions_today),
    worstClass24h: o.worst_class_24h !== undefined ? parseOptClass(o.worst_class_24h) : o.risk !== undefined ? parseOptClass(o.risk) : undefined,
    systems24h: Array.isArray(systems) ? systems.filter((s): s is string => typeof s === 'string') : undefined,
    heldPending: optNum(o.held_pending),
    status: optStr(o.status),
    ...suspensionOf(o),
    // Reported only by Phase 4 servers; a present but unknown value is the strictest.
    memoryAccess: o.memory_access === undefined || o.memory_access === null ? undefined : parseMemoryMode(o.memory_access),
    memoryAccessChangedBy: optStr(o.memory_access_changed_by),
  };
}

/** Phase 4 suspension fields; absent on servers that do not report them (suspended stays undefined = unknown). */
function suspensionOf(o: Obj): Pick<Agent, 'suspended' | 'suspendedAt' | 'suspendedBy' | 'suspendedReason'> {
  const at = optStr(o.suspended_at);
  let suspended: boolean | undefined;
  if (typeof o.suspended === 'boolean') suspended = o.suspended;
  else if (at) suspended = true;
  else if ('suspended_at' in o) suspended = false; // reported, and null
  return { suspended, suspendedAt: at, suspendedBy: optStr(o.suspended_by), suspendedReason: optStr(o.suspended_reason) };
}

/** Normalises GET /v1/agents/{id}. */
export function normAgentDetail(raw: unknown): AgentDetail {
  const o = isObj(raw) ? raw : {};
  const counts24h = emptyClasses();
  if (isObj(o.counts_24h)) for (const [k, v] of Object.entries(o.counts_24h)) counts24h[parseClass(k)] += num(v);
  const profileVersions: Partial<Record<AccessSystem, number>> = {};
  if (isObj(o.access_profiles))
    for (const [k, v] of Object.entries(o.access_profiles)) {
      if ((ACCESS_SYSTEMS as string[]).includes(k) && isObj(v)) profileVersions[k as AccessSystem] = num(v.version);
    }
  const integrations: Record<string, string> = {};
  if (isObj(o.integrations)) for (const [k, v] of Object.entries(o.integrations)) integrations[k] = str(v);
  const agent = normAgent(raw);
  const held = (Array.isArray(o.held) ? o.held : []).map(normHeld).map((h) => ({ ...h, agentId: h.agentId || agent.agentId }));
  return {
    agent,
    counts24h,
    held,
    profileVersions,
    integrations,
    tokenIssued: typeof o.token_issued === 'boolean' ? o.token_issued : null,
  };
}

export function normAgents(raw: unknown): Agent[] {
  const o = isObj(raw) ? raw : {};
  const list = Array.isArray(o.agents) ? o.agents : Array.isArray(raw) ? raw : [];
  return list.map(normAgent).filter((a) => a.agentId !== '');
}

export function normSummary(raw: unknown): Summary {
  let o = isObj(raw) ? raw : {};
  if (isObj(o.kpis)) o = { ...o, ...o.kpis };
  const hourly = pick(o, 'actions_hourly', 'hourly');
  const bc = pick(o, 'by_class_today');
  let byClassToday: Record<ActionClass, number> | undefined;
  if (isObj(bc)) {
    byClassToday = emptyClasses();
    for (const [k, v] of Object.entries(bc)) byClassToday[parseClass(k)] += num(v);
  }
  return {
    totalAgents: num(pick(o, 'total_agents', 'agents_total', 'agents')),
    actionsToday: num(pick(o, 'actions_today')),
    heldPending: num(pick(o, 'held_pending', 'pending_held', 'held')),
    redToday: num(pick(o, 'red_today', 'dangerous_today')),
    agentsNotFull: num(pick(o, 'agents_not_full', 'not_full')),
    actionsHourly: Array.isArray(hourly) ? hourly.map((h) => (isObj(h) ? num(h.count) : num(h))) : undefined,
    byClassToday,
  };
}

export function normAction(raw: unknown): ActionRow {
  const o = isObj(raw) ? raw : {};
  const undo = isObj(o.undo) ? { kind: str(o.undo.kind), status: str(o.undo.status) } : null;
  return {
    actionId: str(o.action_id),
    agentId: str(o.agent_id),
    system: str(o.system),
    verb: str(o.verb, 'UNKNOWN').toUpperCase(),
    class: parseClass(o.class),
    decision: str(o.decision),
    ruleId: str(o.rule_id),
    reason: str(o.reason),
    reversible: bool(o.reversible),
    source: str(o.source),
    ts: str(o.ts),
    failClosed: bool(o.fail_closed),
    held: isObj(o.held) || o.held === true,
    undo,
  };
}

export function normActions(raw: unknown): ActionRow[] {
  const o = isObj(raw) ? raw : {};
  return (Array.isArray(o.actions) ? o.actions : []).map(normAction);
}

export function normHeld(raw: unknown): HeldAction {
  const o = isObj(raw) ? raw : {};
  return {
    actionId: str(o.action_id),
    agentId: str(o.agent_id),
    ruleId: str(o.rule_id),
    reason: str(o.reason),
    class: parseClass(o.class),
    decision: str(o.decision),
    system: str(o.system),
    verb: str(o.verb).toUpperCase(),
    safeForm: formatSafeForm(o.safe_form),
    outcome: str(o.outcome),
    createdAt: str(o.created_at),
    expiresAt: optStr(o.expires_at),
    levelAtDecision: optStr(o.level_at_decision),
    undoAvailable: bool(o.undo_available),
    approverRole: optStr(o.approver_role),
    approvalsRequired: optNum(o.approvals_required),
  };
}

/** Renders a held action's safe form ({kind, sql} or any JSON) as text. */
export function formatSafeForm(v: unknown): string {
  if (v === null || v === undefined) return '';
  if (typeof v === 'string') return v;
  if (isObj(v)) {
    const kind = str(v.kind);
    const body = str(v.sql) || str(v.description);
    if (body) return kind ? `${kind}: ${body}` : body;
  }
  return JSON.stringify(v);
}

export function normHeldList(raw: unknown): HeldAction[] {
  const o = isObj(raw) ? raw : {};
  return (Array.isArray(o.held) ? o.held : []).map(normHeld);
}

function emptyClasses(): Record<ActionClass, number> {
  return { green: 0, blue: 0, yellow: 0, red: 0 };
}

/** Normalises GET /v1/agents/{id}/stats. Returns null if the body has no usable figures. */
export function normStats(raw: unknown, hours: number): AgentStats | null {
  let o = isObj(raw) ? raw : null;
  if (!o) return null;
  if (isObj(o.stats)) o = o.stats;
  const byClassRaw = pick(o, 'by_class', 'classes', 'counts');
  const byVerbRaw = pick(o, 'by_verb', 'verbs', 'action_mix');
  const hourlyRaw = pick(o, 'hourly', 'buckets');
  if (!isObj(byClassRaw) && !isObj(byVerbRaw) && !Array.isArray(hourlyRaw)) return null;
  const byClass = emptyClasses();
  if (isObj(byClassRaw)) for (const [k, v] of Object.entries(byClassRaw)) byClass[parseClass(k)] += num(v);
  const byVerb: Record<string, number> = {};
  if (isObj(byVerbRaw)) for (const [k, v] of Object.entries(byVerbRaw)) byVerb[k.toUpperCase()] = num(v);
  const h = num(o.hours, hours) || hours;
  let hourly: number[] = new Array<number>(h).fill(0);
  let hourlyWorst: (ActionClass | null)[] = new Array<ActionClass | null>(h).fill(null);
  let hourStarts: string[] = [];
  if (Array.isArray(hourlyRaw)) {
    const fit = <T,>(vals: T[], pad: T): T[] =>
      vals.length >= h ? vals.slice(vals.length - h) : [...new Array<T>(h - vals.length).fill(pad), ...vals];
    hourly = fit(
      hourlyRaw.map((x) => (isObj(x) ? num(pick(x, 'count', 'total')) : num(x))),
      0,
    );
    hourlyWorst = fit(
      hourlyRaw.map((x) => (isObj(x) ? parseOptClass(x.worst_class) : null)),
      null,
    );
    const starts = hourlyRaw.map((x) => (isObj(x) ? str(x.hour) : ''));
    hourStarts = starts.length >= h && starts.every((x) => x !== '') ? starts.slice(starts.length - h) : [];
  }
  const total = num(o.total, Object.values(byClass).reduce((a, b) => a + b, 0));
  return { hours: h, byClass, byVerb, hourly, hourlyWorst, hourStarts, total };
}

/** Aggregates stats for one agent from its recent actions (fallback when /stats is unavailable). */
export function statsFromActions(actions: ActionRow[], hours: number, now: number = Date.now()): AgentStats {
  const byClass = emptyClasses();
  const byVerb: Record<string, number> = {};
  const hourly = new Array<number>(hours).fill(0);
  const hourlyWorst = new Array<ActionClass | null>(hours).fill(null);
  const start = now - hours * 3600_000;
  let total = 0;
  for (const a of actions) {
    const t = Date.parse(a.ts);
    if (!Number.isFinite(t) || t < start || t > now + 60_000) continue;
    total++;
    byClass[a.class]++;
    byVerb[a.verb] = (byVerb[a.verb] ?? 0) + 1;
    const idx = Math.min(hours - 1, Math.max(0, Math.floor((t - start) / 3600_000)));
    hourly[idx] = (hourly[idx] ?? 0) + 1;
    hourlyWorst[idx] = worseClass(hourlyWorst[idx], a.class);
  }
  const hourStarts = hourly.map((_, i) => new Date(start + i * 3600_000).toISOString());
  return { hours, byClass, byVerb, hourly, hourlyWorst, hourStarts, total };
}

function startOfToday(now: number): number {
  const d = new Date(now);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

/** Per-agent activity derived from recent actions (fallback when the agent list lacks it). */
export function activityFromActions(
  actions: ActionRow[],
  now: number = Date.now(),
): Map<string, { actionsToday: number; worst24h: ActionClass | null; systems: string[] }> {
  const today = startOfToday(now);
  const dayAgo = now - 24 * 3600_000;
  const out = new Map<string, { actionsToday: number; worst24h: ActionClass | null; systems: Set<string> }>();
  for (const a of actions) {
    const t = Date.parse(a.ts);
    if (!Number.isFinite(t)) continue;
    let e = out.get(a.agentId);
    if (!e) {
      e = { actionsToday: 0, worst24h: null, systems: new Set() };
      out.set(a.agentId, e);
    }
    if (t >= today) e.actionsToday++;
    if (t >= dayAgo) {
      e.worst24h = worseClass(e.worst24h, a.class);
      if (a.system) e.systems.add(a.system);
    }
  }
  const res = new Map<string, { actionsToday: number; worst24h: ActionClass | null; systems: string[] }>();
  for (const [k, v] of out) res.set(k, { actionsToday: v.actionsToday, worst24h: v.worst24h, systems: [...v.systems].sort() });
  return res;
}

/** KPI summary derived from the agent list, recent actions and pending holds (fallback). */
export function summaryFromData(agents: Agent[], actions: ActionRow[], heldPending: number, now: number = Date.now()): Summary {
  const today = startOfToday(now);
  let actionsToday = 0;
  let redToday = 0;
  for (const a of actions) {
    const t = Date.parse(a.ts);
    if (!Number.isFinite(t) || t < today) continue;
    actionsToday++;
    if (a.class === 'red') redToday++;
  }
  return {
    totalAgents: agents.length,
    actionsToday,
    heldPending,
    redToday,
    agentsNotFull: agents.filter((a) => a.level !== 'FULL').length,
  };
}

/** Status label for an agent when the server does not provide one. */
export function deriveStatus(a: Agent, pendingHeld: number): string {
  if (a.status) return a.status;
  if (a.level === 'KILLED') return 'killed';
  if (a.level === 'QUARANTINED') return 'quarantined';
  if (a.suspended) return 'suspended';
  if (pendingHeld > 0) return 'needs review';
  if (a.level !== 'FULL') return 'restricted';
  if ((a.actionsToday ?? 0) > 0) return 'active';
  return 'idle';
}

export function normProfiles(raw: unknown): ProfileView[] {
  const o = isObj(raw) ? raw : {};
  const list = Array.isArray(o.profiles) ? o.profiles : Array.isArray(o.versions) ? o.versions : [];
  return list.filter(isObj).flatMap((p) => {
    const sys = str(p.system) as AccessSystem;
    if (!ACCESS_SYSTEMS.includes(sys)) return [];
    return [
      {
        system: sys,
        version: num(p.version),
        profile: p.profile ?? null,
        changedBy: optStr(p.changed_by),
        changedAt: optStr(p.changed_at),
        reason: optStr(p.reason),
      },
    ];
  });
}

const FIELD_TYPES = ['text', 'textarea', 'password', 'list', 'select', 'number', 'bool'];

export function normSchemas(raw: unknown): IntegrationSchema[] {
  const o = isObj(raw) ? raw : {};
  const list = Array.isArray(o.schemas) ? o.schemas : Array.isArray(raw) ? raw : [];
  return list.filter(isObj).map((s) => ({
    system: str(s.system),
    title: str(s.title, str(s.system)),
    multi: bool(s.multi),
    fields: (Array.isArray(s.fields) ? s.fields : []).filter(isObj).map(
      (f): SchemaField => ({
        key: str(f.key),
        label: str(f.label, str(f.key)),
        // Unknown field types render as plain text; secret fields always as password-style write-only inputs.
        type: (FIELD_TYPES.includes(str(f.type)) ? str(f.type) : 'text') as SchemaField['type'],
        secret: bool(f.secret),
        required: bool(f.required),
        help: optStr(f.help),
        options: Array.isArray(f.options) ? f.options.filter((x): x is string => typeof x === 'string') : undefined,
        default: f.default,
      }),
    ),
  }));
}

const STATUSES: IntegrationStatus[] = ['unconfigured', 'configured', 'ok', 'error'];

export function normIntegration(raw: unknown): Integration {
  const o = isObj(raw) ? raw : {};
  const secrets: Record<string, { set: boolean }> = {};
  if (isObj(o.secrets)) for (const [k, v] of Object.entries(o.secrets)) secrets[k] = { set: isObj(v) && v.set === true };
  const secretFields = Array.isArray(o.secret_fields) ? o.secret_fields.filter((x): x is string => typeof x === 'string') : [];
  for (const f of secretFields) if (!secrets[f]) secrets[f] = { set: true };
  const status = str(o.status);
  return {
    key: str(o.key),
    system: str(o.system),
    config: isObj(o.config) ? o.config : {},
    secretFields,
    secrets,
    status: (STATUSES as string[]).includes(status) ? (status as IntegrationStatus) : 'error',
    lastTestedAt: optStr(o.last_tested_at),
    lastError: optStr(o.last_error),
    updatedBy: optStr(o.updated_by),
    updatedAt: optStr(o.updated_at),
    testAvailable: o.test_available === undefined ? true : bool(o.test_available),
  };
}

export function normIntegrations(raw: unknown): Integration[] {
  const o = isObj(raw) ? raw : {};
  return (Array.isArray(o.integrations) ? o.integrations : []).map(normIntegration).filter((i) => i.key !== '');
}

export function normTestResult(raw: unknown): TestResult {
  const o = isObj(raw) ? raw : {};
  return {
    ok: bool(o.ok),
    error: optStr(o.error),
    durationMs: optNum(o.duration_ms),
    integration: isObj(o.integration) ? normIntegration(o.integration) : undefined,
  };
}

/** Parses one SSE "diary" event payload; returns null for malformed data. */
export function parseDiaryEvent(data: string): DiaryEvent | null {
  let o: unknown;
  try {
    o = JSON.parse(data);
  } catch {
    return null;
  }
  if (!isObj(o) || typeof o.event_type !== 'string') return null;
  return {
    seq: num(o.seq),
    ts: str(o.ts),
    agentId: optStr(o.agent_id),
    eventType: o.event_type,
    data: isObj(o.data) ? o.data : {},
  };
}

// --- Phase 3 ----------------------------------------------------------------------

const listOf = (raw: unknown, ...keys: string[]): unknown[] => {
  if (Array.isArray(raw)) return raw;
  const o = isObj(raw) ? raw : {};
  for (const k of keys) if (Array.isArray(o[k])) return o[k] as unknown[];
  return [];
};
const strArr = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []);

export function normOverride(raw: unknown): Override {
  const o = isObj(raw) ? raw : {};
  // revoke_result is {system: {agent_id: summary}}; flattened to agent -> summary.
  let revokeResult: Record<string, string> | undefined;
  if (isObj(o.revoke_result)) {
    revokeResult = {};
    for (const [k, v] of Object.entries(o.revoke_result)) {
      if (isObj(v)) for (const [agent, desc] of Object.entries(v)) revokeResult[agent] = str(desc, 'unknown');
      else revokeResult[k] = str(v, 'unknown');
    }
  }
  return {
    overrideId: str(o.override_id),
    scope: str(o.scope, 'agent'),
    scopeId: str(o.scope_id),
    system: str(o.system),
    // Unknown modes are shown as the strictest.
    mode: o.mode === 'read_only' ? 'read_only' : 'suspended',
    startsAt: str(o.starts_at),
    expiresAt: optStr(o.expires_at),
    reason: str(o.reason),
    createdBy: str(o.created_by),
    status: str(o.status, 'active'),
    restoredAt: optStr(o.restored_at),
    blockedReason: optStr(o.blocked_reason),
    revokeResult,
  };
}

export function normOverrides(raw: unknown): Override[] {
  return listOf(raw, 'overrides').map(normOverride).filter((x) => x.overrideId !== '');
}

/** Overrides still enforced: active, and blocked (a failed restore keeps it in force). */
export function isEnforced(o: Override): boolean {
  return o.status === 'active' || o.status === 'blocked';
}

export function normInstance(raw: unknown): Instance {
  const o = isObj(raw) ? raw : {};
  return {
    instanceId: str(o.instance_id),
    agentId: str(o.agent_id),
    host: str(o.host),
    parentInstanceId: optStr(o.parent_instance_id),
    startedAt: str(o.started_at),
    lastHeartbeat: str(o.last_heartbeat),
    status: str(o.status, 'stale'),
    reason: optStr(o.reason),
    newHost: bool(o.new_host),
  };
}

export function normInstancesView(raw: unknown): InstancesView {
  const o = isObj(raw) ? raw : {};
  const instances = listOf(raw, 'instances').map(normInstance).filter((i) => i.instanceId !== '');
  const live = optNum(pick(o, 'live', 'agent_live')) ?? instances.filter((i) => i.status === 'live').length;
  const cap = optNum(o.copy_cap);
  return { instances, live, copyCap: cap ?? null };
}

export function normAgentType(raw: unknown): AgentType {
  const o = isObj(raw) ? raw : {};
  return {
    type: str(o.type),
    expectedMaxInstances: num(o.expected_max_instances),
    maxAgents: num(o.max_agents),
    spawnRatePerMin: num(o.spawn_rate_per_min),
    actionRatePerMin: num(o.action_rate_per_min),
  };
}

export function normAgentTypes(raw: unknown): AgentType[] {
  return listOf(raw, 'agent_types', 'types').map(normAgentType).filter((t) => t.type !== '');
}

const SEVERITIES: Severity[] = ['info', 'warning', 'high', 'critical'];
export const SEVERITY_RANK: Record<Severity, number> = { info: 0, warning: 1, high: 2, critical: 3 };

/** Unknown severities are treated as critical so the UI never understates risk. */
export function parseSeverity(v: unknown): Severity {
  return typeof v === 'string' && (SEVERITIES as string[]).includes(v) ? (v as Severity) : 'critical';
}

export function normAlert(raw: unknown): Alert {
  const o = isObj(raw) ? raw : {};
  const st = str(o.status);
  return {
    alertId: str(o.alert_id),
    kind: str(o.kind),
    severity: parseSeverity(o.severity),
    agentId: optStr(o.agent_id),
    agentType: optStr(o.agent_type),
    actionId: optStr(o.action_id),
    summary: str(o.summary),
    count: num(o.count, 1),
    status: st === 'acknowledged' || st === 'resolved' ? st : 'open',
    createdAt: str(o.created_at),
    updatedAt: str(o.updated_at),
    ackedBy: optStr(o.acked_by),
  };
}

export function normAlerts(raw: unknown): Alert[] {
  return listOf(raw, 'alerts').map(normAlert).filter((a) => a.alertId !== '');
}

export function normApprovalResult(raw: unknown): ApprovalResult {
  const o = isObj(raw) ? raw : {};
  const g = isObj(o.grant) ? o.grant : {};
  const sf = isObj(o.safe_form) ? o.safe_form : {};
  return {
    actionId: str(o.action_id),
    outcome: str(o.outcome),
    approvals: num(o.approvals),
    approvalsRequired: num(o.approvals_required, 1),
    grantExpiresAt: optStr(g.expires_at),
    safeFormTrashTable: optStr(sf.trash_table),
  };
}

/** A GET /v1/diary entry (body.data) as a DiaryEvent. */
export function normDiaryEntry(raw: unknown): DiaryEvent | null {
  const o = isObj(raw) ? raw : {};
  if (typeof o.event_type !== 'string') return null;
  let body: unknown = o.body;
  if (!isObj(body) && typeof o.body_json === 'string') {
    try {
      body = JSON.parse(o.body_json);
    } catch {
      body = {};
    }
  }
  const data = isObj(body) && isObj(body.data) ? body.data : isObj(o.data) ? o.data : {};
  return { seq: num(o.seq), ts: str(o.ts), agentId: optStr(o.agent_id), eventType: o.event_type, data };
}

/** internal/delegation.Hop from GET /v1/agents/{id}/delegations. */
export function normHop(raw: unknown): Hop {
  const o = isObj(raw) ? raw : {};
  const chain = strArr(o.chain);
  return {
    delegationId: str(o.delegation_id),
    root: str(pick(o, 'root_agent', 'root')) || chain[0] || '',
    from: str(pick(o, 'from_agent', 'from')),
    to: str(pick(o, 'to_agent', 'to')),
    chain,
    depth: num(o.depth, Math.max(0, chain.length - 1)),
    channel: str(o.channel),
    status: str(o.status, 'open'),
    openedAt: str(pick(o, 'created_at', 'opened_at')),
    expiresAt: optStr(o.expires_at),
    closedAt: optStr(o.closed_at),
    taskId: optStr(o.task_id),
    actionId: optStr(o.action_id),
  };
}

/** Display chain: upstream agents (root first) followed by the executor, once. */
function withExecutor(upstream: string[], executor: string): string[] {
  if (!executor || upstream[upstream.length - 1] === executor) return upstream;
  return [...upstream, executor];
}

const RULE_BYPASS = 'POL-601';

/** One entry of the endpoint's "blocked" list: an actions row refused by POL-601..604. */
export function normBlocked(raw: unknown): BlockedDelegation {
  const o = isObj(raw) ? raw : {};
  const ctx = isObj(o.delegation) ? o.delegation : {};
  const upstream = (Array.isArray(ctx.chain) ? ctx.chain : [])
    .map((h) => (isObj(h) ? str(h.agent_id) : typeof h === 'string' ? h : ''))
    .filter((x) => x !== '');
  const executor = str(o.executor);
  const ruleId = str(o.rule_id);
  return {
    seq: 0,
    ts: str(o.ts),
    actionId: str(o.action_id),
    ruleId,
    reason: str(o.reason),
    executor,
    root: str(ctx.root) || upstream[0] || '',
    chain: withExecutor(upstream, executor),
    system: str(o.system),
    verb: str(o.verb).toUpperCase(),
    bypass: ruleId === RULE_BYPASS,
    steppedDown: [],
    originLevel: '',
  };
}

/** A delegation.bypass_blocked Diary event, or null when the agent is not involved in it. */
export function blockedFromDiary(agentId: string, e: DiaryEvent): BlockedDelegation | null {
  if (e.eventType !== 'delegation.bypass_blocked') return null;
  const d = e.data;
  const executor = str(d.executor);
  const chain = strArr(d.chain);
  const involved = [executor, str(d.root), ...chain, ...strArr(d.roots), e.agentId ?? ''];
  if (!involved.includes(agentId)) return null;
  // stepped_down is the list of originating agents actually stepped down
  // (older events may carry a boolean, meaning the root).
  const stepped = Array.isArray(d.stepped_down) ? strArr(d.stepped_down) : d.stepped_down === true && str(d.root) ? [str(d.root)] : [];
  return {
    seq: e.seq,
    ts: e.ts,
    actionId: str(d.action_id),
    ruleId: str(d.rule_id, RULE_BYPASS),
    reason: str(d.reason),
    executor,
    root: str(d.root) || chain[0] || '',
    chain: withExecutor(chain, executor),
    system: str(d.system),
    verb: str(d.verb).toUpperCase(),
    bypass: true,
    steppedDown: stepped,
    originLevel: str(d.origin_level),
  };
}

const newestHop = (a: Hop, b: Hop) => b.openedAt.localeCompare(a.openedAt);
const newestBlocked = (a: BlockedDelegation, b: BlockedDelegation) => b.ts.localeCompare(a.ts) || b.seq - a.seq;

/** Outbound: the agent delegated (self-delegation, a Claude Code Task subagent, counts as outbound). */
function splitHops(agentId: string, hops: Hop[]): { inbound: Hop[]; outbound: Hop[] } {
  return {
    outbound: hops.filter((h) => h.from === agentId).sort(newestHop),
    inbound: hops.filter((h) => h.to === agentId && h.from !== agentId).sort(newestHop),
  };
}

/** Merges Diary bypass details (who was stepped down) into blocked entries, adding Diary-only ones. */
function mergeBlocked(base: BlockedDelegation[], fromDiary: BlockedDelegation[]): BlockedDelegation[] {
  const byAction = new Map<string, BlockedDelegation>();
  const out: BlockedDelegation[] = [];
  for (const b of base) {
    const copy = { ...b };
    out.push(copy);
    if (copy.actionId) byAction.set(copy.actionId, copy);
  }
  for (const d of fromDiary) {
    const known = d.actionId ? byAction.get(d.actionId) : undefined;
    if (known) {
      known.seq = d.seq;
      known.bypass = true;
      known.steppedDown = d.steppedDown;
      known.originLevel = d.originLevel;
      if (!known.root) known.root = d.root;
      if (known.chain.length < d.chain.length) known.chain = d.chain;
    } else {
      out.push(d);
      if (d.actionId) byAction.set(d.actionId, d);
    }
  }
  return out.sort(newestBlocked);
}

/**
 * Builds the Delegations view from GET /v1/agents/{id}/delegations
 * ({agent_id, hops, blocked}) plus, when readable, the delegation.bypass_blocked
 * Diary events that say which originating agents were stepped down.
 */
export function delegationViewFromApi(agentId: string, raw: unknown, diaryEvents: DiaryEvent[] = []): DelegationView {
  const o = isObj(raw) ? raw : {};
  const hops = listOf(o.hops).map(normHop).filter((h) => h.delegationId !== '');
  const blocked = listOf(o.blocked).map(normBlocked).filter((b) => b.actionId !== '');
  const fromDiary = diaryEvents.map((e) => blockedFromDiary(agentId, e)).filter((b): b is BlockedDelegation => b !== null);
  return { ...splitHops(agentId, hops), blocked: mergeBlocked(blocked, fromDiary), source: 'api' };
}

/**
 * Fallback for servers without the delegations endpoint: rebuilds the view
 * from Diary events (oldest first). delegation.opened/closed become hops,
 * delegation.bypass_blocked events in which the agent appears become
 * blocked bypass attempts.
 */
export function delegationViewFromDiary(agentId: string, events: DiaryEvent[]): DelegationView {
  const hops = new Map<string, Hop>();
  const blocked: BlockedDelegation[] = [];
  for (const e of events) {
    const d = e.data;
    if (e.eventType === 'delegation.opened' || e.eventType === 'delegation.closed') {
      const id = str(d.delegation_id);
      if (!id) continue;
      const chain = strArr(d.chain);
      const hop: Hop = hops.get(id) ?? {
        delegationId: id,
        root: str(d.root) || chain[0] || '',
        from: str(d.from),
        to: str(d.to),
        chain,
        depth: num(d.depth, Math.max(0, chain.length - 1)),
        channel: str(d.channel),
        status: 'open',
        openedAt: e.ts,
        expiresAt: optStr(d.expires_at),
        taskId: optStr(d.task_id),
        actionId: optStr(d.action_id),
      };
      if (e.eventType === 'delegation.closed') {
        hop.status = str(d.status, 'closed');
        hop.closedAt = e.ts;
      }
      hops.set(id, hop);
    } else {
      const b = blockedFromDiary(agentId, e);
      if (b) blocked.push(b);
    }
  }
  return { ...splitHops(agentId, [...hops.values()]), blocked: blocked.sort(newestBlocked), source: 'diary' };
}

// --- Phase 4: containment, memory, undo list ---------------------------------------------

const STEP_STATUSES: StepStatus[] = ['done', 'skipped', 'failed'];
const OP_STATUSES: OpStatus[] = ['running', 'done', 'partial', 'failed'];

export function normStep(raw: unknown): ContainmentStep {
  const o = isObj(raw) ? raw : {};
  const st = str(o.status).toLowerCase();
  return {
    name: str(o.name, 'step'),
    agentId: optStr(o.agent_id),
    // Never upgrade an unrecognised status to "done".
    status: (STEP_STATUSES as string[]).includes(st) ? (st as StepStatus) : 'unknown',
    detail: optStr(o.detail),
    durationMs: num(o.duration_ms),
  };
}

/** True when a body looks like a containment op (directly or wrapped as {op: {...}}). */
export function opBody(raw: unknown): Obj | null {
  if (!isObj(raw)) return null;
  if (typeof raw.op_id === 'string' && raw.op_id !== '') return raw;
  if (isObj(raw.op) && typeof raw.op.op_id === 'string') return raw.op;
  if (isObj(raw.result) && typeof raw.result.op_id === 'string') return raw.result;
  return null;
}

export function normContainmentOp(raw: unknown): ContainmentOp {
  const o = opBody(raw) ?? (isObj(raw) ? raw : {});
  const st = str(o.status).toLowerCase();
  return {
    opId: str(o.op_id),
    op: str(o.op),
    targetType: str(o.target_type),
    targetId: str(o.target_id),
    actor: str(o.actor),
    reason: str(o.reason),
    status: (OP_STATUSES as string[]).includes(st) ? (st as OpStatus) : 'unknown',
    steps: (Array.isArray(o.steps) ? o.steps : []).map(normStep),
    createdAt: str(o.created_at),
    finishedAt: optStr(o.finished_at),
  };
}

export function normContainmentOps(raw: unknown): ContainmentOp[] {
  return listOf(raw, 'ops', 'containment', 'operations', 'items')
    .map(normContainmentOp)
    .filter((x) => x.opId !== '');
}

/** Unknown memory modes are treated as the strictest ("none"): the UI never overstates access. */
export function parseMemoryMode(v: unknown): MemoryMode {
  const s = str(v).toLowerCase();
  if (s === 'full' || s === 'staging_only' || s === 'none') return s;
  return 'none';
}

/** GET /v1/agents/{id}/memory: {access: {mode, ...}, namespaces} or a flat {mode, ...}. */
export function normMemoryAccess(raw: unknown): MemoryAccess {
  const o = isObj(raw) ? raw : {};
  const a = isObj(o.access) ? o.access : o;
  const mode = a.mode === undefined && typeof o.access === 'string' ? o.access : a.mode;
  return {
    // A missing row means the default (full); a present but unknown value is the strictest.
    mode: mode === undefined || mode === null ? 'full' : parseMemoryMode(mode),
    reason: optStr(a.reason),
    changedBy: optStr(a.changed_by),
    changedAt: optStr(a.changed_at),
    namespaces: strArr(o.namespaces),
  };
}

export function normSnapshot(raw: unknown): MemorySnapshot {
  const o = isObj(raw) ? raw : {};
  return {
    snapshotId: str(o.snapshot_id),
    storeKey: str(o.store_key) || str(o.store),
    namespace: str(o.namespace),
    itemCount: num(o.item_count),
    // Not "clean" unless the server says so.
    clean: o.clean === true,
    createdBy: str(o.created_by),
    reason: str(o.reason),
    createdAt: str(o.created_at),
    expiresAt: optStr(o.expires_at),
    purgedAt: optStr(o.purged_at),
  };
}

export function normSnapshots(raw: unknown): MemorySnapshot[] {
  return listOf(raw, 'snapshots').map(normSnapshot).filter((x) => x.snapshotId !== '');
}

/** Memory content is customer data (possibly poisoned): only a short, single-line preview is kept. */
export const MEMORY_PREVIEW_CHARS = 160;

export function normMemoryItem(raw: unknown): MemoryItem {
  const o = isObj(raw) ? raw : {};
  // Full content (older listing) or the server's own preview (memory.StagedItem).
  const content = str(o.content ?? o.content_preview).replace(/\s+/g, ' ').trim();
  const md = isObj(o.metadata) ? o.metadata : {};
  return {
    id: str(o.id),
    namespace: str(o.namespace),
    storeKey: optStr(o.store_key) ?? optStr(o.store),
    contentPreview: content.length > MEMORY_PREVIEW_CHARS ? `${content.slice(0, MEMORY_PREVIEW_CHARS)}…` : content,
    agentId: str(o.agent_id),
    staged: bool(o.staged),
    flagged: bool(o.flagged),
    createdAt: str(o.created_at),
    promoteAt: optStr(o.promote_at),
    // Held for review: a reason, or at least the flag (then said generically).
    holdReason: optStr(o.hold_reason) ?? (o.held_for_review === true ? 'awaiting review' : undefined),
    actionId: optStr(o.action_id) ?? optStr(md.action_id),
    labels: strArr(o.labels),
  };
}

/** Ids of a list of ids or of objects with an id (memory.Held). */
function idList(v: unknown): string[] {
  if (!Array.isArray(v)) return [];
  return v.map((x) => (typeof x === 'string' ? x : isObj(x) ? str(x.id) : '')).filter(Boolean);
}

export function normMemoryRestoreResult(raw: unknown): MemoryRestoreResult {
  const o = isObj(raw) ? raw : {};
  const pre = isObj(o.pre_restore_snapshot) ? optStr(o.pre_restore_snapshot.snapshot_id) : optStr(o.pre_restore_snapshot_id);
  return {
    restored: num(o.restored),
    preRestoreSnapshotId: pre,
    skippedRemovedItems: idList(o.skipped_removed_items),
    heldForReview: idList(o.held_for_review),
    undoHandlesClosed: idList(o.undo_handles_closed),
  };
}

export function normMemoryFlagResult(raw: unknown): MemoryFlagResult {
  const o = isObj(raw) ? raw : {};
  return {
    snapshotsMarkedUnclean: strArr(o.snapshots_marked_unclean),
    promotionStopped: bool(o.promotion_stopped),
    alreadyPromoted: bool(o.already_promoted),
    snapshotCheckError: optStr(o.snapshot_check_error),
  };
}

export function normMemoryItems(raw: unknown): MemoryItem[] {
  return listOf(raw, 'items').map(normMemoryItem).filter((x) => x.id !== '');
}

/**
 * GET /v1/agents/{id}/memory (memory.AgentMemory: {agent_id, access, staged,
 * store_errors}). Items listed under "staged" are the agent's own staged writes.
 */
export function normAgentMemory(raw: unknown, agentId: string): AgentMemoryView {
  const o = isObj(raw) ? raw : {};
  const storeErrors: Record<string, string> = {};
  if (isObj(o.store_errors)) for (const [k, v] of Object.entries(o.store_errors)) storeErrors[k] = str(v);
  const staged = Array.isArray(o.staged)
    ? o.staged
        .map(normMemoryItem)
        .filter((x) => x.id !== '')
        .map((x) => ({ ...x, agentId: x.agentId || agentId, staged: true }))
    : null;
  return { access: normMemoryAccess(raw), staged, storeErrors };
}

/** Human description of what Undo does per kind, used when the server sends none. */
const UNDO_KIND_TEXT: Record<string, string> = {
  pg_rows_snapshot: 'Restore the rows the statement deleted or changed from the snapshot taken before it ran.',
  pg_rename: 'Rename the trashed table back to its original name (the DROP/TRUNCATE was turned into a rename).',
  memory_staging: 'Drop the staged memory item before it is promoted.',
  drive_permission: 'Remove the Drive sharing permission that was added.',
  gmail_delayed_send: 'Cancel the delayed email before it is sent.',
  github_ref: 'Reset the branch or tag to the commit it pointed at before.',
};

/**
 * GET /v1/undo entry. When the server does not say whether a handle is
 * undoable (an older server), the console decides conservatively: only an
 * active handle that has not expired is offered, everything else is NOT undoable.
 */
export function normUndoEntry(raw: unknown, now: number = Date.now()): UndoEntry {
  const o = isObj(raw) ? raw : {};
  const status = str(o.status);
  const expiresAt = optStr(o.expires_at);
  const exp = expiresAt ? Date.parse(expiresAt) : NaN;
  let undoable: boolean;
  let whyNot = optStr(o.why_not);
  if (typeof o.undoable === 'boolean') {
    undoable = o.undoable;
  } else {
    const expired = Number.isFinite(exp) && exp <= now;
    undoable = status === 'active' && !expired;
    if (!undoable && !whyNot) {
      whyNot =
        status === 'used' ? 'already used' : status === 'expired' || expired ? 'expired' : status === 'undoing' ? 'undo in progress' : 'not undoable';
    }
  }
  if (undoable) whyNot = undefined;
  else if (!whyNot) whyNot = 'not undoable';
  const kind = str(o.kind);
  return {
    actionId: str(o.action_id),
    agentId: str(o.agent_id),
    kind,
    status,
    createdAt: str(o.created_at),
    expiresAt,
    usedAt: optStr(o.used_at),
    usedBy: optStr(o.used_by),
    error: optStr(o.error),
    undoable,
    whyNot,
    description: optStr(o.description) ?? UNDO_KIND_TEXT[kind] ?? (kind ? `Reverse the ${kind} change.` : 'No description.'),
  };
}

export function normUndoList(raw: unknown, now: number = Date.now()): UndoEntry[] {
  return listOf(raw, 'undo', 'handles').map((x) => normUndoEntry(x, now)).filter((x) => x.actionId !== '');
}

export function normUndoRunResult(raw: unknown): UndoRunResult {
  const o = isObj(raw) ? raw : {};
  return { actionId: str(o.action_id), kind: str(o.kind), status: str(o.status) };
}

// --- Phase 5 (docs/PHASE5_DESIGN.md) -------------------------------------------------------

const FACT_MAX = 300;

/** Flattens an object into display-only [key, value] pairs (nested values as short JSON). */
export function factsOf(v: unknown, skip: string[] = []): [string, string][] {
  if (!isObj(v)) return typeof v === 'string' && v !== '' ? [['detail', v.slice(0, FACT_MAX)]] : [];
  const out: [string, string][] = [];
  for (const [k, x] of Object.entries(v)) {
    if (skip.includes(k) || x === null || x === undefined || x === '') continue;
    let t: string;
    if (typeof x === 'string') t = x;
    else if (typeof x === 'number' || typeof x === 'boolean') t = String(x);
    else {
      try {
        t = JSON.stringify(x);
      } catch {
        t = '[unreadable]';
      }
    }
    out.push([k, t.length > FACT_MAX ? `${t.slice(0, FACT_MAX)}…` : t]);
  }
  return out;
}

export function normVote(raw: unknown): Vote {
  const o = isObj(raw) ? raw : {};
  return {
    approver: str(pick(o, 'approver', 'actor', 'by', 'voter')),
    decision: str(pick(o, 'decision', 'vote'), 'approve').toLowerCase(),
    at: str(pick(o, 'at', 'created_at', 'ts')),
    reason: optStr(o.reason),
  };
}

/** The approver identity without the "user:" actor prefix, lower-cased (for "did I vote already"). */
export function approverKey(s: string): string {
  return s.replace(/^user:/i, '').trim().toLowerCase();
}

/** Distinct approve votes. */
export function approveCount(votes: Vote[]): number {
  return new Set(votes.filter((v) => v.decision === 'approve' || v.decision === 'approved').map((v) => approverKey(v.approver))).size;
}

export function normQueueItem(raw: unknown): QueueItem {
  const o = isObj(raw) ? raw : {};
  const h = normHeld(raw);
  const votes = listOf(o.votes).map(normVote);
  const swarm = isObj(o.swarm) ? o.swarm : {};
  const group = isObj(o.group) ? str(pick(o.group, 'label', 'swarm_id', 'id')) : str(o.group);
  return {
    ...h,
    votes,
    approvals: optNum(o.approvals) ?? approveCount(votes),
    swarmId: optStr(o.swarm_id) ?? optStr(swarm.swarm_id),
    group: group || undefined,
    assignedTo: optStr(o.assigned_to),
  };
}

export function normQueue(raw: unknown): QueueItem[] {
  return listOf(raw, 'items', 'held', 'queue').map(normQueueItem).filter((x) => x.actionId !== '');
}

/** POST /v1/held/bulk-deny result: {results: [{action_id, outcome | error}]} (also accepts a map id -> outcome). */
export function normBulkDeny(raw: unknown, ids: string[]): BulkDenyOutcome[] {
  const o = isObj(raw) ? raw : {};
  const list = listOf(raw, 'results', 'decisions', 'outcomes');
  if (list.length) {
    return list.map((r) => {
      const x = isObj(r) ? r : {};
      const err = isObj(x.error) ? str(pick(x.error, 'message', 'reason', 'code')) : str(x.error);
      const outcome = str(x.outcome);
      return { actionId: str(x.action_id), ok: err === '' && outcome !== 'error' && outcome !== 'failed', outcome: outcome || (err ? 'error' : ''), error: err || undefined };
    });
  }
  const m = isObj(o.results) ? o.results : null;
  if (m) {
    return Object.entries(m).map(([id, v]) => {
      const x = isObj(v) ? v : { outcome: v };
      const err = str(x.error);
      return { actionId: id, ok: err === '', outcome: str(x.outcome), error: err || undefined };
    });
  }
  // No per-id report: say so rather than claim each was denied.
  return ids.map((id) => ({ actionId: id, ok: false, outcome: 'unknown', error: 'the server did not report this id' }));
}

// Swarms (§1).

// The server's rule (internal/swarm store: active = state <> 'released'): a killed
// swarm stays frozen and holds its calls until two approvers release it.
const TERMINAL_SWARM_STATES = ['released', 'closed', 'sealed', 'dismissed', 'resolved'];

/** Whether a swarm still counts as active (anything not released, killed included). */
export function swarmActive(state: string): boolean {
  return !TERMINAL_SWARM_STATES.includes(state.toLowerCase());
}

function normSignal(o: Obj): SwarmSignal {
  const sig = pick(o, 'signal', 'signal_detail');
  const kind = str(pick(o, 'detected_by', 'signal_kind')) || (isObj(sig) ? str(pick(sig, 'kind', 'type', 'detected_by')) : '') || 'unknown';
  return { kind, facts: factsOf(sig, ['kind', 'type', 'detected_by']) };
}

export function normSwarm(raw: unknown): Swarm {
  let o = isObj(raw) ? raw : {};
  if (isObj(o.swarm)) o = { ...o, ...o.swarm };
  const members = Array.isArray(o.members) ? o.members.length : 0;
  const state = str(o.state, 'unknown').toLowerCase();
  return {
    swarmId: str(pick(o, 'swarm_id', 'id')),
    state,
    detectedBy: str(pick(o, 'detected_by'), '') || normSignal(o).kind,
    signal: normSignal(o),
    root: optStr(pick(o, 'root_agent_id', 'root_agent', 'root')),
    memberCount: num(o.member_count, members),
    createdAt: str(o.created_at),
    updatedAt: optStr(o.updated_at),
    frozen: bool(o.frozen) || state === 'frozen',
  };
}

export function normSwarms(raw: unknown): Swarm[] {
  return listOf(raw, 'swarms', 'items').map(normSwarm).filter((s) => s.swarmId !== '');
}

function normMember(raw: unknown): SwarmMember {
  if (typeof raw === 'string') return { id: raw, agentId: raw.replace(/^agent:/, '') };
  const o = isObj(raw) ? raw : {};
  const agentId = str(pick(o, 'agent_id', 'agent'));
  const instanceId = optStr(o.instance_id);
  const lvl = pick(o, 'level_name', 'level');
  return {
    id: instanceId ?? (agentId || str(o.id)),
    agentId: agentId || str(o.id),
    instanceId,
    parent: optStr(pick(o, 'parent', 'parent_agent_id', 'delegated_by')),
    role: optStr(o.role),
    level: lvl === undefined ? undefined : parseLevel(lvl),
    // The server sends `suspended` (bool), not a status string.
    status: optStr(o.status) ?? (o.suspended === true ? 'suspended' : o.suspended === false ? 'active' : undefined),
    joinedAt: optStr(pick(o, 'joined_at', 'added_at', 'created_at')),
    depth: optNum(o.depth),
  };
}

function normBreaker(raw: unknown): SwarmBreaker {
  const o = isObj(raw) ? raw : {};
  return {
    breakerId: str(pick(o, 'breaker_id', 'id')),
    actionHash: str(pick(o, 'action_hash', 'hash')),
    state: str(pick(o, 'state', 'status'), o.released_at ? 'released' : 'tripped'),
    trippedAt: optStr(o.tripped_at),
    trippedBy: optStr(o.tripped_by),
    releasedAt: optStr(o.released_at),
    matched: optNum(pick(o, 'matched', 'held_count', 'count')),
  };
}

/** Spawn tree as flat parent->child edges: from a list of edges, a nested {agent_id, children} tree, or members' parents. */
export function spawnEdgesOf(raw: unknown, members: SwarmMember[]): SpawnEdge[] {
  const out: SpawnEdge[] = [];
  const walk = (n: unknown, parent: string | undefined, depth: number) => {
    if (!isObj(n)) return;
    const id = str(pick(n, 'agent_id', 'id', 'instance_id'));
    if (parent && id) out.push({ parent, child: id, depth, delegationId: optStr(n.delegation_id) });
    for (const c of listOf(n.children)) walk(c, id || parent, depth + 1);
  };
  if (Array.isArray(raw)) {
    for (const e of raw) {
      if (!isObj(e)) continue;
      if (Array.isArray(e.children)) walk(e, undefined, 0);
      else {
        const parent = str(pick(e, 'parent', 'from'));
        const child = str(pick(e, 'child', 'to', 'agent_id'));
        if (parent && child) out.push({ parent, child, depth: optNum(e.depth), delegationId: optStr(e.delegation_id) });
      }
    }
  } else if (isObj(raw)) walk(raw, undefined, 0);
  if (out.length === 0) for (const m of members) if (m.parent) out.push({ parent: m.parent, child: m.id, depth: m.depth });
  return out;
}

export function normSwarmDetail(raw: unknown): SwarmDetail {
  let o = isObj(raw) ? raw : {};
  if (isObj(o.swarm)) o = { ...o.swarm, ...o, swarm: undefined };
  const base = normSwarm(o);
  const members = listOf(o.members).map(normMember).filter((m) => m.id !== '');
  const rel = isObj(o.release) ? o.release : {};
  const votes = listOf(pick(o, 'release_votes') ?? rel.votes).map(normVote);
  return {
    ...base,
    memberCount: base.memberCount || members.length,
    members,
    breakers: listOf(o.breakers).map(normBreaker),
    held: listOf(pick(o, 'held', 'held_calls', 'held_actions')).map(normHeld),
    releaseVotes: votes,
    releaseRequired: num(pick(o, 'release_required', 'approvals_required') ?? rel.required, 2),
    spawnTree: spawnEdgesOf(o.spawn_tree, members),
    ops: listOf(pick(o, 'ops', 'containment')).map(normContainmentOp).filter((x) => x.opId !== ''),
  };
}

export function normSwarmRelease(raw: unknown): SwarmReleaseResult {
  const o = isObj(raw) ? raw : {};
  const op = opBody(raw);
  return {
    released: bool(o.released),
    votes: num(pick(o, 'votes', 'approvals')),
    required: num(pick(o, 'required', 'approvals_required'), 2),
    op: op ? normContainmentOp(op) : undefined,
  };
}

// Communication map (§2).

const NODE_KINDS: MapNodeKind[] = ['agent', 'instance', 'user', 'app', 'store', 'memory', 'mcp', 'domain', 'swarm'];

/** The node kind from a typed id ("agent:x", "store:postgres:y", "domain:host"). */
export function nodeKindOf(id: string): MapNodeKind {
  const p = id.slice(0, id.indexOf(':')).toLowerCase();
  return (NODE_KINDS as string[]).includes(p) ? (p as MapNodeKind) : 'unknown';
}

/** The id without its kind prefix (the readable part). */
export function nodeName(id: string): string {
  const i = id.indexOf(':');
  return i >= 0 ? id.slice(i + 1) : id;
}

/** Edge classes; "blue" (above normal) is shown as yellow, unknown values as red (never understate). */
export function parseEdgeClass(v: unknown): EdgeClass {
  const s = str(v).toLowerCase();
  if (s === 'hidden' || s === 'green' || s === 'yellow' || s === 'red') return s;
  if (s === 'blue' || s === 'amber') return 'yellow';
  return 'red';
}

export const EDGE_RANK: Record<EdgeClass, number> = { green: 0, yellow: 1, red: 2, hidden: 3 };

export function worseEdge(a: EdgeClass, b: EdgeClass): EdgeClass {
  return EDGE_RANK[b] > EDGE_RANK[a] ? b : a;
}

export function normMapNode(raw: unknown): MapNode {
  const o = isObj(raw) ? raw : {};
  const id = str(pick(o, 'id', 'node_id'));
  const k = str(o.kind).toLowerCase();
  const lvl = pick(o, 'level_name', 'level');
  return {
    id,
    kind: (NODE_KINDS as string[]).includes(k) ? (k as MapNodeKind) : nodeKindOf(id),
    label: str(o.label) || nodeName(id),
    team: optStr(pick(o, 'team', 'business_unit')),
    level: lvl === undefined || lvl === null || lvl === '' ? undefined : parseLevel(lvl),
    suspended: typeof o.suspended === 'boolean' ? o.suspended : undefined,
    discovered: typeof o.discovered === 'boolean' ? o.discovered : undefined,
    owner: optStr(pick(o, 'owner', 'sponsor')),
    swarmIds: strArr(pick(o, 'swarm_ids', 'swarms')),
    reachable: o.reachable === true || o.halo === true || undefined,
  };
}

export function normMapEdge(raw: unknown): MapEdge {
  const o = isObj(raw) ? raw : {};
  return {
    from: str(pick(o, 'from', 'source', 'src')),
    to: str(pick(o, 'to', 'target', 'dst')),
    verb: str(o.verb).toUpperCase(),
    count: num(o.count),
    bytes: num(o.bytes),
    labels: strArr(pick(o, 'labels', 'data_labels')),
    sampleActionIds: strArr(pick(o, 'sample_action_ids', 'action_ids', 'samples')),
    worstClass: parseEdgeClass(pick(o, 'worst_class', 'class')),
    windowStart: optStr(o.window_start),
    reach: o.reach === true || o.reachable === true || str(o.kind) === 'reach' || undefined,
  };
}

/**
 * Whether a server cluster is a swarm. GET /v1/map also returns team clusters
 * ({id: "team:<name>", kind: "team"}, no swarm_id) in the team view; those are
 * drawn as team bands, never collapsed into a swarm node.
 */
export function isSwarmCluster(raw: unknown): boolean {
  const o = isObj(raw) ? raw : {};
  const kind = str(o.kind).toLowerCase();
  if (kind) return kind === 'swarm';
  return str(o.swarm_id) !== '' || (str(o.id) !== '' && !str(o.id).includes(':'));
}

export function normCluster(raw: unknown): MapCluster {
  const o = isObj(raw) ? raw : {};
  return {
    swarmId: str(pick(o, 'swarm_id', 'id')),
    state: str(o.state, 'active').toLowerCase(),
    members: listOf(o.members)
      .map((m) => (typeof m === 'string' ? m : isObj(m) ? str(pick(m, 'id', 'node_id', 'agent_id')) : ''))
      .filter(Boolean)
      .map((m) => (m.includes(':') ? m : `agent:${m}`)),
  };
}

export function normMap(raw: unknown): CommMap {
  const o = isObj(raw) ? raw : {};
  const w = isObj(o.window) ? o.window : {};
  const nodes = listOf(o.nodes).map(normMapNode).filter((n) => n.id !== '');
  const edges = listOf(o.edges).map(normMapEdge).filter((e) => e.from !== '' && e.to !== '');
  return {
    window: { from: str(w.from), to: str(w.to) },
    nodes,
    edges,
    clusters: listOf(o.clusters).filter(isSwarmCluster).map(normCluster).filter((c) => c.swarmId !== ''),
  };
}

export function normPathHops(raw: unknown): PathHop[] {
  return listOf(raw, 'hops', 'path').map((h) => {
    const o = isObj(h) ? h : {};
    return {
      from: str(o.from),
      to: str(o.to),
      verb: str(o.verb).toUpperCase(),
      windowStart: optStr(o.window_start),
      actionIds: strArr(pick(o, 'action_ids', 'sample_action_ids')),
    };
  });
}

// Shadow agents (§3).

export function normShadowFinding(raw: unknown): ShadowFinding {
  const o = isObj(raw) ? raw : {};
  return {
    findingId: str(pick(o, 'finding_id', 'id')),
    system: str(o.system),
    kind: str(o.kind),
    credentialId: str(pick(o, 'credential_id', 'credential')),
    holder: str(o.holder),
    usedBySoftware: bool(o.used_by_software),
    evidence: factsOf(o.evidence),
    status: str(o.status, 'unknown'),
    discoveredAgentId: optStr(pick(o, 'discovered_agent_id', 'agent_id')),
    createdAt: str(pick(o, 'created_at', 'discovered_at', 'first_seen')),
    updatedAt: optStr(pick(o, 'updated_at', 'last_seen')),
  };
}

export function normShadowFindings(raw: unknown): ShadowFinding[] {
  return listOf(raw, 'findings', 'shadow', 'items').map(normShadowFinding).filter((f) => f.findingId !== '');
}

// Baselines (§4).

const optNumNull = (v: unknown): number | null => (typeof v === 'number' && Number.isFinite(v) ? v : null);

export function normBaseline(raw: unknown, agentId: string, verb: string): Baseline {
  let o = isObj(raw) ? raw : {};
  if (isObj(o.baseline)) o = { ...o, ...o.baseline };
  const th = isObj(o.thresholds) ? o.thresholds : {};
  const series: BaselinePoint[] = listOf(pick(o, 'series', 'hourly', 'hours'))
    .map((p) => {
      if (typeof p === 'number') return { hour: '', count: p };
      const x = isObj(p) ? p : {};
      return { hour: str(pick(x, 'hour', 'ts', 'start')), count: num(x.count) };
    })
    .sort((a, b) => (a.hour && b.hour ? a.hour.localeCompare(b.hour) : 0));
  const g = (k: string) => optNumNull(o[k] ?? th[k]);
  return {
    agentId: str(o.agent_id, agentId),
    verb: str(o.verb, verb).toUpperCase(),
    verbs: strArr(o.verbs).map((v) => v.toUpperCase()),
    series,
    mean: g('mean'),
    stddev: optNumNull(o.stddev ?? o.sigma ?? th.stddev),
    median: g('median'),
    historyDays: g('history_days'),
    threshold: g('threshold'),
    current: g('current'),
    aboveNormal: bool(o.above_normal),
    method: optStr(o.method ?? th.method),
    minCount: optNum(o.min_count ?? th.min_count),
  };
}
