// Typed calls to the Fortik API (docs/PHASE2_DESIGN.md, docs/API.md). Where a
// Phase 2 aggregate endpoint is missing (404/405 on an older server), the
// console computes the figure from the Phase 1 endpoints instead.

import { api, ApiError, request, requestText, seg } from './client';
import {
  normBaseline,
  normBulkDeny,
  normMap,
  normPathHops,
  normQueue,
  normShadowFinding,
  normShadowFindings,
  normSwarmDetail,
  normSwarmRelease,
  normSwarms,
  swarmActive,
  normContainmentOp,
  normContainmentOps,
  normAgentMemory,
  normMemoryFlagResult,
  normMemoryItems,
  normMemoryRestoreResult,
  normSnapshots,
  normUndoList,
  normUndoRunResult,
  opBody,
  activityFromActions,
  delegationViewFromApi,
  delegationViewFromDiary,
  normAgentType,
  normAgentTypes,
  normAlert,
  normAlerts,
  normApprovalResult,
  normDiaryEntry,
  normInstancesView,
  normOverride,
  normOverrides,
  normActions,
  normAgent,
  normAgentDetail,
  normAgents,
  normAuthConfig,
  normHeldList,
  normIntegration,
  normIntegrations,
  normMe,
  normProfiles,
  normSchemas,
  normStats,
  normSummary,
  normTestResult,
  statsFromActions,
  summaryFromData,
} from './normalize';
import type {
  ActionClass,
  Baseline,
  BulkDenyOutcome,
  CommMap,
  MapQuery,
  PathHop,
  QueueItem,
  QueueQuery,
  QueueResult,
  ShadowFinding,
  ShadowRegistration,
  Swarm,
  SwarmDetail,
  SwarmOp,
  SwarmReleaseResult,
  ContainmentOp,
  ContainmentTarget,
  AgentMemoryView,
  MemoryAccess,
  MemoryFlagResult,
  MemoryItem,
  MemoryMode,
  MemoryRestoreResult,
  MemorySnapshot,
  UndoEntry,
  UndoRunResult,
  AgentType,
  Alert,
  AlertStatus,
  ApprovalResult,
  DelegationView,
  DiaryEvent,
  InstancesView,
  NewOverride,
  Override,
  AccessSystem,
  ActionRow,
  Agent,
  AgentDetail,
  AgentStats,
  AuthConfig,
  HeldAction,
  Integration,
  IntegrationSchema,
  Level,
  Me,
  NewAgent,
  ProfileView,
  Summary,
  TestResult,
} from './types';
import { countBlockedToday, incidentChain, memoryQuarantined, quarantinedFromAgents } from '../lib/commandCenter';

const notImplemented = (e: unknown) => e instanceof ApiError && (e.status === 404 || e.status === 405 || e.status === 501);

// --- auth ---------------------------------------------------------------------

export async function getMe(): Promise<Me> {
  return normMe(await request('/v1/me', { quiet401: true }));
}

export async function getAuthConfig(): Promise<AuthConfig> {
  return normAuthConfig(await request('/auth/config', { quiet401: true }));
}

export async function devLogin(email: string): Promise<void> {
  await request('/auth/dev-login', { method: 'POST', body: { email }, quiet401: true });
}

export async function logout(): Promise<void> {
  await request('/auth/logout', { method: 'POST', quiet401: true });
}

// --- agents -------------------------------------------------------------------

export interface AgentsPage {
  agents: Agent[];
  summary: Summary;
  heldByAgent: Map<string, number>;
}

/** Loads the Agents screen: list, KPIs and per-agent activity. */
export async function loadAgentsPage(signal?: AbortSignal): Promise<AgentsPage> {
  const [agentsRaw, summaryRes, heldRaw] = await Promise.all([
    api.get('/v1/agents', signal),
    api.get('/v1/stats/summary', signal).then(
      (r) => ({ ok: true as const, r }),
      (e: unknown) => {
        if (notImplemented(e)) return { ok: false as const };
        throw e;
      },
    ),
    api.get('/v1/held?status=pending&limit=1000', signal),
  ]);
  let agents = normAgents(agentsRaw);
  const held = normHeldList(heldRaw);
  const heldByAgent = new Map<string, number>();
  for (const h of held) heldByAgent.set(h.agentId, (heldByAgent.get(h.agentId) ?? 0) + 1);

  const needActivity = agents.some((a) => a.actionsToday === undefined || a.worstClass24h === undefined);
  let actions: ActionRow[] | null = null;
  if (needActivity || !summaryRes.ok) {
    actions = normActions(await api.get('/v1/actions?limit=1000', signal));
  }
  if (needActivity && actions) {
    const act = activityFromActions(actions);
    agents = agents.map((a) => {
      const x = act.get(a.agentId);
      return {
        ...a,
        actionsToday: a.actionsToday ?? x?.actionsToday ?? 0,
        worstClass24h: a.worstClass24h !== undefined ? a.worstClass24h : (x?.worst24h ?? null),
        systems24h: a.systems24h ?? x?.systems ?? [],
      };
    });
  }
  const summary = summaryRes.ok ? normSummary(summaryRes.r) : summaryFromData(agents, actions ?? [], held.length);
  return { agents, summary, heldByAgent };
}

export async function listAgents(signal?: AbortSignal): Promise<Agent[]> {
  return normAgents(await api.get('/v1/agents', signal));
}

export async function getAgent(id: string, signal?: AbortSignal): Promise<AgentDetail> {
  return normAgentDetail(await api.get(`/v1/agents/${seg(id)}`, signal));
}

export async function listActions(agentId: string, limit = 200, signal?: AbortSignal): Promise<ActionRow[]> {
  return normActions(await api.get(`/v1/actions?agent_id=${seg(agentId)}&limit=${limit}`, signal));
}

export async function getAgentStats(id: string, hours: number, signal?: AbortSignal): Promise<AgentStats> {
  try {
    const s = normStats(await api.get(`/v1/agents/${seg(id)}/stats?hours=${hours}`, signal), hours);
    if (s) return s;
  } catch (e) {
    if (!notImplemented(e)) throw e;
  }
  return statsFromActions(await listActions(id, 1000, signal), hours);
}

export async function listHeld(status = 'pending', signal?: AbortSignal): Promise<HeldAction[]> {
  return normHeldList(await api.get(`/v1/held?status=${seg(status)}&limit=1000`, signal));
}

export async function createAgent(a: NewAgent): Promise<Agent> {
  return normAgent(await api.post('/v1/agents', a));
}

export async function setLevel(id: string, level: Level, reason: string): Promise<unknown> {
  return api.put(`/v1/agents/${seg(id)}/level`, { level, reason });
}

export async function issueToken(id: string): Promise<string> {
  const r = await api.post<{ token?: unknown }>(`/v1/agents/${seg(id)}/tokens`, {});
  if (!r || typeof r.token !== 'string' || r.token === '') throw new ApiError(500, 'the server did not return a token');
  return r.token;
}

export async function revokeTokens(id: string): Promise<unknown> {
  return api.del(`/v1/agents/${seg(id)}/tokens`);
}

// --- access profiles ----------------------------------------------------------------

export async function getAccess(id: string, signal?: AbortSignal): Promise<ProfileView[]> {
  return normProfiles(await api.get(`/v1/agents/${seg(id)}/access`, signal));
}

export async function getAccessHistory(id: string, system: AccessSystem, signal?: AbortSignal): Promise<ProfileView[]> {
  return normProfiles(await api.get(`/v1/agents/${seg(id)}/access/${seg(system)}/history?limit=50`, signal)).map((p) => ({
    ...p,
    system,
  }));
}

export async function putAccess(id: string, system: AccessSystem, profile: unknown, reason: string): Promise<unknown> {
  return api.put(`/v1/agents/${seg(id)}/access/${seg(system)}`, { profile, reason });
}

export async function revertAccess(id: string, system: AccessSystem, version: number, reason: string): Promise<unknown> {
  return api.post(`/v1/agents/${seg(id)}/access/${seg(system)}/revert`, { version, reason });
}

// --- integrations -----------------------------------------------------------------

export async function getIntegrationSchemas(signal?: AbortSignal): Promise<IntegrationSchema[]> {
  return normSchemas(await api.get('/v1/integrations/schema', signal));
}

export async function listIntegrations(signal?: AbortSignal): Promise<Integration[]> {
  return normIntegrations(await api.get('/v1/integrations', signal));
}

/** secrets: a new value per field to set, null to remove an optional one; omitted fields keep their stored value. */
export async function saveIntegration(key: string, config: Record<string, unknown>, secrets: Record<string, string | null>): Promise<Integration> {
  return normIntegration(await api.put(`/v1/integrations/${seg(key)}`, { config, secrets }));
}

export async function testIntegration(key: string): Promise<TestResult> {
  return normTestResult(await api.post(`/v1/integrations/${seg(key)}/test`, {}));
}

export async function deleteIntegration(key: string): Promise<void> {
  await api.del(`/v1/integrations/${seg(key)}`);
}

// --- Phase 3: approvals (docs/PHASE3_DESIGN.md §6) -------------------------------------

export async function approveHeld(actionId: string, reason: string, useSafeForm: boolean): Promise<ApprovalResult> {
  return normApprovalResult(await api.post(`/v1/held/${seg(actionId)}/approve`, { reason, use_safe_form: useSafeForm }));
}

export async function denyHeld(actionId: string, reason: string): Promise<ApprovalResult> {
  return normApprovalResult(await api.post(`/v1/held/${seg(actionId)}/deny`, { reason }));
}

// --- Phase 3: timed app suspensions (§5) -------------------------------------------------

export async function listOverrides(agentId: string, status = '', signal?: AbortSignal): Promise<Override[]> {
  const q = `agent_id=${seg(agentId)}${status ? `&status=${seg(status)}` : ''}`;
  return normOverrides(await api.get(`/v1/overrides?${q}`, signal));
}

export async function createOverride(o: NewOverride): Promise<Override> {
  return normOverride(await api.post('/v1/overrides', o));
}

export async function releaseOverride(id: string, reason: string): Promise<Override> {
  return normOverride(await api.post(`/v1/overrides/${seg(id)}/release`, { reason }));
}

export async function extendOverride(id: string, durationSeconds: number, reason: string): Promise<Override> {
  return normOverride(await api.post(`/v1/overrides/${seg(id)}/extend`, { duration_seconds: durationSeconds, reason }));
}

export async function makeOverridePermanent(id: string, reason: string): Promise<Override> {
  return normOverride(await api.post(`/v1/overrides/${seg(id)}/permanent`, { reason }));
}

// --- Phase 3: population (§2.1, §2.6, §2.8) ---------------------------------------------

/** GET /v1/agents/{id}/instances (requested from D4; see the console's contract notes). */
export async function listInstances(agentId: string, signal?: AbortSignal): Promise<InstancesView> {
  return normInstancesView(await api.get(`/v1/agents/${seg(agentId)}/instances`, signal));
}

export interface PauseExtraResult {
  live: number;
  copyCap: number;
  paused: string[];
}

export async function pauseExtraInstances(agentId: string, reason: string): Promise<PauseExtraResult> {
  const r = await api.post<Record<string, unknown> | null>(`/v1/agents/${seg(agentId)}/instances/pause-extra`, { reason });
  const o = r ?? {};
  return {
    live: typeof o.live_after === 'number' ? o.live_after : 0,
    copyCap: typeof o.copy_cap === 'number' ? o.copy_cap : 0,
    paused: Array.isArray(o.paused) ? o.paused.filter((x): x is string => typeof x === 'string') : [],
  };
}

export async function listAgentTypes(signal?: AbortSignal): Promise<AgentType[]> {
  return normAgentTypes(await api.get('/v1/agent-types', signal));
}

export async function putAgentType(t: AgentType, reason: string): Promise<AgentType> {
  const r = await api.put(`/v1/agent-types/${seg(t.type)}`, {
    expected_max_instances: t.expectedMaxInstances,
    max_agents: t.maxAgents,
    spawn_rate_per_min: t.spawnRatePerMin,
    action_rate_per_min: t.actionRatePerMin,
    reason,
  });
  const n = normAgentType(r);
  return n.type ? n : t;
}

// --- Phase 3: alerts (§2.9) ----------------------------------------------------------

export async function listAlerts(status: AlertStatus | '' = 'open', signal?: AbortSignal): Promise<Alert[]> {
  return normAlerts(await api.get(`/v1/alerts?limit=1000${status ? `&status=${seg(status)}` : ''}`, signal));
}

export async function ackAlert(id: string): Promise<Alert> {
  return normAlert(await api.post(`/v1/alerts/${seg(id)}/ack`, {}));
}

export async function resolveAlert(id: string): Promise<Alert> {
  return normAlert(await api.post(`/v1/alerts/${seg(id)}/resolve`, {}));
}

// --- Phase 3: delegations (§1) ---------------------------------------------------------

/** Diary window searched for delegation events. */
export const DELEGATION_WINDOW_HOURS = 24;

/** Delegation events of the last DELEGATION_WINDOW_HOURS (GET /v1/diary, auditor). */
async function delegationDiaryEvents(signal: AbortSignal | undefined, now: number): Promise<DiaryEvent[]> {
  // Not filtered by agent_id: delegation.opened is written under the
  // delegator and delegation.bypass_blocked under the originating agent, so
  // an agent's inbound hops and the attempts it executed would be missed.
  const from = new Date(now - DELEGATION_WINDOW_HOURS * 3600_000).toISOString();
  const raw = await api.get<{ entries?: unknown }>(`/v1/diary?from=${seg(from)}&limit=10000`, signal);
  const entries = raw && Array.isArray(raw.entries) ? raw.entries : [];
  return entries.map(normDiaryEntry).filter((e): e is DiaryEvent => e !== null && e.eventType.startsWith('delegation.'));
}

/**
 * Inbound and outbound hops plus blocked delegations for one agent, from
 * GET /v1/agents/{id}/delegations (auditor, security or the owner). The
 * delegation.bypass_blocked Diary events add who was stepped down; they are
 * best effort (an owner without the auditor role cannot read the Diary).
 * On a server without the endpoint the whole view is rebuilt from the Diary.
 */
export async function getDelegations(agentId: string, signal?: AbortSignal, now: number = Date.now()): Promise<DelegationView> {
  let raw: unknown;
  try {
    raw = await api.get(`/v1/agents/${seg(agentId)}/delegations?direction=all&limit=200`, signal);
  } catch (e) {
    if (!notImplemented(e) || (e instanceof ApiError && e.message === 'agent not found')) throw e;
    return delegationViewFromDiary(agentId, await delegationDiaryEvents(signal, now));
  }
  let events: DiaryEvent[] = [];
  try {
    events = await delegationDiaryEvents(signal, now);
  } catch (e) {
    if (!(e instanceof ApiError) || (e.status !== 403 && !notImplemented(e))) throw e;
  }
  return delegationViewFromApi(agentId, raw, events);
}

// --- Phase 4: containment (docs/PHASE4_DESIGN.md §1) ---------------------------------------

/**
 * Runs one containment call. The server records each step's honest result; a
 * partial or failed run may come back with an error status but still carry
 * the op, which is returned (with httpError set) so every step is shown.
 */
async function runContainment(path: string, body: Record<string, unknown>): Promise<ContainmentOp> {
  try {
    const raw = await api.post<unknown>(path, body);
    const op = normContainmentOp(raw);
    if (!opBody(raw)) throw new ApiError(500, 'the server did not report the operation and its steps');
    return op;
  } catch (e) {
    if (e instanceof ApiError && opBody(e.body)) return { ...normContainmentOp(e.body), httpError: e.message };
    throw e;
  }
}

export type AgentOp = 'suspend' | 'resume' | 'isolate' | 'kill';

/** POST /v1/agents/{id}/suspend | resume | isolate | kill. */
export function agentOp(agentId: string, op: AgentOp, reason: string): Promise<ContainmentOp> {
  return runContainment(`/v1/agents/${seg(agentId)}/${op}`, { reason });
}

/** POST /v1/agents/{id}/memory/remove: access "none" or "staging_only". */
export function removeMemory(agentId: string, mode: Exclude<MemoryMode, 'full'>, reason: string): Promise<ContainmentOp> {
  return runContainment(`/v1/agents/${seg(agentId)}/memory/remove`, { reason, memory_mode: mode });
}

/** POST /v1/agents/{id}/memory/restore, optionally rolling back to a clean snapshot first. */
export function restoreMemory(agentId: string, reason: string, rollbackSnapshotId?: string): Promise<ContainmentOp> {
  const body: Record<string, unknown> = { reason };
  if (rollbackSnapshotId) body.rollback_snapshot_id = rollbackSnapshotId;
  return runContainment(`/v1/agents/${seg(agentId)}/memory/restore`, body);
}

/** POST /v1/agents/{id}/queue/cancel. NOT reversible: cancelled jobs must be resubmitted. */
export function cancelQueue(agentId: string, reason: string): Promise<ContainmentOp> {
  return runContainment(`/v1/agents/${seg(agentId)}/queue/cancel`, { reason });
}

export type TeamOp = 'suspend' | 'resume' | 'kill';

/** POST /v1/teams/{team}/suspend | resume | kill (team = business unit; security). */
export function teamOp(team: string, op: TeamOp, reason: string): Promise<ContainmentOp> {
  return runContainment(`/v1/teams/${seg(team)}/${op}`, { reason });
}

/** POST /v1/fleet/estop: suspends every registered agent (security + typed confirmation). */
export function fleetEStop(reason: string, confirm: string): Promise<ContainmentOp> {
  return runContainment('/v1/fleet/estop', { reason, confirm });
}

/** POST /v1/fleet/release: resumes only the agents the e-stop suspended. */
export function fleetRelease(reason: string): Promise<ContainmentOp> {
  return runContainment('/v1/fleet/release', { reason });
}

export interface ContainmentQuery {
  targetType?: ContainmentTarget;
  targetId?: string;
  limit?: number;
}

/** GET /v1/containment: history with steps, newest first. */
export async function listContainment(q: ContainmentQuery = {}, signal?: AbortSignal): Promise<ContainmentOp[]> {
  const p = new URLSearchParams();
  if (q.targetType) p.set('target_type', q.targetType);
  if (q.targetId) p.set('target_id', q.targetId);
  p.set('limit', String(q.limit ?? 100));
  const ops = normContainmentOps(await api.get(`/v1/containment?${p.toString()}`, signal));
  return ops.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** DELETE /v1/agents/{id}/tokens: revokes every Fortik agent token. Returns whether a token was on file. */
export async function revokeAgentTokens(agentId: string): Promise<boolean> {
  const r = await api.del<{ revoked?: unknown } | null>(`/v1/agents/${seg(agentId)}/tokens`);
  return r?.revoked === true;
}

/** Gmail profile with sending removed; read and the recipient cap are kept (a pure narrowing). */
export function gmailWithoutSend(current: unknown): Record<string, unknown> {
  const c = current !== null && typeof current === 'object' && !Array.isArray(current) ? (current as Record<string, unknown>) : null;
  if (!c) return { send: 'none', read: false, max_recipients: 0 };
  return {
    send: 'none',
    read: c.read === true,
    max_recipients: typeof c.max_recipients === 'number' ? c.max_recipients : 0,
  };
}

export interface DisableSendResult {
  /** The Gmail profile already had send "none": nothing was changed. */
  alreadyDisabled: boolean;
}

/** Narrows the agent's Gmail profile to send "none" (PUT /v1/agents/{id}/access/gmail). */
export async function disableGmailSend(agentId: string, reason: string): Promise<DisableSendResult> {
  const profiles = await getAccess(agentId);
  const current = profiles.find((p) => p.system === 'gmail')?.profile ?? null;
  const cur = current !== null && typeof current === 'object' ? (current as Record<string, unknown>) : null;
  if (cur && cur.send === 'none') return { alreadyDisabled: true };
  await putAccess(agentId, 'gmail', gmailWithoutSend(current), reason);
  return { alreadyDisabled: false };
}

// --- Phase 4: memory (§3) --------------------------------------------------------------

/** Data that only exists on a newer server; null = the endpoint is not there (shown as unavailable). */
async function optional<T>(load: () => Promise<T>): Promise<T | null> {
  try {
    return await load();
  } catch (e) {
    // A route that does not exist is unavailable; "agent not found" is a real error.
    if (notImplemented(e) && !(e instanceof ApiError && /agent not found/i.test(e.message))) return null;
    throw e;
  }
}

/** GET /v1/agents/{id}/memory: access mode, staged items and store errors (null if the server has no such endpoint). */
export async function getAgentMemory(agentId: string, signal?: AbortSignal): Promise<AgentMemoryView | null> {
  return optional(async () => normAgentMemory(await api.get(`/v1/agents/${seg(agentId)}/memory`, signal), agentId));
}

/** Namespaces the agent is known to use: those the server reports plus those of its staged items. */
export function memoryNamespaces(view: AgentMemoryView | null): string[] {
  if (!view) return [];
  return [...new Set([...view.access.namespaces, ...(view.staged ?? []).map((i) => i.namespace)].filter(Boolean))].sort();
}

/** A memory store + namespace an agent is known to use (store "" = the server did not say which store). */
export interface MemoryScope {
  store: string;
  namespace: string;
}

const storeName = (k: string | undefined) => (k ?? '').replace(/^memory:/, '');

/** The store/namespace pairs the agent is known to use: its staged writes, plus the namespaces the server reports. */
export function memoryScopes(view: AgentMemoryView | null): MemoryScope[] {
  if (!view) return [];
  const out = new Map<string, MemoryScope>();
  for (const i of view.staged ?? []) if (i.namespace) out.set(`${storeName(i.storeKey)}\u0000${i.namespace}`, { store: storeName(i.storeKey), namespace: i.namespace });
  for (const n of view.access.namespaces) if (n && ![...out.values()].some((s) => s.namespace === n)) out.set(`\u0000${n}`, { store: '', namespace: n });
  return [...out.values()];
}

/** Whether a snapshot is of a store/namespace the agent uses (never "any namespace" when none is known). */
export function snapshotInScope(s: MemorySnapshot, scopes: MemoryScope[]): boolean {
  return scopes.some((sc) => sc.namespace === s.namespace && (sc.store === '' || sc.store === storeName(s.storeKey)));
}

/**
 * Clean, unpurged snapshots of the stores/namespaces this agent is known to
 * use, newest first, for the rollback in Restore memory (security). When no
 * namespace of the agent is known, nothing is offered: a rollback must not be
 * pointed at a namespace other agents use.
 */
export async function agentRollbackSnapshots(agentId: string, signal?: AbortSignal): Promise<MemorySnapshot[]> {
  const scopes = memoryScopes(await getAgentMemory(agentId, signal));
  const namespaces = [...new Set(scopes.map((s) => s.namespace))];
  if (namespaces.length === 0) return [];
  const lists = await Promise.all(namespaces.map((n) => listSnapshots(n, signal)));
  const byId = new Map<string, MemorySnapshot>();
  for (const s of lists.flat()) if (s.clean && !s.purgedAt && snapshotInScope(s, scopes)) byId.set(s.snapshotId, s);
  return [...byId.values()].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** The agent's memory access mode (null if the server has no such endpoint). */
export async function getMemoryAccess(agentId: string, signal?: AbortSignal): Promise<MemoryAccess | null> {
  return (await getAgentMemory(agentId, signal))?.access ?? null;
}

/** GET /v1/memory/snapshots[?namespace=]. */
export async function listSnapshots(namespace?: string, signal?: AbortSignal): Promise<MemorySnapshot[]> {
  const q = namespace ? `?namespace=${seg(namespace)}` : '';
  const list = normSnapshots(await api.get(`/v1/memory/snapshots${q}`, signal));
  return list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** POST /v1/memory/snapshots/{id}/restore (security): replaces the namespace; a pre-restore snapshot is taken first. */
export async function restoreSnapshot(snapshotId: string, reason: string): Promise<MemoryRestoreResult> {
  return normMemoryRestoreResult(await api.post(`/v1/memory/snapshots/${seg(snapshotId)}/restore`, { reason }));
}

/** GET /v1/memory/items?agent_id=&staged=true (null if the server has no such endpoint). */
export async function listStagedItems(agentId: string, signal?: AbortSignal): Promise<MemoryItem[] | null> {
  return optional(async () => normMemoryItems(await api.get(`/v1/memory/items?agent_id=${seg(agentId)}&staged=true&limit=200`, signal)));
}

/** The path of one memory item: /v1/memory/items/{store}/{namespace}/{id} (store name without "memory:"). */
function memoryItemPath(item: Pick<MemoryItem, 'id' | 'storeKey' | 'namespace'>): string {
  const store = (item.storeKey ?? '').replace(/^memory:/, '');
  if (!store || !item.namespace) throw new Error('This item does not say which memory store and namespace it is in.');
  return `/v1/memory/items/${seg(store)}/${seg(item.namespace)}/${seg(item.id)}`;
}

/** True when the item names its store and namespace (needed to flag or drop it). */
export function memoryItemAddressable(item: Pick<MemoryItem, 'storeKey' | 'namespace'>): boolean {
  return Boolean((item.storeKey ?? '').replace(/^memory:/, '') && item.namespace);
}

/** POST /v1/memory/items/{store}/{namespace}/{id}/flag {reason}: stops the item's promotion (security or the writer's owner). */
export async function flagMemoryItem(item: Pick<MemoryItem, 'id' | 'storeKey' | 'namespace'>, reason: string): Promise<MemoryFlagResult> {
  return normMemoryFlagResult(await api.post(`${memoryItemPath(item)}/flag`, { reason }));
}

/** POST /v1/memory/items/{store}/{namespace}/{id}/drop {reason}: drops a staged item (security or the writer's owner). */
export async function dropMemoryItem(item: Pick<MemoryItem, 'id' | 'storeKey' | 'namespace'>, reason: string): Promise<unknown> {
  return api.post(`${memoryItemPath(item)}/drop`, { reason });
}

// --- Phase 4: undo list (§5) -------------------------------------------------------------

export async function listUndo(agentId = '', signal?: AbortSignal): Promise<UndoEntry[]> {
  const q = `limit=500${agentId ? `&agent_id=${seg(agentId)}` : ''}`;
  const list = normUndoList(await api.get(`/v1/undo?${q}`, signal));
  return list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** POST /v1/undo/{action_id} (security). */
export async function runUndo(actionId: string, reason: string): Promise<UndoRunResult> {
  return normUndoRunResult(await api.post(`/v1/undo/${seg(actionId)}`, { reason }));
}

// --- Phase 4: Command Center (§6) ----------------------------------------------------------

/** Page size for the Command Center's action queries; a full page means "at least this many". */
export const CC_ACTIONS_LIMIT = 1000;

export interface CommandCenterData {
  agents: Agent[];
  pendingApprovals: number;
  /** Denied actions today (from the newest CC_ACTIONS_LIMIT denials). */
  blockedToday: number;
  blockedCapped: boolean;
  /** Red actions (newest first), for the radar's dangerous verbs. */
  redActions: ActionRow[];
  /** Agents with memory access cut; null when the containment history is unavailable. */
  memoryQuarantined: Set<string> | null;
  /** Swarms not yet released or killed; null when the swarms API is unavailable (older server or role). */
  activeSwarms: Swarm[] | null;
  /** Shadow findings flagged for revocation; null when the shadow API is unavailable. */
  shadowFlagged: number | null;
}

/** null for a route this server does not have (404/405/501) or the role may not read (403). */
function unavailable<T>(p: Promise<T>): Promise<T | null> {
  return p.catch((e: unknown) => {
    if (e instanceof ApiError && (notImplemented(e) || e.status === 403)) return null;
    throw e;
  });
}

export async function loadCommandCenter(signal?: AbortSignal, now: number = Date.now()): Promise<CommandCenterData> {
  const [agentsRaw, heldRaw, deniedRaw, redRaw, ops, swarms, shadow] = await Promise.all([
    api.get('/v1/agents', signal),
    api.get('/v1/held?status=pending&limit=1000', signal),
    api.get(`/v1/actions?decision=deny&limit=${CC_ACTIONS_LIMIT}`, signal),
    api.get(`/v1/actions?class=red&limit=${CC_ACTIONS_LIMIT}`, signal),
    listContainment({ limit: 500 }, signal).catch((e: unknown) => {
      // Older server (no containment API) or a role that cannot read it: the tile shows "—".
      if (e instanceof ApiError && (notImplemented(e) || e.status === 403)) return null;
      throw e;
    }),
    unavailable(listSwarms('', signal)),
    unavailable(listShadow('flagged_for_revocation', signal)),
  ]);
  const agents = normAgents(agentsRaw);
  const denied = normActions(deniedRaw);
  return {
    agents,
    pendingApprovals: normHeldList(heldRaw).length,
    blockedToday: countBlockedToday(denied, now),
    blockedCapped: denied.length >= CC_ACTIONS_LIMIT,
    redActions: normActions(redRaw),
    memoryQuarantined: quarantinedFromAgents(agents) ?? (ops ? memoryQuarantined(ops, agents) : null),
    activeSwarms: swarms ? swarms.filter((x) => swarmActive(x.state)) : null,
    shadowFlagged: shadow ? shadow.length : null,
  };
}

export interface Incident {
  latest: ActionRow;
  chain: ActionRow[];
}

/** The latest red decision and the same agent's preceding actions (null = no red decision yet). */
export async function loadIncident(signal?: AbortSignal): Promise<Incident | null> {
  const latest = normActions(await api.get('/v1/actions?class=red&limit=1', signal))[0];
  if (!latest) return null;
  const history = latest.agentId ? await listActions(latest.agentId, 50, signal) : [];
  return { latest, chain: incidentChain(latest, history) };
}

/** Recent Diary entries for the live feed's first paint (GET /v1/diary, auditor), newest first. */
export async function recentDiary(minutes: number, max: number, signal?: AbortSignal, now: number = Date.now()): Promise<DiaryEvent[]> {
  const from = new Date(now - minutes * 60_000).toISOString();
  const raw = await api.get<{ entries?: unknown }>(`/v1/diary?from=${seg(from)}&limit=5000`, signal);
  const entries = raw && Array.isArray(raw.entries) ? raw.entries : [];
  return entries
    .map(normDiaryEntry)
    .filter((e): e is DiaryEvent => e !== null)
    .sort((a, b) => b.seq - a.seq)
    .slice(0, max);
}

// --- Phase 5: action detail (Diary links) ---------------------------------------------------

export interface ActionDetail {
  action: ActionRow;
  /** Diary entries that name this action (data.action_id), oldest first; null when the Diary is not readable. */
  diary: DiaryEvent[] | null;
}

/** GET /v1/actions/{id} plus the Diary entries that mention it (GET /v1/diary around its time). */
export async function getActionDetail(actionId: string, signal?: AbortSignal): Promise<ActionDetail> {
  const [action] = normActions({ actions: [await api.get(`/v1/actions/${seg(actionId)}`, signal)] });
  if (!action) throw new ApiError(404, 'action not found');
  let diary: DiaryEvent[] | null = null;
  const t = Date.parse(action.ts);
  try {
    const p = new URLSearchParams();
    if (action.agentId) p.set('agent_id', action.agentId);
    if (Number.isFinite(t)) {
      p.set('from', new Date(t - 60_000).toISOString());
      p.set('to', new Date(t + 24 * 3600_000).toISOString());
    }
    p.set('limit', '5000');
    const raw = await api.get<{ entries?: unknown }>(`/v1/diary?${p.toString()}`, signal);
    const entries = raw && Array.isArray(raw.entries) ? raw.entries : [];
    diary = entries
      .map(normDiaryEntry)
      .filter((e): e is DiaryEvent => e !== null && (e.data.action_id === actionId || (Array.isArray(e.data.action_ids) && e.data.action_ids.includes(actionId))))
      .sort((a, b) => a.seq - b.seq);
  } catch (e) {
    if (!(e instanceof ApiError) || (e.status !== 403 && !notImplemented(e))) throw e;
  }
  return { action, diary };
}

// --- Phase 5: approval queue (docs/PHASE5_DESIGN.md §5) ---------------------------------------

/** The server's page cap (internal/approvals QueueMaxLimit); larger values are refused with 400. */
export const QUEUE_PAGE = 500;
/** Pages fetched at most (QUEUE_PAGE each); the rest stays reachable through the filters. */
const QUEUE_MAX_PAGES = 4;

/** The query string GET /v1/approvals/queue is called with. */
export function queueParams(q: QueueQuery, offset = 0): string {
  const p = new URLSearchParams();
  if (q.status) p.set('status', q.status);
  if (q.agentId) p.set('agent_id', q.agentId);
  if (q.swarmId) p.set('swarm_id', q.swarmId);
  if (q.ruleId) p.set('rule_id', q.ruleId);
  if (q.class) p.set('class', q.class);
  if (q.assignedTo) p.set('assigned_to', q.assignedTo);
  if (q.sort) p.set('sort', q.sort);
  p.set('limit', String(QUEUE_PAGE));
  if (offset > 0) p.set('offset', String(offset));
  return p.toString();
}

/**
 * GET /v1/approvals/queue with the filters. On a server without the Phase 5
 * queue (404/405) the Phase 3 /v1/held list is used instead; the caller
 * filters both the same way, so the page keeps working.
 */
export async function loadQueue(q: QueueQuery, signal?: AbortSignal): Promise<QueueResult> {
  try {
    const items: QueueItem[] = [];
    let offset: number | null = 0;
    for (let page = 0; page < QUEUE_MAX_PAGES && offset !== null; page++) {
      const raw: unknown = await api.get(`/v1/approvals/queue?${queueParams(q, offset)}`, signal);
      items.push(...normQueue(raw));
      const next = raw && typeof raw === 'object' ? (raw as { next_offset?: unknown }).next_offset : null;
      offset = typeof next === 'number' && next > offset ? next : null;
    }
    return { items, source: 'queue' };
  } catch (e) {
    if (!notImplemented(e)) throw e;
  }
  const raw = await api.get(`/v1/held?status=${seg(q.status || 'pending')}&limit=1000`, signal);
  return { items: normQueue(raw), source: 'held' };
}

/** POST /v1/held/{id}/assign {assignee} (security). */
export async function assignHeld(actionId: string, assignee: string): Promise<QueueItem | null> {
  const r = await api.post<unknown>(`/v1/held/${seg(actionId)}/assign`, { assignee });
  const [item] = normQueue({ items: [r] });
  return item ?? null;
}

/** POST /v1/held/bulk-deny {action_ids, reason} (security): each id is decided and recorded on its own. */
export async function bulkDeny(actionIds: string[], reason: string): Promise<BulkDenyOutcome[]> {
  try {
    return normBulkDeny(await api.post('/v1/held/bulk-deny', { action_ids: actionIds, reason }), actionIds);
  } catch (e) {
    // A partial failure may still report each id.
    if (e instanceof ApiError && e.body && typeof e.body === 'object' && 'results' in e.body) return normBulkDeny(e.body, actionIds);
    throw e;
  }
}

// --- Phase 5: swarms (§1) ------------------------------------------------------------------

export async function listSwarms(state = '', signal?: AbortSignal): Promise<Swarm[]> {
  const list = normSwarms(await api.get(`/v1/swarms${state ? `?state=${seg(state)}` : ''}`, signal));
  return list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

export async function getSwarm(id: string, signal?: AbortSignal): Promise<SwarmDetail> {
  return normSwarmDetail(await api.get(`/v1/swarms/${seg(id)}`, signal));
}

/**
 * POST /v1/swarms/{id}/trip | suspend | isolate | kill (security). Each is a
 * containment op with per-member steps; kill also sends keep_root_read_only.
 * A reply without an op is shown as "no steps reported", never as done.
 */
export async function swarmOp(id: string, op: SwarmOp, reason: string, keepRootReadOnly?: boolean): Promise<ContainmentOp> {
  const body: Record<string, unknown> = { reason };
  if (op === 'kill') body.keep_root_read_only = keepRootReadOnly ?? true;
  const path = `/v1/swarms/${seg(id)}/${op}`;
  try {
    const raw = await api.post<unknown>(path, body);
    if (opBody(raw)) return normContainmentOp(raw);
    return { opId: '', op: op === 'kill' ? 'kill_swarm' : op, targetType: 'swarm', targetId: id, actor: '', reason, status: 'unknown', steps: [], createdAt: '' };
  } catch (e) {
    if (e instanceof ApiError && opBody(e.body)) return { ...normContainmentOp(e.body), httpError: e.message };
    throw e;
  }
}

/** POST /v1/swarms/{id}/release {reason}: the first vote returns {released: false, votes: 1, required: 2}. */
export async function releaseSwarm(id: string, reason: string): Promise<SwarmReleaseResult> {
  return normSwarmRelease(await api.post(`/v1/swarms/${seg(id)}/release`, { reason }));
}

/** GET /v1/swarms/{id}/bundle: the sealed bundle, byte-for-byte (it is signed). */
export async function swarmBundle(id: string): Promise<{ text: string; contentType: string }> {
  return requestText(`/v1/swarms/${seg(id)}/bundle`);
}

// --- Phase 5: communication map (§2) ----------------------------------------------------------

export function mapParams(q: MapQuery): string {
  const p = new URLSearchParams();
  p.set('view', q.view);
  if (q.id) p.set('id', q.id);
  if (q.from) p.set('from', q.from);
  if (q.to) p.set('to', q.to);
  return p.toString();
}

/** GET /v1/map?view=&id=&from=&to= (auditor). */
export async function getMap(q: MapQuery, signal?: AbortSignal): Promise<CommMap> {
  return normMap(await api.get(`/v1/map?${mapParams(q)}`, signal));
}

/** GET /v1/map/path?label=&dest=&from=&to= (auditor). */
export async function tracePath(label: string, dest: string, from?: string, to?: string, signal?: AbortSignal): Promise<PathHop[]> {
  const p = new URLSearchParams({ label, dest });
  if (from) p.set('from', from);
  if (to) p.set('to', to);
  return normPathHops(await api.get(`/v1/map/path?${p.toString()}`, signal));
}

/** SSE stream of edge.updated and swarm.updated (GET /v1/map/live). */
export const MAP_LIVE_URL = '/v1/map/live';

// --- Phase 5: shadow agents (§3) ----------------------------------------------------------------

export async function listShadow(status = '', signal?: AbortSignal): Promise<ShadowFinding[]> {
  const list = normShadowFindings(await api.get(`/v1/shadow${status ? `?status=${seg(status)}` : ''}`, signal));
  return list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
}

/** POST /v1/shadow/scan (security). Returns the raw summary facts the server reports. */
export async function scanShadow(): Promise<Record<string, unknown>> {
  const r = await api.post<unknown>('/v1/shadow/scan', {});
  return r && typeof r === 'object' && !Array.isArray(r) ? (r as Record<string, unknown>) : {};
}

export type ShadowAction = 'revoke' | 'dismiss';

/**
 * What a revoke or dismiss achieved. The server answers 200 for every revoke
 * outcome (revoked | not_revoked | manual_required), so `revoked` is true only
 * when the server says the credential was revoked; never assume it.
 */
export interface ShadowActionResult {
  finding: ShadowFinding | null;
  outcome: string;
  revoked: boolean;
  detail: string;
}

/** POST /v1/shadow/{id}/revoke | dismiss (security). */
export async function shadowAction(id: string, action: ShadowAction): Promise<ShadowActionResult> {
  const r = await api.post<unknown>(`/v1/shadow/${seg(id)}/${action}`, {});
  const o = r && typeof r === 'object' && !Array.isArray(r) ? (r as Record<string, unknown>) : {};
  const f = normShadowFinding('finding' in o ? o.finding : r);
  const finding = f.findingId ? f : null;
  const outcome = typeof o.outcome === 'string' ? o.outcome : '';
  const detail = typeof o.detail === 'string' ? o.detail : '';
  return { finding, outcome, revoked: action === 'revoke' && o.revoked === true, detail };
}

/** POST /v1/shadow/{id}/register {sponsor, name, team} (security). */
export async function registerShadow(id: string, reg: ShadowRegistration): Promise<ShadowFinding | null> {
  const r = await api.post<unknown>(`/v1/shadow/${seg(id)}/register`, { sponsor: reg.sponsor, name: reg.name, team: reg.team });
  const f = normShadowFinding(r && typeof r === 'object' && 'finding' in r ? (r as { finding: unknown }).finding : r);
  return f.findingId ? f : null;
}

// --- Phase 5: baselines (§4) --------------------------------------------------------------------

/** GET /v1/agents/{id}/baseline?verb= (auditor); null when the server has no baselines. */
export async function getBaseline(agentId: string, verb: string, signal?: AbortSignal): Promise<Baseline | null> {
  return optional(async () => normBaseline(await api.get(`/v1/agents/${seg(agentId)}/baseline${verb ? `?verb=${seg(verb)}` : ''}`, signal), agentId, verb));
}

/** Class filter values the queue understands. */
/** (The server refuses class=blue: an above-normal action is held as yellow by POL-660; filter on that rule instead.) */
export const QUEUE_CLASSES: ActionClass[] = ['red', 'yellow', 'green'];
