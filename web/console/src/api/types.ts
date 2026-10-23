// Shapes the console works with. Server responses are normalised into these
// by api/normalize.ts, which tolerates missing optional fields so the console
// keeps working against older (Phase 1) servers and degrades to "—" rather
// than crashing.

export type Level = 'FULL' | 'SUPERVISED' | 'READ_ONLY' | 'ISOLATED' | 'QUARANTINED' | 'KILLED';

/** Policy classes. "blue" (above baseline) arrives with behaviour baselining; it is accepted already. */
export type ActionClass = 'green' | 'blue' | 'yellow' | 'red';

export type Decision = 'allow' | 'allow_reduced' | 'hold' | 'deny';

export type Role = 'admin' | 'security' | 'auditor' | 'interceptor';

export interface Me {
  kind: string;
  email: string;
  name: string;
  roles: string[];
  authMethod: string;
  csrf: string;
  expiresAt?: string;
  devLoginEnabled: boolean;
  oidcEnabled: boolean;
}

export interface AuthConfig {
  oidcEnabled: boolean;
  devLoginEnabled: boolean;
  devUsers: { email: string; name?: string; roles: string[] }[];
}

export interface Agent {
  agentId: string;
  name: string;
  type: string;
  platform: string;
  sponsor: string;
  businessUnit: string;
  workspaceUser: string;
  copyCap: number | null;
  level: Level;
  levelChangedAt?: string;
  discovered: boolean;
  /** Present when the server computes per-agent activity; else filled from /v1/actions. */
  actionsToday?: number;
  worstClass24h?: ActionClass | null;
  systems24h?: string[];
  /** Pending held actions (from the server's agent view). */
  heldPending?: number;
  status?: string;
  /** Phase 4 suspension (reversible, beside the level). undefined = the server does not report it. */
  suspended?: boolean;
  suspendedAt?: string;
  suspendedBy?: string;
  suspendedReason?: string;
  /** Phase 4 memory access (memory_access; default full); undefined when the server does not report it. */
  memoryAccess?: 'full' | 'staging_only' | 'none';
  /** Actor that last changed the memory access (memory_access.changed_by), e.g. "user:<email>" or "estop:<op>". */
  memoryAccessChangedBy?: string;
}

/** GET /v1/agents/{id}: the agent plus 24h counts, pending holds and readiness. */
export interface AgentDetail {
  agent: Agent;
  counts24h: Record<ActionClass, number>;
  held: HeldAction[];
  /** Current access profile version per system (absent = no profile). */
  profileVersions: Partial<Record<AccessSystem, number>>;
  /** Integration key → status. */
  integrations: Record<string, string>;
  tokenIssued: boolean | null;
}

export interface Summary {
  totalAgents: number;
  actionsToday: number;
  heldPending: number;
  redToday: number;
  agentsNotFull: number;
  /** Optional sparkline series (hourly counts, oldest first). */
  actionsHourly?: number[];
  /** Today's actions by class, when the server provides it. */
  byClassToday?: Record<ActionClass, number>;
}

export interface ActionRow {
  actionId: string;
  agentId: string;
  system: string;
  verb: string;
  class: ActionClass;
  decision: Decision | string;
  ruleId: string;
  reason: string;
  reversible: boolean;
  source: string;
  ts: string;
  failClosed: boolean;
  held: boolean;
  undo?: { kind: string; status: string } | null;
}

export interface HeldAction {
  actionId: string;
  agentId: string;
  ruleId: string;
  reason: string;
  class: ActionClass;
  decision: string;
  system: string;
  verb: string;
  safeForm: string;
  outcome: string;
  createdAt: string;
  expiresAt?: string;
  levelAtDecision?: string;
  undoAvailable: boolean;
  approverRole?: string;
  approvalsRequired?: number;
}

export interface AgentStats {
  hours: number;
  byClass: Record<ActionClass, number>;
  byVerb: Record<string, number>;
  /** Count per hour bucket, oldest first, length == hours. */
  hourly: number[];
  /** Worst class per hour bucket (null = no actions), aligned with hourly. */
  hourlyWorst: (ActionClass | null)[];
  /** Start of each hour bucket (ISO), aligned with hourly; empty if unknown. */
  hourStarts: string[];
  total: number;
}

export interface ProfileView {
  system: AccessSystem;
  version: number;
  profile: unknown;
  changedBy?: string;
  changedAt?: string;
  reason?: string;
}

export type AccessSystem = 'gmail' | 'drive' | 'github' | 'aws' | 'postgres' | 'a2a' | 'http' | 'mcp';
export const ACCESS_SYSTEMS: AccessSystem[] = ['gmail', 'drive', 'github', 'aws', 'postgres', 'a2a', 'http', 'mcp'];

export interface SchemaField {
  key: string;
  label: string;
  type: 'text' | 'textarea' | 'password' | 'list' | 'select' | 'number' | 'bool';
  secret: boolean;
  required: boolean;
  help?: string;
  options?: string[];
  default?: unknown;
}

export interface IntegrationSchema {
  system: string;
  title: string;
  multi: boolean;
  fields: SchemaField[];
}

export type IntegrationStatus = 'unconfigured' | 'configured' | 'ok' | 'error';

export interface Integration {
  key: string;
  system: string;
  config: Record<string, unknown>;
  secretFields: string[];
  secrets: Record<string, { set: boolean }>;
  status: IntegrationStatus;
  lastTestedAt?: string;
  lastError?: string;
  updatedBy?: string;
  updatedAt?: string;
  testAvailable: boolean;
}

export interface TestResult {
  ok: boolean;
  error?: string;
  durationMs?: number;
  integration?: Integration;
}

/** One committed Diary entry from the SSE stream. */
export interface DiaryEvent {
  seq: number;
  ts: string;
  agentId?: string;
  eventType: string;
  data: Record<string, unknown>;
}

export interface NewAgent {
  agent_id: string;
  name: string;
  type: string;
  platform: string;
  sponsor: string;
  business_unit: string;
  workspace_user: string;
  copy_cap: number;
}

// --- Phase 3 (docs/PHASE3_DESIGN.md) ----------------------------------------------

/** Systems an app suspension may target (§5). */
export type OverrideSystem = 'gmail' | 'drive' | 'github' | 'aws' | 'postgres';
export const OVERRIDE_SYSTEMS: OverrideSystem[] = ['gmail', 'drive', 'github', 'aws', 'postgres'];
export type OverrideMode = 'suspended' | 'read_only';

/** internal/overrides.Override. */
export interface Override {
  overrideId: string;
  scope: string;
  scopeId: string;
  system: string;
  mode: OverrideMode;
  startsAt: string;
  /** Absent = until released. */
  expiresAt?: string;
  reason: string;
  createdBy: string;
  /** active | restored | released | blocked | superseded */
  status: string;
  restoredAt?: string;
  blockedReason?: string;
  /** Per-system credential revocation result (summary strings only). */
  revokeResult?: Record<string, string>;
}

export interface NewOverride {
  scope: 'agent';
  scope_id: string;
  system: OverrideSystem;
  mode: OverrideMode;
  duration_seconds?: number;
  until_released?: boolean;
  reason: string;
}

/** internal/population.Instance. */
export interface Instance {
  instanceId: string;
  agentId: string;
  host: string;
  parentInstanceId?: string;
  startedAt: string;
  lastHeartbeat: string;
  /** live | paused | stopped | refused | stale */
  status: string;
  reason?: string;
  newHost: boolean;
}

export interface InstancesView {
  instances: Instance[];
  live: number;
  copyCap: number | null;
}

/** internal/population.AgentType. */
export interface AgentType {
  type: string;
  expectedMaxInstances: number;
  maxAgents: number;
  spawnRatePerMin: number;
  actionRatePerMin: number;
}

export type Severity = 'info' | 'warning' | 'high' | 'critical';
export type AlertStatus = 'open' | 'acknowledged' | 'resolved';

/** internal/alerts.Alert (details are shown as a summary, never raw payloads). */
export interface Alert {
  alertId: string;
  kind: string;
  severity: Severity;
  agentId?: string;
  agentType?: string;
  actionId?: string;
  summary: string;
  count: number;
  status: AlertStatus;
  createdAt: string;
  updatedAt: string;
  ackedBy?: string;
}

/**
 * A delegation hop (internal/delegation.Hop from GET /v1/agents/{id}/delegations,
 * or rebuilt from delegation.opened / delegation.closed Diary events).
 */
export interface Hop {
  delegationId: string;
  root: string;
  from: string;
  to: string;
  /** root ... delegatee */
  chain: string[];
  depth: number;
  /** a2a | mcp | spawn | hook_task */
  channel: string;
  /** open | closed | expired | refused */
  status: string;
  openedAt: string;
  expiresAt?: string;
  closedAt?: string;
  taskId?: string;
  actionId?: string;
}

/** A blocked delegation (POL-601..604): the agent executed or was upstream. */
export interface BlockedDelegation {
  /** Diary seq when known (Diary source), else 0. */
  seq: number;
  ts: string;
  actionId: string;
  ruleId: string;
  reason: string;
  executor: string;
  root: string;
  /** The full chain for display: upstream agents (root first), then the executor. */
  chain: string[];
  system: string;
  verb: string;
  /** POL-601: an upstream agent tried to get done what it may not do itself. */
  bypass: boolean;
  /** Originating agents stepped down because of this attempt (POL-601 only). */
  steppedDown: string[];
  originLevel: string;
}

export interface DelegationView {
  inbound: Hop[];
  outbound: Hop[];
  /** Newest first; bypass attempts are flagged with bypass = true. */
  blocked: BlockedDelegation[];
  /** Where the hops came from: the dedicated endpoint, or the Diary fallback. */
  source: 'api' | 'diary';
}

/** internal/approvals.Decision. */
export interface ApprovalResult {
  actionId: string;
  outcome: string;
  approvals: number;
  approvalsRequired: number;
  grantExpiresAt?: string;
  safeFormTrashTable?: string;
}

// --- Phase 4: containment (docs/PHASE4_DESIGN.md) ------------------------------------

/** containment.Op* (matches the containment_ops CHECK constraint). */
export type ContainmentOpName =
  | 'suspend'
  | 'resume'
  | 'isolate'
  | 'kill'
  | 'estop'
  | 'estop_release'
  | 'memory_remove'
  | 'memory_restore'
  | 'cancel_queue';

export type ContainmentTarget = 'instance' | 'agent' | 'team' | 'fleet';

/** Per-step outcome. Anything the server sends outside done/skipped/failed is shown as "unknown", never as done. */
export type StepStatus = 'done' | 'skipped' | 'failed' | 'unknown';

/** containment.Step: one ordered step and what it actually achieved. */
export interface ContainmentStep {
  name: string;
  agentId?: string;
  status: StepStatus;
  /** Honest semantics from the server (e.g. "STS tokens not recallable; deny-by-issue-time attached"). */
  detail?: string;
  durationMs: number;
}

/** Overall op status; unknown values become "unknown" (shown as not done). */
export type OpStatus = 'running' | 'done' | 'partial' | 'failed' | 'unknown';

/** containment.Op: one containment operation with its steps. */
export interface ContainmentOp {
  opId: string;
  op: ContainmentOpName | string;
  targetType: ContainmentTarget | string;
  targetId: string;
  actor: string;
  reason: string;
  status: OpStatus;
  steps: ContainmentStep[];
  createdAt: string;
  finishedAt?: string;
  /** Set when the server answered with an error status but still reported the op (partial or failed run). */
  httpError?: string;
}

/** memory.Access* modes. */
export type MemoryMode = 'full' | 'staging_only' | 'none';

/** An agent's memory access (memory_access row; default full). */
export interface MemoryAccess {
  mode: MemoryMode;
  reason?: string;
  changedBy?: string;
  changedAt?: string;
  /** Memory namespaces the agent writes to, when the server reports them. */
  namespaces: string[];
}

/** POST /v1/memory/snapshots/{id}/restore: what the restore did (memory.RestoreResult). */
export interface MemoryRestoreResult {
  restored: number;
  /** The namespace as it stood before (never clean); restore it to undo this restore. */
  preRestoreSnapshotId?: string;
  /** Items of the snapshot removed on purpose since (undo, drop, delete): not restored. */
  skippedRemovedItems: string[];
  /** Restored staged items held for review (not promoted until a fresh review window). */
  heldForReview: string[];
  /** Staging undo handles of writes the restore removed. */
  undoHandlesClosed: string[];
}

/** POST /v1/memory/items/.../flag: what flagging did (memory.FlagResult). */
export interface MemoryFlagResult {
  snapshotsMarkedUnclean: string[];
  promotionStopped: boolean;
  alreadyPromoted: boolean;
  /** The snapshots holding the item could not be determined, so every candidate was marked unclean. */
  snapshotCheckError?: string;
}

/** memory_snapshots row (a pointer: the data stays in the customer's store). */
export interface MemorySnapshot {
  snapshotId: string;
  storeKey: string;
  namespace: string;
  itemCount: number;
  clean: boolean;
  createdBy: string;
  reason: string;
  createdAt: string;
  expiresAt?: string;
  purgedAt?: string;
}

/** memory.Item as listed for review (content shown as a short preview only). */
export interface MemoryItem {
  id: string;
  namespace: string;
  storeKey?: string;
  contentPreview: string;
  agentId: string;
  staged: boolean;
  flagged: boolean;
  createdAt: string;
  /** When it is promoted; absent while it is held for review (no review window scheduled yet). */
  promoteAt?: string;
  /** Held for review (hold_reason / held_for_review): not promoted until a review window opens. */
  holdReason?: string;
  /** The write's action id: its memory_staging undo handle (Drop = undo). */
  actionId?: string;
  /** Data labels on the write (e.g. pii), when reported. */
  labels: string[];
}

/** GET /v1/agents/{id}/memory: the agent detail memory panel (memory.AgentMemory). */
export interface AgentMemoryView {
  access: MemoryAccess;
  /** The agent's staged items in every store; null when this server does not include them. */
  staged: MemoryItem[] | null;
  /** Stores that could not be read (store -> sanitized message): reported, never hidden. */
  storeErrors: Record<string, string>;
}

/** GET /v1/undo entry: an undo handle plus whether Undo can run, why not, and what it does. */
export interface UndoEntry {
  actionId: string;
  agentId: string;
  kind: string;
  status: string;
  createdAt: string;
  expiresAt?: string;
  usedAt?: string;
  usedBy?: string;
  error?: string;
  undoable: boolean;
  whyNot?: string;
  description: string;
}

/** POST /v1/undo/{id} result. */
export interface UndoRunResult {
  actionId: string;
  kind: string;
  status: string;
}

/** The typed confirmation the server requires for a fleet e-stop. */
export const ESTOP_PHRASE = 'STOP ALL AGENTS';

// --- Phase 5: swarms, communication map, shadow agents, baselines, approval queue -----
// (docs/PHASE5_DESIGN.md §1-§6)

/** A vote on a held action or a swarm release. */
export interface Vote {
  approver: string;
  decision: string;
  at: string;
  reason?: string;
}

/** A held action as the full approval queue returns it (§5). */
export interface QueueItem extends HeldAction {
  votes: Vote[];
  /** Distinct approve votes so far (from votes when the server does not count them). */
  approvals: number;
  swarmId?: string;
  /** The swarm group label the server attaches, when any. */
  group?: string;
  assignedTo?: string;
}

export interface QueueQuery {
  status?: string;
  agentId?: string;
  swarmId?: string;
  ruleId?: string;
  class?: string;
  assignedTo?: string;
  sort?: QueueSort;
}

export type QueueSort = 'newest' | 'oldest' | 'expires' | 'severity';

export interface QueueResult {
  items: QueueItem[];
  /** Where the list came from: the Phase 5 queue, or the Phase 3 /v1/held fallback. */
  source: 'queue' | 'held';
}

/** One id's outcome in POST /v1/held/bulk-deny (each id is decided on its own). */
export interface BulkDenyOutcome {
  actionId: string;
  ok: boolean;
  outcome: string;
  error?: string;
}

/** Swarm detection signals (§1). */
export type SwarmSignalKind = 'action_hash' | 'spawn_tree' | 'copy_surge' | 'converging_targets' | string;

export interface SwarmSignal {
  kind: SwarmSignalKind;
  /** Flat, display-only key/value facts about the signal (hash, target, counts…). */
  facts: [string, string][];
}

export interface SwarmMember {
  /** Node id as given: an agent id, or an instance id for a copy. */
  id: string;
  agentId: string;
  instanceId?: string;
  parent?: string;
  role?: string;
  level?: Level;
  status?: string;
  joinedAt?: string;
  depth?: number;
}

export interface SwarmBreaker {
  breakerId: string;
  actionHash: string;
  state: string;
  trippedAt?: string;
  trippedBy?: string;
  releasedAt?: string;
  matched?: number;
}

/** One edge of the spawn tree (parent delegated to / spawned child). */
export interface SpawnEdge {
  parent: string;
  child: string;
  depth?: number;
  delegationId?: string;
}

export interface Swarm {
  swarmId: string;
  /** active | frozen | killed | released | … (unknown values shown as-is). */
  state: string;
  detectedBy: SwarmSignalKind;
  signal: SwarmSignal;
  root?: string;
  memberCount: number;
  createdAt: string;
  updatedAt?: string;
  frozen: boolean;
}

export interface SwarmDetail extends Swarm {
  members: SwarmMember[];
  breakers: SwarmBreaker[];
  held: HeldAction[];
  releaseVotes: Vote[];
  releaseRequired: number;
  spawnTree: SpawnEdge[];
  /** The swarm's own containment ops when the server includes them. */
  ops: ContainmentOp[];
}

export type SwarmOp = 'trip' | 'suspend' | 'isolate' | 'kill';

/** POST /v1/swarms/{id}/release: a first vote, or the release itself. */
export interface SwarmReleaseResult {
  released: boolean;
  votes: number;
  required: number;
  op?: ContainmentOp;
}

// --- Communication map (§2) ---

export type MapNodeKind = 'agent' | 'instance' | 'user' | 'app' | 'store' | 'memory' | 'mcp' | 'domain' | 'swarm' | 'unknown';
export type EdgeClass = 'green' | 'yellow' | 'red' | 'hidden';
export type MapView = 'team' | 'agent' | 'swarm' | 'external' | 'blast';

export interface MapNode {
  id: string;
  kind: MapNodeKind;
  label: string;
  team?: string;
  level?: Level;
  suspended?: boolean;
  discovered?: boolean;
  owner?: string;
  swarmIds: string[];
  /** Blast radius: reachable with the current access profiles (the halo). */
  reachable?: boolean;
}

export interface MapEdge {
  from: string;
  to: string;
  verb: string;
  count: number;
  bytes: number;
  labels: string[];
  sampleActionIds: string[];
  worstClass: EdgeClass;
  windowStart?: string;
  /** Blast radius: a reach (allowed by access) rather than an observed call. */
  reach?: boolean;
}

export interface MapCluster {
  swarmId: string;
  state: string;
  members: string[];
}

export interface CommMap {
  window: { from: string; to: string };
  nodes: MapNode[];
  edges: MapEdge[];
  clusters: MapCluster[];
}

export interface MapQuery {
  view: MapView;
  id?: string;
  from?: string;
  to?: string;
}

export interface PathHop {
  from: string;
  to: string;
  verb: string;
  windowStart?: string;
  actionIds: string[];
}

// --- Shadow agents (§3) ---

export interface ShadowFinding {
  findingId: string;
  system: string;
  kind: string;
  credentialId: string;
  holder: string;
  usedBySoftware: boolean;
  /** Display-only key/value evidence (never secrets: the server stores identifiers only). */
  evidence: [string, string][];
  status: string;
  discoveredAgentId?: string;
  createdAt: string;
  updatedAt?: string;
}

export interface ShadowRegistration {
  sponsor: string;
  name: string;
  team: string;
}

// --- Baselines (§4) ---

export interface BaselinePoint {
  hour: string;
  count: number;
}

export interface Baseline {
  agentId: string;
  verb: string;
  verbs: string[];
  series: BaselinePoint[];
  mean: number | null;
  stddev: number | null;
  median: number | null;
  historyDays: number | null;
  threshold: number | null;
  current: number | null;
  aboveNormal: boolean;
  /** "mean+3sigma" or "5x_median" when the server says which rule set the threshold. */
  method?: string;
  minCount?: number;
}
