// Client-side mirror of the server's authorization rules (docs/PHASE2_DESIGN.md
// §5, §8, §9). It only decides which buttons are enabled and what explanation
// is shown; the server enforces every rule again and its answer wins.

import type { Agent, Level, Me, Override, QueueItem, SwarmDetail, Vote } from '../api/types';
import { approverKey, LEVELS, levelIndex } from '../api/normalize';

export function hasRole(me: Me | null, role: string): boolean {
  if (!me) return false;
  return me.roles.includes(role) || me.roles.includes('admin');
}

/** A user owns an agent when their email equals agents.sponsor (case-insensitive). */
export function isOwner(me: Me | null, agent: Agent | null): boolean {
  if (!me || !agent || me.kind !== 'user') return false;
  return me.email !== '' && agent.sponsor !== '' && me.email.toLowerCase() === agent.sponsor.toLowerCase();
}

export interface LevelPermissions {
  /** Levels strictly below the current one and below KILLED. */
  stepDownTargets: Level[];
  canStepDown: boolean;
  stepDownWhy?: string;
  /** Exactly one level up (less restrictive), or null at FULL. */
  stepUpTarget: Level | null;
  canStepUp: boolean;
  stepUpWhy?: string;
  canKill: boolean;
  killWhy?: string;
}

export function levelPermissions(me: Me | null, agent: Agent): LevelPermissions {
  const security = hasRole(me, 'security');
  const owner = isOwner(me, agent);
  const cur = levelIndex(agent.level);
  const killed = agent.level === 'KILLED';
  const killIdx = levelIndex('KILLED');

  const stepDownTargets = killed ? [] : LEVELS.filter((_, i) => i > cur && i < killIdx);
  const stepUpTarget = cur > 0 ? (LEVELS[cur - 1] as Level) : null;
  const p: LevelPermissions = {
    stepDownTargets,
    canStepDown: false,
    stepUpTarget,
    canStepUp: false,
    canKill: false,
  };

  if (killed) p.stepDownWhy = 'The agent is KILLED; nothing is below it.';
  else if (stepDownTargets.length === 0) p.stepDownWhy = 'Only KILLED is below this level; use Kill.';
  else if (!security && !owner) p.stepDownWhy = 'Requires the security role or ownership of this agent.';
  else p.canStepDown = true;

  if (!stepUpTarget) p.stepUpWhy = 'The agent is already at FULL.';
  else if (killed && !security) p.stepUpWhy = 'Leaving KILLED requires the security role.';
  else if (!security && !owner) p.stepUpWhy = 'Requires the security role or ownership of this agent.';
  else p.canStepUp = true;

  if (killed) p.killWhy = 'The agent is already KILLED.';
  else if (!security) p.killWhy = 'Killing an agent requires the security role.';
  else p.canKill = true;
  return p;
}

/** Whether the user may edit access profiles at all (owners: narrowing only, enforced by the server). */
export function accessEditMode(me: Me | null, agent: Agent | null): 'full' | 'narrow' | 'none' {
  if (hasRole(me, 'security')) return 'full';
  if (isOwner(me, agent)) return 'narrow';
  return 'none';
}

/** The audit actor string the server records for the signed-in user (authz.Principal.Actor). */
export function actorOf(me: Me | null): string {
  if (!me || me.kind !== 'user' || !me.email) return '';
  return `user:${me.email}`;
}

export interface OverridePermissions {
  canRelease: boolean;
  releaseWhy?: string;
  canExtend: boolean;
  extendWhy?: string;
  canPermanent: boolean;
  permanentWhy?: string;
}

/**
 * Mirrors internal/overrides: security may change any override; the agent's
 * owner may extend or make permanent an agent-scope override on their agent,
 * but may only release one they created themselves. Team overrides need
 * security. Extend needs a timed, active override; Make permanent needs one
 * that is timed or blocked.
 */
export function overridePermissions(me: Me | null, agent: Agent, o: Override): OverridePermissions {
  const security = hasRole(me, 'security');
  const owner = isOwner(me, agent);
  const p: OverridePermissions = { canRelease: false, canExtend: false, canPermanent: false };
  let who: string | undefined;
  if (!security && o.scope !== 'agent') who = 'Team suspensions require the security role.';
  else if (!security && !owner) who = 'Requires the security role or ownership of this agent.';

  if (who) p.releaseWhy = who;
  else if (!security && o.createdBy !== actorOf(me)) p.releaseWhy = "Lifting someone else's suspension requires the security role.";
  else p.canRelease = true;

  if (who) p.extendWhy = who;
  else if (o.status === 'blocked') p.extendWhy = 'Automatic restore was blocked: release it or make it permanent.';
  else if (!o.expiresAt) p.extendWhy = 'Already in force until released.';
  else p.canExtend = true;

  if (who) p.permanentWhy = who;
  else if (o.status === 'active' && !o.expiresAt) p.permanentWhy = 'Already in force until released.';
  else p.canPermanent = true;
  return p;
}

// --- Phase 4: containment (docs/PHASE4_DESIGN.md §1 roles) -----------------------------

/** A button's state: enabled, or disabled with the reason shown to the user. */
export interface Permit {
  ok: boolean;
  why?: string;
}

const allow: Permit = { ok: true };
const deny = (why: string): Permit => ({ ok: false, why });

export const WHY_SECURITY_OR_OWNER = 'Requires the security role or ownership of this agent.';
export const WHY_SECURITY = 'Requires the security role.';

/** suspended_by prefix of agents suspended by a fleet e-stop (internal/containment estopMarker). */
export const ESTOP_SUSPENDED_BY = 'estop:';

export interface ContainmentPermissions {
  suspend: Permit;
  resume: Permit;
  isolate: Permit;
  kill: Permit;
  memoryRemove: Permit;
  memoryRestore: Permit;
  cancelQueue: Permit;
  /** DELETE /v1/agents/{id}/tokens (security). */
  revokeTokens: Permit;
  /** Narrow the Gmail profile to send "none" (security, or the owner: narrowing only). */
  disableSend: Permit;
  /** Restore a memory snapshot (security). */
  restoreSnapshot: Permit;
  /** Roll back to a snapshot as part of Restore memory (memory_restore with rollback_snapshot_id: security, D1). */
  rollbackSnapshot: Permit;
  /** Flag a staged memory item (security or owner). */
  flagItem: Permit;
}

/** Whether the containment was imposed by the signed-in user themselves (D2: actor strings must be equal). */
function imposedByMe(me: Me | null, by: string | undefined): boolean {
  const actor = actorOf(me);
  return actor !== '' && by === actor;
}

/**
 * Mirrors the containment roles: kill, cancel_queue, team ops and the fleet
 * e-stop need security; suspend, resume, isolate and memory remove/restore on
 * one agent need security or that agent's owner. Resuming a KILLED agent is
 * refused (re-enable goes through the level API, security only).
 *
 * D2: an owner without the security role may only lift what they imposed
 * themselves: Resume needs agents.suspended_by, and Restore memory needs
 * memory_access.changed_by, to equal "user:<their email>". A suspension or
 * memory cut imposed by anyone else (security, a fleet e-stop "estop:<op>",
 * the level API / quarantine / kill path, system:*) needs the security role;
 * the server answers 403 otherwise. When the server does not say who imposed
 * it, the console cannot tell, so it treats it as someone else's.
 *
 * D1: rolling memory back to a snapshot as part of Restore memory needs the
 * security role.
 */
export function containmentPermissions(me: Me | null, agent: Agent): ContainmentPermissions {
  const security = hasRole(me, 'security');
  const owner = isOwner(me, agent);
  const either = security || owner ? allow : deny(WHY_SECURITY_OR_OWNER);
  const killPermit = security ? allow : deny('Killing an agent requires the security role.');
  const killed = agent.level === 'KILLED';
  const suspendedBy = agent.suspendedBy ?? '';
  // The containment service records "estop:<op_id>" as suspended_by for agents a fleet e-stop suspended.
  const estopped = agent.suspended === true && suspendedBy.startsWith(ESTOP_SUSPENDED_BY);

  let resume = either;
  if (killed) resume = deny('A KILLED agent cannot be resumed: re-enable it from the Level tab (security role).');
  else if (!security && owner && agent.suspended === true && !imposedByMe(me, agent.suspendedBy)) {
    resume = estopped
      ? deny('This agent was suspended by a fleet e-stop: only the security role may resume it (or Release the e-stop).')
      : deny(`Lifting a suspension imposed by ${suspendedBy || 'someone else'} requires the security role.`);
  }

  let memoryRestore = either;
  const memoryCut = agent.memoryAccess !== undefined && agent.memoryAccess !== 'full';
  if (killed) memoryRestore = deny('Re-enable the agent before restoring its memory access.');
  else if (!security && owner && memoryCut && !imposedByMe(me, agent.memoryAccessChangedBy)) {
    memoryRestore = deny(`Restoring memory access cut by ${agent.memoryAccessChangedBy || 'someone else'} requires the security role.`);
  }

  return {
    suspend: killed ? deny('The agent is KILLED, which already refuses everything.') : either,
    resume,
    isolate: killed ? deny('The agent is KILLED, which is stricter than ISOLATED.') : either,
    kill: killed ? deny('The agent is already KILLED.') : killPermit,
    memoryRemove: either,
    memoryRestore,
    cancelQueue: security ? allow : deny('Cancelling queued work requires the security role.'),
    revokeTokens: security ? allow : deny('Revoking agent tokens requires the security role.'),
    disableSend: accessEditMode(me, agent) === 'none' ? deny(WHY_SECURITY_OR_OWNER) : allow,
    restoreSnapshot: security ? allow : deny('Restoring a memory snapshot requires the security role.'),
    rollbackSnapshot: security ? allow : deny('Rolling memory back to a snapshot requires the security role.'),
    flagItem: either,
  };
}

/** Team and fleet operations (security only). */
export function fleetPermit(me: Me | null): Permit {
  return hasRole(me, 'security') ? allow : deny('Team and fleet operations require the security role.');
}

/** POST /v1/undo/{id} (security). */
export function undoPermit(me: Me | null): Permit {
  return hasRole(me, 'security') ? allow : deny('Running an undo requires the security role.');
}

// --- Phase 5 (docs/PHASE5_DESIGN.md) -----------------------------------------------------

/**
 * Whether the signed-in principal is the approver of one of these votes. The
 * server records users as "user:<email>" and API tokens as "token:<name>".
 */
export function votedAlready(me: Me | null, votes: Vote[], decision?: string): boolean {
  if (!me) return false;
  const mine = me.kind === 'user' || (me.kind === '' && me.email) ? approverKey(me.email) : me.name ? approverKey(`${me.kind || 'token'}:${me.name}`) : '';
  if (!mine) return false;
  return votes.some((v) => approverKey(v.approver) === mine && (!decision || v.decision.startsWith(decision)));
}

/** Reading the queue, map, swarms and shadow findings (auditor; security and admin read too). */
export function canRead(me: Me | null): boolean {
  return hasRole(me, 'auditor') || hasRole(me, 'security');
}

export interface SwarmPermissions {
  trip: Permit;
  suspend: Permit;
  isolate: Permit;
  kill: Permit;
  release: Permit;
  bundle: Permit;
}

/** Swarm actions are security only; release needs a second, different security approver. */
export function swarmPermissions(me: Me | null, s: SwarmDetail): SwarmPermissions {
  const security = hasRole(me, 'security');
  const sec = (what: string): Permit => (security ? allow : deny(`${what} requires the security role.`));
  const st = s.state.toLowerCase();
  let release = sec('Releasing a swarm');
  if (release.ok && st === 'released') release = deny('This swarm is already released.');
  else if (release.ok && votedAlready(me, s.releaseVotes))
    release = deny('You already voted to release this swarm. A different security approver must give the second approval.');
  let kill = sec('Killing a swarm');
  if (kill.ok && st === 'killed') kill = deny('This swarm is already killed.');
  const closed = st === 'killed' || st === 'released';
  const live = (p: Permit, what: string): Permit => (p.ok && closed ? deny(`The swarm is ${st}: nothing left to ${what}.`) : p);
  return {
    trip: live(sec('Tripping a breaker'), 'hold'),
    suspend: live(sec('Suspending a swarm'), 'suspend'),
    isolate: live(sec('Isolating a swarm'), 'isolate'),
    kill,
    release,
    bundle: canRead(me) ? allow : deny('Exporting the bundle requires the auditor role.'),
  };
}

export interface QueuePermissions {
  approve: Permit;
  deny: Permit;
  assign: Permit;
}

/** Approve / deny / assign one held action (security); a second approval must come from someone else. */
export function queuePermissions(me: Me | null, h: QueueItem): QueuePermissions {
  const security = hasRole(me, 'security');
  const base = security ? allow : deny('Deciding held actions requires the security role.');
  const approve =
    base.ok && votedAlready(me, h.votes, 'approve')
      ? deny(`You already approved this action. ${h.approvalsRequired && h.approvalsRequired > 1 ? 'A different approver must give the next approval.' : ''}`.trim())
      : base;
  return { approve, deny: base, assign: security ? allow : deny('Assigning held actions requires the security role.') };
}

/** Shadow-agent actions: scan, revoke, dismiss, register (security). */
export function shadowPermit(me: Me | null): Permit {
  return hasRole(me, 'security') ? allow : deny('Shadow-agent actions require the security role.');
}
