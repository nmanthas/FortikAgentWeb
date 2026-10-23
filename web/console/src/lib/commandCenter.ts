// Pure computations behind the Command Center (docs/PHASE4_DESIGN.md §6):
// KPI figures, the Agent Radar's dangerous verbs, memory quarantines derived
// from the containment history, and the live incident's action chain.

import type { ActionRow, Agent, ContainmentOp } from '../api/types';

/** Start of the current UTC day (the server counts "today" from 00:00 UTC). */
export function utcDayStart(now: number = Date.now()): number {
  const d = new Date(now);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}

/** Denied actions since 00:00 UTC. */
export function countBlockedToday(actions: ActionRow[], now: number = Date.now()): number {
  const start = utcDayStart(now);
  let n = 0;
  for (const a of actions) {
    if (a.decision !== 'deny') continue;
    const t = Date.parse(a.ts);
    if (Number.isFinite(t) && t >= start) n++;
  }
  return n;
}

/** High-risk agent: did something dangerous (red) in the last 24 hours. */
export function isHighRisk(a: Agent): boolean {
  return a.worstClass24h === 'red';
}

/**
 * Distinct red-class verbs per agent in the last `hours` hours, most frequent
 * first ("gmail SEND", "postgres DROP").
 */
export function dangerousVerbs(actions: ActionRow[], now: number = Date.now(), hours = 24): Map<string, string[]> {
  const since = now - hours * 3600_000;
  const counts = new Map<string, Map<string, number>>();
  for (const a of actions) {
    if (a.class !== 'red') continue;
    const t = Date.parse(a.ts);
    if (!Number.isFinite(t) || t < since) continue;
    const label = a.system ? `${a.system} ${a.verb}` : a.verb;
    let m = counts.get(a.agentId);
    if (!m) counts.set(a.agentId, (m = new Map()));
    m.set(label, (m.get(label) ?? 0) + 1);
  }
  const out = new Map<string, string[]>();
  for (const [agent, m] of counts) out.set(agent, [...m.entries()].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).map(([v]) => v));
  return out;
}

const CUTS_MEMORY = new Set(['memory_remove', 'kill']);
const MEMORY_STEPS = new Set(['set_memory_access', 'memory_access']);

/**
 * Whether an op's memory change took effect for one agent. When the op
 * reports a memory-access step for the agent, only a "done" step counts (a
 * partial op whose memory step failed or was skipped changed nothing);
 * otherwise only an op that finished "done" counts.
 */
function memoryChanged(op: ContainmentOp, agentId: string): boolean {
  const steps = op.steps.filter((s) => MEMORY_STEPS.has(s.name) && (!s.agentId || s.agentId === agentId));
  if (steps.length > 0) return steps.some((s) => s.status === 'done');
  return op.status === 'done';
}

/**
 * Agents whose memory access is currently cut (none or staging_only), derived
 * from the containment history: memory_remove and kill cut it, memory_restore
 * gives it back. Team ops apply to the agents of that business unit. Ops that
 * failed outright or are still running are ignored, and so is a partial op
 * whose memory step did not take effect.
 */
export function memoryQuarantined(ops: ContainmentOp[], agents: Agent[]): Set<string> {
  const byTeam = new Map<string, string[]>();
  for (const a of agents) {
    if (!a.businessUnit) continue;
    const l = byTeam.get(a.businessUnit) ?? [];
    l.push(a.agentId);
    byTeam.set(a.businessUnit, l);
  }
  const out = new Set<string>();
  const ordered = [...ops].sort((a, b) => a.createdAt.localeCompare(b.createdAt));
  for (const op of ordered) {
    if (op.status !== 'done' && op.status !== 'partial') continue;
    const cut = CUTS_MEMORY.has(op.op);
    if (!cut && op.op !== 'memory_restore') continue;
    const targets = op.targetType === 'agent' ? [op.targetId] : op.targetType === 'team' ? (byTeam.get(op.targetId) ?? []) : [];
    for (const id of targets) {
      if (!memoryChanged(op, id)) continue;
      if (cut) out.add(id);
      else out.delete(id);
    }
  }
  return out;
}

/**
 * Agents whose memory access is not full, when the server reports each
 * agent's memory access (authoritative); null when it does not, so the
 * caller falls back to the containment history.
 */
export function quarantinedFromAgents(agents: Agent[]): Set<string> | null {
  if (!agents.some((a) => a.memoryAccess !== undefined)) return null;
  return new Set(agents.filter((a) => a.memoryAccess !== undefined && a.memoryAccess !== 'full').map((a) => a.agentId));
}

/**
 * The incident's chain: up to `max` of the same agent's actions that came
 * before the red decision (oldest first), followed by the red decision itself.
 */
export function incidentChain(latest: ActionRow, history: ActionRow[], max = 6): ActionRow[] {
  const t0 = Date.parse(latest.ts);
  const before = history
    .filter((a) => a.actionId !== latest.actionId && a.agentId === latest.agentId)
    .filter((a) => {
      const t = Date.parse(a.ts);
      return Number.isFinite(t) && Number.isFinite(t0) && t <= t0;
    })
    .sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts))
    .slice(0, max)
    .reverse();
  return [...before, latest];
}

/** The agent the Action Control panel acts on: the user's pick, else the incident's agent, else the riskiest. */
export function pickSelected(agents: Agent[], picked: string | null, incidentAgent: string | null): Agent | null {
  const by = (id: string | null) => (id ? (agents.find((a) => a.agentId === id) ?? null) : null);
  return by(picked) ?? by(incidentAgent) ?? agents.find(isHighRisk) ?? agents[0] ?? null;
}
