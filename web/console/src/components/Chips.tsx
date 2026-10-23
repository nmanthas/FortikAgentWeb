// Status chips: control levels, action classes, decisions, integration status.

import type { ActionClass, IntegrationStatus, Level } from '../api/types';
import { titleCase } from '../lib/format';

const LEVEL_COLOR: Record<Level, string> = {
  FULL: 'green',
  SUPERVISED: 'blue',
  READ_ONLY: 'amber',
  ISOLATED: 'orange',
  QUARANTINED: 'purple',
  KILLED: 'black',
};

/** Solid colours for the level ladder (current step). */
export const LEVEL_SOLID: Record<Level, string> = {
  FULL: '#16a34a',
  SUPERVISED: '#2563eb',
  READ_ONLY: '#f59e0b',
  ISOLATED: '#ea580c',
  QUARANTINED: '#7c3aed',
  KILLED: '#111827',
};

export function LevelChip({ level }: { level: Level }) {
  return (
    <span className={`chip ${LEVEL_COLOR[level]}`} data-testid="level-chip">
      <span className="dot" />
      {level.replace('_', ' ')}
    </span>
  );
}

const CLASS_CHIP: Record<ActionClass, string> = { green: 'green', blue: 'blue', yellow: 'amber', red: 'red' };
const CLASS_LABEL: Record<ActionClass, string> = { green: 'Normal', blue: 'Above normal', yellow: 'Risky', red: 'Dangerous' };

/** Hex colours for classes (charts). */
export const CLASS_COLOR: Record<ActionClass, string> = { green: '#16a34a', blue: '#2563eb', yellow: '#f59e0b', red: '#dc2626' };

export function classLabel(c: ActionClass): string {
  return CLASS_LABEL[c];
}

export function ClassChip({ cls, label }: { cls: ActionClass | null | undefined; label?: string }) {
  if (!cls) return <span className="chip gray">No activity</span>;
  return (
    <span className={`chip ${CLASS_CHIP[cls]}`}>
      <span className="dot" />
      {label ?? CLASS_LABEL[cls]}
    </span>
  );
}

export function DecisionChip({ decision }: { decision: string }) {
  const d = decision.toLowerCase();
  const color = d === 'allow' ? 'green' : d === 'allow_reduced' ? 'blue' : d === 'hold' ? 'amber' : d === 'deny' ? 'red' : 'gray';
  return <span className={`chip ${color}`}>{d ? d.replace('_', ' ') : 'unknown'}</span>;
}

const STATUS: Record<IntegrationStatus, { color: string; label: string }> = {
  unconfigured: { color: 'gray', label: 'Not configured' },
  configured: { color: 'blue', label: 'Configured' },
  ok: { color: 'green', label: 'Connected' },
  error: { color: 'red', label: 'Error' },
};

export function IntegrationStatusChip({ status }: { status: IntegrationStatus }) {
  const s = STATUS[status];
  return (
    <span className={`chip ${s.color}`} data-testid="integration-status">
      <span className="dot" />
      {s.label}
    </span>
  );
}

export function AgentStatusChip({ status }: { status: string }) {
  const s = status.toLowerCase();
  const color =
    s === 'active' ? 'green' : s === 'idle' ? 'gray' : s === 'needs review' ? 'amber' : s === 'killed' ? 'black' : s === 'quarantined' ? 'purple' : s === 'suspended' ? 'orange' : 'blue';
  return <span className={`chip ${color}`}>{titleCase(status)}</span>;
}
