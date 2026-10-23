// Containment UI pieces (docs/PHASE4_DESIGN.md §1, §6): the per-step result
// view, the reason dialog that runs an operation and then shows its result,
// the Fleet E-Stop dialog with typed confirmation, and the history list.
//
// Results are shown exactly as the server reports them: a step is "done"
// only when the server says so; anything else is skipped, failed or unknown.

import { useId, useState, type ReactNode } from 'react';
import { fleetEStop } from '../api/endpoints';
import { ESTOP_PHRASE, type ContainmentOp, type OpStatus, type StepStatus } from '../api/types';
import { fmtAgo, fmtTime, titleCase } from '../lib/format';
import { cleanReason, reasonOk } from '../lib/reason';
import { ErrorBox, Modal, ReasonField } from './ui';

const STEP_CHIP: Record<StepStatus, { color: string; label: string }> = {
  done: { color: 'green', label: 'done' },
  skipped: { color: 'gray', label: 'skipped' },
  failed: { color: 'red', label: 'failed' },
  unknown: { color: 'amber', label: 'unknown' },
};

const OP_CHIP: Record<OpStatus, { color: string; label: string }> = {
  done: { color: 'green', label: 'done' },
  partial: { color: 'amber', label: 'partial' },
  failed: { color: 'red', label: 'failed' },
  running: { color: 'blue', label: 'running' },
  unknown: { color: 'amber', label: 'unknown' },
};

export function StepStatusChip({ status }: { status: StepStatus }) {
  const c = STEP_CHIP[status];
  return (
    <span className={`chip ${c.color}`} data-testid="step-status">
      <span className="dot" />
      {c.label}
    </span>
  );
}

export function OpStatusChip({ status }: { status: OpStatus }) {
  const c = OP_CHIP[status];
  return (
    <span className={`chip ${c.color}`} data-testid="op-status">
      <span className="dot" />
      {c.label}
    </span>
  );
}

const OP_LABEL: Record<string, string> = {
  suspend: 'Suspend',
  resume: 'Resume',
  isolate: 'Isolate',
  kill: 'Kill',
  estop: 'Fleet E-Stop',
  estop_release: 'Fleet release',
  memory_remove: 'Remove memory access',
  memory_restore: 'Restore memory access',
  cancel_queue: 'Cancel queued work',
  kill_swarm: 'Kill swarm',
  trip_breaker: 'Trip breaker',
  release_swarm: 'Release swarm',
  trip: 'Trip breaker',
};

export function opLabel(op: string): string {
  return OP_LABEL[op] ?? titleCase(op);
}

/** Step names emitted by internal/containment (plus older aliases). Unknown names are title-cased. */
const STEP_LABEL: Record<string, string> = {
  mark_suspended: 'Mark suspended',
  clear_suspension: 'Clear suspension',
  revoke_credentials: 'Revoke live credentials',
  pause_queue: 'Pause queued jobs',
  resume_queue: 'Resume queued jobs',
  cancel_queue: 'Cancel queued jobs',
  suspend_instances: 'Tell running copies to pause',
  resume_instances: 'Resume running copies',
  stop_instances: 'Stop all copies',
  pause_extra_copies: 'Pause copies over the cap',
  set_level: 'Set control level',
  set_memory_access: 'Set memory access',
  revoke_memory_credentials: 'Revoke vector-store credentials',
  rollback_snapshot: 'Roll back to snapshot',
  terminate_db_sessions: 'Terminate database sessions',
  seal: 'Seal',
  // Phase 5 kill-swarm steps (docs/PHASE5_DESIGN.md §1) and swarm ops.
  freeze_spawning: 'Freeze spawning',
  freeze: 'Freeze spawning',
  hold_pending: 'Hold every pending matching call',
  hold_pending_calls: 'Hold every pending matching call',
  hold_matching_calls: 'Hold every pending matching call',
  cancel_delayed_sends: 'Cancel pending delayed sends',
  revoke_live_credentials: 'Revoke live credentials',
  cancel_jobs: 'Cancel queued jobs and retries',
  remove_memory: 'Remove memory access',
  remove_memory_access: 'Remove memory access',
  stop_copies: 'Stop all copies',
  stop_all_copies: 'Stop all copies',
  keep_root_read_only: 'Keep the root at READ_ONLY',
  seal_bundle: 'Seal the Diary bundle',
  seal_diary_bundle: 'Seal the Diary bundle',
  trip_breaker: 'Trip breaker',
  release_breakers: 'Release breakers',
  lift_freeze: 'Lift the freeze',
  resume_members: 'Resume members',
  // Aliases.
  pause_queues: 'Pause queued jobs',
  resume_queues: 'Resume queued jobs',
  cancel_queues: 'Cancel queued jobs',
  pause_instances: 'Tell running copies to pause',
  pause_extra: 'Pause copies over the cap',
  memory_access: 'Set memory access',
};

export function stepLabel(name: string): string {
  return STEP_LABEL[name] ?? titleCase(name);
}

function targetText(op: ContainmentOp): string {
  if (op.targetType === 'fleet') return 'the fleet';
  return op.targetType ? `${op.targetType} ${op.targetId}` : op.targetId;
}

/** Counts per step status, for the one-line summary. */
export function stepCounts(op: ContainmentOp): Record<StepStatus, number> {
  const c: Record<StepStatus, number> = { done: 0, skipped: 0, failed: 0, unknown: 0 };
  for (const s of op.steps) c[s.status]++;
  return c;
}

/** One operation's result: overall status and every step with its honest detail. */
export function ContainmentResultView({ op }: { op: ContainmentOp }) {
  const counts = stepCounts(op);
  const parts = (['done', 'skipped', 'failed', 'unknown'] as StepStatus[]).filter((k) => counts[k] > 0).map((k) => `${counts[k]} ${k}`);
  return (
    <div className="op-result" data-testid="containment-result">
      <div className="row" style={{ flexWrap: 'wrap' }}>
        <strong>
          {opLabel(op.op)} · {targetText(op)}
        </strong>
        <OpStatusChip status={op.status} />
        <span className="muted small">{parts.length ? parts.join(', ') : 'no steps reported'}</span>
      </div>
      {op.httpError && (
        <div className="alert warn" role="alert">
          The server reported a problem: {op.httpError}
        </div>
      )}
      {op.status !== 'done' && op.status !== 'running' && (
        <p className="help" style={{ margin: 0 }}>
          Not every step succeeded. Only the steps marked done took effect; review the failed ones below.
        </p>
      )}
      <ol className="steps" aria-label="Steps">
        {op.steps.map((s, i) => (
          <li key={i} className={`step-row ${s.status}`} data-testid="containment-step">
            <span className="step-n">{i + 1}</span>
            <div className="grow">
              <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
                <span className="step-name">{stepLabel(s.name)}</span>
                {s.agentId && <span className="rule">{s.agentId}</span>}
                <StepStatusChip status={s.status} />
                {s.durationMs > 0 && <span className="muted small">{s.durationMs} ms</span>}
              </div>
              {s.detail && <div className="step-detail">{s.detail}</div>}
            </div>
          </li>
        ))}
      </ol>
      {op.steps.length === 0 && <div className="muted small">The server did not report any steps for this operation.</div>}
      {op.opId && (
        <div className="muted small mono" style={{ marginTop: 6 }}>
          {op.opId}
          {op.actor && ` · ${op.actor}`}
        </div>
      )}
    </div>
  );
}

/**
 * Asks for a reason (plus optional extra fields), runs the operation and then
 * shows its per-step result in the same dialog. The reason may span several
 * lines and is capped at 1000 bytes, as the containment API accepts (D3).
 */
export function OpDialog({
  title,
  description,
  confirmLabel,
  danger,
  warning,
  children,
  canSubmit = true,
  run,
  onDone,
  onClose,
}: {
  title: string;
  description?: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  warning?: ReactNode;
  children?: ReactNode;
  canSubmit?: boolean;
  run: (reason: string) => Promise<ContainmentOp>;
  onDone?: (op: ContainmentOp) => void;
  onClose: () => void;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [result, setResult] = useState<ContainmentOp | null>(null);

  const submit = async () => {
    if (!reasonOk(reason) || !canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const op = await run(cleanReason(reason));
      setResult(op);
      onDone?.(op);
    } catch (e) {
      setError(e);
    } finally {
      setBusy(false);
    }
  };

  if (result) {
    return (
      <Modal
        title={`${title} — result`}
        onClose={onClose}
        footer={
          <button className="btn primary" onClick={onClose}>
            Close
          </button>
        }
      >
        <ContainmentResultView op={result} />
      </Modal>
    );
  }
  return (
    <Modal
      title={title}
      description={description}
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className={`btn ${danger ? 'danger' : 'primary'}`} onClick={() => void submit()} disabled={busy || !canSubmit || !reasonOk(reason)}>
            {busy && <span className="spinner" />} {confirmLabel}
          </button>
        </>
      }
    >
      {warning && (
        <div className="alert warn" role="alert">
          <div>{warning}</div>
        </div>
      )}
      {children}
      <ReasonField value={reason} onChange={setReason} />
      <ErrorBox error={error} />
    </Modal>
  );
}

/** Fleet E-Stop: the user must type the exact phrase and give a reason. */
export function EStopDialog({ onDone, onClose }: { onDone?: (op: ContainmentOp) => void; onClose: () => void }) {
  const [phrase, setPhrase] = useState('');
  const pid = useId();
  const matches = phrase === ESTOP_PHRASE;
  return (
    <OpDialog
      title="Fleet E-Stop"
      description="Suspends every registered agent: all actions are refused, live credentials revoked, queued jobs paused and running copies told to pause. Memory and state are kept; Release resumes exactly the agents this e-stop suspended."
      confirmLabel="Stop all agents"
      danger
      canSubmit={matches}
      run={(reason) => fleetEStop(reason, phrase)}
      onDone={onDone}
      onClose={onClose}
    >
      <div className="field">
        <label htmlFor={pid}>
          Type <code>{ESTOP_PHRASE}</code> to confirm<span className="req">*</span>
        </label>
        <input
          id={pid}
          className="input"
          value={phrase}
          autoComplete="off"
          spellCheck={false}
          aria-invalid={phrase !== '' && !matches}
          onChange={(e) => setPhrase(e.target.value)}
        />
      </div>
    </OpDialog>
  );
}

/** Containment history: newest first, each op expandable to its steps. */
export function ContainmentHistory({ ops, showTarget = true }: { ops: ContainmentOp[]; showTarget?: boolean }) {
  const [open, setOpen] = useState<string | null>(null);
  if (ops.length === 0) return <div className="empty">No containment operations yet.</div>;
  return (
    <div className="history" data-testid="containment-history">
      {ops.map((op) => {
        const c = stepCounts(op);
        const expanded = open === op.opId;
        return (
          <div key={op.opId} className="history-item">
            <div className="body">
              <div className="row" style={{ flexWrap: 'wrap', gap: 6 }}>
                <strong>{opLabel(op.op)}</strong>
                {showTarget && <span className="muted">{targetText(op)}</span>}
                <OpStatusChip status={op.status} />
                <span className="muted small">
                  {c.done} done{c.failed ? `, ${c.failed} failed` : ''}
                  {c.skipped ? `, ${c.skipped} skipped` : ''}
                  {c.unknown ? `, ${c.unknown} unknown` : ''}
                </span>
                <div className="spacer" />
                <span className="muted small" title={fmtTime(op.createdAt)}>
                  {fmtAgo(op.createdAt)}
                </span>
                <button className="btn small ghost" aria-expanded={expanded} onClick={() => setOpen(expanded ? null : op.opId)}>
                  {expanded ? 'Hide steps' : 'Steps'}
                </button>
              </div>
              <div className="by">
                {op.actor || 'unknown actor'}
                {op.reason && ` — ${op.reason}`}
              </div>
              {expanded && (
                <div style={{ marginTop: 8 }}>
                  <ContainmentResultView op={op} />
                </div>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
