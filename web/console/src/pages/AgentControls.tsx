// Containment buttons for one agent (docs/PHASE4_DESIGN.md §1, §6), shared
// by the Command Center's Action Control panel and the agent detail's
// Containment tab. Every button is role-aware: when the user may not run it,
// it is disabled and the reason is shown. Each operation asks for a reason and
// then shows the per-step result the server reported.
//
// The target is frozen when a dialog opens (F23): the dialog keeps the Agent
// it was opened for, even if the surface (e.g. the Command Center following
// the live incident) passes a different agent while it is open. Surfaces also
// key this component by agent id and pin their selection via onOpen.

import { useState, type ReactNode } from 'react';
import {
  agentOp,
  agentRollbackSnapshots,
  cancelQueue,
  disableGmailSend,
  removeMemory,
  restoreMemory,
  revokeAgentTokens,
  type AgentOp,
} from '../api/endpoints';
import type { Agent, ContainmentOp, MemorySnapshot } from '../api/types';
import { useMe } from '../App';
import { OpDialog } from '../components/Containment';
import { IconBrain, IconKey, IconMail, IconPause, IconRefresh, IconShield, IconSkull, IconX } from '../components/Icons';
import { useToast } from '../components/Toasts';
import { ErrorBox, Modal, ReasonDialog } from '../components/ui';
import { fmtAgo } from '../lib/format';
import { containmentPermissions, type Permit } from '../lib/permissions';
import { useAsync } from '../lib/useAsync';

export type ControlKind =
  | 'suspend'
  | 'resume'
  | 'isolate'
  | 'kill'
  | 'memory_remove'
  | 'memory_restore'
  | 'cancel_queue'
  | 'revoke_tokens'
  | 'disable_send';

interface ButtonDef {
  kind: ControlKind;
  label: string;
  icon: ReactNode;
  tone?: 'danger' | 'warn';
  permit: Permit;
}

/** Buttons per surface: the Command Center's Action Control, and the agent detail. */
export const COMMAND_CONTROLS: ControlKind[] = ['suspend', 'resume', 'memory_remove', 'revoke_tokens', 'cancel_queue', 'disable_send'];
export const DETAIL_CONTROLS: ControlKind[] = ['suspend', 'resume', 'isolate', 'kill', 'memory_remove', 'memory_restore', 'cancel_queue'];

export function AgentControls({
  agent,
  controls,
  labels = {},
  onChanged,
  onOpen,
}: {
  agent: Agent;
  controls: ControlKind[];
  /** Surface-specific labels (e.g. "Freeze agent" for suspend on the Command Center). */
  labels?: Partial<Record<ControlKind, string>>;
  onChanged?: (op?: ContainmentOp) => void;
  /** Called with the target's id when a dialog opens, so the surface can pin its selection. */
  onOpen?: (agentId: string) => void;
}) {
  const me = useMe();
  const perms = containmentPermissions(me, agent);
  // The dialog's target is a snapshot taken when it opened, never the live prop.
  const [open, setOpen] = useState<{ kind: ControlKind; agent: Agent } | null>(null);

  const defs: Record<ControlKind, ButtonDef> = {
    suspend: { kind: 'suspend', label: 'Suspend', icon: <IconPause size={15} />, tone: 'warn', permit: perms.suspend },
    resume: { kind: 'resume', label: 'Resume', icon: <IconRefresh size={15} />, permit: perms.resume },
    isolate: { kind: 'isolate', label: 'Isolate', icon: <IconShield size={15} />, tone: 'warn', permit: perms.isolate },
    kill: { kind: 'kill', label: 'Kill', icon: <IconSkull size={15} />, tone: 'danger', permit: perms.kill },
    memory_remove: { kind: 'memory_remove', label: 'Remove memory', icon: <IconBrain size={15} />, tone: 'warn', permit: perms.memoryRemove },
    memory_restore: { kind: 'memory_restore', label: 'Restore memory', icon: <IconBrain size={15} />, permit: perms.memoryRestore },
    cancel_queue: { kind: 'cancel_queue', label: 'Cancel queue', icon: <IconX size={15} />, tone: 'danger', permit: perms.cancelQueue },
    revoke_tokens: { kind: 'revoke_tokens', label: 'Revoke token', icon: <IconKey size={15} />, tone: 'warn', permit: perms.revokeTokens },
    disable_send: { kind: 'disable_send', label: 'Disable SEND', icon: <IconMail size={15} />, tone: 'warn', permit: perms.disableSend },
  };
  const shown = controls.map((k) => defs[k]);
  const reasons = [...new Set(shown.filter((d) => !d.permit.ok && d.permit.why).map((d) => d.permit.why as string))];
  const done = (op?: ContainmentOp) => onChanged?.(op);

  return (
    <>
      <div className="control-grid">
        {shown.map((d) => (
          <button
            key={d.kind}
            className={`btn control-btn${d.tone ? ` ${d.tone}` : ''}`}
            disabled={!d.permit.ok}
            title={d.permit.ok ? undefined : d.permit.why}
            onClick={() => {
              setOpen({ kind: d.kind, agent });
              onOpen?.(agent.agentId);
            }}
          >
            {d.icon}
            {labels[d.kind] ?? d.label}
          </button>
        ))}
      </div>
      {reasons.length > 0 && (
        <ul className="why-list" aria-label="Why some controls are disabled">
          {reasons.map((r) => (
            <li key={r}>{r}</li>
          ))}
        </ul>
      )}
      {open && (
        <ControlDialog
          kind={open.kind}
          agent={open.agent}
          canRollback={containmentPermissions(me, open.agent).rollbackSnapshot}
          label={labels[open.kind] ?? defs[open.kind].label}
          onDone={done}
          onClose={() => setOpen(null)}
        />
      )}
    </>
  );
}

function ControlDialog({
  kind,
  agent,
  canRollback,
  label,
  onDone,
  onClose,
}: {
  kind: ControlKind;
  /** The agent the dialog was opened for (frozen; see AgentControls). */
  agent: Agent;
  canRollback: Permit;
  label: string;
  onDone: (op?: ContainmentOp) => void;
  onClose: () => void;
}) {
  const id = agent.agentId;
  const simple = (op: AgentOp, description: ReactNode, danger = false, warning?: ReactNode) => (
    <OpDialog
      title={`${label}: ${id}`}
      description={description}
      confirmLabel={label}
      danger={danger}
      warning={warning}
      run={(reason) => agentOp(id, op, reason)}
      onDone={onDone}
      onClose={onClose}
    />
  );
  switch (kind) {
    case 'suspend':
      return simple(
        'suspend',
        'Every action is refused, live credentials are revoked, queued jobs are paused (not cancelled) and running copies are told to pause. Memory and state are kept, so Resume continues where the agent stopped.',
      );
    case 'resume':
      return simple('resume', 'Clears the suspension, resumes paused queued jobs and lets suspended copies continue. Credentials are issued again on request.');
    case 'isolate':
      return simple(
        'isolate',
        'Steps the agent down to ISOLATED (never loosens a stricter level), revokes live credentials and pauses copies over the cap. Lifted by stepping up (owner or security).',
      );
    case 'kill':
      return simple(
        'kill',
        'Level KILLED, every credential revoked, queued jobs cancelled, database sessions terminated, all copies stopped and memory access removed.',
        true,
        'Re-enabling a killed agent is manual and needs the security role. Cancelled jobs are NOT reversible.',
      );
    case 'memory_remove':
      return <MemoryRemoveDialog agentId={id} label={label} onDone={onDone} onClose={onClose} />;
    case 'memory_restore':
      return <MemoryRestoreDialog agentId={id} label={label} canRollback={canRollback} onDone={onDone} onClose={onClose} />;
    case 'cancel_queue':
      return (
        <OpDialog
          title={`${label}: ${id}`}
          description="Cancels the agent's queued jobs, retries and schedules in every configured queue system (Temporal, Celery, webhook)."
          confirmLabel="Cancel queued work"
          danger
          warning={
            <>
              <strong>NOT REVERSIBLE.</strong> Cancelled jobs are gone and must be resubmitted by their producers. To stop work temporarily, use Suspend
              instead (it pauses queued jobs and Resume releases them).
            </>
          }
          run={(reason) => cancelQueue(id, reason)}
          onDone={onDone}
          onClose={onClose}
        />
      );
    case 'revoke_tokens':
      return <RevokeTokensDialog agentId={id} label={label} onDone={() => onDone()} onClose={onClose} />;
    case 'disable_send':
      return <DisableSendDialog agentId={id} label={label} onDone={() => onDone()} onClose={onClose} />;
  }
}

function MemoryRemoveDialog({
  agentId,
  label,
  onDone,
  onClose,
}: {
  agentId: string;
  label: string;
  onDone: (op: ContainmentOp) => void;
  onClose: () => void;
}) {
  const [mode, setMode] = useState<'staging_only' | 'none'>('staging_only');
  return (
    <OpDialog
      title={`${label}: ${agentId}`}
      description="Cuts the agent's long-term memory and revokes its vector-store credentials. Existing memory is frozen, not deleted; Restore memory gives access back."
      confirmLabel={label}
      run={(reason) => removeMemory(agentId, mode, reason)}
      onDone={onDone}
      onClose={onClose}
    >
      <fieldset className="radio-group">
        <legend className="label">Memory access</legend>
        <label className="check">
          <input type="radio" name="memory-mode" value="staging_only" checked={mode === 'staging_only'} onChange={() => setMode('staging_only')} />
          Staging only — reads allowed; new writes are staged and never promoted
        </label>
        <label className="check">
          <input type="radio" name="memory-mode" value="none" checked={mode === 'none'} onChange={() => setMode('none')} />
          None — no memory reads or writes at all
        </label>
      </fieldset>
    </OpDialog>
  );
}

function MemoryRestoreDialog({
  agentId,
  label,
  canRollback,
  onDone,
  onClose,
}: {
  agentId: string;
  label: string;
  /** Rollback to a snapshot needs the security role (D1); owners restore access only. */
  canRollback: Permit;
  onDone: (op: ContainmentOp) => void;
  onClose: () => void;
}) {
  return canRollback.ok ? (
    <MemoryRestoreWithRollback agentId={agentId} label={label} onDone={onDone} onClose={onClose} />
  ) : (
    <OpDialog
      title={`${label}: ${agentId}`}
      description="Gives the agent full memory access again. Its current memory is kept as it is."
      confirmLabel={label}
      run={(reason) => restoreMemory(agentId, reason)}
      onDone={onDone}
      onClose={onClose}
    >
      <p className="help" data-testid="rollback-unavailable" style={{ margin: 0 }}>
        {canRollback.why} To roll the memory back to a clean snapshot, ask the security team.
      </p>
    </OpDialog>
  );
}

/** Restore memory for security: optionally roll back first, to a clean snapshot of a namespace this agent uses. */
function MemoryRestoreWithRollback({
  agentId,
  label,
  onDone,
  onClose,
}: {
  agentId: string;
  label: string;
  onDone: (op: ContainmentOp) => void;
  onClose: () => void;
}) {
  const snaps = useAsync<MemorySnapshot[]>((s) => agentRollbackSnapshots(agentId, s), [agentId]);
  const [snapshot, setSnapshot] = useState('');
  return (
    <OpDialog
      title={`${label}: ${agentId}`}
      description="Gives the agent full memory access again. Optionally roll its namespace back to a clean snapshot first (a pre-restore snapshot is taken, so the rollback itself can be undone)."
      confirmLabel={label}
      run={(reason) => restoreMemory(agentId, reason, snapshot || undefined)}
      onDone={onDone}
      onClose={onClose}
    >
      <div className="field">
        <label htmlFor="rollback-snapshot">Roll back first</label>
        <select id="rollback-snapshot" className="select" value={snapshot} onChange={(e) => setSnapshot(e.target.value)}>
          <option value="">No rollback: keep the current memory</option>
          {(snaps.data ?? []).map((s) => (
            <option key={s.snapshotId} value={s.snapshotId}>
              {s.storeKey.replace(/^memory:/, '')}/{s.namespace} · {s.itemCount} items · {fmtAgo(s.createdAt)}
            </option>
          ))}
        </select>
        <span className="help">Only clean snapshots of the stores and namespaces this agent is known to write to are listed.</span>
        {snaps.loading && !snaps.data && <span className="help">Loading clean snapshots…</span>}
        {snaps.error && <span className="help">Snapshots could not be loaded ({snaps.error.message}); you can still restore without a rollback.</span>}
        {snaps.data && snaps.data.length === 0 && (
          <span className="help">No clean snapshot of a namespace this agent uses is available. Snapshots of other namespaces are restored from the Memory tab.</span>
        )}
      </div>
    </OpDialog>
  );
}

function RevokeTokensDialog({ agentId, label, onDone, onClose }: { agentId: string; label: string; onDone: () => void; onClose: () => void }) {
  const toast = useToast();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const run = async () => {
    setBusy(true);
    setError(null);
    try {
      const revoked = await revokeAgentTokens(agentId);
      toast(
        revoked
          ? { tone: 'amber', title: `Agent tokens of ${agentId} revoked`, body: 'It cannot reach the gateway, credential issuance or pgproxy until a new token is issued.' }
          : { tone: 'info', title: `${agentId} had no agent token on file`, body: 'Nothing was revoked.' },
      );
      onDone();
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={`${label}: ${agentId}?`}
      description="Revokes every Fortik agent token of this agent (DELETE /v1/agents/{id}/tokens). The agent can no longer reach the gateway, ask for credentials or connect through pgproxy until a new token is issued."
      onClose={busy ? () => undefined : onClose}
      footer={
        <>
          <button className="btn" onClick={onClose} disabled={busy}>
            Cancel
          </button>
          <button className="btn danger" onClick={() => void run()} disabled={busy}>
            {busy && <span className="spinner" />} Revoke all agent tokens
          </button>
        </>
      }
    >
      <div className="alert info">
        <div>
          Short-lived system credentials the agent already holds (for example a 15-minute AWS session) are not touched by this button and stay valid until
          they expire. <strong>Freeze agent</strong> (suspend) revokes those as well and reports what each system allows.
        </div>
      </div>
      <ErrorBox error={error} />
    </Modal>
  );
}

function DisableSendDialog({ agentId, label, onDone, onClose }: { agentId: string; label: string; onDone: () => void; onClose: () => void }) {
  const toast = useToast();
  return (
    <ReasonDialog
      title={`${label}: ${agentId}?`}
      description="Narrows the agent's Gmail access profile to send: none. Reading and the recipient cap are kept. The change is versioned and can be reverted from the Access tab."
      confirmLabel="Disable sending"
      onConfirm={async (reason) => {
        const r = await disableGmailSend(agentId, reason);
        toast(
          r.alreadyDisabled
            ? { tone: 'info', title: `${agentId} already cannot send email`, body: 'Its Gmail profile has send: none; nothing was changed.' }
            : { tone: 'amber', title: `Gmail SEND disabled for ${agentId}` },
        );
        onDone();
      }}
      onClose={onClose}
    />
  );
}
