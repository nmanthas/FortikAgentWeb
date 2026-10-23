// Shared UI pieces: modal, drawer, error/loading states, reason dialog.

import { useEffect, useId, useState, type ReactNode } from 'react';
import { ApiError } from '../api/client';
import { cleanReason, REASON_MAX_BYTES, reasonOk, reasonProblem, utf8Bytes } from '../lib/reason';
import { IconX } from './Icons';

function useEscape(onClose: () => void) {
  useEffect(() => {
    const h = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', h);
    return () => window.removeEventListener('keydown', h);
  }, [onClose]);
}

export function Modal({
  title,
  description,
  onClose,
  children,
  footer,
}: {
  title: string;
  description?: ReactNode;
  onClose: () => void;
  children?: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(onClose);
  const id = useId();
  return (
    <>
      <div className="overlay modal" onClick={onClose} />
      <div className="modal-wrap" onClick={onClose}>
        <div className="modal" role="dialog" aria-modal="true" aria-labelledby={id} onClick={(e) => e.stopPropagation()}>
          <div className="modal-head">
            <h3 id={id}>{title}</h3>
            {description && <p>{description}</p>}
          </div>
          {children && <div className="modal-body">{children}</div>}
          {footer && <div className="modal-foot">{footer}</div>}
        </div>
      </div>
    </>
  );
}

export function Drawer({
  title,
  subtitle,
  onClose,
  children,
  footer,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  onClose: () => void;
  children: ReactNode;
  footer?: ReactNode;
}) {
  useEscape(onClose);
  const id = useId();
  return (
    <>
      <div className="overlay top" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true" aria-labelledby={id}>
        <div className="drawer-head">
          <div className="grow">
            <h2 id={id} style={{ fontSize: 17 }}>
              {title}
            </h2>
            {subtitle && <div className="muted small" style={{ marginTop: 2 }}>{subtitle}</div>}
          </div>
          <button className="icon-btn" onClick={onClose} aria-label="Close">
            <IconX />
          </button>
        </div>
        <div className="drawer-body">{children}</div>
        {footer && <div className="drawer-foot">{footer}</div>}
      </aside>
    </>
  );
}

export function errText(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 403) return `Not allowed: ${e.message}`;
    return e.message;
  }
  if (e instanceof Error) return e.message;
  return String(e);
}

/** Splits a server validation message ("invalid access profile: a; b") into readable lines. */
export function errLines(e: unknown): string[] {
  const t = errText(e);
  const idx = t.indexOf(': ');
  if (idx > 0 && /invalid/i.test(t.slice(0, idx))) {
    const rest = t.slice(idx + 2);
    const parts = rest.split(/;\s+/).filter(Boolean);
    if (parts.length > 1) return [t.slice(0, idx), ...parts];
  }
  return [t];
}

export function ErrorBox({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  if (!error) return null;
  const lines = errLines(error);
  return (
    <div className="alert error" role="alert">
      <div className="grow">
        <div>{lines[0]}</div>
        {lines.length > 1 && (
          <ul>
            {lines.slice(1).map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        )}
      </div>
      {onRetry && (
        <button className="btn small" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function Loading({ label = 'Loading…' }: { label?: string }) {
  return (
    <div className="center">
      <div className="row">
        <span className="spinner" /> {label}
      </div>
    </div>
  );
}

/**
 * The written-reason input shared by every dialog that records a reason
 * (containment, level changes, access edits, memory review). Several lines
 * are allowed; the limit is REASON_MAX_BYTES bytes of UTF-8, as the server
 * counts it, and going over is reported instead of silently cutting the text.
 */
export function ReasonField({
  value,
  onChange,
  placeholder = 'Why is this needed? It is recorded in the Diary.',
  autoFocus = true,
  disabled,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  disabled?: boolean;
}) {
  const id = useId();
  const problem = reasonProblem(value);
  const bytes = utf8Bytes(cleanReason(value));
  return (
    <div className="field">
      <label htmlFor={id}>
        Reason<span className="req">*</span>
      </label>
      <textarea
        id={id}
        className="input"
        rows={4}
        value={value}
        autoFocus={autoFocus}
        disabled={disabled}
        placeholder={placeholder}
        aria-invalid={problem ? true : undefined}
        aria-describedby={`${id}-help`}
        onChange={(e) => onChange(e.target.value)}
      />
      <span id={`${id}-help`} className="help" role={problem ? 'alert' : undefined} data-testid="reason-help">
        {problem ?? `Several lines are fine. ${bytes} / ${REASON_MAX_BYTES} bytes.`}
      </span>
    </div>
  );
}

/**
 * Confirmation dialog that requires a written reason (level changes, access
 * edits, reverts). The reason is cleaned (see lib/reason) and trimmed; an
 * empty or over-long reason cannot be submitted.
 */
export function ReasonDialog({
  title,
  description,
  confirmLabel,
  danger,
  onConfirm,
  onClose,
}: {
  title: string;
  description?: ReactNode;
  confirmLabel: string;
  danger?: boolean;
  onConfirm: (reason: string) => Promise<void>;
  onClose: () => void;
}) {
  const [reason, setReason] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const submit = async () => {
    if (!reasonOk(reason)) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm(cleanReason(reason));
      onClose();
    } catch (e) {
      setError(e);
      setBusy(false);
    }
  };
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
          <button className={`btn ${danger ? 'danger' : 'primary'}`} onClick={() => void submit()} disabled={busy || !reasonOk(reason)}>
            {busy && <span className="spinner" />} {confirmLabel}
          </button>
        </>
      }
    >
      <ReasonField value={reason} onChange={setReason} placeholder="Why is this change needed? It is recorded in the Diary." />
      <ErrorBox error={error} />
    </Modal>
  );
}
