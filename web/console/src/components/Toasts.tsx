// Transient notifications (bottom right). Toasts auto-dismiss after 8 s;
// at most five are shown.

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { IconX } from './Icons';

export interface Toast {
  id: number;
  title: string;
  body?: string;
  tone: 'red' | 'amber' | 'green' | 'info';
}

type ToastFn = (t: Omit<Toast, 'id'>) => void;

const ToastContext = createContext<ToastFn>(() => undefined);

export function useToast(): ToastFn {
  return useContext(ToastContext);
}

const MAX = 5;
const TTL_MS = 8000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const next = useRef(1);
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: number) => {
    setToasts((ts) => ts.filter((t) => t.id !== id));
    const tm = timers.current.get(id);
    if (tm) clearTimeout(tm);
    timers.current.delete(id);
  }, []);

  const push = useCallback<ToastFn>(
    (t) => {
      const id = next.current++;
      setToasts((ts) => [...ts, { ...t, id }].slice(-MAX));
      timers.current.set(
        id,
        setTimeout(() => dismiss(id), TTL_MS),
      );
    },
    [dismiss],
  );

  useEffect(() => {
    const m = timers.current;
    return () => {
      for (const tm of m.values()) clearTimeout(tm);
      m.clear();
    };
  }, []);

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div key={t.id} className={`toast ${t.tone}`} role="status">
            <div className="grow">
              <div className="t-title">{t.title}</div>
              {t.body && <div className="t-body">{t.body}</div>}
            </div>
            <button className="icon-btn" aria-label="Dismiss" onClick={() => dismiss(t.id)}>
              <IconX size={14} />
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}
