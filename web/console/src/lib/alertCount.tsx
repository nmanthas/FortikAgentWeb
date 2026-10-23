// Open-alert count for the nav badge. Loaded once, refreshed on alert.* live
// events (and after a stream reconnect), and by pages that change alerts.

import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from 'react';
import { listAlerts } from '../api/endpoints';
import { useLiveRefresh } from './live';

interface AlertCountValue {
  /** null until loaded, or when the caller may not list alerts. */
  open: number | null;
  refresh: () => void;
}

const AlertCountContext = createContext<AlertCountValue>({ open: null, refresh: () => undefined });

export function useAlertCount(): AlertCountValue {
  return useContext(AlertCountContext);
}

export function AlertCountProvider({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState<number | null>(null);
  const [tick, setTick] = useState(0);
  const refresh = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    const ac = new AbortController();
    listAlerts('open', ac.signal).then(
      (a) => {
        if (!ac.signal.aborted) setOpen(a.length);
      },
      () => {
        if (!ac.signal.aborted) setOpen(null);
      },
    );
    return () => ac.abort();
  }, [tick]);
  useLiveRefresh((e) => e.eventType.startsWith('alert.'), refresh, 1000);
  return <AlertCountContext.Provider value={{ open, refresh }}>{children}</AlertCountContext.Provider>;
}
