// Live Diary events over Server-Sent Events (GET /v1/events/stream).
//
// One EventSource per signed-in console. The browser reconnects on its own
// (sending Last-Event-ID); if the stream is closed for good (e.g. a 401 after
// the session expired, or the server restarting), we reopen it with backoff
// and ask subscribers to refresh, since events may have been missed.
// Subscribers get parsed events and decide what to refresh (debounced via
// useLiveRefresh).

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { parseDiaryEvent } from '../api/normalize';
import type { DiaryEvent } from '../api/types';

/** A null event means "reconnected: refresh everything". */
export type LiveListener = (e: DiaryEvent | null) => void;

interface LiveContextValue {
  connected: boolean;
  subscribe: (fn: LiveListener) => () => void;
}

const LiveContext = createContext<LiveContextValue>({ connected: false, subscribe: () => () => undefined });

export function useLive(): LiveContextValue {
  return useContext(LiveContext);
}

export const STREAM_URL = '/v1/events/stream';
const MAX_BACKOFF_MS = 30_000;

export function LiveProvider({ enabled, children }: { enabled: boolean; children: ReactNode }) {
  const [connected, setConnected] = useState(false);
  const listeners = useRef(new Set<LiveListener>());

  const subscribe = useCallback((fn: LiveListener) => {
    listeners.current.add(fn);
    return () => {
      listeners.current.delete(fn);
    };
  }, []);

  useEffect(() => {
    if (!enabled || typeof EventSource === 'undefined') return;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let backoff = 1000;
    let stopped = false;
    let hadConnection = false;

    const emit = (e: DiaryEvent | null) => {
      for (const fn of [...listeners.current]) {
        try {
          fn(e);
        } catch {
          // A failing subscriber must not break the stream for the others.
        }
      }
    };

    const open = () => {
      if (stopped) return;
      es = new EventSource(STREAM_URL, { withCredentials: true });
      es.onopen = () => {
        setConnected(true);
        backoff = 1000;
        if (hadConnection) emit(null);
        hadConnection = true;
      };
      es.addEventListener('diary', (msg) => {
        const ev = parseDiaryEvent((msg as MessageEvent<string>).data);
        if (ev) emit(ev);
      });
      es.onerror = () => {
        setConnected(false);
        if (es && es.readyState === EventSource.CLOSED) {
          es.close();
          es = null;
          timer = setTimeout(open, backoff);
          backoff = Math.min(MAX_BACKOFF_MS, backoff * 2);
        }
      };
    };
    open();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      es?.close();
      setConnected(false);
    };
  }, [enabled]);

  return <LiveContext.Provider value={{ connected, subscribe }}>{children}</LiveContext.Provider>;
}

/**
 * Calls `reload` (at most once per `delayMs`) whenever a live event matching
 * `match` arrives, and after a reconnect.
 */
export function useLiveRefresh(match: (e: DiaryEvent) => boolean, reload: () => void, delayMs = 700): void {
  const { subscribe } = useLive();
  const matchRef = useRef(match);
  const reloadRef = useRef(reload);
  matchRef.current = match;
  reloadRef.current = reload;
  useEffect(() => {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const unsub = subscribe((e) => {
      if (e !== null && !matchRef.current(e)) return;
      // Throttle rather than debounce: a steady event stream still refreshes
      // at most once per delay instead of never.
      if (timer) return;
      timer = setTimeout(() => {
        timer = undefined;
        reloadRef.current();
      }, delayMs);
    });
    return () => {
      unsub();
      if (timer) clearTimeout(timer);
    };
  }, [subscribe, delayMs]);
}

/**
 * A dedicated SSE stream (e.g. GET /v1/map/live) with named events. The
 * browser reconnects on its own; a stream closed for good is reopened with
 * backoff and `onReconnect` runs (events may have been missed). Handlers get
 * the raw data string; parsing is the caller's job.
 */
export function useEventStream(
  url: string,
  events: string[],
  onEvent: (type: string, data: string) => void,
  opts: { enabled: boolean; onReconnect?: () => void },
): { connected: boolean } {
  const [connected, setConnected] = useState(false);
  const onEventRef = useRef(onEvent);
  const onReconnectRef = useRef(opts.onReconnect);
  onEventRef.current = onEvent;
  onReconnectRef.current = opts.onReconnect;
  const key = events.join(',');

  useEffect(() => {
    if (!opts.enabled || typeof EventSource === 'undefined') return;
    let es: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let backoff = 1000;
    let stopped = false;
    let hadConnection = false;
    const names = key.split(',').filter(Boolean);

    const open = () => {
      if (stopped) return;
      es = new EventSource(url, { withCredentials: true });
      es.onopen = () => {
        setConnected(true);
        backoff = 1000;
        if (hadConnection) onReconnectRef.current?.();
        hadConnection = true;
      };
      for (const n of names) {
        es.addEventListener(n, (msg) => {
          try {
            onEventRef.current(n, String((msg as MessageEvent<string>).data));
          } catch {
            // A malformed event must not break the stream.
          }
        });
      }
      es.onerror = () => {
        setConnected(false);
        if (es && es.readyState === EventSource.CLOSED) {
          es.close();
          es = null;
          timer = setTimeout(open, backoff);
          backoff = Math.min(MAX_BACKOFF_MS, backoff * 2);
        }
      };
    };
    open();
    return () => {
      stopped = true;
      if (timer) clearTimeout(timer);
      es?.close();
      setConnected(false);
    };
  }, [url, key, opts.enabled]);

  return { connected };
}
