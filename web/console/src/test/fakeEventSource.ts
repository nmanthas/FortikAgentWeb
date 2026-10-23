// FakeEventSource stands in for the browser EventSource (jsdom has none).
// Install it with vi.stubGlobal('EventSource', FakeEventSource).

import type { DiaryEvent } from '../api/types';

export class FakeEventSource {
  static instances: FakeEventSource[] = [];
  static CLOSED = 2;
  readyState = 0;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  listeners = new Map<string, (m: { data: string }) => void>();
  constructor(
    public url: string,
    public init?: EventSourceInit,
  ) {
    FakeEventSource.instances.push(this);
  }
  addEventListener(type: string, fn: (m: { data: string }) => void) {
    this.listeners.set(type, fn);
  }
  close() {
    this.readyState = FakeEventSource.CLOSED;
  }
  /** Delivers one committed Diary entry in the server's SSE wire format. */
  emit(ev: Partial<DiaryEvent> & { event_type: string; agent_id?: string; data?: Record<string, unknown> }) {
    this.listeners.get('diary')?.({ data: JSON.stringify({ seq: 1, ts: '', data: {}, ...ev }) });
  }

  /** Delivers one named event (e.g. "edge.updated") with a JSON payload. */
  emitNamed(type: string, data: unknown) {
    this.listeners.get(type)?.({ data: JSON.stringify(data) });
  }

  /** The newest stream opened for a URL (path prefix match). */
  static forUrl(prefix: string): FakeEventSource {
    const list = FakeEventSource.instances.filter((e) => e.url.startsWith(prefix));
    const es = list[list.length - 1];
    if (!es) throw new Error(`no EventSource was opened for ${prefix}`);
    return es;
  }

  static latest(): FakeEventSource {
    const es = FakeEventSource.instances[FakeEventSource.instances.length - 1];
    if (!es) throw new Error('no EventSource was opened');
    return es;
  }
}
