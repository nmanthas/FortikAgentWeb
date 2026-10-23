import { act, render } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { FakeEventSource } from '../test/fakeEventSource';
import { LiveProvider, STREAM_URL, useLiveRefresh } from './live';

function Probe({ reload }: { reload: () => void }) {
  useLiveRefresh((e) => e.eventType === 'action.decided', reload, 100);
  return null;
}

beforeEach(() => {
  vi.useFakeTimers();
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
});
afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('LiveProvider', () => {
  it('opens one stream and throttles matching refreshes', () => {
    const reload = vi.fn();
    render(
      <LiveProvider enabled>
        <Probe reload={reload} />
      </LiveProvider>,
    );
    expect(FakeEventSource.instances).toHaveLength(1);
    const es = FakeEventSource.instances[0]!;
    expect(es.url).toBe(STREAM_URL);
    act(() => {
      es.onopen?.();
      es.emit({ event_type: 'action.decided' });
      es.emit({ event_type: 'action.decided' });
      es.emit({ event_type: 'integration.tested' });
    });
    act(() => vi.advanceTimersByTime(150));
    expect(reload).toHaveBeenCalledTimes(1);
    act(() => es.emit({ event_type: 'integration.tested' }));
    act(() => vi.advanceTimersByTime(150));
    expect(reload).toHaveBeenCalledTimes(1);
  });

  it('reopens a closed stream with backoff and refreshes after reconnecting', () => {
    const reload = vi.fn();
    render(
      <LiveProvider enabled>
        <Probe reload={reload} />
      </LiveProvider>,
    );
    const es = FakeEventSource.instances[0]!;
    act(() => es.onopen?.());
    act(() => {
      es.readyState = FakeEventSource.CLOSED;
      es.onerror?.();
    });
    act(() => vi.advanceTimersByTime(1000));
    expect(FakeEventSource.instances).toHaveLength(2);
    act(() => FakeEventSource.instances[1]!.onopen?.());
    act(() => vi.advanceTimersByTime(150));
    expect(reload).toHaveBeenCalledTimes(1);
  });
});
