// Timer chip for a timed app suspension (docs/PHASE3_DESIGN.md §5):
// "GitHub suspended · restores at 11:55" with a live countdown.

import type { Override } from '../api/types';
import { fmtClock, fmtCountdown } from '../lib/format';
import { SYSTEM_LABELS } from '../lib/profiles';
import { useNow } from '../lib/useNow';
import { IconClock } from './Icons';

export function systemLabel(system: string): string {
  return (SYSTEM_LABELS as Record<string, string>)[system] ?? system;
}

/** The chip's text without the countdown, e.g. "GitHub suspended · restores at 11:55". */
export function suspensionText(o: Override): string {
  const what = `${systemLabel(o.system)} ${o.mode === 'read_only' ? 'read-only' : 'suspended'}`;
  if (o.status === 'blocked') return `${what} · restore blocked`;
  if (!o.expiresAt) return `${what} · until released`;
  return `${what} · restores at ${fmtClock(o.expiresAt)}`;
}

/** `now` is for tests; by default the chip ticks every second. */
export function SuspensionChip({ o, now }: { o: Override; now?: number }) {
  const ticking = useNow(1000);
  const t = now ?? ticking;
  const left = o.expiresAt && o.status === 'active' ? fmtCountdown(o.expiresAt, t) : '';
  const color = o.status === 'blocked' ? 'red' : o.mode === 'read_only' ? 'amber' : 'orange';
  return (
    <span className={`chip ${color}`} data-testid="suspension-chip" title={o.blockedReason ?? o.reason}>
      <IconClock size={12} />
      {suspensionText(o)}
      {left && (
        <span className="countdown" aria-label={`time left ${left}`}>
          ({left})
        </span>
      )}
    </span>
  );
}
