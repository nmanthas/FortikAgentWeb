// Turns live Diary events into toasts: red decisions, control-level
// changes and newly raised alerts. Only summaries from the event (agent, verb, rule, levels) are
// shown, never payloads.

import { useEffect } from 'react';
import type { DiaryEvent } from '../api/types';
import { useLive } from '../lib/live';
import { useToast, type Toast } from './Toasts';

const s = (v: unknown): string => (typeof v === 'string' ? v : '');

/** Returns the toast for an event, or null when it does not warrant one. */
export function toastFor(e: DiaryEvent): Omit<Toast, 'id'> | null {
  const agent = e.agentId ?? 'unknown agent';
  if (e.eventType === 'action.decided' && s(e.data.class) === 'red') {
    const decision = s(e.data.decision) || 'decided';
    const what = [s(e.data.system), s(e.data.verb)].filter(Boolean).join(' ');
    const rule = s(e.data.rule_id);
    return {
      tone: 'red',
      title: `Dangerous action ${decision.replace('_', ' ')}: ${agent}`,
      body: [what, rule && `rule ${rule}`, s(e.data.reason)].filter(Boolean).join(' · '),
    };
  }
  if (e.eventType === 'agent.level_changed') {
    const from = s(e.data.from);
    const to = s(e.data.to);
    const auto = e.data.automatic === true;
    const down = s(e.data.direction) !== 'up';
    const reason = s(e.data.reason) || s(e.data.rule_id);
    return {
      tone: down ? (to === 'KILLED' || to === 'QUARANTINED' ? 'red' : 'amber') : 'green',
      title: `${agent}: ${from || '?'} → ${to || '?'}${auto ? ' (automatic)' : ''}`,
      body: reason || undefined,
    };
  }
  if (e.eventType === 'alert.raised') {
    const sev = s(e.data.severity);
    const kind = s(e.data.kind).replace(/_/g, ' ');
    return {
      tone: sev === 'info' ? 'info' : sev === 'warning' ? 'amber' : 'red',
      title: `Alert (${sev || 'unknown'}): ${kind || 'alert'}${e.agentId ? ` · ${e.agentId}` : ''}`,
      body: s(e.data.summary) || undefined,
    };
  }
  return null;
}

export function LiveToasts() {
  const { subscribe } = useLive();
  const toast = useToast();
  useEffect(
    () =>
      subscribe((e) => {
        if (!e) return;
        const t = toastFor(e);
        if (t) toast(t);
      }),
    [subscribe, toast],
  );
  return null;
}
