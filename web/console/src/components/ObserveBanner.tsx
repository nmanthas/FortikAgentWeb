// Observe mode (Phase 6): when the deployment, or some agents, only record
// what Fortik would enforce, every screen says so. Nothing is shown when the
// server has no observe mode or everything is enforced.
import { Link } from 'react-router-dom';
import { getEnforcement, type Enforcement } from '../api/phase6';
import { useAsync } from '../lib/useAsync';

export function observeText(e: Enforcement | null | undefined): string | null {
  if (!e) return null;
  if (e.mode === 'observe') {
    const n = e.enforceAgents.length;
    return `OBSERVE MODE — Fortik records what it would enforce and does not enforce it${n ? ` (except ${n} agent${n === 1 ? '' : 's'} set to enforce)` : ''}. Unknown actions, fail-closed outcomes and levels set by people are still enforced.`;
  }
  const n = e.observeAgents.length;
  if (n === 0) return null;
  return `${n} agent${n === 1 ? ' is' : 's are'} in observe mode: their decisions are recorded, not enforced (${e.observeAgents.slice(0, 3).join(', ')}${n > 3 ? ', …' : ''}).`;
}

export function ObserveBanner() {
  const e = useAsync((s) => getEnforcement(s), []);
  const text = observeText(e.data);
  if (!text) return null;
  return (
    <div className="observe-banner" role="status" data-testid="observe-banner">
      {text} <Link to="/agents">Agents</Link>
    </div>
  );
}
