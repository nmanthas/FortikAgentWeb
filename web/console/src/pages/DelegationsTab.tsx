// Agent → Delegations (docs/PHASE3_DESIGN.md §1, §7): inbound and outbound
// hops drawn as A → B → C, and blocked delegations, with bypass attempts
// (POL-601, Diary event delegation.bypass_blocked) highlighted.
//
// Data: GET /v1/agents/{id}/delegations (hops + refusals by POL-601..604),
// enriched with delegation.bypass_blocked Diary events (who was stepped
// down). Servers without the endpoint fall back to the Diary alone.

import { getDelegations, DELEGATION_WINDOW_HOURS } from '../api/endpoints';
import type { BlockedDelegation, DelegationView, Hop } from '../api/types';
import { DelegationChain } from '../components/DelegationChain';
import { IconAlert } from '../components/Icons';
import { ErrorBox, Loading } from '../components/ui';
import { fmtAgo, fmtTime } from '../lib/format';
import { useLiveRefresh } from '../lib/live';
import { useAsync } from '../lib/useAsync';

const RULE_TEXT: Record<string, string> = {
  'POL-601': 'bypass blocked',
  'POL-602': 'too deep',
  'POL-603': 'delegation not allowed',
  'POL-604': 'invalid delegation token',
};

const CHANNEL_TEXT: Record<string, string> = { a2a: 'A2A', mcp: 'MCP', spawn: 'spawn', hook_task: 'Claude Code subagent' };

export function DelegationsTab({ agentId }: { agentId: string }) {
  const view = useAsync<DelegationView>((s) => getDelegations(agentId, s), [agentId]);
  useLiveRefresh(
    (e) => e.eventType.startsWith('delegation.') || (e.eventType === 'action.decided' && /^POL-60[1-4]$/.test(String(e.data.rule_id ?? ''))),
    view.reload,
    800,
  );
  const v = view.data;
  const bypasses = v?.blocked.filter((b) => b.bypass) ?? [];
  const other = v?.blocked.filter((b) => !b.bypass) ?? [];
  return (
    <>
      {view.error && <ErrorBox error={view.error} onRetry={view.reload} />}
      {!v && view.loading && <Loading />}
      {v && (
        <>
          <div className="card">
            <div className="card-head">
              <div>
                <h2>Blocked bypass attempts</h2>
                <div className="sub">An agent asked others to do what it may not do itself. Every hop&apos;s permissions are checked (POL-601).</div>
              </div>
              {bypasses.length > 0 && <span className="chip red">{bypasses.length}</span>}
            </div>
            {bypasses.length === 0 && <div className="empty">No blocked bypass attempts involving this agent.</div>}
            <div className="timeline" style={{ padding: '0 20px' }}>
              {bypasses.map((b) => (
                <BlockedRow key={b.actionId || b.seq} b={b} agentId={agentId} />
              ))}
            </div>
          </div>
          {other.length > 0 && (
            <div className="card">
              <div className="card-head">
                <div>
                  <h2>Other refused delegations</h2>
                  <div className="sub">Chains that were too deep, delegations the profile does not allow, and invalid delegation tokens.</div>
                </div>
              </div>
              <div className="timeline" style={{ padding: '0 20px' }}>
                {other.map((b) => (
                  <BlockedRow key={b.actionId || b.seq} b={b} agentId={agentId} />
                ))}
              </div>
            </div>
          )}
          <HopList title="Outbound" sub="Tasks this agent handed to other agents (or to its own subagents)." hops={v.outbound} agentId={agentId} />
          <HopList title="Inbound" sub="Tasks other agents handed to this agent. Its actions are checked against everyone upstream." hops={v.inbound} agentId={agentId} />
          {v.source === 'diary' && (
            <p className="help">This server has no delegations endpoint: the view is rebuilt from the last {DELEGATION_WINDOW_HOURS} hours of the Diary.</p>
          )}
        </>
      )}
    </>
  );
}

function BlockedRow({ b, agentId }: { b: BlockedDelegation; agentId: string }) {
  return (
    <div className={`tl-item${b.bypass ? ' bypass' : ''}`} data-testid={b.bypass ? 'bypass-item' : 'blocked-item'}>
      <div className="tl-time" title={fmtTime(b.ts)}>
        {fmtAgo(b.ts)}
      </div>
      <div className="tl-main">
        <div className="tl-line">
          <span className={`chip ${b.bypass ? 'red' : 'amber'}`}>
            {b.bypass && <IconAlert size={12} />} {RULE_TEXT[b.ruleId] ?? 'blocked'}
          </span>
          <strong>
            {b.system} {b.verb}
          </strong>
          {b.ruleId && <span className="rule">{b.ruleId}</span>}
        </div>
        {b.chain.length > 0 && (
          <div style={{ margin: '6px 0' }}>
            <DelegationChain chain={b.chain} status="blocked" current={agentId} blocked={b.bypass} />
          </div>
        )}
        {b.reason && <div className="tl-reason">{b.reason}</div>}
        {b.steppedDown.length > 0 && (
          <div className="muted small">
            Originating agent{b.steppedDown.length > 1 ? 's' : ''} {b.steppedDown.join(', ')} stepped down
            {b.originLevel ? ` to ${b.originLevel.replace(/_/g, ' ')}` : ''}.
          </div>
        )}
        {b.actionId && <div className="muted small">action {b.actionId}</div>}
      </div>
    </div>
  );
}

function HopList({ title, sub, hops, agentId }: { title: string; sub: string; hops: Hop[]; agentId: string }) {
  return (
    <div className="card">
      <div className="card-head">
        <div>
          <h2>{title}</h2>
          <div className="sub">{sub}</div>
        </div>
        {hops.length > 0 && <span className="chip gray">{hops.length}</span>}
      </div>
      {hops.length === 0 && <div className="empty">No {title.toLowerCase()} delegations.</div>}
      <div className="timeline" style={{ padding: '0 20px' }}>
        {hops.map((h) => (
          <div key={h.delegationId} className="tl-item" data-testid={`hop-${title.toLowerCase()}`}>
            <div className="tl-time" title={fmtTime(h.openedAt)}>
              {fmtAgo(h.openedAt)}
            </div>
            <div className="tl-main">
              <DelegationChain chain={h.chain.length ? h.chain : [h.from, h.to]} status={h.status} current={agentId} />
              <div className="muted small">
                depth {h.depth} · via {CHANNEL_TEXT[h.channel] ?? (h.channel || 'unknown')}
                {h.taskId && ` · task ${h.taskId}`}
                {h.status === 'open' && h.expiresAt && ` · expires ${fmtTime(h.expiresAt)}`}
                {h.closedAt && ` · ended ${fmtTime(h.closedAt)}`}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
