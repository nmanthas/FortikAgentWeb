// Renders a delegation chain as "A → B → C" with a status chip
// (docs/PHASE3_DESIGN.md §1, §7). The current agent is emphasised; a blocked
// bypass marks the originating agent and the executor.

import { Fragment } from 'react';

const STATUS_COLOR: Record<string, string> = { open: 'blue', closed: 'gray', expired: 'gray', refused: 'red', blocked: 'red' };

export function DelegationChain({
  chain,
  status,
  current,
  blocked,
}: {
  chain: string[];
  status: string;
  current?: string;
  blocked?: boolean;
}) {
  const label = chain.join(' → ');
  return (
    <span className={`chain${blocked ? ' blocked' : ''}`} data-testid="delegation-chain" aria-label={`chain ${label}, ${status}`}>
      {chain.map((a, i) => (
        <Fragment key={`${a}-${i}`}>
          {i > 0 && (
            <span className="chain-arrow" aria-hidden="true">
              →
            </span>
          )}
          <span
            className={`chain-node${a === current ? ' current' : ''}${blocked && i === 0 ? ' origin' : ''}${blocked && i === chain.length - 1 ? ' executor' : ''}`}
            title={blocked && i === 0 ? 'originating agent' : blocked && i === chain.length - 1 ? 'executor' : undefined}
          >
            {a}
          </span>
        </Fragment>
      ))}
      <span className={`chip ${STATUS_COLOR[status] ?? 'gray'}`}>{status}</span>
    </span>
  );
}
