import { render, screen, within } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { DelegationChain } from './DelegationChain';

describe('DelegationChain', () => {
  it('renders A → B → C with the status and the current agent emphasised', () => {
    render(<DelegationChain chain={['planner', 'researcher', 'db-bot']} status="open" current="researcher" />);
    const chain = screen.getByTestId('delegation-chain');
    expect(chain.textContent).toBe('planner→researcher→db-bot' + 'open');
    expect(chain.getAttribute('aria-label')).toBe('chain planner → researcher → db-bot, open');
    expect(within(chain).getAllByText('→')).toHaveLength(2);
    expect(within(chain).getByText('researcher').className).toContain('current');
    expect(within(chain).getByText('planner').className).not.toContain('origin');
    expect(within(chain).getByText('open').className).toBe('chip blue');
  });

  it('marks the originating agent and the executor of a blocked bypass', () => {
    render(<DelegationChain chain={['intern-bot', 'helper', 'db-bot']} status="blocked" current="helper" blocked />);
    const chain = screen.getByTestId('delegation-chain');
    expect(chain.className).toContain('blocked');
    const origin = within(chain).getByText('intern-bot');
    expect(origin.className).toContain('origin');
    expect(origin.getAttribute('title')).toBe('originating agent');
    expect(within(chain).getByText('db-bot').className).toContain('executor');
    expect(within(chain).getByText('blocked').className).toBe('chip red');
  });

  it('renders a single hop and repeated agents', () => {
    render(<DelegationChain chain={['coder', 'coder']} status="closed" />);
    const chain = screen.getByTestId('delegation-chain');
    expect(within(chain).getAllByText('coder')).toHaveLength(2);
    expect(within(chain).getByText('closed').className).toBe('chip gray');
  });
});
