import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp } from '../test/render';
import { BaselineTab } from './BaselineTab';

afterEach(() => {
  vi.unstubAllGlobals();
});

const hour = (i: number) => new Date(Date.UTC(2026, 9, 19, 0) + i * 3600_000).toISOString();
const series = Array.from({ length: 48 }, (_, i) => ({ hour: hour(i), count: i === 47 ? 30 : 4 }));

describe('Baseline tab', () => {
  it('draws the hourly bars with the threshold line and the stats', async () => {
    const { calls } = installFakeApi({
      'GET /v1/agents/billing-bot/baseline': { agent_id: 'billing-bot', verb: 'SEND', verbs: ['SEND', 'READ'], series, mean: 4, stddev: 1.2, median: 4, history_days: 2, threshold: 20, current: 30, above_normal: true, method: '5x_median' },
    });
    renderWithApp(<BaselineTab agentId="billing-bot" />, auditorMe);
    const chart = await screen.findByTestId('baseline-chart');
    expect(calls[0]!.path).toBe('/v1/agents/billing-bot/baseline');
    expect(within(chart).getAllByTestId('bar')).toHaveLength(47);
    expect(within(chart).getAllByTestId('bar-above')).toHaveLength(1);
    expect(within(chart).getByTestId('baseline-threshold').textContent).toContain('threshold 20');
    expect(chart.getAttribute('aria-label')).toContain('1 hour above it');
    expect(screen.getByText('Above normal now')).toBeTruthy();
    expect(screen.getByText(/Less than 3 days of history/)).toBeTruthy();
    const stats = screen.getByTestId('baseline-stats');
    expect(within(stats).getByText('4 ± 1.2')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Verb'), { target: { value: 'READ' } });
    await waitFor(() => expect(calls.some((c) => c.path === '/v1/agents/billing-bot/baseline?verb=READ')).toBe(true));
  });

  it('says so when the server has no baselines', async () => {
    installFakeApi({});
    renderWithApp(<BaselineTab agentId="billing-bot" />, auditorMe);
    expect(await screen.findByText(/does not compute behaviour baselines yet/)).toBeTruthy();
  });
});
