import { act, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Override } from '../api/types';
import { SuspensionChip, suspensionText } from './SuspensionChip';

afterEach(() => {
  vi.useRealTimers();
});

// Local times: the chip shows the restore time in the viewer's time zone.
const at = (h: number, m: number, s = 0) => new Date(2026, 9, 13, h, m, s);

const github: Override = {
  overrideId: 'ovr_1',
  scope: 'agent',
  scopeId: 'billing-bot',
  system: 'github',
  mode: 'suspended',
  startsAt: at(11, 25).toISOString(),
  expiresAt: at(11, 55).toISOString(),
  reason: 'leaked token investigation',
  createdBy: 'user:sec@example.com',
  status: 'active',
};

describe('SuspensionChip', () => {
  it('reads "GitHub suspended · restores at 11:55" with the time left', () => {
    render(<SuspensionChip o={github} now={at(11, 43, 30).getTime()} />);
    const chip = screen.getByTestId('suspension-chip');
    expect(chip.textContent).toContain('GitHub suspended · restores at 11:55');
    expect(chip.textContent).toContain('(11m 30s)');
    expect(screen.getByLabelText('time left 11m 30s')).toBeTruthy();
  });

  it('counts down live, once a second', () => {
    vi.useFakeTimers();
    vi.setSystemTime(at(11, 54, 58));
    render(<SuspensionChip o={github} />);
    expect(screen.getByTestId('suspension-chip').textContent).toContain('(2s)');
    act(() => {
      vi.advanceTimersByTime(1000);
    });
    expect(screen.getByTestId('suspension-chip').textContent).toContain('(1s)');
    act(() => {
      vi.advanceTimersByTime(2000);
    });
    expect(screen.getByTestId('suspension-chip').textContent).toContain('(due)');
  });

  it('words read-only, until-released and blocked suspensions', () => {
    expect(suspensionText({ ...github, mode: 'read_only' })).toBe('GitHub read-only · restores at 11:55');
    expect(suspensionText({ ...github, system: 'drive', expiresAt: undefined })).toBe('Google Drive suspended · until released');
    expect(suspensionText({ ...github, status: 'blocked' })).toBe('GitHub suspended · restore blocked');

    // No countdown once restore is blocked or when there is no expiry.
    const { rerender } = render(<SuspensionChip o={{ ...github, status: 'blocked', blockedReason: 'red action during suspension' }} now={at(11, 43).getTime()} />);
    expect(screen.queryByLabelText(/time left/)).toBeNull();
    expect(screen.getByTestId('suspension-chip').getAttribute('title')).toBe('red action during suspension');
    rerender(<SuspensionChip o={{ ...github, expiresAt: undefined }} now={at(11, 43).getTime()} />);
    expect(screen.queryByLabelText(/time left/)).toBeNull();
  });
});
