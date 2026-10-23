import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { normContainmentOp } from '../api/normalize';
import { installFakeApi } from '../test/fakeApi';
import { ContainmentResultView, EStopDialog, OpDialog, stepLabel } from './Containment';
import { ReasonDialog } from './ui';

afterEach(() => {
  vi.unstubAllGlobals();
});

const opRaw = (extra: Record<string, unknown> = {}) => ({
  op_id: 'cop_1',
  op: 'estop',
  target_type: 'fleet',
  target_id: '',
  actor: 'user:sec@example.com',
  reason: 'incident',
  status: 'partial',
  steps: [
    { name: 'mark_suspended', agent_id: 'billing-bot', status: 'done', duration_ms: 3 },
    { name: 'revoke_credentials', agent_id: 'billing-bot', status: 'done', detail: 'aws: STS tokens not recallable; deny-by-issue-time attached', duration_ms: 40 },
    { name: 'pause_queues', agent_id: 'billing-bot', status: 'skipped', detail: 'no queue integration configured', duration_ms: 0 },
    { name: 'pause_instances', agent_id: 'billing-bot', status: 'failed', detail: 'instance store unavailable', duration_ms: 5 },
    { name: 'seal', status: 'exploded' },
  ],
  created_at: '2026-10-18T10:00:00Z',
  ...extra,
});

describe('Fleet E-Stop dialog', () => {
  it('requires the exact phrase and a reason, then posts the confirmation and shows every step', async () => {
    const { calls } = installFakeApi({ 'POST /v1/fleet/estop': opRaw() });
    const onDone = vi.fn();
    render(<EStopDialog onDone={onDone} onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog', { name: 'Fleet E-Stop' });
    const go = within(dialog).getByRole('button', { name: /Stop all agents/ }) as HTMLButtonElement;
    const phrase = within(dialog).getByLabelText(/to confirm/);
    const reason = within(dialog).getByLabelText(/Reason/);

    expect(go.disabled).toBe(true);
    fireEvent.change(reason, { target: { value: 'credential leak' } });
    expect(go.disabled).toBe(true); // phrase still missing
    fireEvent.change(phrase, { target: { value: 'stop all agents' } });
    expect(go.disabled).toBe(true); // case matters
    fireEvent.change(phrase, { target: { value: 'STOP ALL AGENTS ' } });
    expect(go.disabled).toBe(true); // exact, no trailing space
    fireEvent.change(phrase, { target: { value: 'STOP ALL AGENTS' } });
    expect(go.disabled).toBe(false);
    fireEvent.click(go);

    expect(await screen.findByRole('dialog', { name: 'Fleet E-Stop — result' })).toBeTruthy();
    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe('POST');
    expect(calls[0]!.path).toBe('/v1/fleet/estop');
    expect(calls[0]!.body).toEqual({ reason: 'credential leak', confirm: 'STOP ALL AGENTS' });
    expect(screen.getAllByTestId('containment-step')).toHaveLength(5);
    expect(onDone).toHaveBeenCalledTimes(1);
  });

  it('shows the server error and stays open when the e-stop is refused', async () => {
    installFakeApi({ 'POST /v1/fleet/estop': () => ({ status: 403, body: { error: 'fleet e-stop requires the security role' } }) });
    render(<EStopDialog onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog', { name: 'Fleet E-Stop' });
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'x' } });
    fireEvent.change(within(dialog).getByLabelText(/to confirm/), { target: { value: 'STOP ALL AGENTS' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /Stop all agents/ }));
    expect(await within(dialog).findByText(/Not allowed: fleet e-stop requires the security role/)).toBeTruthy();
    expect(screen.queryByTestId('containment-result')).toBeNull();
  });
});

describe('ContainmentResultView', () => {
  it('lists every step with its own status and detail, never upgrading an unknown status', () => {
    render(<ContainmentResultView op={normContainmentOp(opRaw())} />);
    const steps = screen.getAllByTestId('containment-step');
    const statuses = steps.map((s) => within(s).getByTestId('step-status').textContent);
    expect(statuses).toEqual(['done', 'done', 'skipped', 'failed', 'unknown']);
    expect(within(steps[1]!).getByText('Revoke live credentials')).toBeTruthy();
    expect(within(steps[1]!).getByText('aws: STS tokens not recallable; deny-by-issue-time attached')).toBeTruthy();
    expect(within(steps[3]!).getByText('instance store unavailable')).toBeTruthy();
    expect(screen.getByTestId('op-status').textContent).toBe('partial');
    expect(screen.getByText('2 done, 1 skipped, 1 failed, 1 unknown')).toBeTruthy();
    expect(screen.getByText(/Only the steps marked done took effect/)).toBeTruthy();
  });

  it('still reports the steps when the server answers a partial run with an error status', async () => {
    installFakeApi({
      'POST /v1/agents/billing-bot/suspend': () => ({
        status: 502,
        body: { error: 'some steps failed', ...opRaw({ op: 'suspend', target_type: 'agent', target_id: 'billing-bot' }) },
      }),
    });
    const { agentOp } = await import('../api/endpoints');
    const op = await agentOp('billing-bot', 'suspend', 'r');
    expect(op.httpError).toBe('some steps failed');
    render(<ContainmentResultView op={op} />);
    expect(screen.getByRole('alert').textContent).toContain('some steps failed');
    await waitFor(() => expect(screen.getAllByTestId('containment-step')).toHaveLength(5));
  });

  it('refuses to invent a result when the server reports no op', async () => {
    installFakeApi({ 'POST /v1/agents/billing-bot/resume': { ok: true } });
    const { agentOp } = await import('../api/endpoints');
    await expect(agentOp('billing-bot', 'resume', 'r')).rejects.toThrow(/did not report the operation/);
  });
});

describe('step labels', () => {
  it('names the steps internal/containment reports, and title-cases unknown ones', () => {
    expect(stepLabel('pause_queue')).toBe('Pause queued jobs');
    expect(stepLabel('cancel_queue')).toBe('Cancel queued jobs');
    expect(stepLabel('suspend_instances')).toBe('Tell running copies to pause');
    expect(stepLabel('pause_extra_copies')).toBe('Pause copies over the cap');
    expect(stepLabel('set_memory_access')).toBe('Set memory access');
    expect(stepLabel('terminate_db_sessions')).toBe('Terminate database sessions');
    expect(stepLabel('some_new_step')).toBe('Some New Step');
  });
});

describe('reason fields (F27 / D3)', () => {
  const run = vi.fn(async () => normContainmentOp({ ...opRaw(), op: 'suspend', status: 'done', steps: [] }));

  it('OpDialog sends a multi-line reason with its newlines and tabs, without other control characters', async () => {
    run.mockClear();
    render(<OpDialog title="Suspend: billing-bot" confirmLabel="Suspend" run={run} onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog', { name: 'Suspend: billing-bot' });
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: '  Incident 42:\r\n- exfil attempt\n\t- see ticket\u0007  ' } });
    expect(within(dialog).getByTestId('reason-help').textContent).toMatch(/Several lines are fine\. \d+ \/ 1000 bytes\./);
    fireEvent.click(within(dialog).getByRole('button', { name: 'Suspend' }));
    await screen.findByRole('dialog', { name: 'Suspend: billing-bot — result' });
    expect(run).toHaveBeenCalledWith('Incident 42:\n- exfil attempt\n\t- see ticket');
  });

  it('OpDialog refuses a reason over 1000 bytes and says by how much, instead of cutting it', () => {
    run.mockClear();
    render(<OpDialog title="Suspend: billing-bot" confirmLabel="Suspend" run={run} onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog', { name: 'Suspend: billing-bot' });
    const field = within(dialog).getByLabelText(/Reason/) as HTMLTextAreaElement;
    const go = within(dialog).getByRole('button', { name: 'Suspend' }) as HTMLButtonElement;
    expect(field.maxLength).toBe(-1); // never silently truncated
    fireEvent.change(field, { target: { value: 'é'.repeat(501) } }); // 501 characters, 1002 bytes
    expect(go.disabled).toBe(true);
    expect(field.getAttribute('aria-invalid')).toBe('true');
    expect(within(dialog).getByRole('alert').textContent).toMatch(/1002 bytes long; at most 1000 are allowed\. Shorten it by 2\./);
    fireEvent.click(go);
    expect(run).not.toHaveBeenCalled();
    fireEvent.change(field, { target: { value: 'é'.repeat(500) } }); // exactly 1000 bytes
    expect(go.disabled).toBe(false);
  });

  it('ReasonDialog applies the same rules', async () => {
    const onConfirm = vi.fn(async () => undefined);
    render(<ReasonDialog title="Pause extra copies?" confirmLabel="Pause extra" onConfirm={onConfirm} onClose={() => undefined} />);
    const dialog = screen.getByRole('dialog', { name: 'Pause extra copies?' });
    const go = within(dialog).getByRole('button', { name: 'Pause extra' }) as HTMLButtonElement;
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'x'.repeat(1001) } });
    expect(go.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'first line\nsecond line' } });
    fireEvent.click(go);
    await waitFor(() => expect(onConfirm).toHaveBeenCalledWith('first line\nsecond line'));
  });
});
