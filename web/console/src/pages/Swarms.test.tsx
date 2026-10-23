import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp, securityMe } from '../test/render';
import { KILL_STEPS, SwarmsPage, swarmTiming } from './Swarms';

beforeEach(() => {
  swarmTiming.tickMs = 0;
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const ago = (m: number) => new Date(Date.now() - m * 60_000).toISOString();
const members = ['root-bot', 'w1', 'w2'];
const STEP_NAMES = ['freeze_spawning', 'hold_pending', 'revoke_credentials', 'cancel_queue', 'remove_memory', 'stop_copies', 'seal_bundle'];

const detail = (extra: Record<string, unknown> = {}) => ({
  swarm_id: 'dlg_root1',
  state: 'active',
  detected_by: 'action_hash',
  signal: { kind: 'action_hash', action_hash: 'sha256:abc', distinct_agents: 6, window_seconds: 60 },
  root_agent_id: 'root-bot',
  member_count: 3,
  created_at: ago(5),
  members: [
    { agent_id: 'root-bot', role: 'root', level: 'FULL' },
    { agent_id: 'w1', parent: 'root-bot', level: 'FULL' },
    { agent_id: 'w2', parent: 'root-bot', level: 'FULL' },
  ],
  breakers: [{ breaker_id: 'brk_1', action_hash: 'sha256:abc', state: 'tripped', tripped_at: ago(4), tripped_by: 'system:swarm', matched: 35 }],
  held: [{ action_id: 'act_h6', agent_id: 'w6', rule_id: 'POL-651', class: 'yellow', system: 'gmail', verb: 'SEND', outcome: 'pending', approvals_required: 2, created_at: ago(3), expires_at: new Date(Date.now() + 3600_000).toISOString() }],
  release_votes: [],
  release_required: 2,
  ...extra,
});

function renderDetail(me = securityMe) {
  return renderWithApp(
    <Routes>
      <Route path="/swarms/:swarmId" element={<SwarmsPage />} />
      <Route path="/swarms" element={<SwarmsPage />} />
    </Routes>,
    me,
    false,
    '/swarms/dlg_root1',
  );
}

describe('Swarms', () => {
  it('lists swarms with state chips, signal, members and created', async () => {
    installFakeApi({
      'GET /v1/swarms': {
        swarms: [
          { swarm_id: 'dlg_root1', state: 'active', detected_by: 'action_hash', member_count: 41, created_at: ago(2), root_agent_id: 'root-bot' },
          { swarm_id: 'swm_01', state: 'released', detected_by: 'copy_surge', member_count: 7, created_at: ago(90) },
        ],
      },
    });
    renderWithApp(<SwarmsPage />, auditorMe);
    const rows = await screen.findAllByTestId('swarm-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText('Identical action (Max-5 breaker)')).toBeTruthy();
    expect(within(rows[0]!).getByText('41')).toBeTruthy();
    expect(within(rows[0]!).getByTestId('swarm-state').textContent).toBe('active');
    expect(within(rows[1]!).getByText('Copy surge')).toBeTruthy();
    expect(screen.getByText('1 active')).toBeTruthy();
  });

  it('shows the detail and kills the swarm with each of the 7 steps ticking off per member', async () => {
    const { calls } = installFakeApi({
      'GET /v1/swarms/dlg_root1': detail(),
      'POST /v1/swarms/dlg_root1/kill': () => ({
        body: {
          op_id: 'op_k1',
          op: 'kill_swarm',
          target_type: 'swarm',
          target_id: 'dlg_root1',
          status: 'partial',
          steps: STEP_NAMES.flatMap((name) =>
            name === 'freeze_spawning' || name === 'seal_bundle'
              ? [{ name, status: 'done', detail: name === 'seal_bundle' ? 'swarm.sealed seq 812' : undefined }]
              : members.map((m) => ({
                  name,
                  agent_id: m,
                  status: name === 'revoke_credentials' && m === 'w2' ? 'failed' : name === 'stop_copies' && m === 'root-bot' ? 'skipped' : 'done',
                  detail: name === 'revoke_credentials' && m === 'w2' ? 'aws: STS tokens not recallable' : undefined,
                })),
          ),
        },
      }),
    });
    renderDetail();
    await screen.findByTestId('swarm-detail');
    expect(screen.getAllByTestId('swarm-member')).toHaveLength(3);
    expect(within(screen.getByTestId('spawn-tree')).getByText('w2')).toBeTruthy();
    expect(within(screen.getByTestId('signal-facts')).getByText('sha256:abc')).toBeTruthy();
    expect(screen.getByText('35')).toBeTruthy(); // breaker matched count
    expect(screen.getAllByTestId('held-item')).toHaveLength(1);

    fireEvent.click(screen.getByRole('button', { name: 'Kill swarm' }));
    const dialog = screen.getByRole('dialog');
    for (const s of KILL_STEPS) expect(within(dialog).getByText(s)).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'kill-swarm demo' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /Kill swarm/ }));

    const result = await screen.findByTestId('swarm-op-result');
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ reason: 'kill-swarm demo', keep_root_read_only: true });
    const steps = within(result).getAllByTestId('swarm-step');
    expect(steps).toHaveLength(7);
    expect(within(steps[0]!).getByText('Freeze spawning')).toBeTruthy();
    expect(steps[2]!.getAttribute('data-status')).toBe('failed');
    expect(within(steps[2]!).getByTestId('swarm-step-counts').textContent).toBe('2 done · 1 failed');
    expect(within(steps[2]!).getByText('w2: aws: STS tokens not recallable')).toBeTruthy();
    expect(steps[5]!.getAttribute('data-status')).toBe('done');
    expect(within(steps[5]!).getByTestId('swarm-step-counts').textContent).toBe('2 done · 1 skipped');
    expect(within(steps[6]!).getByText('Seal the Diary bundle')).toBeTruthy();
    expect(within(result).getByTestId('op-status').textContent).toBe('partial');
  });

  it('reveals the kill steps one by one', async () => {
    swarmTiming.tickMs = 15;
    installFakeApi({
      'GET /v1/swarms/dlg_root1': detail(),
      'POST /v1/swarms/dlg_root1/kill': { op_id: 'op_k2', op: 'kill_swarm', target_id: 'dlg_root1', status: 'done', steps: STEP_NAMES.map((name) => ({ name, status: 'done' })) },
    });
    renderDetail();
    await screen.findByTestId('swarm-detail');
    fireEvent.click(screen.getByRole('button', { name: 'Kill swarm' }));
    fireEvent.change(screen.getByLabelText(/Reason/), { target: { value: 'x' } });
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: /Kill swarm/ }));
    const result = await screen.findByTestId('swarm-op-result');
    const statuses = () => within(result).getAllByTestId('swarm-step').map((s) => s.getAttribute('data-status'));
    expect(statuses()).toContain('pending');
    await waitFor(() => expect(statuses().every((s) => s === 'done')).toBe(true));
  });

  it('records the first release vote as 1 of 2 and blocks the same approver from the second', async () => {
    let votes: unknown[] = [];
    const { calls } = installFakeApi({
      'GET /v1/swarms/dlg_root1': () => ({ body: detail({ release_votes: votes }) }),
      'POST /v1/swarms/dlg_root1/release': () => {
        votes = [{ approver: 'user:sec@example.com', at: new Date().toISOString() }];
        return { body: { released: false, votes: 1, required: 2 } };
      },
    });
    renderDetail();
    await screen.findByTestId('swarm-detail');
    expect(within(screen.getByTestId('release-progress')).getByText('0 of 2 approvals')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Release (0 of 2)' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByText(/Your vote is the first of 2/)).toBeTruthy();
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'false positive' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Vote to release' }));
    expect(await screen.findByText('Vote recorded (1 of 2 approvals)')).toBeTruthy();
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ reason: 'false positive' });
    await waitFor(() => expect(within(screen.getByTestId('release-progress')).getByText('1 of 2 approvals')).toBeTruthy());
    const btn = screen.getByRole('button', { name: 'Release (1 of 2)' }) as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(btn.title).toMatch(/different security approver/);
    expect(within(screen.getByTestId('release-progress')).getByText(/never un-kills/)).toBeTruthy();
  });

  it('lets an auditor read and export the bundle but not act', async () => {
    const created: Blob[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => undefined);
    vi.stubGlobal('URL', Object.assign(URL, { createObjectURL: (b: Blob) => (created.push(b), 'blob:x'), revokeObjectURL: () => undefined }));
    const { calls } = installFakeApi({ 'GET /v1/swarms/dlg_root1': detail(), 'GET /v1/swarms/dlg_root1/bundle': { swarm_id: 'dlg_root1', signature: 'ed25519:...' } });
    renderDetail(auditorMe);
    await screen.findByTestId('swarm-detail');
    for (const name of ['Trip breaker', 'Suspend', 'Isolate', 'Kill swarm', 'Release (0 of 2)']) {
      expect((screen.getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect(screen.getByText(/Swarm actions require the security role/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /Export bundle/ }));
    expect(await screen.findByText('Bundle exported')).toBeTruthy();
    expect(calls.some((c) => c.path === '/v1/swarms/dlg_root1/bundle')).toBe(true);
    expect(created).toHaveLength(1);
    expect(click).toHaveBeenCalledTimes(1);
    click.mockRestore();
  });
});
