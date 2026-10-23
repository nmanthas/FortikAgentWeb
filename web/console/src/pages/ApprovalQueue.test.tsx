import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi, type Recorded } from '../test/fakeApi';
import { auditorMe, renderWithApp, securityMe } from '../test/render';
import { ApprovalsPage, DEFAULT_FILTERS, filterQueue, PAGE_SIZE, sortQueue } from './Approvals';
import { normQueue } from '../api/normalize';

afterEach(() => {
  vi.unstubAllGlobals();
});

const later = () => new Date(Date.now() + 3600_000).toISOString();
const item = (id: string, extra: Record<string, unknown> = {}) => ({
  action_id: id,
  agent_id: 'billing-bot',
  rule_id: 'POL-201',
  reason: 'needs a human',
  approvals_required: 1,
  approver_role: 'security',
  expires_at: later(),
  outcome: 'pending',
  created_at: new Date(Date.now() - Number(id.replace(/\D/g, '') || 0) * 1000).toISOString(),
  class: 'yellow',
  system: 'gmail',
  verb: 'SEND',
  votes: [],
  ...extra,
});

const swarmItems = [
  item('h1', { agent_id: 'w1', rule_id: 'POL-651', swarm_id: 'dlg_root1', approvals_required: 2, votes: [{ approver: 'user:sec@example.com', decision: 'approve', at: new Date().toISOString() }] }),
  item('h2', { agent_id: 'w2', rule_id: 'POL-651', swarm_id: 'dlg_root1', approvals_required: 2, votes: [{ approver: 'user:other@example.com', decision: 'approve', at: new Date().toISOString() }] }),
];
const other = [item('h3', { class: 'red', system: 'postgres', verb: 'DELETE', assigned_to: 'sec@example.com' }), item('h4', { agent_id: 'mail-bot' })];

function routes(items: unknown[], extra: Record<string, unknown> = {}) {
  return {
    'GET /v1/approvals/queue': (req: Recorded) => {
      const q = new URL(req.path, 'http://x').searchParams;
      // The server contract (internal/approvals/queue.go normalize): limit 1..500, class green|yellow|red, paged by offset.
      const limit = Number(q.get('limit') ?? '100');
      const offset = Number(q.get('offset') ?? '0');
      if (!(limit >= 1 && limit <= 500)) return { status: 400, body: { error: 'invalid request: limit must be 1..500' } };
      const cls = q.get('class');
      if (cls && !['green', 'yellow', 'red'].includes(cls)) return { status: 400, body: { error: 'invalid request: class must be green, yellow or red' } };
      const all = cls ? (items as { class: string }[]).filter((i) => i.class === cls) : items;
      const page = all.slice(offset, offset + limit);
      return { body: { items: page, offset, limit, next_offset: offset + limit < all.length ? offset + limit : null } };
    },
    'GET /v1/agents': { agents: [{ agent_id: 'billing-bot' }, { agent_id: 'w1' }, { agent_id: 'mail-bot' }] },
    'GET /v1/swarms': { swarms: [{ swarm_id: 'dlg_root1', state: 'active' }] },
    ...extra,
  };
}

describe('Approval queue', () => {
  it('groups swarm-held calls, shows "1 of 2 approvals" and blocks a second vote by the same approver', async () => {
    const { calls } = installFakeApi(routes([...swarmItems, ...other]));
    renderWithApp(<ApprovalsPage />, securityMe);
    const group = await screen.findByTestId('swarm-group');
    expect(calls[0]!.path).toBe('/v1/approvals/queue?status=pending&sort=severity&limit=500');
    expect(within(group).getAllByTestId('held-item')).toHaveLength(2);
    expect(within(group).getByRole('link', { name: 'dlg_root1' }).getAttribute('href')).toBe('/swarms/dlg_root1');
    const [mine, theirs] = within(group).getAllByTestId('held-item');
    expect(within(mine!).getByText('1 of 2 approvals')).toBeTruthy();
    const approveMine = within(mine!).getByRole('button', { name: 'Approve gmail SEND by w1' }) as HTMLButtonElement;
    expect(approveMine.disabled).toBe(true);
    expect(within(mine!).getByText(/You already approved this action. A different approver/)).toBeTruthy();
    // Deny stays possible; the other swarm call can still be approved by me.
    expect((within(mine!).getByRole('button', { name: 'Deny gmail SEND by w1' }) as HTMLButtonElement).disabled).toBe(false);
    expect((within(theirs!).getByRole('button', { name: 'Approve gmail SEND by w2' }) as HTMLButtonElement).disabled).toBe(false);
    // The rest, dangerous first: the red hold is assigned to me.
    const rest = screen.getAllByTestId('held-item').filter((x) => !group.contains(x));
    expect(within(rest[0]!).getByText('postgres DELETE')).toBeTruthy();
    expect(within(rest[0]!).getByText('sec@example.com')).toBeTruthy();
  });

  it('sends the filters to the server and applies them', async () => {
    const { calls } = installFakeApi(routes([...swarmItems, ...other]));
    renderWithApp(<ApprovalsPage />, securityMe);
    await screen.findAllByTestId('held-item');
    fireEvent.change(screen.getByLabelText('Class'), { target: { value: 'red' } });
    await waitFor(() => expect(screen.getAllByTestId('held-item')).toHaveLength(1));
    expect(calls.some((c) => c.path.includes('class=red'))).toBe(true);
    fireEvent.change(screen.getByLabelText('Class'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Assigned to'), { target: { value: 'me' } });
    await waitFor(() => expect(calls.some((c) => c.path.includes('assigned_to=sec%40example.com'))).toBe(true));
    await waitFor(() => expect(screen.getAllByTestId('held-item')).toHaveLength(1));
    fireEvent.change(screen.getByLabelText('Assigned to'), { target: { value: '' } });
    fireEvent.change(screen.getByLabelText('Swarm'), { target: { value: 'dlg_root1' } });
    await waitFor(() => expect(calls.some((c) => c.path.includes('swarm_id=dlg_root1'))).toBe(true));
    await waitFor(() => expect(screen.getAllByTestId('held-item')).toHaveLength(2));
    fireEvent.change(screen.getByLabelText('Agent'), { target: { value: 'w1' } });
    await waitFor(() => expect(calls.some((c) => c.path.includes('agent_id=w1'))).toBe(true));
    await waitFor(() => expect(screen.getAllByTestId('held-item')).toHaveLength(1));
  });

  it('bulk-denies the selected holds with one reason and reports each outcome', async () => {
    const { calls } = installFakeApi(
      routes([...swarmItems, ...other], {
        'POST /v1/held/bulk-deny': {
          results: [
            { action_id: 'h1', outcome: 'denied' },
            { action_id: 'h2', error: 'already decided' },
          ],
        },
      }),
    );
    renderWithApp(<ApprovalsPage />, securityMe);
    await screen.findAllByTestId('held-item');
    fireEvent.click(screen.getByLabelText('Select gmail SEND by w1'));
    fireEvent.click(screen.getByLabelText('Select gmail SEND by w2'));
    fireEvent.click(screen.getByRole('button', { name: 'Deny selected (2)' }));
    const dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'swarm spam' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Deny 2' }));
    const result = await screen.findByTestId('bulk-result');
    expect(calls.find((c) => c.path === '/v1/held/bulk-deny')!.body).toEqual({ action_ids: ['h1', 'h2'], reason: 'swarm spam' });
    expect(within(result).getByText(/1 of 2 denied/)).toBeTruthy();
    expect(within(result).getByText(/already decided/)).toBeTruthy();
    expect(screen.getByText('Denied 1 of 2')).toBeTruthy();
  });

  it('assigns a hold to me', async () => {
    const { calls } = installFakeApi(routes(other, { 'POST /v1/held/h4/assign': item('h4', { assigned_to: 'sec@example.com' }) }));
    renderWithApp(<ApprovalsPage />, securityMe);
    await screen.findAllByTestId('held-item');
    fireEvent.click(screen.getByRole('button', { name: 'Assign gmail SEND by mail-bot' }));
    const dialog = screen.getByRole('dialog');
    expect((within(dialog).getByLabelText(/Assignee email/) as HTMLInputElement).value).toBe('sec@example.com');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Assign' }));
    await screen.findByText('Assigned to sec@example.com');
    expect(calls.find((c) => c.method === 'POST')!.body).toEqual({ assignee: 'sec@example.com' });
  });

  it('pages through long queues and is read-only for auditors', async () => {
    const many = Array.from({ length: PAGE_SIZE + 5 }, (_, i) => item(`h${i + 1}`));
    installFakeApi(routes(many));
    renderWithApp(<ApprovalsPage />, auditorMe);
    await screen.findAllByTestId('held-item');
    expect(screen.getAllByTestId('held-item')).toHaveLength(PAGE_SIZE);
    expect(screen.getByText(`${PAGE_SIZE + 5} matching · page 1 of 2`)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Next' }));
    expect(screen.getAllByTestId('held-item')).toHaveLength(5);
    expect((screen.getAllByRole('button', { name: /^Approve/ })[0] as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole('button', { name: /Deny selected/ }) as HTMLButtonElement).disabled).toBe(true);
    expect(screen.getByText(/requires the security role/)).toBeTruthy();
  });

  it('loads a queue longer than one server page (limit at most 500, then offset)', async () => {
    const many = Array.from({ length: 620 }, (_, i) => item(`h${i + 1}`));
    const { calls } = installFakeApi(routes(many));
    renderWithApp(<ApprovalsPage />, securityMe);
    await screen.findAllByTestId('held-item');
    expect(screen.getByText(/620 matching/)).toBeTruthy();
    const queue = calls.filter((c) => c.path.startsWith('/v1/approvals/queue'));
    expect(queue.map((c) => new URL(c.path, 'http://x').searchParams.get('limit'))).toEqual(['500', '500']);
    expect(new URL(queue[1]!.path, 'http://x').searchParams.get('offset')).toBe('500');
    expect(screen.queryByRole('alert')).toBeNull();
  });

  it('offers only the classes the server accepts', async () => {
    installFakeApi(routes([...swarmItems, ...other]));
    renderWithApp(<ApprovalsPage />, securityMe);
    await screen.findAllByTestId('held-item');
    const values = Array.from((screen.getByLabelText('Class') as HTMLSelectElement).options).map((o) => o.value);
    expect(values).toEqual(['', 'red', 'yellow', 'green']);
  });

  it('filters and sorts the same way in the browser (the /v1/held fallback)', () => {
    const items = normQueue({ items: [...swarmItems, ...other, item('h9', { outcome: 'approved' })] });
    const f = { ...DEFAULT_FILTERS, ruleId: 'pol-651' };
    expect(filterQueue(items, f, securityMe).map((i) => i.actionId)).toEqual(['h1', 'h2']);
    expect(filterQueue(items, { ...DEFAULT_FILTERS, assigned: 'unassigned' }, securityMe).map((i) => i.actionId)).toEqual(['h1', 'h2', 'h4']);
    expect(filterQueue(items, { ...DEFAULT_FILTERS, status: 'approved' }, securityMe).map((i) => i.actionId)).toEqual(['h9']);
    expect(sortQueue(items, 'severity')[0]!.actionId).toBe('h3');
    expect(sortQueue(items, 'oldest')[0]!.actionId).toBe('h9');
    expect(items[0]!.approvals).toBe(1);
  });
});
