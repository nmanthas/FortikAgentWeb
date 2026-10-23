import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi, type Recorded } from '../test/fakeApi';
import { FakeEventSource } from '../test/fakeEventSource';
import { auditorMe, renderWithApp, securityMe } from '../test/render';
import { CommandCenterPage, EVENT_TITLE, eventTone } from './CommandCenter';

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const now = Date.now();
const ago = (min: number) => new Date(now - min * 60_000).toISOString();
const yesterday = new Date(Date.UTC(new Date(now).getUTCFullYear(), new Date(now).getUTCMonth(), new Date(now).getUTCDate()) - 3600_000).toISOString();

const agents = {
  agents: [
    { agent_id: 'billing-bot', type: 'support', sponsor: 'owner@example.com', business_unit: 'Support', level_name: 'FULL', worst_class_24h: 'red', systems_24h: ['gmail', 'postgres'], discovered: false },
    { agent_id: 'ops-bot', type: 'ops', sponsor: '', business_unit: 'Ops', level_name: 'READ_ONLY', worst_class_24h: 'yellow', systems_24h: [], discovered: true, suspended_at: ago(5) },
    { agent_id: 'idle-bot', type: 'ops', sponsor: '', business_unit: 'Ops', level_name: 'FULL', worst_class_24h: null, systems_24h: [], discovered: true },
  ],
};

const act_ = (id: string, agent: string, system: string, verb: string, cls: string, decision: string, ts: string) => ({
  action_id: id,
  agent_id: agent,
  system,
  verb,
  class: cls,
  decision,
  rule_id: cls === 'red' ? 'POL-101' : '',
  reason: cls === 'red' ? 'external send of customer data' : '',
  ts,
});

const op = (id: string, opName: string, target: string, status: string, min: number, targetType = 'agent') => ({
  op_id: id,
  op: opName,
  target_type: targetType,
  target_id: target,
  actor: 'user:sec@example.com',
  reason: 'r',
  status,
  steps: [],
  created_at: ago(min),
});

function routes(extra: Record<string, unknown> = {}) {
  return {
    'GET /v1/agents': agents,
    'GET /v1/held': { held: [{ action_id: 'h1', agent_id: 'billing-bot' }, { action_id: 'h2', agent_id: 'ops-bot' }] },
    'GET /v1/actions': (req: Recorded) => {
      const q = new URL(req.path, 'http://x').searchParams;
      if (q.get('decision') === 'deny')
        return {
          body: {
            actions: [
              act_('d1', 'billing-bot', 'gmail', 'SEND', 'red', 'deny', ago(1)),
              act_('d2', 'ops-bot', 'postgres', 'DROP', 'red', 'deny', ago(2)),
              act_('d3', 'ops-bot', 'github', 'PUSH', 'yellow', 'deny', ago(3)),
              act_('d4', 'ops-bot', 'github', 'PUSH', 'yellow', 'deny', yesterday),
            ],
          },
        };
      if (q.get('class') === 'red' && q.get('limit') === '1') return { body: { actions: [act_('r1', 'billing-bot', 'gmail', 'SEND', 'red', 'deny', ago(1))] } };
      if (q.get('class') === 'red')
        return {
          body: {
            actions: [
              act_('r1', 'billing-bot', 'gmail', 'SEND', 'red', 'deny', ago(1)),
              act_('r2', 'billing-bot', 'gmail', 'SEND', 'red', 'hold', ago(4)),
              act_('r3', 'billing-bot', 'postgres', 'DROP', 'red', 'deny', ago(6)),
            ],
          },
        };
      if (q.get('agent_id') === 'billing-bot')
        return {
          body: {
            actions: [
              act_('r1', 'billing-bot', 'gmail', 'SEND', 'red', 'deny', ago(1)),
              act_('a3', 'billing-bot', 'drive', 'READ', 'green', 'allow', ago(2)),
              act_('a2', 'billing-bot', 'postgres', 'SELECT', 'green', 'allow', ago(3)),
              act_('a1', 'billing-bot', 'gmail', 'READ', 'green', 'allow', ago(4)),
            ],
          },
        };
      return { body: { actions: [] } };
    },
    'GET /v1/containment': {
      ops: [
        op('c1', 'memory_remove', 'billing-bot', 'done', 30),
        op('c2', 'memory_remove', 'ops-bot', 'done', 20),
        op('c3', 'memory_restore', 'ops-bot', 'done', 10),
        op('c4', 'memory_remove', 'idle-bot', 'failed', 5),
      ],
    },
    'GET /v1/diary': { entries: [{ seq: 7, ts: ago(1), agent_id: 'billing-bot', event_type: 'action.decided', data: { system: 'gmail', verb: 'SEND', decision: 'deny', rule_id: 'POL-101' } }] },
    ...extra,
  };
}

const kpi = (key: string) => within(screen.getByTestId(`kpi-${key}`)).getByText((_, el) => el?.className === 'kpi-value').textContent;

describe('Command Center', () => {
  it('computes the KPI tiles and shows the latest red decision with its chain', async () => {
    const { calls } = installFakeApi(routes());
    renderWithApp(<CommandCenterPage />, securityMe);
    await screen.findByTestId('cc-kpis');
    expect(kpi('agents')).toBe('3');
    expect(within(screen.getByTestId('kpi-agents')).getByText('2 found automatically')).toBeTruthy();
    expect(kpi('risk')).toBe('1');
    expect(kpi('blocked')).toBe('3'); // yesterday's denial is not counted
    expect(kpi('approvals')).toBe('2');
    expect(kpi('memory')).toBe('1'); // ops-bot restored; idle-bot's removal failed

    expect(calls.some((c) => c.path === '/v1/actions?class=red&limit=1')).toBe(true);
    expect(calls.some((c) => c.path === '/v1/actions?agent_id=billing-bot&limit=50')).toBe(true);
    const incident = screen.getByTestId('incident');
    await waitFor(() => expect(within(incident).getAllByTestId('chain-step')).toHaveLength(4));
    const chain = within(incident).getAllByTestId('chain-step');
    expect(chain[0]!.textContent).toContain('gmail READ');
    expect(chain[3]!.textContent).toContain('gmail SEND');
    expect(chain[3]!.className).toContain('incident');

    const radar = screen.getByRole('table', { name: 'Agent Radar' });
    const row = within(radar).getByText('billing-bot').closest('tr')!;
    expect(within(row).getByText('gmail SEND')).toBeTruthy();
    expect(within(row).getByText('postgres DROP')).toBeTruthy();
    expect(within(row).getByText('Memory cut')).toBeTruthy();
    expect(within(within(radar).getByText('ops-bot').closest('tr')!).getByText('Suspended')).toBeTruthy();

    // Architecture panel and the Diary feed's first paint.
    expect(screen.getByTestId('architecture')).toBeTruthy();
    expect(await within(screen.getByTestId('diary-feed')).findByText('gmail SEND · deny · POL-101')).toBeTruthy();
  });

  it('acts on the selected agent: freeze with a reason, cancel queue with a NOT REVERSIBLE warning, disable SEND', async () => {
    const { calls } = installFakeApi(
      routes({
        'POST /v1/agents/ops-bot/suspend': {
          op_id: 'cop_9',
          op: 'suspend',
          target_type: 'agent',
          target_id: 'ops-bot',
          status: 'done',
          steps: [{ name: 'mark_suspended', status: 'done' }, { name: 'revoke_credentials', status: 'done', detail: 'github: installation token deleted' }],
          created_at: ago(0),
        },
        'GET /v1/agents/billing-bot/access': { profiles: [{ system: 'gmail', version: 3, profile: { send: 'any', read: true, max_recipients: 10 } }] },
        'PUT /v1/agents/billing-bot/access/gmail': { system: 'gmail', version: 4 },
      }),
    );
    renderWithApp(<CommandCenterPage />, securityMe);
    const panel = await screen.findByTestId('action-control');
    // Defaults to the incident's agent.
    await waitFor(() => expect(within(panel).getByText('billing-bot')).toBeTruthy());

    // Cancel queue warns that it is not reversible.
    fireEvent.click(within(panel).getByRole('button', { name: /Cancel queue/ }));
    let dialog = screen.getByRole('dialog');
    expect(dialog.textContent).toContain('NOT REVERSIBLE');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel' }));

    // Disable SEND narrows gmail to send: none, keeping read and the cap.
    fireEvent.click(within(panel).getByRole('button', { name: /Disable SEND/ }));
    dialog = screen.getByRole('dialog');
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'exfil attempt' } });
    fireEvent.click(within(dialog).getByRole('button', { name: /Disable sending/ }));
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({ profile: { send: 'none', read: true, max_recipients: 10 }, reason: 'exfil attempt' });

    // Select another agent in the radar and freeze it.
    fireEvent.click(within(screen.getByRole('table', { name: 'Agent Radar' })).getByText('ops-bot'));
    await waitFor(() => expect(within(panel).getByText('ops-bot')).toBeTruthy());
    fireEvent.click(within(panel).getByRole('button', { name: /Freeze agent/ }));
    dialog = screen.getByRole('dialog', { name: 'Freeze agent: ops-bot' });
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'suspicious burst' } });
    fireEvent.click(within(dialog).getByRole('button', { name: 'Freeze agent' }));
    const result = await screen.findByRole('dialog', { name: 'Freeze agent: ops-bot — result' });
    const post = calls.find((c) => c.method === 'POST')!;
    expect(post.path).toBe('/v1/agents/ops-bot/suspend');
    expect(post.body).toEqual({ reason: 'suspicious burst' });
    expect(within(result).getAllByTestId('containment-step')).toHaveLength(2);
    expect(within(result).getByText('github: installation token deleted')).toBeTruthy();
  });

  it('F23: an open dialog keeps its agent when the live incident moves to another agent', async () => {
    // The incident starts on billing-bot; a later red decision is ops-bot's.
    let latestRed = 'billing-bot';
    const base = routes();
    const actions = base['GET /v1/actions'] as (req: Recorded) => { body: unknown };
    const { calls } = installFakeApi({
      ...base,
      'GET /v1/actions': (req: Recorded) => {
        const q = new URL(req.path, 'http://x').searchParams;
        if (q.get('class') === 'red' && q.get('limit') === '1') return { body: { actions: [act_('r9', latestRed, 'postgres', 'DROP', 'red', 'deny', ago(0))] } };
        return actions(req);
      },
      'POST /v1/agents/billing-bot/queue/cancel': {
        op_id: 'cop_q',
        op: 'cancel_queue',
        target_type: 'agent',
        target_id: 'billing-bot',
        status: 'done',
        steps: [{ name: 'cancel_queue', status: 'done' }],
        created_at: ago(0),
      },
    });
    renderWithApp(<CommandCenterPage />, securityMe, true);
    const panel = await screen.findByTestId('action-control');
    const incident = screen.getByTestId('incident');
    await waitFor(() => expect(within(panel).getByText('billing-bot')).toBeTruthy());
    await within(incident).findByRole('button', { name: 'Act on billing-bot' });

    // Open Cancel queue for billing-bot (the incident's agent, never clicked in the radar) and type a reason.
    fireEvent.click(within(panel).getByRole('button', { name: /Cancel queue/ }));
    let dialog = screen.getByRole('dialog', { name: 'Cancel queue: billing-bot' });
    fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: 'drop billing-bot jobs' } });

    // A newer red decision by ops-bot arrives live; the incident reloads.
    latestRed = 'ops-bot';
    act(() => {
      const es = FakeEventSource.latest();
      es.onopen?.();
      es.emit({ seq: 100, event_type: 'action.decided', agent_id: 'ops-bot', data: { decision: 'deny' } });
    });
    await within(incident).findByRole('button', { name: 'Act on ops-bot' }, { timeout: 4000 });

    // The dialog and the panel still target billing-bot.
    dialog = screen.getByRole('dialog', { name: 'Cancel queue: billing-bot' });
    expect(within(panel).getByRole('link', { name: 'billing-bot' })).toBeTruthy();
    expect(within(dialog).getByLabelText(/Reason/)).toHaveProperty('value', 'drop billing-bot jobs');
    fireEvent.click(within(dialog).getByRole('button', { name: 'Cancel queued work' }));
    await screen.findByRole('dialog', { name: 'Cancel queue: billing-bot — result' });
    const posts = calls.filter((c) => c.method === 'POST');
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({ path: '/v1/agents/billing-bot/queue/cancel', body: { reason: 'drop billing-bot jobs' } });

    // After closing, the selection stays pinned to the agent the user acted on.
    fireEvent.click(screen.getByRole('button', { name: 'Close' }));
    expect(within(panel).getByRole('link', { name: 'billing-bot' })).toBeTruthy();
  }, 10_000);

  it('disables controls for an auditor with the reasons, including the Fleet E-Stop', async () => {
    installFakeApi(routes());
    renderWithApp(<CommandCenterPage />, auditorMe);
    const panel = await screen.findByTestId('action-control');
    await waitFor(() => expect(within(panel).getByText('billing-bot')).toBeTruthy());
    for (const name of [/Freeze agent/, /Quarantine memory/, /Revoke token/, /Cancel queue/, /Disable SEND/, /Fleet E-Stop/, /^Release$/]) {
      expect((within(panel).getByRole('button', { name }) as HTMLButtonElement).disabled).toBe(true);
    }
    expect(within(panel).getByText('Requires the security role or ownership of this agent.')).toBeTruthy();
    expect(within(panel).getByText('Cancelling queued work requires the security role.')).toBeTruthy();
    expect(within(panel).getAllByText('Team and fleet operations require the security role.').length).toBeGreaterThan(0);
  });

  it('adds live Diary entries to the feed', async () => {
    installFakeApi(routes({ 'GET /v1/diary': { entries: [] } }));
    renderWithApp(<CommandCenterPage />, securityMe, true);
    const feed = await screen.findByTestId('diary-feed');
    await within(feed).findByText('No Diary entries in the last 30 minutes.');
    act(() => {
      const es = FakeEventSource.latest();
      es.onopen?.();
      es.emit({ seq: 99, event_type: 'containment.suspend', agent_id: 'ops-bot', data: { op: 'suspend', target_id: 'ops-bot', status: 'done', reason: 'burst' } });
    });
    expect(await within(feed).findByText('containment.suspend')).toBeTruthy();
    expect(within(feed).getByText('suspend ops-bot · done — burst')).toBeTruthy();
  });
});

describe('Diary feed event types', () => {
  it('labels the new memory events', () => {
    expect(eventTone('memory.item_deleted')).toBe('amber');
    expect(eventTone('memory.snapshot_marked_unclean')).toBe('amber');
    expect(eventTone('memory.review_window_opened')).toBe('blue');
    for (const t of ['memory.item_deleted', 'memory.review_window_opened', 'memory.snapshot_marked_unclean']) expect(EVENT_TITLE[t]).toBeTruthy();
  });

  it('shows the label on hover in the live feed', async () => {
    installFakeApi(routes({ 'GET /v1/diary': { entries: [] } }));
    renderWithApp(<CommandCenterPage />, securityMe, true);
    const feed = await screen.findByTestId('diary-feed');
    await within(feed).findByText('No Diary entries in the last 30 minutes.');
    act(() => {
      const es = FakeEventSource.latest();
      es.onopen?.();
      es.emit({ seq: 101, event_type: 'memory.review_window_opened', agent_id: 'billing-bot', data: {} });
    });
    const chip = await within(feed).findByText('memory.review_window_opened');
    expect(chip.className).toContain('blue');
    expect(chip.getAttribute('title')).toBe(EVENT_TITLE['memory.review_window_opened']);
  });

  it('adds the active-swarms and discovered-agents tiles (Phase 5)', async () => {
    installFakeApi(
      routes({
        'GET /v1/swarms': {
          swarms: [
            { swarm_id: 'dlg_1', state: 'active', member_count: 41 },
            { swarm_id: 'swm_2', state: 'frozen', member_count: 3 },
            { swarm_id: 'swm_3', state: 'released', member_count: 9 },
          ],
        },
        'GET /v1/shadow': { findings: [{ finding_id: 'f1', status: 'flagged_for_revocation' }] },
      }),
    );
    renderWithApp(<CommandCenterPage />, securityMe);
    await screen.findByTestId('cc-kpis');
    expect(kpi('swarms')).toBe('2');
    expect(within(screen.getByTestId('kpi-swarms')).getByRole('link', { name: '44 members' }).getAttribute('href')).toBe('/swarms');
    expect(kpi('discovered')).toBe('2');
    expect(within(screen.getByTestId('kpi-discovered')).getByRole('link', { name: '1 flagged for revocation' })).toBeTruthy();
    // The Phase 4 tiles are kept.
    expect(kpi('agents')).toBe('3');
    expect(kpi('memory')).toBe('1');
  });

  it('shows "—" for the Phase 5 tiles on a server without those APIs', async () => {
    installFakeApi(routes());
    renderWithApp(<CommandCenterPage />, securityMe);
    await screen.findByTestId('cc-kpis');
    expect(kpi('swarms')).toBe('—');
    expect(within(screen.getByTestId('kpi-swarms')).getByText('swarms unavailable')).toBeTruthy();
    expect(within(screen.getByTestId('kpi-discovered')).getByText('shadow scan unavailable')).toBeTruthy();
  });
});
