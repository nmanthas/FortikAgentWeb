import { act, fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi, type Recorded } from '../test/fakeApi';
import { FakeEventSource } from '../test/fakeEventSource';
import { auditorMe, renderWithApp } from '../test/render';
import { CommMapPage } from './CommMap';

beforeEach(() => {
  FakeEventSource.instances = [];
  vi.stubGlobal('EventSource', FakeEventSource);
});
afterEach(() => {
  vi.unstubAllGlobals();
});

const map = {
  window: { from: '2026-10-20T10:00:00Z', to: '2026-10-20T11:00:00Z' },
  nodes: [
    { id: 'user:owner@example.com', kind: 'user', label: 'owner@example.com' },
    { id: 'agent:billing-bot', kind: 'agent', label: 'billing-bot', team: 'Support', level: 'FULL' },
    { id: 'agent:<script>x</script>', kind: 'agent', label: '<img src=x onerror=alert(1)>', team: 'Support', discovered: true },
    { id: 'agent:w1', kind: 'agent', label: 'w1', team: 'Sales', swarm_ids: ['swm_1'] },
    { id: 'agent:w2', kind: 'agent', label: 'w2', team: 'Sales', swarm_ids: ['swm_1'] },
    { id: 'app:gmail', kind: 'app', label: 'gmail' },
    { id: 'memory:vec/support', kind: 'memory', label: 'vec/support' },
    { id: 'domain:paste.example', kind: 'domain', label: 'paste.example' },
  ],
  edges: [
    { from: 'user:owner@example.com', to: 'agent:billing-bot', verb: 'DELEGATE', count: 1, bytes: 0, worst_class: 'green', window_start: '2026-10-20T10:00:00Z' },
    { from: 'agent:billing-bot', to: 'app:gmail', verb: 'READ', count: 40, bytes: 2048, worst_class: 'green', window_start: '2026-10-20T10:05:00Z', sample_action_ids: ['act_r1'] },
    { from: 'agent:billing-bot', to: 'memory:vec/support', verb: 'WRITE', count: 2, bytes: 512, worst_class: 'hidden', labels: ['customer_pii'], window_start: '2026-10-20T10:10:00Z', sample_action_ids: ['act_m1'] },
    { from: 'agent:w1', to: 'app:gmail', verb: 'SEND', count: 5, bytes: 100, worst_class: 'red', window_start: '2026-10-20T10:15:00Z', sample_action_ids: ['act_s1'] },
    { from: 'agent:w2', to: 'app:gmail', verb: 'SEND', count: 5, bytes: 100, worst_class: 'yellow', window_start: '2026-10-20T10:15:00Z' },
    { from: 'agent:<script>x</script>', to: 'domain:paste.example', verb: 'POST', count: 1, bytes: 9000, worst_class: 'yellow', labels: ['customer_pii'], sample_action_ids: ['act_x1'] },
  ],
  clusters: [{ id: 'swm_1', kind: 'swarm', swarm_id: 'swm_1', state: 'active', members: ['agent:w1', 'agent:w2'] }],
};
// As internal/commap/view.go returns them: the team view has team clusters (no swarm_id), never swarm clusters.
const teamClusters = [
  { id: 'team:Support', kind: 'team', label: 'Support', member_count: 2, members: ['agent:billing-bot', 'agent:<script>x</script>'], collapsed: false },
  { id: 'team:Sales', kind: 'team', label: 'Sales', member_count: 2, members: ['agent:w1', 'agent:w2'], collapsed: false },
];

const agents = { agents: [{ agent_id: 'billing-bot', level_name: 'FULL' }, { agent_id: 'w1', level_name: 'FULL' }] };

function routes(extra: Record<string, unknown> = {}) {
  return {
    'GET /v1/agents': agents,
    'GET /v1/map': (req: Recorded) => {
      const q = new URL(req.path, 'http://x').searchParams;
      if (q.get('view') === 'blast')
        return {
          body: {
            window: map.window,
            nodes: [
              { id: 'agent:billing-bot', kind: 'agent' },
              { id: 'app:gmail', kind: 'app', reachable: true },
              { id: 'store:postgres:prod', kind: 'store', reachable: true },
            ],
            edges: [
              { from: 'agent:billing-bot', to: 'app:gmail', verb: 'READ', count: 3, worst_class: 'green' },
              { from: 'agent:billing-bot', to: 'store:postgres:prod', verb: 'SELECT', count: 0, worst_class: 'green', reach: true },
            ],
            clusters: [],
          },
        };
      if (q.get('view') === 'swarm') return { body: map };
      return { body: { ...map, clusters: teamClusters } };
    },
    ...extra,
  };
}

const edges = () => screen.getAllByTestId('map-edge');
const node = (id: string) => screen.getAllByTestId('map-node').find((n) => n.getAttribute('data-id') === id);

describe('Communication Map', () => {
  it('draws typed nodes and class-coloured edges, collapses the swarm and expands it on click', async () => {
    const { calls } = installFakeApi(routes());
    renderWithApp(<CommMapPage />, auditorMe);
    await screen.findByTestId('map-svg');
    expect(calls.some((c) => c.path === '/v1/map?view=team')).toBe(true);
    // Team clusters are never drawn as swarm nodes: every agent stays visible.
    await waitFor(() => expect(node('agent:w1')).toBeTruthy());
    expect(node('swarm:team:Sales')).toBeUndefined();
    expect(screen.getAllByTestId('map-node').some((n) => n.getAttribute('data-kind') === 'swarm')).toBe(false);

    fireEvent.click(screen.getByRole('tab', { name: 'Swarm' }));
    await waitFor(() => expect(node('swarm:swm_1')).toBeTruthy());
    // The swarm is one red node; its members are not drawn.
    const swarm = node('swarm:swm_1')!;
    expect(swarm.getAttribute('data-kind')).toBe('swarm');
    expect(node('agent:w1')).toBeUndefined();
    expect(node('memory:vec/support')!.getAttribute('data-kind')).toBe('memory');
    expect(node('domain:paste.example')!.getAttribute('data-kind')).toBe('domain');
    expect(node('user:owner@example.com')!.getAttribute('data-kind')).toBe('user');
    const classes = edges().map((e) => e.getAttribute('data-class'));
    expect(classes).toEqual(expect.arrayContaining(['green', 'yellow', 'red', 'hidden']));
    // w1 (red) and w2 (yellow) -> gmail fold into one red edge from the swarm.
    const fromSwarm = edges().find((e) => e.getAttribute('data-from') === 'swarm:swm_1')!;
    expect(fromSwarm.getAttribute('data-class')).toBe('red');
    // Agent-controlled labels are text, never markup.
    expect(document.querySelector('img')).toBeNull();
    expect(screen.getAllByText(/<img src=x/).length).toBeGreaterThan(0);

    fireEvent.click(swarm);
    await waitFor(() => expect(node('agent:w1')).toBeTruthy());
    expect(node('swarm:swm_1')).toBeUndefined();
    expect(screen.getByTestId('cluster-outline')).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Collapse swarm swm_1' }));
    await waitFor(() => expect(node('swarm:swm_1')).toBeTruthy());
  });

  it('shows edge details with Diary links and traces a path with highlighted hops', async () => {
    const { calls } = installFakeApi(
      routes({
        'GET /v1/map/path': {
          hops: [
            { from: 'agent:billing-bot', to: 'memory:vec/support', verb: 'WRITE', window_start: '2026-10-20T10:10:00Z', action_ids: ['act_m1'] },
            { from: 'agent:<script>x</script>', to: 'domain:paste.example', verb: 'POST', action_ids: ['act_x1'] },
          ],
        },
      }),
    );
    renderWithApp(<CommMapPage />, auditorMe);
    await screen.findByTestId('map-svg');
    const hidden = edges().find((e) => e.getAttribute('data-class') === 'hidden')!;
    fireEvent.click(hidden);
    const detail = await screen.findByTestId('edge-detail');
    expect(within(detail).getAllByText('Hidden signal').length).toBeGreaterThan(0);
    expect(within(detail).getByText('customer_pii')).toBeTruthy();
    expect(within(detail).getByRole('link', { name: 'act_m1' }).getAttribute('href')).toBe('/actions/act_m1');

    const panel = screen.getByTestId('path-trace');
    fireEvent.change(within(panel).getByLabelText('Data label'), { target: { value: 'customer_pii' } });
    fireEvent.change(within(panel).getByLabelText('Destination'), { target: { value: 'domain:paste.example' } });
    fireEvent.click(within(panel).getByRole('button', { name: /Trace/ }));
    const hops = await screen.findByTestId('path-hops');
    expect(calls.some((c) => c.path === '/v1/map/path?label=customer_pii&dest=domain%3Apaste.example')).toBe(true);
    expect(within(hops).getAllByRole('listitem')).toHaveLength(2);
    expect(within(hops).getByRole('link', { name: 'act_x1' }).getAttribute('href')).toBe('/actions/act_x1');
    const lit = edges().filter((e) => e.getAttribute('data-highlight') === 'true');
    expect(lit.map((e) => `${e.getAttribute('data-from')}>${e.getAttribute('data-to')}`).sort()).toEqual(
      ['agent:<script>x</script>>domain:paste.example', 'agent:billing-bot>memory:vec/support'].sort(),
    );
  });

  it('replays a past window with from/to', async () => {
    const { calls } = installFakeApi(routes());
    renderWithApp(<CommMapPage />, auditorMe);
    await screen.findByTestId('map-svg');
    fireEvent.change(screen.getByLabelText('Replay window'), { target: { value: '3' } });
    await waitFor(() => expect(calls.some((c) => c.path.startsWith('/v1/map?view=team&from='))).toBe(true));
    const q = new URL(calls.find((c) => c.path.startsWith('/v1/map?view=team&from='))!.path, 'http://x').searchParams;
    const from = Date.parse(q.get('from')!);
    const to = Date.parse(q.get('to')!);
    expect(to - from).toBe(5 * 60_000);
    expect(Date.now() - to).toBeGreaterThan(40 * 60_000); // frame 3 of 12 in the last hour
    expect(await screen.findByText('Back to live')).toBeTruthy();
    expect(screen.getByTestId('map-live').textContent).toContain('Replay');
  });

  it('applies live edge and swarm updates, and buffers them while paused', async () => {
    installFakeApi(routes());
    renderWithApp(<CommMapPage />, auditorMe);
    await screen.findByTestId('map-svg');
    const es = FakeEventSource.forUrl('/v1/map/live');
    act(() => es.onopen?.());
    expect(screen.getByTestId('map-live').textContent).toContain('Live');

    act(() => es.emitNamed('edge.updated', { from: 'agent:billing-bot', to: 'domain:exfil.example', verb: 'POST', count: 3, worst_class: 'red' }));
    await waitFor(() => expect(node('domain:exfil.example')).toBeTruthy());
    expect(edges().find((e) => e.getAttribute('data-to') === 'domain:exfil.example')!.getAttribute('data-class')).toBe('red');

    // In the team view a live swarm event must not fold agents into a swarm node.
    act(() => es.emitNamed('swarm.updated', { swarm_id: 'swm_2', state: 'active', members: ['agent:billing-bot'] }));
    await waitFor(() => expect(screen.getByTestId('map-live').textContent).toContain('Live'));
    expect(node('swarm:swm_2')).toBeUndefined();
    expect(node('agent:billing-bot')).toBeTruthy();

    fireEvent.click(screen.getByRole('tab', { name: 'Swarm' }));
    await waitFor(() => expect(node('swarm:swm_1')).toBeTruthy());
    const es2 = FakeEventSource.instances.filter((x) => x.url.includes('/v1/map/live')).at(-1)!;
    act(() => es2.onopen?.());
    act(() => es2.emitNamed('swarm.updated', { swarm_id: 'swm_2', state: 'active', members: ['agent:billing-bot'] }));
    await waitFor(() => expect(node('swarm:swm_2')).toBeTruthy());

    fireEvent.click(screen.getByRole('button', { name: 'Pause live' }));
    act(() => es.emitNamed('edge.updated', { from: 'agent:new-bot', to: 'app:github', verb: 'PUSH', count: 1, worst_class: 'yellow' }));
    expect(node('app:github')).toBeUndefined();
    fireEvent.click(screen.getByRole('button', { name: 'Resume live (1 waiting)' }));
    await waitFor(() => expect(node('app:github')).toBeTruthy());
  });

  it('draws the blast radius of a picked agent as a halo', async () => {
    const { calls } = installFakeApi(routes());
    renderWithApp(<CommMapPage />, auditorMe);
    await screen.findByTestId('map-svg');
    fireEvent.click(screen.getByRole('tab', { name: 'Blast radius' }));
    expect(await screen.findByText(/Pick an agent to see its blast radius/)).toBeTruthy();
    await waitFor(() => expect(screen.getByRole('option', { name: 'billing-bot' })).toBeTruthy());
    fireEvent.change(screen.getByLabelText('Agent'), { target: { value: 'billing-bot' } });
    expect(await screen.findByTestId('blast-halo')).toBeTruthy();
    expect(calls.some((c) => c.path === '/v1/map?view=blast&id=billing-bot')).toBe(true);
    expect(edges().find((e) => e.getAttribute('data-to') === 'store:postgres:prod')!.getAttribute('data-class')).toBe('reach');
  });

  it('shows an honest error when the map cannot be loaded', async () => {
    installFakeApi({ 'GET /v1/agents': agents, 'GET /v1/map': () => ({ status: 403, body: { error: 'requires the auditor role' } }) });
    renderWithApp(<CommMapPage />, auditorMe);
    expect(await screen.findByText('Not allowed: requires the auditor role')).toBeTruthy();
  });
});
