import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Agent } from '../api/types';
import { installFakeApi } from '../test/fakeApi';
import { renderWithApp } from '../test/render';
import { AccessTab } from './AccessTab';

afterEach(() => {
  vi.unstubAllGlobals();
});

const agent: Agent = {
  agentId: 'planner',
  name: 'Planner',
  type: 'orchestrator',
  platform: 'test',
  sponsor: 'owner@example.com',
  businessUnit: '',
  workspaceUser: '',
  copyCap: 1,
  level: 'FULL',
  discovered: false,
};

function setup(profiles: unknown[] = []) {
  return installFakeApi({
    'GET /v1/agents/planner/access': { profiles },
    'GET /v1/agents/planner/access/a2a/history': { versions: [] },
    'GET /v1/agents/planner/access/http/history': { versions: [] },
    'GET /v1/agents/planner/access/mcp/history': { versions: [] },
    'GET /v1/agents/planner/access/gmail/history': { versions: [] },
    'PUT /v1/agents/planner/access/a2a': { ok: true },
    'PUT /v1/agents/planner/access/http': { ok: true },
    'PUT /v1/agents/planner/access/mcp': { ok: true },
  });
}

async function saveWithReason(reason: string) {
  fireEvent.click(screen.getByRole('button', { name: 'Save new version' }));
  const dialog = screen.getByRole('dialog');
  fireEvent.change(within(dialog).getByLabelText(/Reason/), { target: { value: reason } });
  fireEvent.click(within(dialog).getByRole('button', { name: 'Save' }));
}

describe('Access editors for a2a, http and mcp', () => {
  it('edits the a2a profile: delegation targets and max depth', async () => {
    const { calls } = setup();
    renderWithApp(<AccessTab agent={agent} />);
    fireEvent.click(await screen.findByRole('tab', { name: /Agent-to-agent/ }));
    expect(await screen.findByText('no profile yet: all access denied')).toBeTruthy();

    fireEvent.change(screen.getByLabelText('Max delegation depth'), { target: { value: '0' } });
    expect(screen.getByText(/Max depth must be a whole number between 1 and 32/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Save new version' }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Max delegation depth'), { target: { value: '2' } });

    fireEvent.click(screen.getByRole('button', { name: 'Add to May delegate to' }));
    fireEvent.change(screen.getByLabelText('May delegate to 1'), { target: { value: 'researcher' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add to May delegate to' }));
    fireEvent.change(screen.getByLabelText('May delegate to 2'), { target: { value: 'bad id!' } });
    expect(screen.getByText('"bad id!" is not a valid agent id.')).toBeTruthy();
    fireEvent.change(screen.getByLabelText('May delegate to 2'), { target: { value: 'db-bot' } });
    expect(screen.getByText(/may delegate to researcher, db-bot, max depth 2/)).toBeTruthy();

    await saveWithReason('planner hands work to two agents');
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect(calls.find((c) => c.method === 'PUT')!.body).toEqual({
      profile: { may_delegate_to: ['researcher', 'db-bot'], max_depth: 2 },
      reason: 'planner hands work to two agents',
    });
  });

  it('sends ["*"] when any agent is allowed', async () => {
    const { calls } = setup([{ system: 'a2a', version: 1, profile: { may_delegate_to: ['researcher'], max_depth: 3 } }]);
    renderWithApp(<AccessTab agent={agent} />);
    fireEvent.click(await screen.findByRole('tab', { name: /Agent-to-agent/ }));
    fireEvent.click(await screen.findByLabelText('May delegate to any agent'));
    expect(screen.queryByLabelText('May delegate to 1')).toBeNull();
    await saveWithReason('broad orchestrator');
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect((calls.find((c) => c.method === 'PUT')!.body as { profile: unknown }).profile).toEqual({ may_delegate_to: ['*'], max_depth: 3 });
  });

  it('edits the http profile: external mode and allowed domains', async () => {
    const { calls } = setup();
    renderWithApp(<AccessTab agent={agent} />);
    fireEvent.click(await screen.findByRole('tab', { name: /Web \(HTTP\)/ }));
    const external = (await screen.findByLabelText('External web access')) as HTMLSelectElement;
    expect([...external.options].map((o) => o.value)).toEqual(['none', 'allowlist', 'any']);
    expect(external.value).toBe('none');

    fireEvent.change(external, { target: { value: 'allowlist' } });
    expect(screen.getByText(/An allowlist needs at least one domain/)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: 'Add to Allowed domains' }));
    fireEvent.change(screen.getByLabelText('Allowed domains 1'), { target: { value: 'API.Example.com.' } });
    fireEvent.click(screen.getByRole('button', { name: 'Add to Allowed domains' }));
    fireEvent.change(screen.getByLabelText('Allowed domains 2'), { target: { value: '*.example.org' } });

    await saveWithReason('docs and API only');
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect((calls.find((c) => c.method === 'PUT')!.body as { profile: unknown }).profile).toEqual({
      external: 'allowlist',
      allowed_domains: ['api.example.com', '*.example.org'],
    });
  });

  it('edits the mcp profile: servers and their tools', async () => {
    const { calls } = setup([{ system: 'mcp', version: 2, profile: { servers: { memory: ['read_graph'] } } }]);
    renderWithApp(<AccessTab agent={agent} />);
    fireEvent.click(await screen.findByRole('tab', { name: /MCP tools/ }));
    expect(((await screen.findByLabelText('Tools on memory 1')) as HTMLInputElement).value).toBe('read_graph');
    fireEvent.click(screen.getByRole('button', { name: 'Add to Tools on memory' }));
    fireEvent.change(screen.getByLabelText('Tools on memory 2'), { target: { value: 'search_nodes' } });

    fireEvent.click(screen.getByRole('button', { name: /Add server/ }));
    const names = screen.getAllByLabelText('MCP server name');
    fireEvent.change(names[1]!, { target: { value: 'github-mcp' } });
    fireEvent.click(screen.getByLabelText('All tools on github-mcp'));
    expect(screen.queryByLabelText('Tools on github-mcp 1')).toBeNull();

    await saveWithReason('add github MCP');
    await waitFor(() => expect(calls.some((c) => c.method === 'PUT')).toBe(true));
    expect((calls.find((c) => c.method === 'PUT')!.body as { profile: unknown }).profile).toEqual({
      servers: { memory: ['read_graph', 'search_nodes'], 'github-mcp': ['*'] },
    });
  });
});
