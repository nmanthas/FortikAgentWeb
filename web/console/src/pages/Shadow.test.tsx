import { fireEvent, screen, waitFor, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi } from '../test/fakeApi';
import { auditorMe, renderWithApp, securityMe } from '../test/render';
import { ShadowPage } from './Shadow';

afterEach(() => {
  vi.unstubAllGlobals();
});

const findings = [
  {
    finding_id: 'shf_1',
    system: 'postgres',
    kind: 'standing_credential',
    credential_id: 'postgres:prod/report_writer',
    holder: 'report_writer',
    used_by_software: true,
    evidence: { client_addr: '10.0.4.17', application_name: 'python-requests', sessions_24h: 212 },
    status: 'flagged_for_revocation',
    discovered_agent_id: 'disc-report-writer',
    created_at: new Date(Date.now() - 600_000).toISOString(),
  },
  { finding_id: 'shf_2', system: 'github', kind: 'pat', credential_id: 'github_pat_…7Q', holder: 'alice', used_by_software: false, status: 'dismissed', created_at: new Date(Date.now() - 900_000).toISOString() },
];

describe('Shadow agents', () => {
  it('lists findings with evidence and the discovered agent, and runs scan, revoke and register', async () => {
    const { calls } = installFakeApi({
      'GET /v1/shadow': { findings },
      'POST /v1/shadow/scan': { scan_id: 'scn_1', actor: 'user:sec@example.com', started_at: '2026-10-20T10:00:00Z', finished_at: '2026-10-20T10:00:01Z', systems: [], credentials: 7, used_by_software: 2, new_findings: 1, newly_flagged: 1, not_scanned: ['google_workspace'] },
      'POST /v1/shadow/shf_1/revoke': { finding: { ...findings[0], status: 'revoked' }, outcome: 'revoked', revoked: true, detail: 'ALTER ROLE report_writer NOLOGIN' },
      'POST /v1/shadow/shf_1/register': { ...findings[0], status: 'registered' },
    });
    renderWithApp(<ShadowPage />, securityMe);
    const rows = await screen.findAllByTestId('shadow-row');
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText('postgres:prod/report_writer')).toBeTruthy();
    expect(within(rows[0]!).getByText('software')).toBeTruthy();
    expect(within(rows[0]!).getByRole('link', { name: 'disc-report-writer' }).getAttribute('href')).toBe('/agents/disc-report-writer');
    expect(screen.getByText('1 flagged for revocation')).toBeTruthy();
    // Closed findings cannot be acted on again.
    expect((within(rows[1]!).getByRole('button', { name: /^Revoke/ }) as HTMLButtonElement).disabled).toBe(true);

    fireEvent.click(within(rows[0]!).getByRole('button', { name: 'Evidence' }));
    expect(within(screen.getByTestId('shadow-evidence')).getByText('python-requests')).toBeTruthy();

    fireEvent.click(screen.getByRole('button', { name: /Scan now/ }));
    expect(await screen.findByText('Scan finished')).toBeTruthy();
    expect(screen.getByText('Credentials: 7 · Used by software: 2 · New findings: 1 · Newly flagged: 1 · Not scanned: google_workspace')).toBeTruthy();
    expect(screen.queryByText(/scn_1/)).toBeNull();

    fireEvent.click(within(rows[0]!).getByRole('button', { name: 'Revoke postgres:prod/report_writer' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }));
    expect(await screen.findByText('Credential revoked')).toBeTruthy();
    expect(calls.find((c) => c.path === '/v1/shadow/shf_1/revoke')!.body).toEqual({});

    fireEvent.click(within(screen.getAllByTestId('shadow-row')[0]!).getByRole('button', { name: 'Register postgres:prod/report_writer' }));
    const dialog = screen.getByRole('dialog');
    const submit = within(dialog).getByRole('button', { name: 'Register' }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.change(within(dialog).getByLabelText(/Sponsor/), { target: { value: 'owner@example.com' } });
    fireEvent.change(within(dialog).getByLabelText(/Team/), { target: { value: 'Finance' } });
    fireEvent.click(submit);
    expect(await screen.findByText('Agent registered')).toBeTruthy();
    expect(calls.find((c) => c.path === '/v1/shadow/shf_1/register')!.body).toEqual({ sponsor: 'owner@example.com', name: 'disc-report-writer', team: 'Finance' });
  });

  it('never says "revoked" when the server answers 200 without revoking (manual_required)', async () => {
    installFakeApi({
      'GET /v1/shadow': { findings },
      'POST /v1/shadow/shf_1/revoke': {
        finding: { ...findings[0], status: 'flagged_for_revocation' },
        outcome: 'manual_required',
        revoked: false,
        detail: 'Fortik did not issue this credential; find and stop the caller at its source.',
      },
    });
    renderWithApp(<ShadowPage />, securityMe);
    const rows = await screen.findAllByTestId('shadow-row');
    fireEvent.click(within(rows[0]!).getByRole('button', { name: 'Revoke postgres:prod/report_writer' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }));
    expect(await screen.findByText('NOT revoked: manual action required')).toBeTruthy();
    expect(screen.getByText(/find and stop the caller at its source.*still flagged for revocation/)).toBeTruthy();
    expect(screen.queryByText('Credential revoked')).toBeNull();
  });

  it('shows the server error honestly when a revoke is not possible', async () => {
    installFakeApi({ 'GET /v1/shadow': { findings }, 'POST /v1/shadow/shf_1/revoke': () => ({ status: 409, body: { error: 'fortik cannot revoke this credential on postgres: role is a superuser' } }) });
    renderWithApp(<ShadowPage />, securityMe);
    const rows = await screen.findAllByTestId('shadow-row');
    fireEvent.click(within(rows[0]!).getByRole('button', { name: 'Revoke postgres:prod/report_writer' }));
    fireEvent.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Revoke' }));
    expect(await screen.findByText(/role is a superuser/)).toBeTruthy();
  });

  it('is read-only for auditors and filters by status', async () => {
    const { calls } = installFakeApi({ 'GET /v1/shadow': { findings } });
    renderWithApp(<ShadowPage />, auditorMe);
    const rows = await screen.findAllByTestId('shadow-row');
    expect((screen.getByRole('button', { name: /Scan now/ }) as HTMLButtonElement).disabled).toBe(true);
    for (const n of ['Revoke', 'Dismiss', 'Register']) expect((within(rows[0]!).getByRole('button', { name: new RegExp(`^${n}`) }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.change(screen.getByLabelText('Status'), { target: { value: 'flagged_for_revocation' } });
    await waitFor(() => expect(calls.some((c) => c.path === '/v1/shadow?status=flagged_for_revocation')).toBe(true));
  });
});
