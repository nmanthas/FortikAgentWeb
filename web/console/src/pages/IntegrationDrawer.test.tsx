import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Integration, IntegrationSchema } from '../api/types';
import { ToastProvider } from '../components/Toasts';
import { installFakeApi } from '../test/fakeApi';
import { IntegrationDrawer } from './IntegrationDrawer';

afterEach(() => vi.unstubAllGlobals());

const schema: IntegrationSchema = {
  system: 'github',
  title: 'GitHub',
  multi: false,
  fields: [
    { key: 'api_base_url', label: 'API base URL', type: 'text', secret: false, required: false, default: 'https://api.github.com' },
    { key: 'app_id', label: 'GitHub App ID', type: 'text', secret: false, required: true, help: 'The numeric App ID.' },
    { key: 'installation_id', label: 'Installation ID', type: 'text', secret: false, required: true },
    { key: 'private_key_pem', label: 'App private key (.pem)', type: 'textarea', secret: true, required: true },
  ],
};

const configured: Integration = {
  key: 'github',
  system: 'github',
  config: { api_base_url: 'https://api.github.com', app_id: '123', installation_id: '456' },
  secretFields: ['private_key_pem'],
  secrets: { private_key_pem: { set: true } },
  status: 'error',
  lastError: 'GET /app/installations/456: 401',
  testAvailable: true,
};

const view = (over: Record<string, unknown> = {}) => ({
  key: 'github',
  system: 'github',
  config: configured.config,
  secret_fields: ['private_key_pem'],
  secrets: { private_key_pem: { set: true } },
  status: 'configured',
  test_available: true,
  ...over,
});

describe('IntegrationDrawer', () => {
  it('shows stored secrets as set, never their value, and keeps them on save', async () => {
    const { calls } = installFakeApi({ 'PUT /v1/integrations/github': view() });
    render(
      <ToastProvider>
        <IntegrationDrawer integrationKey="github" schema={schema} current={configured} canEdit onClose={() => undefined} onSaved={() => undefined} />
      </ToastProvider>,
    );
    expect(screen.getByTestId('secret-set-private_key_pem').textContent).toContain('••• set');
    expect(screen.queryByTestId('secret-input-private_key_pem')).toBeNull();
    expect(screen.getByText(/Last error: GET \/app\/installations\/456: 401/)).toBeTruthy();
    expect(screen.getByText('The numeric App ID.')).toBeTruthy();

    fireEvent.change(screen.getByLabelText(/Installation ID/), { target: { value: '789' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.length).toBe(1));
    expect(calls[0]!.body).toEqual({ config: { api_base_url: 'https://api.github.com', app_id: '123', installation_id: '789' }, secrets: {} });
  });

  it('sends a replaced secret once and clears it from the form', async () => {
    const { calls } = installFakeApi({ 'PUT /v1/integrations/github': view() });
    render(
      <ToastProvider>
        <IntegrationDrawer integrationKey="github" schema={schema} current={configured} canEdit onClose={() => undefined} onSaved={() => undefined} />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: 'Replace' }));
    const input = screen.getByTestId('secret-input-private_key_pem') as HTMLTextAreaElement;
    expect(input.value).toBe('');
    fireEvent.change(input, { target: { value: '-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    await waitFor(() => expect(calls.length).toBe(1));
    expect((calls[0]!.body as { secrets: Record<string, string> }).secrets.private_key_pem).toContain('BEGIN RSA PRIVATE KEY');
    expect(await screen.findByTestId('secret-set-private_key_pem')).toBeTruthy();
    expect(screen.queryByDisplayValue(/BEGIN RSA/)).toBeNull();
  });

  it('shows server validation errors and test results', async () => {
    installFakeApi({
      'PUT /v1/integrations/github': () => ({ status: 400, body: { error: 'invalid integration settings: app_id must be a positive integer' } }),
      'POST /v1/integrations/github/test': { ok: false, error: 'installation 456 not found', duration_ms: 12, integration: view({ status: 'error' }) },
    });
    render(
      <ToastProvider>
        <IntegrationDrawer integrationKey="github" schema={schema} current={configured} canEdit onClose={() => undefined} onSaved={() => undefined} />
      </ToastProvider>,
    );
    fireEvent.click(screen.getByRole('button', { name: /Test connection/ }));
    expect(await screen.findByText('installation 456 not found')).toBeTruthy();
    fireEvent.change(screen.getByLabelText(/GitHub App ID/), { target: { value: 'abc' } });
    fireEvent.click(screen.getByRole('button', { name: 'Save' }));
    expect(await screen.findByText(/app_id must be a positive integer/)).toBeTruthy();
  });

  it('requires secrets for a new integration and is read-only without the role', () => {
    installFakeApi({});
    const { unmount } = render(
      <ToastProvider>
        <IntegrationDrawer integrationKey="github" schema={schema} current={undefined} canEdit onClose={() => undefined} onSaved={() => undefined} />
      </ToastProvider>,
    );
    expect((screen.getByLabelText(/API base URL/) as HTMLInputElement).value).toBe('https://api.github.com');
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
    unmount();
    render(
      <ToastProvider>
        <IntegrationDrawer integrationKey="github" schema={schema} current={configured} canEdit={false} onClose={() => undefined} onSaved={() => undefined} />
      </ToastProvider>,
    );
    expect(screen.getByText(/requires the security role/)).toBeTruthy();
    expect((screen.getByRole('button', { name: 'Save' }) as HTMLButtonElement).disabled).toBe(true);
  });
});
