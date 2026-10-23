import { afterEach, describe, expect, it, vi } from 'vitest';
import { installFakeApi } from '../test/fakeApi';
import { api, ApiError, errorMessage, onUnauthorized, setCsrf } from './client';

afterEach(() => {
  vi.unstubAllGlobals();
  setCsrf('');
  onUnauthorized(null);
});

describe('api client', () => {
  it('sends the CSRF header on non-GET requests only, with same-origin credentials', async () => {
    const { calls, fetchMock } = installFakeApi({ 'GET /v1/x': { ok: 1 }, 'POST /v1/x': { ok: 2 } });
    setCsrf('csrf-123');
    await api.get('/v1/x');
    await api.post('/v1/x', { a: 1 });
    expect(calls[0]!.headers['x-fortik-csrf']).toBeUndefined();
    expect(calls[1]!.headers['x-fortik-csrf']).toBe('csrf-123');
    expect(calls[1]!.headers['content-type']).toBe('application/json');
    expect(calls[1]!.body).toEqual({ a: 1 });
    for (const c of fetchMock.mock.calls) expect((c[1] as RequestInit).credentials).toBe('same-origin');
  });

  it('calls the unauthorized handler on 401', async () => {
    installFakeApi({ 'GET /v1/x': () => ({ status: 401, body: { error: 'authentication required' } }) });
    const h = vi.fn();
    onUnauthorized(h);
    await expect(api.get('/v1/x')).rejects.toBeInstanceOf(ApiError);
    expect(h).toHaveBeenCalledTimes(1);
  });

  it('surfaces string and structured error bodies', async () => {
    installFakeApi({ 'PUT /v1/x': () => ({ status: 400, body: { error: 'invalid access profile: send must be one of none, internal_only, any' } }) });
    await expect(api.put('/v1/x', {})).rejects.toMatchObject({ status: 400, message: 'invalid access profile: send must be one of none, internal_only, any' });
    expect(errorMessage(503, { error: { code: 'integration_not_configured', system: 'github' } })).toEqual({
      message: 'integration not configured (github)',
      code: 'integration_not_configured',
    });
    expect(errorMessage(403, { error: { code: 'fortik_refused', reason: 'POL-020 no profile' } }).message).toBe('POL-020 no profile');
    expect(errorMessage(500, 'garbage').message).toBe('request failed (500)');
  });

  it('reports an unreachable API', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Promise.reject(new TypeError('network'))));
    await expect(api.get('/v1/x')).rejects.toMatchObject({ status: 0 });
  });
});
