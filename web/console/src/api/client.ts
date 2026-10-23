// Minimal fetch wrapper for the Fortik API.
//
// - Same-origin credentials only: the session cookie (HttpOnly, SameSite=Strict)
//   is never readable by script, and no token is kept in browser storage.
// - Every non-GET request carries X-Fortik-CSRF, the value from GET /v1/me.
// - A 401 from any call notifies the app, which shows the login screen.
// - Error bodies {"error": "..."} or {"error": {"code": ..., "reason": ...}}
//   become ApiError with a readable message.

export const CSRF_HEADER = 'X-Fortik-CSRF';

export class ApiError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly body: unknown;

  constructor(status: number, message: string, body?: unknown, code?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
    this.code = code;
  }
}

let csrfToken = '';
let unauthorizedHandler: (() => void) | null = null;

/** Sets the CSRF value sent on non-GET requests (from GET /v1/me). */
export function setCsrf(token: string): void {
  csrfToken = token;
}

/** Registers the callback run when the API answers 401. */
export function onUnauthorized(fn: (() => void) | null): void {
  unauthorizedHandler = fn;
}

/** Extracts a human-readable message from an API error body. */
export function errorMessage(status: number, body: unknown): { message: string; code?: string } {
  if (body && typeof body === 'object' && 'error' in body) {
    const e = (body as { error: unknown }).error;
    if (typeof e === 'string' && e !== '') return { message: e };
    if (e && typeof e === 'object') {
      const o = e as Record<string, unknown>;
      const code = typeof o.code === 'string' ? o.code : undefined;
      const parts = [o.message, o.reason].filter((x): x is string => typeof x === 'string' && x !== '');
      if (code === 'integration_not_configured') {
        const sys = typeof o.system === 'string' ? ` (${o.system})` : '';
        return { message: `integration not configured${sys}`, code };
      }
      return { message: parts[0] ?? code ?? `request failed (${status})`, code };
    }
  }
  return { message: `request failed (${status})` };
}

export interface RequestOptions {
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  body?: unknown;
  signal?: AbortSignal;
  /** Do not trigger the global 401 handler (used by the initial /v1/me probe). */
  quiet401?: boolean;
}

export async function request<T>(path: string, opts: RequestOptions = {}): Promise<T> {
  const method = opts.method ?? 'GET';
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (method !== 'GET') {
    if (csrfToken) headers[CSRF_HEADER] = csrfToken;
  }
  let body: string | undefined;
  if (opts.body !== undefined) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(opts.body);
  }
  let res: Response;
  try {
    res = await fetch(path, { method, headers, body, credentials: 'same-origin', signal: opts.signal, cache: 'no-store' });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err;
    throw new ApiError(0, 'Fortik API unreachable — is `fortik serve` running?');
  }
  const text = await res.text();
  let parsed: unknown = undefined;
  if (text !== '') {
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
  }
  if (!res.ok) {
    if (res.status === 401 && !opts.quiet401 && unauthorizedHandler) unauthorizedHandler();
    const { message, code } = errorMessage(res.status, parsed);
    throw new ApiError(res.status, message, parsed, code);
  }
  if (parsed === undefined && text !== '') {
    throw new ApiError(res.status, 'unexpected non-JSON response from the API');
  }
  return parsed as T;
}

export const api = {
  get: <T>(path: string, signal?: AbortSignal) => request<T>(path, { signal }),
  post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body: body ?? {} }),
  put: <T>(path: string, body: unknown) => request<T>(path, { method: 'PUT', body }),
  patch: <T>(path: string, body: unknown) => request<T>(path, { method: 'PATCH', body }),
  del: <T>(path: string) => request<T>(path, { method: 'DELETE' }),
};

/** Encodes one path segment (agent ids, integration keys). */
export const seg = (s: string) => encodeURIComponent(s);

/**
 * GET returning the body as text, byte-for-byte (signed exports must not be
 * re-serialised). Errors are reported like request().
 */
export async function requestText(path: string, signal?: AbortSignal): Promise<{ text: string; contentType: string }> {
  let res: Response;
  try {
    res = await fetch(path, { method: 'GET', headers: { Accept: 'application/json' }, credentials: 'same-origin', signal, cache: 'no-store' });
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') throw err;
    throw new ApiError(0, 'Fortik API unreachable — is `fortik serve` running?');
  }
  const text = await res.text();
  if (!res.ok) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = undefined;
    }
    if (res.status === 401 && unauthorizedHandler) unauthorizedHandler();
    const { message, code } = errorMessage(res.status, parsed);
    throw new ApiError(res.status, message, parsed, code);
  }
  return { text, contentType: res.headers.get('Content-Type') ?? 'application/json' };
}
