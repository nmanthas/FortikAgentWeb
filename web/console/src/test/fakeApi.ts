// A fake Fortik API for component tests: routes "METHOD /path" to handlers
// and records every request (method, path, headers, parsed body).

import { vi } from 'vitest';

export interface Recorded {
  method: string;
  path: string;
  headers: Record<string, string>;
  body: unknown;
}

type Handler = (req: Recorded) => { status?: number; body?: unknown };

export function installFakeApi(routes: Record<string, Handler | unknown>) {
  const calls: Recorded[] = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = new URL(String(input), 'http://console.test');
    const method = (init?.method ?? 'GET').toUpperCase();
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries((init?.headers as Record<string, string>) ?? {})) headers[k.toLowerCase()] = v;
    const req: Recorded = { method, path: url.pathname + url.search, headers, body: init?.body ? JSON.parse(String(init.body)) : undefined };
    calls.push(req);
    const route = routes[`${method} ${url.pathname}`];
    if (route === undefined) return new Response(JSON.stringify({ error: 'not found' }), { status: 404 });
    const res = typeof route === 'function' ? (route as Handler)(req) : { body: route };
    return new Response(res.body === undefined ? '' : JSON.stringify(res.body), { status: res.status ?? 200, headers: { 'Content-Type': 'application/json' } });
  });
  vi.stubGlobal('fetch', fetchMock);
  return { calls, fetchMock };
}
