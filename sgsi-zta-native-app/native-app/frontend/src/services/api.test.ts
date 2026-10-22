import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError, initializeCsrf } from './api';

afterEach(() => vi.unstubAllGlobals());

describe('cookie API transport', () => {
  it('sends credentials and the CSRF header for mutations without authorization storage', async () => {
    const fetcher = vi
      .fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({ csrf_token: 'test-csrf' })))
      .mockResolvedValueOnce(new Response(JSON.stringify({ status: 'signed_out' })));
    vi.stubGlobal('fetch', fetcher);
    await initializeCsrf();
    await api('/auth/logout', { method: 'POST' });
    const options = fetcher.mock.calls[1][1] as RequestInit;
    expect(options.credentials).toBe('include');
    expect(new Headers(options.headers).get('X-CSRF-Token')).toBe('test-csrf');
    expect(new Headers(options.headers).has('Authorization')).toBe(false);
  });
  it('propagates login failures instead of treating them as a session', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ detail: 'Usuario o contraseña incorrectos' }), {
          status: 401,
        }),
      ),
    );
    await expect(api('/auth/login', { method: 'POST', body: '{}' })).rejects.toBeInstanceOf(
      ApiError,
    );
  });
});
