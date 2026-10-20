import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ApiError, apiFetch, clearCsrfToken } from './api';

/**
 * Contract smoke tests for the fetch layer. Every V2 page goes through
 * apiFetch, so the two behaviours that have burned this console before —
 * drops the CSRF header on a mutation, or un-envelopes the wrong shape —
 * fail here instead of as an empty table in production.
 */

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

const fetchMock = vi.fn<typeof fetch>();

beforeEach(() => {
  clearCsrfToken();
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
  vi.stubGlobal('window', {
    location: { href: '' },
    dispatchEvent: () => true,
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('apiFetch', () => {
  it('unwraps the {success,data} envelope', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ success: true, data: { role: 'admin' } }));

    await expect(apiFetch('/admin/api/me')).resolves.toEqual({ role: 'admin' });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('keeps pagination fields that ride alongside data', async () => {
    const payload = { data: [{ id: 1 }], total: 42, page: 1 };
    fetchMock.mockResolvedValueOnce(jsonResponse(payload));

    await expect(apiFetch('/admin/api/events')).resolves.toEqual(payload);
  });

  it('fetches a CSRF token once and sends it on mutations', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'tok-1' }))
      .mockResolvedValueOnce(jsonResponse({ success: true, data: { ok: true } }));

    await apiFetch('/admin/api/users', { method: 'POST', body: { username: 'ops' } });

    const [tokenCall, mutationCall] = fetchMock.mock.calls;
    expect(tokenCall?.[0]).toBe('/admin/api/csrf-token');
    const headers = new Headers(mutationCall?.[1]?.headers);
    expect(headers.get('X-CSRF-Token')).toBe('tok-1');
    expect(headers.get('Content-Type')).toBe('application/json');
    expect(mutationCall?.[1]?.body).toBe(JSON.stringify({ username: 'ops' }));
  });

  it('does not fetch a CSRF token for reads', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ success: true, data: [] }));

    await apiFetch('/admin/api/users');

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(fetchMock.mock.calls[0]?.[0]).toBe('/admin/api/users');
  });

  it('surfaces the server error message and status', async () => {
    fetchMock
      .mockResolvedValueOnce(jsonResponse({ csrf_token: 'tok-1' }))
      .mockResolvedValueOnce(jsonResponse({ success: false, error: 'username already exists' }, 409));

    await expect(apiFetch('/admin/api/users', { method: 'POST', body: {} })).rejects.toMatchObject({
      name: 'ApiError',
      status: 409,
      message: 'username already exists',
    });
  });

  it('is an ApiError, not a bare Error, so callers can branch on code', async () => {
    fetchMock.mockResolvedValueOnce(jsonResponse({ error: 'nope', code: 'forbidden' }, 403));

    const err = await apiFetch('/admin/api/x').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).code).toBe('forbidden');
  });
});
