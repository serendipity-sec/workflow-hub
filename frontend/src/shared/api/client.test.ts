import { describe, expect, it, vi } from 'vitest';
import { ApiError, createApiClient } from './client';

describe('authenticated API transport', () => {
  it('does not send unauthenticated requests', async () => {
    const fetcher = vi.fn<typeof fetch>();
    const request = createApiClient(async () => null, fetcher);
    await expect(request('/api/me')).rejects.toMatchObject({ status: 401 });
    expect(fetcher).not.toHaveBeenCalled();
  });

  it('attaches the latest token and prevents cookie and redirect transport', async () => {
    const fetcher = vi.fn<typeof fetch>().mockResolvedValue(new Response('{}'));
    const request = createApiClient(async () => 'test-token', fetcher);
    await request('/api/me', { headers: { Accept: 'application/json' } });
    const [path, options] = fetcher.mock.calls[0];
    expect(path).toBe('/api/me');
    expect(new Headers(options?.headers).get('Authorization')).toBe(
      'Bearer test-token',
    );
    expect(new Headers(options?.headers).get('Accept')).toBe(
      'application/json',
    );
    expect(options).toMatchObject({
      credentials: 'omit',
      redirect: 'error',
      cache: 'no-store',
    });
  });

  it('rejects external destinations before accessing a token', async () => {
    const token = vi.fn(async () => 'test-token');
    const request = createApiClient(token);
    await expect(request('https://example.com/api/me')).rejects.toThrow(
      'same-origin',
    );
    await expect(request('//example.com/api/me')).rejects.toThrow(
      'same-origin',
    );
    expect(token).not.toHaveBeenCalled();
  });

  it('surfaces server denial without refresh loops or exposing response bodies', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response('private detail', { status: 403 }));
    const request = createApiClient(async () => 'test-token', fetcher);
    await expect(request('/api/me')).rejects.toEqual(new ApiError(403));
    expect(fetcher).toHaveBeenCalledTimes(1);
  });
});
