import { describe, expect, it, vi } from 'vitest';
import { ApiError, createApiClient } from './client';

function failingClient(response: Response) {
  const fetcher = vi.fn<typeof fetch>().mockResolvedValue(response);
  return createApiClient(async () => 'test-token', fetcher);
}

describe('API error details', () => {
  it('keeps the error code and request id from the server error body', async () => {
    const request = failingClient(
      new Response(
        JSON.stringify({
          code: 'FILE_TOO_LARGE',
          message: 'Upload exceeds the size limit',
          requestId: '3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11',
        }),
        { status: 413 },
      ),
    );
    await expect(request('/api/workflows')).rejects.toEqual(
      new ApiError(
        413,
        'FILE_TOO_LARGE',
        '3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11',
      ),
    );
  });

  it('ignores codes that do not look like error codes', async () => {
    const request = failingClient(
      new Response(JSON.stringify({ code: '<script>', requestId: 42 }), {
        status: 400,
      }),
    );
    const error = await request('/api/workflows').catch((e: unknown) => e);
    expect(error).toMatchObject({ status: 400 });
    expect(error).toHaveProperty('code', undefined);
    expect(error).toHaveProperty('requestId', undefined);
  });

  it('does not expose the server message text', async () => {
    const request = failingClient(
      new Response(
        JSON.stringify({ code: 'INVALID_WORKFLOW', message: 'secret' }),
        {
          status: 422,
        },
      ),
    );
    const error = (await request('/api/workflows').catch(
      (e: unknown) => e,
    )) as ApiError;
    expect(JSON.stringify(error)).not.toContain('secret');
    expect(error.message).not.toContain('secret');
  });

  it('keeps the newest version the server reports on a 409 conflict', async () => {
    const latestVersion = {
      versionId: '5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33',
      versionLabel: 'v1.2',
    };
    const request = failingClient(
      new Response(
        JSON.stringify({
          code: 'LATEST_VERSION_CHANGED',
          message: 'changed',
          requestId: 'req-1',
          details: {
            latestVersion: {
              ...latestVersion,
              createdAt: '2026-01-01T00:00:00Z',
            },
          },
        }),
        { status: 409 },
      ),
    );
    const error = await request('/api/workflows/w/versions').catch(
      (e: unknown) => e,
    );
    expect(error).toMatchObject({
      status: 409,
      code: 'LATEST_VERSION_CHANGED',
      latestVersion,
    });
  });

  it('drops a latest version that does not look like one', async () => {
    const request = failingClient(
      new Response(
        JSON.stringify({
          code: 'LATEST_VERSION_CHANGED',
          details: {
            latestVersion: { versionId: '../x', versionLabel: '<b>' },
          },
        }),
        { status: 409 },
      ),
    );
    const error = await request('/api/workflows/w/versions').catch(
      (e: unknown) => e,
    );
    expect(error).toHaveProperty('latestVersion', undefined);
  });
});
