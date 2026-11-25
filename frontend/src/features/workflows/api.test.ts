import { beforeEach, describe, expect, it, vi } from 'vitest';

const authenticatedFetch =
  vi.fn<(path: string, init?: RequestInit) => Promise<Response>>();
vi.mock('../auth/api', () => ({
  authenticatedFetch: (path: string, init?: RequestInit) =>
    authenticatedFetch(path, init),
}));

import { compareVersion, registerVersion } from './api';

function ok(data: unknown, status = 200) {
  return new Response(JSON.stringify({ data }), { status });
}

beforeEach(() => authenticatedFetch.mockReset());

describe('compareVersion', () => {
  it('posts only the file to the comparison path of the chosen version', async () => {
    authenticatedFetch.mockResolvedValue(ok({ comparisonId: 'c1' }));
    const file = new File(['{}'], 'flow.json', { type: 'application/json' });

    const result = await compareVersion('wf 1', 'ver/1', file);

    const [path, init] = authenticatedFetch.mock.calls[0];
    expect(path).toBe('/api/workflows/wf%201/versions/ver%2F1/comparisons');
    expect(init?.method).toBe('POST');
    const body = init?.body as FormData;
    expect([...body.keys()]).toEqual(['file']);
    expect((body.get('file') as File).name).toBe('flow.json');
    expect(result).toEqual({ comparisonId: 'c1' });
  });
});

describe('registerVersion', () => {
  it('sends comparisonId and updateType as JSON with the idempotency key', async () => {
    authenticatedFetch.mockResolvedValue(
      ok({ workflowId: 'w', versionId: 'v', versionLabel: 'v1.1' }, 201),
    );

    const result = await registerVersion({
      workflowId: 'w',
      comparisonId: 'c1',
      updateType: 'MINOR',
      idempotencyKey: 'key-1',
    });

    const [path, init] = authenticatedFetch.mock.calls[0];
    expect(path).toBe('/api/workflows/w/versions');
    expect(init?.method).toBe('POST');
    expect(init?.headers).toEqual({
      'Content-Type': 'application/json',
      'Idempotency-Key': 'key-1',
    });
    expect(JSON.parse(init?.body as string)).toEqual({
      comparisonId: 'c1',
      updateType: 'MINOR',
    });
    expect(result.versionLabel).toBe('v1.1');
  });
});
