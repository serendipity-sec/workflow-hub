import { beforeEach, describe, expect, it, vi } from 'vitest';

const authenticatedFetch =
  vi.fn<(path: string, init?: RequestInit) => Promise<Response>>();
vi.mock('../auth/api', () => ({
  authenticatedFetch: (path: string, init?: RequestInit) =>
    authenticatedFetch(path, init),
}));

import {
  compareVersion,
  deleteVersion,
  deleteWorkflow,
  listMyWorkflows,
  listVersions,
  registerVersion,
  restoreVersion,
  restoreWorkflow,
  setDownloadAvailability,
} from './api';

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

describe('list queries', () => {
  it('asks for deleted items only when requested', async () => {
    authenticatedFetch.mockImplementation(() =>
      Promise.resolve(ok({ items: [], nextCursor: null })),
    );

    await listMyWorkflows(null);
    await listMyWorkflows('c 1', true);
    await listVersions('w', null, true);
    await listVersions('w', 'next');

    expect(authenticatedFetch.mock.calls.map(([path]) => path)).toEqual([
      '/api/me/workflows',
      '/api/me/workflows?cursor=c+1&includeDeleted=true',
      '/api/workflows/w/versions?includeDeleted=true',
      '/api/workflows/w/versions?cursor=next',
    ]);
  });
});

describe('setDownloadAvailability', () => {
  it('patches only the downloadEnabled flag as JSON', async () => {
    authenticatedFetch.mockResolvedValue(
      ok({ workflowId: 'w', versionId: 'v', downloadEnabled: false }),
    );

    const result = await setDownloadAvailability('w', 'v/1', false);

    const [path, init] = authenticatedFetch.mock.calls[0];
    expect(path).toBe('/api/workflows/w/versions/v%2F1/download-availability');
    expect(init?.method).toBe('PATCH');
    expect(init?.headers).toEqual({ 'Content-Type': 'application/json' });
    expect(JSON.parse(init?.body as string)).toEqual({
      downloadEnabled: false,
    });
    expect(result.downloadEnabled).toBe(false);
  });
});

describe('delete and restore', () => {
  it('uses DELETE for a version and for a whole workflow', async () => {
    authenticatedFetch.mockImplementation(() =>
      Promise.resolve(
        ok({
          workflowId: 'w',
          versionId: null,
          workflowDeleted: true,
          deletedAt: '2026-11-22T04:15:30Z',
          restoreUntil: '2026-11-29T04:15:30Z',
        }),
      ),
    );

    await deleteVersion('w', 'v 1', { allowWorkflowDelete: true });
    const result = await deleteWorkflow('w');

    expect(authenticatedFetch.mock.calls).toEqual([
      [
        '/api/workflows/w/versions/v%201?allowWorkflowDelete=true',
        { method: 'DELETE' },
      ],
      ['/api/workflows/w', { method: 'DELETE' }],
    ]);
    expect(result.restoreUntil).toBe('2026-11-29T04:15:30Z');
  });

  it('asks the server to keep the workflow for a version-only delete', async () => {
    authenticatedFetch.mockImplementation(() =>
      Promise.resolve(
        ok({
          workflowId: 'w',
          versionId: 'v',
          workflowDeleted: false,
          deletedAt: '2026-11-22T04:15:30Z',
          restoreUntil: '2026-11-29T04:15:30Z',
        }),
      ),
    );

    await deleteVersion('w', 'v', { allowWorkflowDelete: false });

    expect(authenticatedFetch).toHaveBeenCalledWith(
      '/api/workflows/w/versions/v?allowWorkflowDelete=false',
      { method: 'DELETE' },
    );
  });

  it('posts to the restore paths without a body', async () => {
    authenticatedFetch.mockImplementation(() =>
      Promise.resolve(
        ok({
          workflowId: 'w',
          workflowRestored: true,
          restoredVersionIds: ['v'],
          unavailableVersionIds: ['x'],
        }),
      ),
    );

    await restoreVersion('w', 'v');
    const result = await restoreWorkflow('w');

    expect(authenticatedFetch.mock.calls).toEqual([
      ['/api/workflows/w/versions/v/restore', { method: 'POST' }],
      ['/api/workflows/w/restore', { method: 'POST' }],
    ]);
    expect(result.unavailableVersionIds).toEqual(['x']);
  });
});
