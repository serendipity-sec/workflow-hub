import { describe, expect, it } from 'vitest';
import { describeChanges, displayPath, hasChanges } from './changeSummary';
import type { Comparison } from './types';

const comparison: Comparison = {
  comparisonId: 'c1',
  baseVersion: {
    versionId: 'v-1',
    versionLabel: 'v1',
    createdAt: '2026-01-01',
  },
  expiresAt: '2026-01-02T00:00:00Z',
  summary: {
    nodesAdded: 1,
    nodesRemoved: 1,
    nodesModified: 1,
    connectionsAdded: 1,
    connectionsRemoved: 1,
  },
  graphs: {
    base: {
      nodes: [
        { id: 'n0', label: 'Webhook' },
        { id: 'n1', label: 'Old Slack' },
        { id: 'n2', label: 'HTTP Request' },
      ],
      connections: [{ id: 'e0', sourceId: 'n0', targetId: 'n1' }],
    },
    candidate: {
      nodes: [
        { id: 'n0', label: 'Webhook' },
        { id: 'n2', label: 'HTTP Request' },
        { id: 'n3', label: 'Notify' },
      ],
      connections: [{ id: 'e1', sourceId: 'n0', targetId: 'n3' }],
    },
  },
  changes: [
    { kind: 'NODE_ADDED', targetId: 'n3', fields: [] },
    { kind: 'NODE_REMOVED', targetId: 'n1', fields: [] },
    {
      kind: 'NODE_MODIFIED',
      targetId: 'n2',
      fields: [
        { path: '/parameters/method', before: 'GET', after: 'POST' },
        { path: '/parameters/url' },
      ],
    },
    { kind: 'CONNECTION_ADDED', targetId: 'e1', fields: [] },
    { kind: 'CONNECTION_REMOVED', targetId: 'e0', fields: [] },
  ],
};

describe('describeChanges', () => {
  const rows = describeChanges(comparison);

  it('names added nodes from the new file and removed nodes from the old file', () => {
    expect(rows[0]).toMatchObject({ kindLabel: '노드 추가', target: 'Notify' });
    expect(rows[1]).toMatchObject({
      kindLabel: '노드 삭제',
      target: 'Old Slack',
    });
  });

  it('prints connections as source → target using the matching file', () => {
    expect(rows[3].target).toBe('Webhook → Notify');
    expect(rows[4].target).toBe('Webhook → Old Slack');
  });

  it('shows visible field values and hides the rest', () => {
    expect(rows[2].fields).toEqual([
      'parameters/method: GET → POST',
      'parameters/url (값은 표시하지 않음)',
    ]);
  });

  it('keeps row keys unique', () => {
    expect(new Set(rows.map((row) => row.key)).size).toBe(rows.length);
  });

  it('falls back safely when a connection is missing from the graph', () => {
    const [row] = describeChanges({
      ...comparison,
      changes: [{ kind: 'CONNECTION_ADDED', targetId: 'missing', fields: [] }],
    });
    expect(row.target).toBe('연결');
  });
});

describe('hasChanges', () => {
  it('is false when the server reports no changes', () => {
    expect(hasChanges({ ...comparison, changes: [] })).toBe(false);
    expect(hasChanges(comparison)).toBe(true);
  });
});

describe('displayPath', () => {
  it('drops the leading slash', () => {
    expect(displayPath('/parameters/url')).toBe('parameters/url');
  });

  it('undoes JSON Pointer escapes in each segment', () => {
    expect(displayPath('/parameters/a~1b')).toBe('parameters/a/b');
    expect(displayPath('/parameters/a~0b')).toBe('parameters/a~b');
    // "~01" is an escaped "~" followed by "1", not a slash.
    expect(displayPath('/parameters/~01')).toBe('parameters/~1');
  });
});
