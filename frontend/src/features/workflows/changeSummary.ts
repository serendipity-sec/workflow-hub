import type {
  Change,
  ChangeKind,
  Comparison,
  FieldChange,
  Graph,
} from './types';

export type ChangeRow = {
  key: string;
  kind: ChangeKind;
  kindLabel: string;
  /** Node name, or "source → target" for a connection. */
  target: string;
  /** One short line per changed field. Hidden values are never shown. */
  fields: string[];
};

const KIND_LABELS: Record<ChangeKind, string> = {
  NODE_ADDED: '노드 추가',
  NODE_REMOVED: '노드 삭제',
  NODE_MODIFIED: '노드 변경',
  CONNECTION_ADDED: '연결 추가',
  CONNECTION_REMOVED: '연결 삭제',
};

function nodeName(graph: Graph, nodeId: string): string {
  const node = graph.nodes.find((candidate) => candidate.id === nodeId);
  return node?.label ?? node?.type ?? '이름 없는 노드';
}

function describeTarget(change: Change, comparison: Comparison): string {
  const { base, candidate } = comparison.graphs;
  // A removed item exists only in the base file; everything else is in the new file.
  const graph = change.kind.endsWith('REMOVED') ? base : candidate;
  if (change.kind.startsWith('NODE')) {
    return nodeName(graph, change.targetId);
  }
  const connection = graph.connections.find(
    (item) => item.id === change.targetId,
  );
  if (!connection) return '연결';
  return `${nodeName(graph, connection.sourceId)} → ${nodeName(graph, connection.targetId)}`;
}

function describeField(field: FieldChange): string {
  const path = field.path.replace(/^\//, '');
  if (field.before === undefined && field.after === undefined) {
    return `${path} (값은 표시하지 않음)`;
  }
  const show = (value: FieldChange['before']) =>
    value === undefined ? '없음' : String(value);
  return `${path}: ${show(field.before)} → ${show(field.after)}`;
}

/** Turns the server's change list into rows the screen can print as they are. */
export function describeChanges(comparison: Comparison): ChangeRow[] {
  return comparison.changes.map((change, index) => ({
    key: `${index}-${change.kind}-${change.targetId}`,
    kind: change.kind,
    kindLabel: KIND_LABELS[change.kind],
    target: describeTarget(change, comparison),
    fields: change.fields.map(describeField),
  }));
}

export function hasChanges(comparison: Comparison): boolean {
  return comparison.changes.length > 0;
}
