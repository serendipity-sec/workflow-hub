/** Response shapes of the implemented workflow API (see backend OpenAPI / Swagger). */

export type VersionMetadata = {
  versionId: string;
  /** e.g. "v1", "v1.1", "v2" — issued by the server. */
  versionLabel: string;
  createdAt: string;
};

export type WorkflowSummary = {
  workflowId: string;
  title: string;
  latestVersion: VersionMetadata | null;
};

export type WorkflowDetail = WorkflowSummary & { createdAt: string };

export type UploadResult = {
  workflowId: string;
  versionId: string;
  versionLabel: string;
};

export type UpdateType = 'MINOR' | 'MAJOR';

export type ChangeKind =
  | 'NODE_ADDED'
  | 'NODE_REMOVED'
  | 'NODE_MODIFIED'
  | 'CONNECTION_ADDED'
  | 'CONNECTION_REMOVED';

/** `before`/`after` are present only for fields the server considers safe to show. */
export type FieldChange = {
  path: string;
  before?: string | number | boolean;
  after?: string | number | boolean;
};

export type Change = {
  kind: ChangeKind;
  targetId: string;
  fields: FieldChange[];
};

export type GraphNode = { id: string; label?: string; type?: string };
export type GraphConnection = {
  id: string;
  sourceId: string;
  targetId: string;
};
export type Graph = { nodes: GraphNode[]; connections: GraphConnection[] };

export type ComparisonSummary = {
  nodesAdded: number;
  nodesRemoved: number;
  nodesModified: number;
  connectionsAdded: number;
  connectionsRemoved: number;
};

export type Comparison = {
  /** Valid for registration until `expiresAt` (24 hours). */
  comparisonId: string;
  baseVersion: VersionMetadata;
  expiresAt: string;
  summary: ComparisonSummary;
  graphs: { base: Graph; candidate: Graph };
  changes: Change[];
};
