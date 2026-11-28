/** Response shapes of the implemented workflow API (see backend OpenAPI / Swagger). */

/** Identifies one version, as in a comparison's `baseVersion`. */
export type VersionReference = {
  versionId: string;
  /** e.g. "v1", "v1.1", "v2" — issued by the server. */
  versionLabel: string;
  createdAt: string;
};

/** A version as returned by the version list and workflow detail. */
export type VersionMetadata = VersionReference & {
  /** False after the owner stopped downloads. The version can still be viewed and compared. */
  downloadEnabled: boolean;
  /**
   * SHA-256 (lowercase hex) and byte size of the exact bytes the server stored.
   * Both are null for versions registered before they were recorded (#29).
   */
  sha256: string | null;
  sizeBytes: number | null;
  /** Only on deleted versions, which are listed with `includeDeleted=true`. */
  deletedAt?: string;
  /** Deadline for restoring a deleted version, shown exactly as the server sent it. */
  restoreUntil?: string;
};

export type WorkflowSummary = {
  workflowId: string;
  title: string;
  latestVersion: VersionMetadata | null;
  /** Only on deleted workflows, which are listed with `includeDeleted=true`. */
  deletedAt?: string;
  restoreUntil?: string;
};

export type DeletionResult = {
  workflowId: string;
  /** null when the whole workflow was deleted directly. */
  versionId: string | null;
  /** True when the whole workflow is now deleted, also after deleting its last version. */
  workflowDeleted: boolean;
  deletedAt: string;
  restoreUntil: string;
};

export type RestoreResult = {
  workflowId: string;
  /** True when this request also brought back the deleted workflow. */
  workflowRestored: boolean;
  restoredVersionIds: string[];
  /** Versions deleted together that could not be restored, e.g. the file is gone. */
  unavailableVersionIds: string[];
};

export type DownloadAvailability = {
  workflowId: string;
  versionId: string;
  downloadEnabled: boolean;
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
  baseVersion: VersionReference;
  expiresAt: string;
  summary: ComparisonSummary;
  graphs: { base: Graph; candidate: Graph };
  changes: Change[];
};
