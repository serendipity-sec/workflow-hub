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
