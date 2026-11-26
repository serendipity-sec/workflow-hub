import { authenticatedFetch } from '../auth/api';
import { saveResponseAsFile } from '../../shared/api/download';
import { readData } from '../../shared/api/types';
import type { Page } from '../../shared/api/types';
import type {
  Comparison,
  DeletionResult,
  DownloadAvailability,
  RestoreResult,
  UpdateType,
  UploadResult,
  VersionMetadata,
  WorkflowDetail,
  WorkflowSummary,
} from './types';

/** `includeDeleted` adds deleted items that can still be restored. */
function listQuery(cursor: string | null, includeDeleted: boolean): string {
  const params = new URLSearchParams();
  if (cursor) params.set('cursor', cursor);
  if (includeDeleted) params.set('includeDeleted', 'true');
  const query = params.toString();
  return query ? `?${query}` : '';
}

function workflowPath(workflowId: string): string {
  return `/api/workflows/${encodeURIComponent(workflowId)}`;
}

function versionPath(workflowId: string, versionId: string): string {
  return `${workflowPath(workflowId)}/versions/${encodeURIComponent(versionId)}`;
}

export async function listMyWorkflows(
  cursor: string | null,
  includeDeleted = false,
): Promise<Page<WorkflowSummary>> {
  const response = await authenticatedFetch(
    `/api/me/workflows${listQuery(cursor, includeDeleted)}`,
  );
  return readData(response);
}

export async function getWorkflow(workflowId: string): Promise<WorkflowDetail> {
  return readData(await authenticatedFetch(workflowPath(workflowId)));
}

export async function listVersions(
  workflowId: string,
  cursor: string | null,
  includeDeleted = false,
): Promise<Page<VersionMetadata>> {
  const response = await authenticatedFetch(
    `${workflowPath(workflowId)}/versions${listQuery(cursor, includeDeleted)}`,
  );
  return readData(response);
}

/** Allows or stops downloads of one version. The file itself is kept. */
export async function setDownloadAvailability(
  workflowId: string,
  versionId: string,
  downloadEnabled: boolean,
): Promise<DownloadAvailability> {
  const response = await authenticatedFetch(
    `${versionPath(workflowId, versionId)}/download-availability`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ downloadEnabled }),
    },
  );
  return readData(response);
}

/** Deleting the only remaining version deletes the whole workflow (`workflowDeleted`). */
export async function deleteVersion(
  workflowId: string,
  versionId: string,
): Promise<DeletionResult> {
  const response = await authenticatedFetch(
    versionPath(workflowId, versionId),
    { method: 'DELETE' },
  );
  return readData(response);
}

export async function deleteWorkflow(
  workflowId: string,
): Promise<DeletionResult> {
  const response = await authenticatedFetch(workflowPath(workflowId), {
    method: 'DELETE',
  });
  return readData(response);
}

export async function restoreVersion(
  workflowId: string,
  versionId: string,
): Promise<RestoreResult> {
  const response = await authenticatedFetch(
    `${versionPath(workflowId, versionId)}/restore`,
    { method: 'POST' },
  );
  return readData(response);
}

/** Restores the versions deleted together with the workflow, where still possible. */
export async function restoreWorkflow(
  workflowId: string,
): Promise<RestoreResult> {
  const response = await authenticatedFetch(
    `${workflowPath(workflowId)}/restore`,
    { method: 'POST' },
  );
  return readData(response);
}

/** Downloads the exact original JSON registered for one version. */
export async function downloadVersion(
  workflowId: string,
  version: VersionMetadata,
): Promise<void> {
  const response = await authenticatedFetch(
    `${workflowPath(workflowId)}/versions/${encodeURIComponent(version.versionId)}/download`,
  );
  await saveResponseAsFile(response, `workflow-${version.versionLabel}.json`);
}

/**
 * Registers a new workflow as v1. Retrying the same request must reuse the same
 * `idempotencyKey` so the server does not create a duplicate.
 */
export async function uploadWorkflow(input: {
  title: string;
  file: File;
  idempotencyKey: string;
}): Promise<UploadResult> {
  const body = new FormData();
  if (input.title) body.set('title', input.title);
  body.set('file', input.file);
  const response = await authenticatedFetch('/api/workflows', {
    method: 'POST',
    headers: { 'Idempotency-Key': input.idempotencyKey },
    body,
  });
  return readData(response);
}

/** Compares a modified file with one stored version. Nothing is registered yet. */
export async function compareVersion(
  workflowId: string,
  versionId: string,
  file: File,
): Promise<Comparison> {
  const body = new FormData();
  body.set('file', file);
  const response = await authenticatedFetch(
    `${workflowPath(workflowId)}/versions/${encodeURIComponent(versionId)}/comparisons`,
    { method: 'POST', body },
  );
  return readData(response);
}

/**
 * Registers the compared file as the next version. Retrying the same request must
 * reuse the same `idempotencyKey` so the server does not create a duplicate.
 */
export async function registerVersion(input: {
  workflowId: string;
  comparisonId: string;
  updateType: UpdateType;
  idempotencyKey: string;
}): Promise<UploadResult> {
  const response = await authenticatedFetch(
    `${workflowPath(input.workflowId)}/versions`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Idempotency-Key': input.idempotencyKey,
      },
      body: JSON.stringify({
        comparisonId: input.comparisonId,
        updateType: input.updateType,
      }),
    },
  );
  return readData(response);
}
