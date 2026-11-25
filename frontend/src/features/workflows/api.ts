import { authenticatedFetch } from '../auth/api';
import { saveResponseAsFile } from '../../shared/api/download';
import { readData } from '../../shared/api/types';
import type { Page } from '../../shared/api/types';
import type {
  Comparison,
  UpdateType,
  UploadResult,
  VersionMetadata,
  WorkflowDetail,
  WorkflowSummary,
} from './types';

function pageQuery(cursor: string | null): string {
  return cursor ? `?cursor=${encodeURIComponent(cursor)}` : '';
}

function workflowPath(workflowId: string): string {
  return `/api/workflows/${encodeURIComponent(workflowId)}`;
}

export async function listMyWorkflows(
  cursor: string | null,
): Promise<Page<WorkflowSummary>> {
  const response = await authenticatedFetch(
    `/api/me/workflows${pageQuery(cursor)}`,
  );
  return readData(response);
}

export async function getWorkflow(workflowId: string): Promise<WorkflowDetail> {
  return readData(await authenticatedFetch(workflowPath(workflowId)));
}

export async function listVersions(
  workflowId: string,
  cursor: string | null,
): Promise<Page<VersionMetadata>> {
  const response = await authenticatedFetch(
    `${workflowPath(workflowId)}/versions${pageQuery(cursor)}`,
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
