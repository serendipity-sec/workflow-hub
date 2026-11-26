import { ApiError } from '../../shared/api/client';
import { formatDateTime } from '../../shared/format';
import type { DeletionResult, RestoreResult, VersionMetadata } from './types';

/**
 * Deleted items carry `deletedAt`. The server omits it for alive items; a null
 * value is treated the same way so an alive item is never shown as deleted.
 */
export function isDeleted(item: { deletedAt?: string | null }): boolean {
  return item.deletedAt !== undefined && item.deletedAt !== null;
}

/** The deadline is the server's `restoreUntil`, never computed on the client. */
export function restoreDeadline(restoreUntil: string): string {
  return `${formatDateTime(restoreUntil)}까지 복구할 수 있습니다.`;
}

/**
 * Whether deleting one alive version leaves the workflow without versions, in
 * which case the server deletes the whole workflow.
 * - `last`: the loaded list proves it is the only alive version.
 * - `maybe-last`: unloaded pages of a list that includes deleted versions may or
 *   may not hold other alive versions.
 * - `not-last`: another alive version is known to exist.
 */
export type LastVersionRisk = 'last' | 'maybe-last' | 'not-last';

export function lastVersionRisk(
  target: VersionMetadata,
  loaded: VersionMetadata[],
  hasMore: boolean,
  includeDeleted: boolean,
): LastVersionRisk {
  const othersAlive = loaded.filter(
    (version) => !isDeleted(version) && version.versionId !== target.versionId,
  ).length;
  if (othersAlive > 0) return 'not-last';
  if (!hasMore) return 'last';
  // Without deleted items every unloaded entry is an alive version.
  return includeDeleted ? 'maybe-last' : 'not-last';
}

/**
 * How to confirm a version delete.
 * - `allowWorkflowDelete`: only a confirmation that warned about deleting the
 *   workflow allows it; a plain "delete this version" asks the server to refuse
 *   when the version has become the last one meanwhile.
 * - `askAboutWorkflow`: after such a refusal (`serverSaysLast`), ask again about
 *   the whole workflow, but only while the reloaded list still shows the version
 *   as the last one. A version registered or restored since then makes it a
 *   version-only delete again.
 */
export function deleteConfirmation(
  risk: LastVersionRisk,
  serverSaysLast: boolean,
): { askAboutWorkflow: boolean; allowWorkflowDelete: boolean } {
  const askAboutWorkflow = serverSaysLast && risk !== 'not-last';
  return {
    askAboutWorkflow,
    allowWorkflowDelete: askAboutWorkflow || risk !== 'not-last',
  };
}

/** Asked again when the server refused a version-only delete of the last version. */
export const LAST_VERSION_PROMPT =
  '마지막 버전이 되었습니다. 워크플로 전체를 삭제할까요?';

/**
 * True when the server refused a version-only delete because the version became
 * the last one (e.g. the others were deleted in another tab). Nothing changed.
 */
export function isLastVersionRemaining(error: unknown): boolean {
  return error instanceof ApiError && error.code === 'LAST_VERSION_REMAINING';
}

/**
 * One line for the page after a delete. `versionLabel` is the deleted version,
 * or null when the whole workflow was deleted directly.
 */
export function deletionNotice(
  result: DeletionResult,
  versionLabel: string | null,
): string {
  const date = formatDateTime(result.restoreUntil);
  if (versionLabel === null) {
    return `워크플로를 삭제했습니다. ${date}까지 '삭제된 항목 보기'에서 복구할 수 있습니다.`;
  }
  if (result.workflowDeleted) {
    return `${versionLabel}이(가) 마지막 버전이어서 워크플로 전체를 삭제했습니다. ${date}까지 '삭제된 항목 보기'에서 복구할 수 있습니다.`;
  }
  return `${versionLabel}을(를) 삭제했습니다. ${date}까지 '삭제된 버전 보기'에서 복구할 수 있습니다.`;
}

/** One line for the page after a restore, including versions that could not come back. */
export function restoreNotice(result: RestoreResult, name: string): string {
  const restored = `${name}을(를) 복구했습니다.`;
  const missing = result.unavailableVersionIds.length;
  return missing > 0
    ? `${restored} 원본 파일을 확인하지 못한 버전 ${missing}개는 복구하지 못했습니다.`
    : restored;
}

/**
 * True when the server's state moved on since the page loaded, e.g. the item was
 * deleted, restored or cleaned up elsewhere. The page should reload what it shows.
 */
export function isStaleError(error: unknown): boolean {
  if (!(error instanceof ApiError)) return false;
  return (
    error.status === 404 ||
    error.code === 'NOT_DELETED' ||
    error.code === 'RESTORE_UNAVAILABLE'
  );
}

/** Reads the notice a previous page passed through navigation state. */
export function noticeFrom(state: unknown): string {
  if (typeof state !== 'object' || state === null) return '';
  const { notice } = state as Record<string, unknown>;
  return typeof notice === 'string' ? notice : '';
}
