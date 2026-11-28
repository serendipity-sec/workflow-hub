import { describe, expect, it } from 'vitest';
import { ApiError } from '../../../shared/api/client';
import { formatDateTime } from '../../../shared/format';
import {
  allowsWorkflowDelete,
  asksAboutWorkflowAgain,
  deletionNotice,
  isDeleted,
  isLastVersionRemaining,
  isStaleError,
  LAST_VERSION_PROMPT,
  lastVersionRisk,
  noticeFrom,
  restoreDeadline,
  restoreNotice,
} from './deletion';
import type { VersionMetadata } from '../api/types';

const RESTORE_UNTIL = '2026-11-29T04:15:30Z';

function version(id: string, deleted = false): VersionMetadata {
  return {
    versionId: id,
    versionLabel: id,
    createdAt: '2026-11-22T04:15:30Z',
    downloadEnabled: true,
    sha256: null,
    sizeBytes: null,
    ...(deleted
      ? { deletedAt: '2026-11-22T05:00:00Z', restoreUntil: RESTORE_UNTIL }
      : {}),
  };
}

describe('isDeleted', () => {
  it('uses deletedAt to tell deleted items from alive ones', () => {
    expect(isDeleted(version('v1'))).toBe(false);
    expect(isDeleted(version('v1', true))).toBe(true);
  });

  it('treats an explicit null like a missing deletedAt', () => {
    expect(isDeleted({ deletedAt: null })).toBe(false);
  });
});

describe('restoreDeadline', () => {
  it('shows the server deadline as it is', () => {
    expect(restoreDeadline(RESTORE_UNTIL)).toBe(
      `${formatDateTime(RESTORE_UNTIL)}까지 복구할 수 있습니다.`,
    );
  });
});

describe('lastVersionRisk', () => {
  const v1 = version('v1');

  it('is last when the complete list holds no other alive version', () => {
    expect(lastVersionRisk(v1, [v1], false, false)).toBe('last');
    expect(lastVersionRisk(v1, [v1, version('v2', true)], false, true)).toBe(
      'last',
    );
  });

  it('is not last when another alive version is loaded', () => {
    expect(lastVersionRisk(v1, [v1, version('v2')], false, false)).toBe(
      'not-last',
    );
  });

  it('is not last when more pages of alive versions follow', () => {
    expect(lastVersionRisk(v1, [v1], true, false)).toBe('not-last');
  });

  it('is uncertain when unloaded pages may hold only deleted versions', () => {
    expect(lastVersionRisk(v1, [v1, version('v2', true)], true, true)).toBe(
      'maybe-last',
    );
  });

  it('counts only versions other than the one being deleted', () => {
    // Even if the target is missing from or stale in the loaded list.
    expect(lastVersionRisk(v1, [version('v2')], false, false)).toBe('not-last');
    expect(lastVersionRisk(v1, [version('v1', true)], false, true)).toBe(
      'last',
    );
  });
});

describe('allowsWorkflowDelete', () => {
  it('lets the workflow go only when the confirmation warned about it', () => {
    expect(allowsWorkflowDelete('last')).toBe(true);
    expect(allowsWorkflowDelete('maybe-last')).toBe(true);
  });

  it('keeps the workflow for a plain version delete', () => {
    expect(allowsWorkflowDelete('not-last')).toBe(false);
  });
});

describe('asksAboutWorkflowAgain', () => {
  const v1 = version('v1');

  it('asks even when the refused version is on a page that is not loaded', () => {
    // Deleted versions are shown and newer ones fill the first page, so v1 is
    // not among the loaded rows after the reload.
    const firstPage = [version('v9', true), version('v8', true)];
    expect(asksAboutWorkflowAgain(v1, firstPage, true, true)).toBe(true);
  });

  it('asks when the reloaded list shows it as the last version', () => {
    expect(asksAboutWorkflowAgain(v1, [v1], false, false)).toBe(true);
    expect(
      asksAboutWorkflowAgain(v1, [version('v2', true), v1], false, true),
    ).toBe(true);
  });

  it('stops asking once another alive version is loaded', () => {
    // e.g. a version registered or restored after the refusal.
    expect(asksAboutWorkflowAgain(v1, [version('v2'), v1], false, false)).toBe(
      false,
    );
    expect(asksAboutWorkflowAgain(v1, [version('v2')], true, true)).toBe(false);
  });

  it('does not ask about a version that is no longer listed', () => {
    // Every page is loaded and v1 is not among them, e.g. cleaned up.
    expect(asksAboutWorkflowAgain(v1, [version('v2', true)], false, true)).toBe(
      false,
    );
  });

  it('does not ask about a version the reloaded list shows as deleted', () => {
    // e.g. deleted in another tab before the reload.
    const firstPage = [version('v2', true), version('v1', true)];
    expect(asksAboutWorkflowAgain(v1, firstPage, true, true)).toBe(false);
  });
});

describe('isLastVersionRemaining', () => {
  it('recognizes the refusal of a version-only delete', () => {
    expect(
      isLastVersionRemaining(new ApiError(409, 'LAST_VERSION_REMAINING')),
    ).toBe(true);
  });

  it('ignores other conflicts and failures', () => {
    expect(isLastVersionRemaining(new ApiError(409, 'NOT_DELETED'))).toBe(
      false,
    );
    expect(isLastVersionRemaining(new ApiError(409))).toBe(false);
    expect(isLastVersionRemaining(new TypeError('Failed to fetch'))).toBe(
      false,
    );
  });

  it('asks again about the whole workflow', () => {
    expect(LAST_VERSION_PROMPT).toBe(
      '마지막 버전이 되었습니다. 워크플로 전체를 삭제할까요?',
    );
  });
});

describe('isStaleError', () => {
  it('treats gone, already restored and expired items as stale', () => {
    expect(isStaleError(new ApiError(404, 'WORKFLOW_VERSION_NOT_FOUND'))).toBe(
      true,
    );
    expect(isStaleError(new ApiError(404))).toBe(true);
    expect(isStaleError(new ApiError(409, 'NOT_DELETED'))).toBe(true);
    expect(isStaleError(new ApiError(409, 'RESTORE_UNAVAILABLE'))).toBe(true);
  });

  it('keeps the page as it is for other failures', () => {
    expect(isStaleError(new ApiError(503, 'STORAGE_UNAVAILABLE'))).toBe(false);
    expect(isStaleError(new ApiError(409, 'LATEST_VERSION_CHANGED'))).toBe(
      false,
    );
    expect(isStaleError(new TypeError('Failed to fetch'))).toBe(false);
  });
});

describe('deletionNotice', () => {
  const base = {
    workflowId: 'w',
    deletedAt: '2026-11-22T04:15:30Z',
    restoreUntil: RESTORE_UNTIL,
  };
  const date = formatDateTime(RESTORE_UNTIL);

  it('names the version and where to restore it', () => {
    const notice = deletionNotice(
      { ...base, versionId: 'v', workflowDeleted: false },
      'v1.1',
    );
    expect(notice).toContain('v1.1을(를) 삭제했습니다');
    expect(notice).toContain(`${date}까지 '삭제된 버전 보기'`);
  });

  it('says the whole workflow went away with its last version', () => {
    const notice = deletionNotice(
      { ...base, versionId: 'v', workflowDeleted: true },
      'v1',
    );
    expect(notice).toContain('워크플로 전체를 삭제했습니다');
    expect(notice).toContain("'삭제된 항목 보기'");
  });

  it('describes a direct workflow delete', () => {
    const notice = deletionNotice(
      { ...base, versionId: null, workflowDeleted: true },
      null,
    );
    expect(notice).toMatch(/^워크플로를 삭제했습니다/);
    expect(notice).toContain(date);
  });
});

describe('restoreNotice', () => {
  const result = {
    workflowId: 'w',
    workflowRestored: true,
    restoredVersionIds: ['a'],
    unavailableVersionIds: [],
  };

  it('confirms a full restore', () => {
    expect(restoreNotice(result, 'v1')).toBe('v1을(를) 복구했습니다.');
  });

  it('counts versions that could not be restored', () => {
    expect(
      restoreNotice({ ...result, unavailableVersionIds: ['b', 'c'] }, 'v1'),
    ).toContain('버전 2개는 복구하지 못했습니다');
  });
});

describe('noticeFrom', () => {
  it('reads a string notice from navigation state', () => {
    expect(noticeFrom({ notice: '삭제했습니다.' })).toBe('삭제했습니다.');
  });

  it('ignores anything else', () => {
    expect(noticeFrom(null)).toBe('');
    expect(noticeFrom('text')).toBe('');
    expect(noticeFrom({ notice: 1 })).toBe('');
  });
});
