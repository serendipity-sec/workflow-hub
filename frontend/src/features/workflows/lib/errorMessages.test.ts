import { describe, expect, it } from 'vitest';
import { ApiError } from '../../../shared/api/client';
import { describeWorkflowError } from './errorMessages';

describe('describeWorkflowError', () => {
  it('prefers the message for a known error code', () => {
    expect(
      describeWorkflowError(new ApiError(422, 'INVALID_WORKFLOW')),
    ).toMatch(/n8n/);
    expect(
      describeWorkflowError(new ApiError(404, 'WORKFLOW_NOT_FOUND')),
    ).toMatch(/워크플로를 찾을 수 없/);
  });

  it('falls back to the HTTP status when the code is unknown', () => {
    expect(describeWorkflowError(new ApiError(401))).toMatch(/로그인/);
    expect(describeWorkflowError(new ApiError(403))).toMatch(/권한/);
    expect(describeWorkflowError(new ApiError(404, 'SOMETHING_NEW'))).toMatch(
      /찾을 수 없/,
    );
  });

  it('shows the request id only for failures the user may need to report', () => {
    const server = describeWorkflowError(
      new ApiError(500, 'INTERNAL_ERROR', 'req-1'),
    );
    expect(server).toContain('req-1');
    expect(
      describeWorkflowError(new ApiError(404, 'WORKFLOW_NOT_FOUND', 'req-2')),
    ).not.toContain('req-2');
  });

  it('explains network failures', () => {
    expect(describeWorkflowError(new TypeError('Failed to fetch'))).toMatch(
      /연결/,
    );
  });

  it('explains version registration conflicts and limits', () => {
    expect(
      describeWorkflowError(new ApiError(409, 'LATEST_VERSION_CHANGED')),
    ).toMatch(/다시 비교/);
    expect(
      describeWorkflowError(new ApiError(404, 'COMPARISON_NOT_FOUND')),
    ).toMatch(/만료/);
    expect(
      describeWorkflowError(new ApiError(422, 'WORKFLOW_LIMIT_EXCEEDED')),
    ).toMatch(/한도/);
  });

  it('explains stopped downloads instead of a generic permission error', () => {
    const message = describeWorkflowError(
      new ApiError(403, 'VERSION_DOWNLOAD_DISABLED'),
    );
    expect(message).toMatch(/다운로드가 중지/);
    expect(message).not.toMatch(/권한/);
  });

  it('explains why a delete or restore was refused', () => {
    expect(
      describeWorkflowError(new ApiError(409, 'RESTORE_UNAVAILABLE')),
    ).toMatch(/복구할 수 없습니다/);
    expect(describeWorkflowError(new ApiError(409, 'NOT_DELETED'))).toMatch(
      /이미 복구/,
    );
    expect(
      describeWorkflowError(new ApiError(404, 'WORKFLOW_VERSION_NOT_FOUND')),
    ).toMatch(/이미 삭제/);
    expect(
      describeWorkflowError(new ApiError(503, 'STORAGE_UNAVAILABLE')),
    ).toMatch(/다시 시도/);
    expect(
      describeWorkflowError(new ApiError(409, 'LAST_VERSION_REMAINING')),
    ).toMatch(/아무것도 삭제하지 않았습니다/);
  });

  it('never throws for unexpected values', () => {
    expect(describeWorkflowError('boom')).toMatch(/알 수 없는/);
    expect(describeWorkflowError(null)).toMatch(/알 수 없는/);
  });
});
