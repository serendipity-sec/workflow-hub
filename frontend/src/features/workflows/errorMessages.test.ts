import { describe, expect, it } from 'vitest';
import { ApiError } from '../../shared/api/client';
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

  it('never throws for unexpected values', () => {
    expect(describeWorkflowError('boom')).toMatch(/알 수 없는/);
    expect(describeWorkflowError(null)).toMatch(/알 수 없는/);
  });
});
