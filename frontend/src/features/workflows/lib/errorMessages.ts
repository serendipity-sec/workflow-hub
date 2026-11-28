import { ApiError } from '../../../shared/api/client';

const MESSAGES_BY_CODE: Record<string, string> = {
  UNAUTHORIZED: '로그인이 필요하거나 만료되었습니다. 다시 로그인해 주세요.',
  FILE_REQUIRED: '파일을 선택해 주세요.',
  FILE_TOO_LARGE: '파일이 너무 큽니다. 최대 5 MiB까지 등록할 수 있습니다.',
  FILE_UNREADABLE: '파일을 읽지 못했습니다. 파일을 다시 선택해 주세요.',
  INVALID_WORKFLOW:
    'n8n 워크플로 JSON 형식이 아닙니다. n8n 편집기에서 내보낸 파일인지 확인해 주세요.',
  TITLE_REQUIRED: '제목을 입력해 주세요.',
  TITLE_TOO_LONG: '제목이 너무 깁니다. 200자 이하로 입력해 주세요.',
  TITLE_INVALID: '제목에 사용할 수 없는 문자가 있습니다.',
  IDEMPOTENCY_KEY_REUSED:
    '같은 요청이 다른 내용으로 다시 전송되었습니다. 다시 시도해 주세요.',
  WORKFLOW_LIMIT_EXCEEDED:
    '워크플로가 너무 큽니다. 노드·연결 수나 중첩 깊이가 허용 한도를 넘었습니다.',
  INVALID_FILE_COUNT: '파일은 하나만 선택해 주세요.',
  INVALID_VERSION_REQUEST: '비교 결과와 수정 종류를 다시 선택해 주세요.',
  LATEST_VERSION_CHANGED:
    '그사이 더 새로운 버전이 등록되었습니다. 최신 버전 기준으로 다시 비교해 주세요.',
  COMPARISON_NOT_FOUND:
    '비교 결과가 없거나 만료되었습니다. 파일을 다시 비교해 주세요.',
  WORKFLOW_NOT_FOUND:
    '워크플로를 찾을 수 없습니다. 이미 삭제되었을 수 있습니다.',
  WORKFLOW_VERSION_NOT_FOUND:
    '버전을 찾을 수 없습니다. 이미 삭제되었을 수 있습니다.',
  STORAGE_UNAVAILABLE:
    '파일 저장소에 일시적인 문제가 있습니다. 잠시 후 다시 시도해 주세요.',
  VERSION_DOWNLOAD_DISABLED:
    '이 버전은 다운로드가 중지되어 있습니다. 다운로드를 다시 허용하면 내려받을 수 있습니다.',
  RESTORE_UNAVAILABLE:
    '복구할 수 없습니다. 복구 기한이 지났거나 원본 파일이 이미 정리되었습니다.',
  NOT_DELETED: '삭제된 상태가 아닙니다. 이미 복구되었을 수 있습니다.',
  LAST_VERSION_REMAINING:
    '그사이 다른 버전이 삭제되어 이 버전이 마지막 버전이 되었습니다. 아무것도 삭제하지 않았습니다.',
};

function withRequestId(message: string, requestId?: string): string {
  return requestId ? `${message} (요청 ID: ${requestId})` : message;
}

/** Turns any thrown value into a short Korean sentence for the user. */
export function describeWorkflowError(error: unknown): string {
  if (error instanceof ApiError) {
    const known = error.code ? MESSAGES_BY_CODE[error.code] : undefined;
    if (known) return known;
    if (error.status === 401) return MESSAGES_BY_CODE.UNAUTHORIZED;
    if (error.status === 403) return '이 작업을 할 권한이 없습니다.';
    if (error.status === 404) return '요청한 항목을 찾을 수 없습니다.';
    if (error.status === 413) return MESSAGES_BY_CODE.FILE_TOO_LARGE;
    if (error.status >= 500) {
      return withRequestId(
        '서버에 문제가 발생했습니다. 잠시 후 다시 시도해 주세요.',
        error.requestId,
      );
    }
    return withRequestId('요청을 처리하지 못했습니다.', error.requestId);
  }
  if (error instanceof TypeError) {
    return '서버에 연결하지 못했습니다. 백엔드가 실행 중인지 확인해 주세요.';
  }
  return '알 수 없는 오류가 발생했습니다. 다시 시도해 주세요.';
}
