/** Initial candidate; keep in sync with the server's default upload limit. */
export const MAX_UPLOAD_BYTES = 5 * 1024 * 1024;
export const MAX_TITLE_LENGTH = 200;

export const UPLOAD_NOTICE =
  '등록하면 선택한 워크플로 JSON 파일이 AWS S3에 저장됩니다.';

/** Early checks for a nicer UI. The server remains the source of truth. */
export function validateUploadFile(
  file: { name: string; size: number } | null,
): string | null {
  if (!file) return 'n8n에서 내보낸 JSON 파일을 선택해 주세요.';
  if (!file.name.toLowerCase().endsWith('.json')) {
    return '.json 파일만 등록할 수 있습니다.';
  }
  if (file.size === 0) return '비어 있는 파일입니다.';
  if (file.size > MAX_UPLOAD_BYTES) {
    return `파일이 너무 큽니다. 최대 ${MAX_UPLOAD_BYTES / 1024 / 1024} MiB까지 등록할 수 있습니다.`;
  }
  return null;
}

/** The server counts Unicode code points, not UTF-16 units (emoji count once). */
function countCodePoints(text: string): number {
  return Array.from(text).length;
}

export function validateTitle(title: string): string | null {
  if (countCodePoints(title) > MAX_TITLE_LENGTH) {
    return `제목은 ${MAX_TITLE_LENGTH}자 이하로 입력해 주세요.`;
  }
  return null;
}
