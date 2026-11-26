/**
 * The page notice while the registration panel works: starting a comparison or
 * registration clears the previous notice, and finishing keeps whatever was set
 * meanwhile (e.g. "v1.1을(를) 새 버전으로 등록했습니다.").
 */
export function noticeOnPanelBusy(notice: string, busy: boolean): string {
  return busy ? '' : notice;
}
