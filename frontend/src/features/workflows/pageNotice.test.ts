import { describe, expect, it } from 'vitest';
import { noticeOnPanelBusy } from './pageNotice';

describe('noticeOnPanelBusy', () => {
  it('clears the previous notice when a comparison or registration starts', () => {
    expect(noticeOnPanelBusy('v1을(를) 삭제했습니다.', true)).toBe('');
  });

  it('keeps the notice set during a registration once it finishes', () => {
    // The registration sets this while the panel is busy; finishing keeps it.
    const registered = 'v1.2을(를) 새 버전으로 등록했습니다.';
    expect(noticeOnPanelBusy(registered, false)).toBe(registered);
  });
});
