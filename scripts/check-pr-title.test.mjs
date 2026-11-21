import assert from 'node:assert/strict';
import test from 'node:test';
import { isValidTitle } from './check-pr-title.mjs';

test('accepts domain scopes, optional scope, breaking marker and Korean descriptions', () => {
  for (const title of [
    'feat(workflow): 업로드 추가',
    'ci: 검사 추가',
    'feat(auth)!: 신원 확인 방식 변경',
  ]) {
    assert.equal(isValidTitle(title), true, title);
  }
});

test('rejects area scopes, missing descriptions and unsupported types', () => {
  for (const title of [
    'feat(frontend): upload',
    'fix(back): auth',
    'feat: ',
    'update: dependencies',
    'plain title',
  ]) {
    assert.equal(isValidTitle(title), false, title);
  }
});
