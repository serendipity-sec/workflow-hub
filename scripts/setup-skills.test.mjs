import assert from 'node:assert/strict';
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  realpathSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { setupSkills, SKILL_NAMES } from './setup-skills.mjs';

function makeRepo() {
  const root = mkdtempSync(path.join(tmpdir(), 'setup-skills-'));
  for (const name of SKILL_NAMES) {
    const dir = path.join(root, '.agents', 'skills', name);
    mkdirSync(dir, { recursive: true });
    writeFileSync(path.join(dir, 'SKILL.md'), `---\nname: ${name}\n---\n`);
  }
  return root;
}

test('creates links from .claude/skills to .agents/skills and keeps them on rerun', () => {
  const root = makeRepo();
  try {
    const first = setupSkills(root);
    assert.deepEqual(
      first.map((r) => r.status),
      ['created', 'created'],
    );
    for (const name of SKILL_NAMES) {
      assert.equal(
        realpathSync(path.join(root, '.claude', 'skills', name)),
        realpathSync(path.join(root, '.agents', 'skills', name)),
      );
    }

    const second = setupSkills(root);
    assert.deepEqual(
      second.map((r) => r.status),
      ['kept', 'kept'],
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('refuses to overwrite an existing regular directory', () => {
  const root = makeRepo();
  try {
    const existing = path.join(root, '.claude', 'skills', 'start-task');
    mkdirSync(existing, { recursive: true });
    writeFileSync(path.join(existing, 'SKILL.md'), 'local edit');
    assert.throws(() => setupSkills(root), /덮어쓰지 않습니다/);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('fails before creating any link when a source skill is missing', () => {
  const root = makeRepo();
  try {
    rmSync(path.join(root, '.agents', 'skills', 'finish-task'), { recursive: true, force: true });
    assert.throws(() => setupSkills(root), /원본 스킬을 찾을 수 없습니다/);
    assert.equal(existsSync(path.join(root, '.claude', 'skills', 'start-task')), false);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});

test('reports a dangling link instead of overwriting it', () => {
  const root = makeRepo();
  try {
    // 원본은 있지만 링크가 사라진 대상을 가리키는 상황을 만든다.
    mkdirSync(path.join(root, '.claude', 'skills'), { recursive: true });
    symlinkSync(
      path.join(root, 'gone'),
      path.join(root, '.claude', 'skills', 'start-task'),
      'junction',
    );
    assert.throws(() => setupSkills(root), /끊어진 링크/);
    assert.equal(
      lstatSync(path.join(root, '.claude', 'skills', 'start-task')).isSymbolicLink(),
      true,
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
