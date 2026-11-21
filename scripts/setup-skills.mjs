// .agents/skills의 워크플로 스킬을 .claude/skills에서 찾을 수 있도록 링크를 만든다.
// 원본은 .agents/skills에만 있고, .claude/skills의 링크는 git에 올라가지 않는다.
// Windows는 디렉터리 정션을 써서 관리자 권한 없이 만든다.
import { existsSync, lstatSync, mkdirSync, realpathSync, symlinkSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SKILL_NAMES = ['start-task', 'finish-task'];

// 경로에 항목이 있는지(끊어진 링크 포함) 확인한다.
function present(p) {
  try {
    lstatSync(p);
    return true;
  } catch {
    return false;
  }
}

export function setupSkills(rootDir) {
  const sourceDir = path.join(rootDir, '.agents', 'skills');
  const targetDir = path.join(rootDir, '.claude', 'skills');

  // 1) 원본을 모두 확인한 뒤에만 링크를 만든다. 실패 시 중간 상태를 남기지 않는다.
  for (const name of SKILL_NAMES) {
    const skillFile = path.join(sourceDir, name, 'SKILL.md');
    if (!existsSync(skillFile)) {
      throw new Error(`원본 스킬을 찾을 수 없습니다: ${skillFile}`);
    }
  }

  // 2) 대상 상태를 먼저 점검한다. 링크가 끊어졌거나 다른 내용이면 지우지 않고 멈춘다.
  const plan = SKILL_NAMES.map((name) => {
    const from = path.join(sourceDir, name);
    const to = path.join(targetDir, name);
    if (!present(to)) return { name, from, to, action: 'create' };
    if (!existsSync(to)) {
      throw new Error(`끊어진 링크가 있습니다. 직접 삭제한 뒤 다시 실행하세요: ${to}`);
    }
    if (realpathSync(to) === realpathSync(from)) return { name, from, to, action: 'keep' };
    throw new Error(`기존 항목이 있어 덮어쓰지 않습니다. 직접 확인하세요: ${to}`);
  });

  mkdirSync(targetDir, { recursive: true });
  return plan.map(({ name, from, to, action }) => {
    if (action === 'create') {
      symlinkSync(from, to, process.platform === 'win32' ? 'junction' : 'dir');
    }
    return { name, status: action === 'create' ? 'created' : 'kept' };
  });
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (isMain) {
  const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  for (const { name, status } of setupSkills(rootDir)) {
    console.log(`${status === 'created' ? '생성' : '유지'}: .claude/skills/${name}`);
  }
}
