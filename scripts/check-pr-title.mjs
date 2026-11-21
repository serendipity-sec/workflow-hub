import { pathToFileURL } from 'node:url';

export function isValidTitle(title) {
  const match =
    /^(feat|fix|docs|style|refactor|perf|test|build|ci|chore|revert)(?:\(([a-z][a-z0-9-]*)\))?!?: (\S.*)$/.exec(
      title,
    );
  return Boolean(match && !['front', 'back', 'frontend', 'backend'].includes(match[2]));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const title = process.env.PR_TITLE ?? process.argv[2] ?? '';
  if (!isValidTitle(title)) {
    console.error('PR title must be type(domain): description. Use labels for frontend/backend.');
    process.exitCode = 1;
  }
}
