import { useEffect, useState } from 'react';
import { canCopy, copyText, describeFileIdentity } from './fileIdentityView';
import './workflows.css';

type Copy = { state: 'idle' | 'copied' | 'failed'; at: number };
const IDLE: Copy = { state: 'idle', at: 0 };

/**
 * The server-recorded SHA-256 and size of one version's original file, so the
 * owner can check a downloaded file against it. The full hash can be copied.
 * `name` tells the copy buttons apart, e.g. "v1.1" or "최신 버전 v2".
 */
export function FileIdentity({
  name,
  sha256,
  sizeBytes,
}: {
  name: string;
  sha256: string | null;
  sizeBytes: number | null;
}) {
  const identity = describeFileIdentity({ sha256, sizeBytes });
  const [copy, setCopy] = useState<Copy>(IDLE);

  // The confirmation is shown briefly. A new copy restarts the timer (`at`).
  useEffect(() => {
    if (copy.state === 'idle') return;
    const timer = window.setTimeout(() => setCopy(IDLE), 2000);
    return () => window.clearTimeout(timer);
  }, [copy]);

  if (!identity.known) {
    return (
      <span className="file-identity muted">
        파일 해시·크기 미확인(기록 전에 등록된 버전)
      </span>
    );
  }

  const clipboard =
    typeof navigator === 'undefined' ? undefined : navigator.clipboard;

  async function copyHash(value: string) {
    // Clear first so the live region changes and a repeated copy is announced again.
    setCopy(IDLE);
    const result = await copyText(clipboard, value);
    setCopy({ state: result, at: Date.now() });
  }

  return (
    <span className="file-identity">
      <span className="muted">SHA-256</span>
      {canCopy(clipboard) ? (
        <>
          <code title={identity.sha256}>{identity.shortHash}</code>
          <span className="muted">· {identity.size}</span>
          <button
            type="button"
            className="file-identity-copy"
            aria-label={`${name} 전체 SHA-256 복사`}
            onClick={() => void copyHash(identity.sha256)}
          >
            {copy.state === 'copied'
              ? '복사함'
              : copy.state === 'failed'
                ? '복사 실패'
                : '복사'}
          </button>
          <span className="file-identity-status" aria-live="polite">
            {copy.state === 'copied'
              ? `${name}의 SHA-256을 복사했습니다.`
              : copy.state === 'failed'
                ? '복사하지 못했습니다. 브라우저의 클립보드 권한을 확인해 주세요.'
                : ''}
          </span>
        </>
      ) : (
        <>
          {/* No clipboard here (e.g. plain http), so show the whole value to select by hand. */}
          <code className="file-identity-full">{identity.sha256}</code>
          <span className="muted">· {identity.size}</span>
        </>
      )}
    </span>
  );
}
