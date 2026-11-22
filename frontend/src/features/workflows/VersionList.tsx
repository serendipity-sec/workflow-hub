import { useCallback, useState } from 'react';
import { usePagedList } from '../../shared/api/usePagedList';
import { formatDateTime } from '../../shared/format';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../../shared/ui/PageStates';
import { downloadVersion, listVersions } from './api';
import { describeWorkflowError } from './errorMessages';
import type { VersionMetadata } from './types';

/** Version history of one workflow with a download button per version. */
export function VersionList({ workflowId }: { workflowId: string }) {
  const fetchPage = useCallback(
    (cursor: string | null) => listVersions(workflowId, cursor),
    [workflowId],
  );
  const { state, retry, loadMore } = usePagedList(fetchPage);
  const [downloadingId, setDownloadingId] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState('');

  async function download(version: VersionMetadata) {
    setDownloadingId(version.versionId);
    setDownloadError('');
    try {
      await downloadVersion(workflowId, version);
    } catch (error) {
      setDownloadError(describeWorkflowError(error));
    } finally {
      setDownloadingId(null);
    }
  }

  return (
    <section className="panel" aria-labelledby="versions-heading">
      <h2 id="versions-heading">버전 이력</h2>
      <p className="muted">
        각 버전은 등록 당시의 원본 그대로 내려받을 수 있습니다.
      </p>

      {state.status === 'loading' && <LoadingState />}
      {state.status === 'error' && (
        <ErrorState
          message={describeWorkflowError(state.error)}
          onRetry={retry}
        />
      )}
      {state.status === 'ready' && state.items.length === 0 && (
        <EmptyState title="등록된 버전이 없습니다." />
      )}
      {state.status === 'ready' && state.items.length > 0 && (
        <>
          <ul className="version-list">
            {state.items.map((version) => (
              <li key={version.versionId}>
                <span className="version-label">{version.versionLabel}</span>
                <span className="muted">
                  {formatDateTime(version.createdAt)}
                </span>
                <button
                  type="button"
                  className="button-secondary"
                  disabled={downloadingId !== null}
                  onClick={() => void download(version)}
                >
                  {downloadingId === version.versionId
                    ? '내려받는 중…'
                    : 'JSON 다운로드'}
                </button>
              </li>
            ))}
          </ul>
          {downloadError && <p role="alert">{downloadError}</p>}
          {state.error != null && (
            <p role="alert">{describeWorkflowError(state.error)}</p>
          )}
          {state.nextCursor && (
            <button
              type="button"
              className="button-secondary"
              disabled={state.loadingMore}
              onClick={loadMore}
            >
              {state.loadingMore ? '불러오는 중…' : '이전 버전 더 보기'}
            </button>
          )}
        </>
      )}
    </section>
  );
}
