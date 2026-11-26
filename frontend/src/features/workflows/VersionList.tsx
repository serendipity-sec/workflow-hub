import { useCallback, useState } from 'react';
import { usePagedList } from '../../shared/api/usePagedList';
import { formatDateTime } from '../../shared/format';
import { Button } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../../shared/ui/PageStates';
import { Tag } from '../../shared/ui/Tag';
import {
  deleteVersion,
  downloadVersion,
  listVersions,
  restoreVersion,
  setDownloadAvailability,
} from './api';
import {
  deleteConfirmation,
  deletionNotice,
  isDeleted,
  isLastVersionRemaining,
  isStaleError,
  LAST_VERSION_PROMPT,
  lastVersionRisk,
  restoreDeadline,
  restoreNotice,
} from './deletion';
import type { LastVersionRisk } from './deletion';
import { describeWorkflowError } from './errorMessages';
import { FileIdentity } from './FileIdentity';
import type { DeletionResult, VersionMetadata } from './types';
import './workflows.css';

type Action = 'download' | 'availability' | 'delete' | 'restore';
type Busy = { versionId: string; action: Action };

type Actions = {
  download: (version: VersionMetadata) => void;
  toggleDownload: (version: VersionMetadata) => void;
  /** `allowWorkflowDelete` is true only when the user confirmed that outcome. */
  remove: (version: VersionMetadata, allowWorkflowDelete: boolean) => void;
  restore: (version: VersionMetadata) => void;
};

/**
 * Version history of one workflow: download, stop or allow downloads, delete,
 * and restore deleted versions until their deadline. One action runs at a time.
 */
export function VersionList({
  workflowId,
  reloadSignal,
  locked,
  onBusyChange,
  onChanged,
  onStale,
  onWorkflowDeleted,
}: {
  workflowId: string;
  /** Changes when the page knows the list is out of date, e.g. after a registration. */
  reloadSignal: number;
  /** Set while another part of the page runs an action. */
  locked: boolean;
  onBusyChange: (busy: boolean) => void;
  /**
   * A version changed; the page shows `notice` and reloads the latest version.
   * The action stays busy until the returned reload has finished.
   */
  onChanged: (notice: string) => Promise<void>;
  /** The server no longer has what the page shows, e.g. deleted in another tab. */
  onStale: () => Promise<void>;
  /** The last version was deleted, so the whole workflow is deleted too. */
  onWorkflowDeleted: (notice: string) => void;
}) {
  const [includeDeleted, setIncludeDeleted] = useState(false);
  // Bumped after every change so the list shows what the server now has.
  const [reloadKey, setReloadKey] = useState(0);
  // Kept here, not in the rows, so a reload or toggle cannot drop the lock.
  const [busy, setBusy] = useState<Busy | null>(null);
  const [confirmingId, setConfirmingId] = useState<string | null>(null);
  // The version the server reported as the last one after a version-only delete.
  const [lastVersionId, setLastVersionId] = useState<string | null>(null);
  const [actionError, setActionError] = useState('');

  function updateBusy(next: Busy | null) {
    setBusy(next);
    onBusyChange(next !== null);
  }

  function closeConfirm() {
    setConfirmingId(null);
    setLastVersionId(null);
  }

  function reload() {
    closeConfirm();
    setReloadKey((key) => key + 1);
  }

  async function run(
    version: VersionMetadata,
    action: Action,
    task: () => Promise<void>,
  ) {
    updateBusy({ versionId: version.versionId, action });
    setActionError('');
    try {
      await task();
    } catch (error) {
      setActionError(describeWorkflowError(error));
      // Deleted, restored or cleaned up elsewhere: show the server's state.
      if (isStaleError(error)) {
        reload();
        await onStale();
      }
    } finally {
      updateBusy(null);
    }
  }

  const actions: Actions = {
    download: (version) =>
      void run(version, 'download', () => downloadVersion(workflowId, version)),
    toggleDownload: (version) =>
      void run(version, 'availability', async () => {
        const result = await setDownloadAvailability(
          workflowId,
          version.versionId,
          !version.downloadEnabled,
        );
        reload();
        await onChanged(
          result.downloadEnabled
            ? `${version.versionLabel}의 다운로드를 다시 허용했습니다.`
            : `${version.versionLabel}의 다운로드를 중지했습니다. 조회와 비교에는 계속 쓸 수 있습니다.`,
        );
      }),
    remove: (version, allowWorkflowDelete) =>
      void run(version, 'delete', async () => {
        let result: DeletionResult;
        try {
          result = await deleteVersion(workflowId, version.versionId, {
            allowWorkflowDelete,
          });
        } catch (error) {
          if (!isLastVersionRemaining(error)) throw error;
          // Nothing was deleted: the other versions went away elsewhere. Reload
          // the list and keep this confirmation open to ask about the workflow.
          setReloadKey((key) => key + 1);
          setConfirmingId(version.versionId);
          setLastVersionId(version.versionId);
          setActionError(describeWorkflowError(error));
          await onStale();
          return;
        }
        const notice = deletionNotice(result, version.versionLabel);
        if (result.workflowDeleted) {
          onWorkflowDeleted(notice);
          return;
        }
        reload();
        await onChanged(notice);
      }),
    restore: (version) =>
      void run(version, 'restore', async () => {
        const result = await restoreVersion(workflowId, version.versionId);
        reload();
        await onChanged(restoreNotice(result, version.versionLabel));
      }),
  };

  const idle = busy === null && !locked;

  return (
    <Card aria-labelledby="versions-heading">
      <div className="card-heading">
        <h2 id="versions-heading">버전 이력</h2>
        <label className="toggle">
          <input
            type="checkbox"
            checked={includeDeleted}
            disabled={!idle}
            onChange={(event) => {
              closeConfirm();
              setIncludeDeleted(event.target.checked);
            }}
          />
          삭제된 버전 보기
        </label>
      </div>
      <p className="muted">
        각 버전은 등록 당시의 원본 그대로 내려받을 수 있습니다. 내려받은 파일의
        SHA-256을 아래 값과 비교하면 같은 파일인지 확인할 수 있습니다. 삭제한
        버전은 복구 기한까지 되살릴 수 있습니다.
      </p>
      <VersionRows
        key={`${includeDeleted}-${reloadKey}-${reloadSignal}`}
        workflowId={workflowId}
        includeDeleted={includeDeleted}
        busy={busy}
        idle={idle}
        confirmingId={confirmingId}
        lastVersionId={lastVersionId}
        onConfirmToggle={(versionId) => {
          setLastVersionId(null);
          setConfirmingId((current) =>
            current === versionId ? null : versionId,
          );
        }}
        actions={actions}
      />
      {actionError && <p role="alert">{actionError}</p>}
    </Card>
  );
}

function VersionRows({
  workflowId,
  includeDeleted,
  busy,
  idle,
  confirmingId,
  lastVersionId,
  onConfirmToggle,
  actions,
}: {
  workflowId: string;
  includeDeleted: boolean;
  busy: Busy | null;
  idle: boolean;
  confirmingId: string | null;
  lastVersionId: string | null;
  onConfirmToggle: (versionId: string) => void;
  actions: Actions;
}) {
  const fetchPage = useCallback(
    (cursor: string | null) => listVersions(workflowId, cursor, includeDeleted),
    [workflowId, includeDeleted],
  );
  const { state, retry, loadMore } = usePagedList(fetchPage);

  const working = (version: VersionMetadata, action: Action) =>
    busy?.versionId === version.versionId && busy.action === action;

  return (
    <>
      {/* Mounted before the fetch starts so screen readers announce the result. */}
      <div aria-live="polite">
        {state.status === 'loading' && <LoadingState />}
        {state.status === 'ready' && state.items.length === 0 && (
          <EmptyState title="등록된 버전이 없습니다." />
        )}
      </div>
      {state.status === 'error' && (
        <ErrorState
          message={describeWorkflowError(state.error)}
          onRetry={retry}
        />
      )}
      {state.status === 'ready' && state.items.length > 0 && (
        <>
          <ul className="version-list">
            {state.items.map((version) => {
              const deleted = isDeleted(version);
              return (
                <li
                  key={version.versionId}
                  className={deleted ? 'is-deleted' : undefined}
                >
                  <div className="version-row">
                    <span className="version-label">
                      {version.versionLabel}
                    </span>
                    <span className="version-meta">
                      <span className="muted">
                        {formatDateTime(version.createdAt)}
                      </span>
                      {deleted ? (
                        <Tag tone="outline">삭제됨</Tag>
                      ) : (
                        !version.downloadEnabled && (
                          <Tag tone="outline">다운로드 중지</Tag>
                        )
                      )}
                    </span>
                    <span className="version-actions">
                      {deleted ? (
                        <Button
                          variant="secondary"
                          size="sm"
                          disabled={!idle}
                          onClick={() => actions.restore(version)}
                        >
                          <Icon name="refresh" size={16} />
                          {working(version, 'restore')
                            ? '복구하는 중…'
                            : '복구'}
                        </Button>
                      ) : (
                        <>
                          <Button
                            variant="secondary"
                            size="sm"
                            disabled={!idle || !version.downloadEnabled}
                            onClick={() => actions.download(version)}
                          >
                            <Icon name="download" size={16} />
                            {working(version, 'download')
                              ? '내려받는 중…'
                              : 'JSON 다운로드'}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={!idle}
                            onClick={() => actions.toggleDownload(version)}
                          >
                            {working(version, 'availability')
                              ? '바꾸는 중…'
                              : version.downloadEnabled
                                ? '다운로드 중지'
                                : '다운로드 허용'}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            disabled={!idle}
                            aria-expanded={confirmingId === version.versionId}
                            onClick={() => onConfirmToggle(version.versionId)}
                          >
                            삭제
                          </Button>
                        </>
                      )}
                    </span>
                  </div>
                  <FileIdentity
                    name={version.versionLabel}
                    sha256={version.sha256}
                    sizeBytes={version.sizeBytes}
                  />
                  {deleted && version.restoreUntil && (
                    <p className="muted version-note">
                      {restoreDeadline(version.restoreUntil)}
                    </p>
                  )}
                  {!deleted && confirmingId === version.versionId && (
                    <DeleteConfirm
                      versionLabel={version.versionLabel}
                      risk={lastVersionRisk(
                        version,
                        state.items,
                        state.nextCursor !== null,
                        includeDeleted,
                      )}
                      serverSaysLast={lastVersionId === version.versionId}
                      deleting={working(version, 'delete')}
                      disabled={!idle}
                      onConfirm={(allowWorkflowDelete) =>
                        actions.remove(version, allowWorkflowDelete)
                      }
                      onCancel={() => onConfirmToggle(version.versionId)}
                    />
                  )}
                </li>
              );
            })}
          </ul>
          {state.error != null && (
            <p role="alert">{describeWorkflowError(state.error)}</p>
          )}
          {state.nextCursor && (
            <Button
              variant="secondary"
              size="sm"
              disabled={state.loadingMore || !idle}
              onClick={loadMore}
            >
              {state.loadingMore ? '불러오는 중…' : '이전 버전 더 보기'}
            </Button>
          )}
        </>
      )}
    </>
  );
}

const RISK_WARNINGS: Record<LastVersionRisk, string> = {
  last: '이 버전이 마지막으로 남은 버전입니다. 삭제하면 워크플로 전체가 삭제됩니다.',
  'maybe-last': '남은 버전이 이 버전뿐이면 워크플로 전체가 삭제됩니다.',
  'not-last': '',
};

function DeleteConfirm({
  versionLabel,
  risk,
  serverSaysLast,
  deleting,
  disabled,
  onConfirm,
  onCancel,
}: {
  versionLabel: string;
  risk: LastVersionRisk;
  /** The server refused a version-only delete because this became the last version. */
  serverSaysLast: boolean;
  deleting: boolean;
  disabled: boolean;
  onConfirm: (allowWorkflowDelete: boolean) => void;
  onCancel: () => void;
}) {
  const { askAboutWorkflow, allowWorkflowDelete } = deleteConfirmation(
    risk,
    serverSaysLast,
  );
  const warning = askAboutWorkflow ? LAST_VERSION_PROMPT : RISK_WARNINGS[risk];
  return (
    <div
      className="confirm-box"
      role="group"
      aria-label={`${versionLabel} 삭제 확인`}
    >
      {warning && <p className="confirm-warning">{warning}</p>}
      <p>
        삭제하면 바로 조회·다운로드·비교에서 빠집니다. 복구 기한 안에는 되살릴
        수 있고, 같은 버전 번호는 다시 쓰지 않습니다.
      </p>
      <div className="confirm-actions">
        <Button
          size="sm"
          disabled={disabled}
          onClick={() => onConfirm(allowWorkflowDelete)}
        >
          {deleting
            ? '삭제하는 중…'
            : askAboutWorkflow
              ? '워크플로 전체 삭제'
              : `${versionLabel} 삭제`}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          disabled={disabled}
          onClick={onCancel}
        >
          취소
        </Button>
      </div>
    </div>
  );
}
