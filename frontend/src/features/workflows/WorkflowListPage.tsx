import { useCallback, useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router';
import { usePagedList } from '../../shared/api/usePagedList';
import { formatDateTime } from '../../shared/format';
import { Button, ButtonLink } from '../../shared/ui/Button';
import { Icon } from '../../shared/ui/Icon';
import { PageHeader } from '../../shared/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../../shared/ui/PageStates';
import { Tag } from '../../shared/ui/Tag';
import { listMyWorkflows, restoreWorkflow } from './api';
import {
  isDeleted,
  isStaleError,
  noticeFrom,
  restoreDeadline,
  restoreNotice,
} from './deletion';
import { describeWorkflowError } from './errorMessages';
import type { WorkflowSummary } from './types';
import './workflows.css';

export function WorkflowListPage() {
  const location = useLocation();
  const navigate = useNavigate();
  // A notice passed by the previous page, e.g. after deleting a workflow.
  const [passedNotice] = useState(() => noticeFrom(location.state));
  const [notice, setNotice] = useState('');
  const [includeDeleted, setIncludeDeleted] = useState(false);
  // Bumped after a restore so the list shows what the server now has.
  const [reloadKey, setReloadKey] = useState(0);
  // Kept here, not in the rows, so toggling the list cannot drop the lock.
  const [restoringId, setRestoringId] = useState<string | null>(null);
  const [restoreError, setRestoreError] = useState('');
  const passedStillInHistory = noticeFrom(location.state) !== '';

  // Drop the passed notice from history so reloading the page does not repeat it.
  useEffect(() => {
    if (passedStillInHistory) {
      void navigate(
        {
          pathname: location.pathname,
          search: location.search,
          hash: location.hash,
        },
        { replace: true, state: null },
      );
    }
  }, [
    passedStillInHistory,
    location.pathname,
    location.search,
    location.hash,
    navigate,
  ]);

  // The passed notice appears only after that replace, i.e. after the live
  // region has mounted, so screen readers announce it.
  const shownNotice = notice || (passedStillInHistory ? '' : passedNotice);

  async function restore(workflow: WorkflowSummary) {
    setRestoringId(workflow.workflowId);
    setRestoreError('');
    try {
      const result = await restoreWorkflow(workflow.workflowId);
      setNotice(restoreNotice(result, `‘${workflow.title}’`));
      setReloadKey((key) => key + 1);
    } catch (error) {
      setRestoreError(describeWorkflowError(error));
      // Restored, expired or cleaned up elsewhere: show the server's state.
      if (isStaleError(error)) {
        setReloadKey((key) => key + 1);
      }
    } finally {
      setRestoringId(null);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="내 워크플로"
        title="등록한 워크플로"
        description="내가 등록한 n8n 워크플로와 최신 버전입니다."
        actions={
          <ButtonLink to="/workflows/new">
            <Icon name="plus" size={16} />새 워크플로 등록
          </ButtonLink>
        }
      />
      <div aria-live="polite">
        {shownNotice && <p className="flash">{shownNotice}</p>}
      </div>
      <div className="list-toolbar">
        <label className="toggle">
          <input
            type="checkbox"
            checked={includeDeleted}
            disabled={restoringId !== null}
            onChange={(event) => setIncludeDeleted(event.target.checked)}
          />
          삭제된 항목 보기
        </label>
      </div>
      <WorkflowRows
        key={`${includeDeleted}-${reloadKey}`}
        includeDeleted={includeDeleted}
        restoringId={restoringId}
        onRestore={(workflow) => void restore(workflow)}
      />
      {restoreError && <p role="alert">{restoreError}</p>}
    </>
  );
}

function WorkflowRows({
  includeDeleted,
  restoringId,
  onRestore,
}: {
  includeDeleted: boolean;
  restoringId: string | null;
  onRestore: (workflow: WorkflowSummary) => void;
}) {
  const fetchPage = useCallback(
    (cursor: string | null) => listMyWorkflows(cursor, includeDeleted),
    [includeDeleted],
  );
  const { state, retry, loadMore } = usePagedList(fetchPage);

  return (
    <>
      {/* Mounted before the fetch starts so screen readers announce the result. */}
      <div aria-live="polite">
        {state.status === 'loading' && <LoadingState />}
        {state.status === 'ready' &&
          state.items.length === 0 &&
          (includeDeleted ? (
            <EmptyState title="워크플로도, 복구할 수 있는 삭제 항목도 없습니다." />
          ) : (
            <EmptyState title="아직 등록한 워크플로가 없습니다.">
              <p className="muted">
                n8n에서 내보낸 JSON 파일을 올려 시작해 보세요.
              </p>
              <ButtonLink to="/workflows/new">첫 워크플로 등록</ButtonLink>
            </EmptyState>
          ))}
      </div>
      {state.status === 'error' && (
        <ErrorState
          message={describeWorkflowError(state.error)}
          onRetry={retry}
        />
      )}
      {state.status === 'ready' && state.items.length > 0 && (
        <>
          <ul className="row-list">
            {state.items.map((workflow) => (
              <li key={workflow.workflowId}>
                {isDeleted(workflow) ? (
                  <DeletedWorkflowRow
                    workflow={workflow}
                    restoring={restoringId === workflow.workflowId}
                    disabled={restoringId !== null}
                    onRestore={() => onRestore(workflow)}
                  />
                ) : (
                  <Link
                    className="row-card"
                    to={`/workflows/${workflow.workflowId}`}
                  >
                    <span className="row-icon">
                      <Icon name="file" size={20} />
                    </span>
                    <span className="row-main">
                      <strong>{workflow.title}</strong>
                      <span className="muted">
                        {workflow.latestVersion
                          ? formatDateTime(workflow.latestVersion.createdAt)
                          : '등록된 버전 없음'}
                      </span>
                    </span>
                    {workflow.latestVersion && (
                      <Tag tone="dark">
                        {workflow.latestVersion.versionLabel}
                      </Tag>
                    )}
                    <span className="row-arrow">
                      <Icon name="arrow-right" size={18} />
                    </span>
                  </Link>
                )}
              </li>
            ))}
          </ul>
          {state.error != null && (
            <ErrorState message={describeWorkflowError(state.error)} />
          )}
          {state.nextCursor && (
            <Button
              variant="secondary"
              disabled={state.loadingMore}
              onClick={loadMore}
            >
              {state.loadingMore ? '불러오는 중…' : '더 보기'}
            </Button>
          )}
        </>
      )}
    </>
  );
}

/** Deleted workflows have no detail page, so they are restored from the list. */
function DeletedWorkflowRow({
  workflow,
  restoring,
  disabled,
  onRestore,
}: {
  workflow: WorkflowSummary;
  restoring: boolean;
  disabled: boolean;
  onRestore: () => void;
}) {
  return (
    <div className="row-card is-deleted">
      <span className="row-icon">
        <Icon name="file" size={20} />
      </span>
      <span className="row-main">
        <strong>{workflow.title}</strong>
        <span className="muted">
          {workflow.restoreUntil
            ? restoreDeadline(workflow.restoreUntil)
            : '삭제됨'}
        </span>
      </span>
      <Tag tone="outline">삭제됨</Tag>
      <Button
        variant="secondary"
        size="sm"
        disabled={disabled}
        onClick={onRestore}
      >
        <Icon name="refresh" size={16} />
        {restoring ? '복구하는 중…' : '복구'}
      </Button>
    </div>
  );
}
