import { Link } from 'react-router';
import { usePagedList } from '../../shared/api/usePagedList';
import { formatDateTime } from '../../shared/format';
import { PageHeader } from '../../shared/ui/PageHeader';
import {
  EmptyState,
  ErrorState,
  LoadingState,
} from '../../shared/ui/PageStates';
import { listMyWorkflows } from './api';
import { describeWorkflowError } from './errorMessages';

export function WorkflowListPage() {
  const { state, retry, loadMore } = usePagedList(listMyWorkflows);

  return (
    <>
      <PageHeader
        title="내 워크플로"
        description="내가 등록한 n8n 워크플로와 최신 버전입니다."
        actions={
          <Link className="button" to="/workflows/new">
            새 워크플로 등록
          </Link>
        }
      />

      {state.status === 'loading' && <LoadingState />}
      {state.status === 'error' && (
        <ErrorState
          message={describeWorkflowError(state.error)}
          onRetry={retry}
        />
      )}
      {state.status === 'ready' && state.items.length === 0 && (
        <EmptyState title="아직 등록한 워크플로가 없습니다.">
          <p className="muted">
            n8n에서 내보낸 JSON 파일을 올려 시작해 보세요.
          </p>
          <Link className="button" to="/workflows/new">
            첫 워크플로 등록
          </Link>
        </EmptyState>
      )}
      {state.status === 'ready' && state.items.length > 0 && (
        <>
          <ul className="card-list">
            {state.items.map((workflow) => (
              <li key={workflow.workflowId}>
                <Link
                  className="card card-link"
                  to={`/workflows/${workflow.workflowId}`}
                >
                  <strong>{workflow.title}</strong>
                  <span className="muted">
                    {workflow.latestVersion
                      ? `${workflow.latestVersion.versionLabel} · ${formatDateTime(workflow.latestVersion.createdAt)}`
                      : '등록된 버전 없음'}
                  </span>
                </Link>
              </li>
            ))}
          </ul>
          {state.error != null && (
            <ErrorState message={describeWorkflowError(state.error)} />
          )}
          {state.nextCursor && (
            <button
              type="button"
              className="button-secondary"
              disabled={state.loadingMore}
              onClick={loadMore}
            >
              {state.loadingMore ? '불러오는 중…' : '더 보기'}
            </button>
          )}
        </>
      )}
    </>
  );
}
