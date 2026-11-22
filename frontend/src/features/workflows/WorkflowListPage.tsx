import { Link } from 'react-router';
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
import { listMyWorkflows } from './api';
import { describeWorkflowError } from './errorMessages';
import './workflows.css';

export function WorkflowListPage() {
  const { state, retry, loadMore } = usePagedList(listMyWorkflows);

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
          <ButtonLink to="/workflows/new">첫 워크플로 등록</ButtonLink>
        </EmptyState>
      )}
      {state.status === 'ready' && state.items.length > 0 && (
        <>
          <ul className="row-list">
            {state.items.map((workflow) => (
              <li key={workflow.workflowId}>
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
                    <Tag tone="dark">{workflow.latestVersion.versionLabel}</Tag>
                  )}
                  <span className="row-arrow">
                    <Icon name="arrow-right" size={18} />
                  </span>
                </Link>
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
