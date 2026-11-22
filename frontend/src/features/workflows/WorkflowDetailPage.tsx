import { useCallback } from 'react';
import { Link, useParams } from 'react-router';
import { useRequest } from '../../shared/api/useRequest';
import { formatDateTime } from '../../shared/format';
import { PageHeader } from '../../shared/ui/PageHeader';
import { ErrorState, LoadingState } from '../../shared/ui/PageStates';
import { NextVersionPanel } from '../revisions/NextVersionPanel';
import { SecurityCheckPanel } from '../security/SecurityCheckPanel';
import { getWorkflow } from './api';
import { describeWorkflowError } from './errorMessages';
import { VersionList } from './VersionList';

/** Route entry. The key remounts the content when the URL points to another workflow. */
export function WorkflowDetailPage() {
  const { workflowId } = useParams();
  if (!workflowId) return null;
  return <WorkflowDetail key={workflowId} workflowId={workflowId} />;
}

function WorkflowDetail({ workflowId }: { workflowId: string }) {
  const fetchWorkflow = useCallback(
    () => getWorkflow(workflowId),
    [workflowId],
  );
  const { state, retry } = useRequest(fetchWorkflow);

  if (state.status === 'loading') return <LoadingState />;
  if (state.status === 'error') {
    return (
      <>
        <ErrorState
          message={describeWorkflowError(state.error)}
          onRetry={retry}
        />
        <Link to="/workflows">← 내 워크플로로 돌아가기</Link>
      </>
    );
  }

  const workflow = state.data;
  return (
    <>
      <p>
        <Link to="/workflows">← 내 워크플로</Link>
      </p>
      <PageHeader
        title={workflow.title}
        description={`등록일 ${formatDateTime(workflow.createdAt)} · 최신 ${workflow.latestVersion?.versionLabel ?? '없음'}`}
      />
      <div className="stack">
        <VersionList workflowId={workflowId} />
        <NextVersionPanel />
        <SecurityCheckPanel
          versionLabel={workflow.latestVersion?.versionLabel}
        />
      </div>
    </>
  );
}
