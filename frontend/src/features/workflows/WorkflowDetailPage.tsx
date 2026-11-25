import { useCallback, useState } from 'react';
import { useParams } from 'react-router';
import { useRequest } from '../../shared/api/useRequest';
import { formatDateTime } from '../../shared/format';
import { ButtonLink } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import { PageHeader } from '../../shared/ui/PageHeader';
import { ErrorState, LoadingState } from '../../shared/ui/PageStates';
import { SecurityCheckPanel } from '../security/SecurityCheckPanel';
import { getWorkflow } from './api';
import { describeWorkflowError } from './errorMessages';
import { VersionList } from './VersionList';
import { VersionRegisterPanel } from './VersionRegisterPanel';
import './workflows.css';

/** Route entry. The key remounts the content when the URL points to another workflow. */
export function WorkflowDetailPage() {
  const { workflowId } = useParams();
  if (!workflowId) return null;
  return <WorkflowDetail key={workflowId} workflowId={workflowId} />;
}

function BackLink() {
  return (
    <ButtonLink to="/workflows" variant="ghost" size="sm" className="back-link">
      <Icon name="arrow-left" size={16} />내 워크플로
    </ButtonLink>
  );
}

function WorkflowDetail({ workflowId }: { workflowId: string }) {
  const fetchWorkflow = useCallback(
    () => getWorkflow(workflowId),
    [workflowId],
  );
  const { state, retry, refresh } = useRequest(fetchWorkflow);
  const [notice, setNotice] = useState('');
  const [versionsKey, setVersionsKey] = useState(0);

  function registered(versionLabel: string) {
    setNotice(`${versionLabel}을(를) 새 버전으로 등록했습니다.`);
    setVersionsKey((key) => key + 1);
    refresh();
  }

  if (state.status === 'loading') return <LoadingState />;
  if (state.status === 'error') {
    return (
      <>
        <BackLink />
        <ErrorState
          message={describeWorkflowError(state.error)}
          onRetry={retry}
        />
      </>
    );
  }

  const workflow = state.data;
  const latest = workflow.latestVersion;
  return (
    <>
      <BackLink />
      <PageHeader
        eyebrow="워크플로"
        title={workflow.title}
        description={`등록일 ${formatDateTime(workflow.createdAt)}`}
      />
      <div aria-live="polite">
        {notice && <p className="flash">{notice}</p>}
      </div>
      <div className="detail-grid">
        <div className="stack">
          <Card tone="dark" className="latest-card">
            <p className="latest-label">최신 버전</p>
            <p className="latest-version">{latest?.versionLabel ?? '없음'}</p>
            {latest && (
              <p className="muted">{formatDateTime(latest.createdAt)} 등록</p>
            )}
          </Card>
          <VersionList key={versionsKey} workflowId={workflowId} />
        </div>
        <div className="stack">
          <VersionRegisterPanel
            key={latest?.versionId ?? 'none'}
            workflowId={workflowId}
            latest={latest}
            onRegistered={registered}
          />
          <SecurityCheckPanel versionLabel={latest?.versionLabel} />
        </div>
      </div>
    </>
  );
}
