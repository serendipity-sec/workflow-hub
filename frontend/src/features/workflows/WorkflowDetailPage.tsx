import { useCallback, useState } from 'react';
import { useNavigate, useParams } from 'react-router';
import { useRequest } from '../../shared/api/useRequest';
import { formatDateTime } from '../../shared/format';
import { Button, ButtonLink } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Icon } from '../../shared/ui/Icon';
import { PageHeader } from '../../shared/ui/PageHeader';
import { ErrorState, LoadingState } from '../../shared/ui/PageStates';
import { Tag } from '../../shared/ui/Tag';
import { SecurityCheckPanel } from '../security/SecurityCheckPanel';
import { deleteWorkflow, getWorkflow } from './api';
import { deletionNotice, isStaleError } from './deletion';
import { describeWorkflowError } from './errorMessages';
import { FileIdentity } from './FileIdentity';
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
  const navigate = useNavigate();
  const [notice, setNotice] = useState('');
  const [versionsKey, setVersionsKey] = useState(0);
  const [confirmingDelete, setConfirmingDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  // One action at a time on this page: a version action in the list, a
  // comparison or registration in the panel, or deleting the workflow.
  const [versionBusy, setVersionBusy] = useState(false);
  const [panelBusy, setPanelBusy] = useState(false);
  const blocked = deleting || versionBusy || panelBusy;

  function toggleDeleteConfirm(open: boolean) {
    setDeleteError('');
    setConfirmingDelete(open);
  }

  // Both return the detail reload, so the caller keeps its lock until the page
  // shows the new latest version. Otherwise a comparison started in between
  // would be lost when the panel is replaced for the new latest version.
  function registered(versionLabel: string): Promise<void> {
    setNotice(`${versionLabel}을(를) 새 버전으로 등록했습니다.`);
    setVersionsKey((key) => key + 1);
    return refresh();
  }

  /** A version was deleted, restored or its downloads changed; the latest may differ now. */
  function versionChanged(message: string): Promise<void> {
    setNotice(message);
    return refresh();
  }

  /** The workflow no longer exists for normal views, so go back to the list. */
  function leave(message: string) {
    void navigate('/workflows', { state: { notice: message } });
  }

  async function removeWorkflow() {
    setDeleting(true);
    setDeleteError('');
    try {
      leave(deletionNotice(await deleteWorkflow(workflowId), null));
    } catch (error) {
      setDeleteError(describeWorkflowError(error));
      setDeleting(false);
      // Already deleted elsewhere: show the server's state instead of stale data.
      if (isStaleError(error)) void refresh();
    }
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
        actions={
          <Button
            variant="secondary"
            disabled={blocked}
            aria-expanded={confirmingDelete}
            onClick={() => toggleDeleteConfirm(!confirmingDelete)}
          >
            워크플로 삭제
          </Button>
        }
      />
      {confirmingDelete && (
        <div
          className="confirm-box page-confirm"
          role="group"
          aria-label="워크플로 삭제 확인"
        >
          <p className="confirm-warning">
            이 워크플로와 남아 있는 모든 버전을 삭제합니다.
          </p>
          <p>
            삭제하면 바로 목록·다운로드·비교에서 빠집니다. 복구 기한 안에는 내
            워크플로의 &apos;삭제된 항목 보기&apos;에서 되살릴 수 있습니다.
          </p>
          <div className="confirm-actions">
            <Button
              size="sm"
              disabled={blocked}
              onClick={() => void removeWorkflow()}
            >
              {deleting ? '삭제하는 중…' : '워크플로 삭제'}
            </Button>
            <Button
              variant="ghost"
              size="sm"
              disabled={deleting}
              onClick={() => toggleDeleteConfirm(false)}
            >
              취소
            </Button>
          </div>
          {deleteError && <p role="alert">{deleteError}</p>}
        </div>
      )}
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
            {latest && (
              <FileIdentity
                name={`최신 버전 ${latest.versionLabel}`}
                sha256={latest.sha256}
                sizeBytes={latest.sizeBytes}
              />
            )}
            {latest && !latest.downloadEnabled && (
              <Tag tone="outline" className="latest-tag">
                다운로드 중지
              </Tag>
            )}
          </Card>
          <VersionList
            workflowId={workflowId}
            reloadSignal={versionsKey}
            locked={deleting || panelBusy}
            onBusyChange={setVersionBusy}
            onChanged={versionChanged}
            onStale={refresh}
            onWorkflowDeleted={leave}
          />
        </div>
        <div className="stack">
          <VersionRegisterPanel
            key={latest?.versionId ?? 'none'}
            workflowId={workflowId}
            latest={latest}
            // panelBusy too: a refresh can swap in a new panel while the old
            // one's request is still running, and the new panel must wait for it.
            locked={deleting || versionBusy || panelBusy}
            onBusyChange={setPanelBusy}
            onRegistered={registered}
          />
          <SecurityCheckPanel versionLabel={latest?.versionLabel} />
        </div>
      </div>
    </>
  );
}
