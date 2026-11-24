import { useRef, useState } from 'react';
import type { ChangeEvent } from 'react';
import { ApiError } from '../../shared/api/client';
import type { LatestVersion } from '../../shared/api/client';
import { formatDateTime } from '../../shared/format';
import { Button } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Field } from '../../shared/ui/Field';
import { Icon } from '../../shared/ui/Icon';
import { compareVersion, registerVersion } from './api';
import { describeChanges, hasChanges } from './changeSummary';
import { describeWorkflowError } from './errorMessages';
import type { Comparison, UpdateType, VersionMetadata } from './types';
import { validateUploadFile } from './uploadValidation';
import './workflows.css';

type PanelError =
  | { kind: 'message'; text: string }
  /** 409: a newer version exists. `latest` is missing if the server did not say which. */
  | { kind: 'latest-changed'; latest?: LatestVersion }
  /** 404: the comparison result expired or is gone. */
  | { kind: 'expired' };

function toPanelError(error: unknown): PanelError {
  if (error instanceof ApiError) {
    if (error.code === 'LATEST_VERSION_CHANGED') {
      return { kind: 'latest-changed', latest: error.latestVersion };
    }
    if (error.code === 'COMPARISON_NOT_FOUND') return { kind: 'expired' };
  }
  return { kind: 'message', text: describeWorkflowError(error) };
}

const UPDATE_OPTIONS: { value: UpdateType; title: string; hint: string }[] = [
  {
    value: 'MINOR',
    title: '작은 수정',
    hint: '같은 계열 안에서 번호가 올라갑니다. 예: v1 → v1.1',
  },
  {
    value: 'MAJOR',
    title: '큰 수정',
    hint: '새 큰 번호가 시작됩니다. 예: v1.2 → v2',
  },
];

const SUMMARY_ITEMS: { key: keyof Comparison['summary']; label: string }[] = [
  { key: 'nodesAdded', label: '노드 추가' },
  { key: 'nodesRemoved', label: '노드 삭제' },
  { key: 'nodesModified', label: '노드 변경' },
  { key: 'connectionsAdded', label: '연결 추가' },
  { key: 'connectionsRemoved', label: '연결 삭제' },
];

/**
 * Compare a modified file with the newest version, then register it as the next
 * version. The server decides the version number; this screen only picks MINOR/MAJOR.
 */
export function VersionRegisterPanel({
  workflowId,
  latest,
  onRegistered,
}: {
  workflowId: string;
  latest: VersionMetadata | null;
  onRegistered: (versionLabel: string) => void;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [inputKey, setInputKey] = useState(0);
  const [baseVersionId, setBaseVersionId] = useState(latest?.versionId ?? '');
  const [comparison, setComparison] = useState<Comparison | null>(null);
  const [updateType, setUpdateType] = useState<UpdateType>('MINOR');
  const [busy, setBusy] = useState<'compare' | 'register' | null>(null);
  const [error, setError] = useState<PanelError | null>(null);
  // One key per (comparison, update type): retrying the same registration must not
  // create a duplicate version, while another choice is a different request.
  const registration = useRef<{ fingerprint: string; key: string } | null>(
    null,
  );

  function keyFor(comparisonId: string, type: UpdateType): string {
    const fingerprint = `${comparisonId}:${type}`;
    if (registration.current?.fingerprint !== fingerprint) {
      registration.current = { fingerprint, key: crypto.randomUUID() };
    }
    return registration.current.key;
  }

  function chooseFile(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] ?? null);
    setComparison(null);
    setError(null);
  }

  async function compare(versionId: string) {
    const invalid = validateUploadFile(file);
    if (invalid || !file) {
      setError({ kind: 'message', text: invalid ?? '' });
      return;
    }
    setBusy('compare');
    setError(null);
    setComparison(null);
    try {
      const result = await compareVersion(workflowId, versionId, file);
      setBaseVersionId(result.baseVersion.versionId);
      setComparison(result);
    } catch (compareError) {
      setError(toPanelError(compareError));
    } finally {
      setBusy(null);
    }
  }

  async function register() {
    if (!comparison) return;
    setBusy('register');
    setError(null);
    try {
      const result = await registerVersion({
        workflowId,
        comparisonId: comparison.comparisonId,
        updateType,
        idempotencyKey: keyFor(comparison.comparisonId, updateType),
      });
      setComparison(null);
      setFile(null);
      setInputKey((key) => key + 1);
      setBaseVersionId(result.versionId);
      onRegistered(result.versionLabel);
    } catch (registerError) {
      // The comparison is stale after 409/404; ask for a fresh one.
      const next = toPanelError(registerError);
      if (next.kind !== 'message') setComparison(null);
      setError(next);
    } finally {
      setBusy(null);
    }
  }

  if (!latest) {
    return (
      <Card aria-labelledby="register-heading">
        <h2 id="register-heading">새 버전 등록</h2>
        <p className="muted">비교할 기준 버전이 없습니다.</p>
      </Card>
    );
  }

  const rows = comparison ? describeChanges(comparison) : [];
  const idle = busy === null;

  return (
    <Card aria-labelledby="register-heading">
      <h2 id="register-heading">새 버전 등록</h2>
      <p className="muted">
        수정한 JSON을 최신 버전({latest.versionLabel})과 비교한 뒤, 작은
        수정이나 큰 수정으로 등록합니다. 번호는 서버가 매기며, 이전 버전은
        그대로 남습니다.
      </p>

      <div className="register-form">
        <Field label="수정한 워크플로 JSON">
          <input
            key={inputKey}
            type="file"
            accept=".json,application/json"
            disabled={!idle}
            onChange={chooseFile}
          />
        </Field>
        <div>
          <Button
            variant="secondary"
            disabled={!idle || !file}
            onClick={() => void compare(baseVersionId || latest.versionId)}
          >
            <Icon name="layers" size={16} />
            {busy === 'compare' ? '비교하는 중…' : '최신 버전과 비교'}
          </Button>
        </div>
      </div>

      {error?.kind === 'message' && error.text && (
        <p role="alert">{error.text}</p>
      )}
      {error?.kind === 'latest-changed' && (
        <div className="register-alert" role="alert">
          <p>
            그사이 더 새로운 버전
            {error.latest ? `(${error.latest.versionLabel})` : ''}이
            등록되었습니다. 이전 최신 버전 기준의 비교는 사용할 수 없습니다.
          </p>
          <Button
            variant="secondary"
            size="sm"
            disabled={!idle || !file}
            onClick={() =>
              void compare(error.latest?.versionId ?? latest.versionId)
            }
          >
            <Icon name="refresh" size={16} />
            {error.latest
              ? `${error.latest.versionLabel} 기준으로 다시 비교`
              : '다시 비교'}
          </Button>
        </div>
      )}
      {error?.kind === 'expired' && (
        <div className="register-alert" role="alert">
          <p>비교 결과가 없거나 만료되었습니다. 파일을 다시 비교해 주세요.</p>
          <Button
            variant="secondary"
            size="sm"
            disabled={!idle || !file}
            onClick={() => void compare(baseVersionId || latest.versionId)}
          >
            <Icon name="refresh" size={16} />
            다시 비교
          </Button>
        </div>
      )}

      {comparison && (
        <div className="register-result">
          <h3>{comparison.baseVersion.versionLabel}과(와) 비교한 결과</h3>
          <ul className="change-stats">
            {SUMMARY_ITEMS.map((item) => (
              <li key={item.key}>
                <strong>{comparison.summary[item.key]}</strong>
                <span className="muted">{item.label}</span>
              </li>
            ))}
          </ul>
          {hasChanges(comparison) ? (
            <ul className="change-list">
              {rows.map((row) => (
                <li key={row.key}>
                  <span className="change-kind">{row.kindLabel}</span>
                  <div>
                    <strong>{row.target}</strong>
                    {row.fields.map((field) => (
                      <p key={field} className="muted">
                        {field}
                      </p>
                    ))}
                  </div>
                </li>
              ))}
            </ul>
          ) : (
            <p className="muted">
              노드와 연결에 달라진 점이 없습니다. 그래도 새 버전으로 등록할 수
              있습니다.
            </p>
          )}
          <p className="muted">
            비교 결과는 {formatDateTime(comparison.expiresAt)}까지 등록에 쓸 수
            있습니다. 값이 민감할 수 있는 항목은 변경 사실만 표시합니다.
          </p>

          <fieldset className="update-type" disabled={!idle}>
            <legend>수정 종류</legend>
            {UPDATE_OPTIONS.map((option) => (
              <label key={option.value}>
                <input
                  type="radio"
                  name="update-type"
                  value={option.value}
                  checked={updateType === option.value}
                  onChange={() => setUpdateType(option.value)}
                />
                <span>
                  <strong>{option.title}</strong>
                  <span className="muted">{option.hint}</span>
                </span>
              </label>
            ))}
          </fieldset>
          <Button disabled={!idle} onClick={() => void register()}>
            <Icon name="upload" size={16} />
            {busy === 'register' ? '등록하는 중…' : '새 버전으로 등록'}
          </Button>
        </div>
      )}
    </Card>
  );
}
