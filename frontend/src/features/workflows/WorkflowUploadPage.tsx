import { useRef, useState } from 'react';
import type { ChangeEvent, FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { Button } from '../../shared/ui/Button';
import { Card } from '../../shared/ui/Card';
import { Field } from '../../shared/ui/Field';
import { Icon } from '../../shared/ui/Icon';
import { PageHeader } from '../../shared/ui/PageHeader';
import { uploadWorkflow } from './api';
import { describeWorkflowError } from './errorMessages';
import {
  MAX_TITLE_LENGTH,
  UPLOAD_NOTICE,
  validateTitle,
  validateUploadFile,
} from './uploadValidation';
import './workflows.css';

export function WorkflowUploadPage() {
  const navigate = useNavigate();
  const [title, setTitle] = useState('');
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  // One key per distinct input: a retry of the same upload must not create a duplicate.
  const idempotencyKey = useRef(crypto.randomUUID());

  function changeTitle(event: ChangeEvent<HTMLInputElement>) {
    setTitle(event.target.value);
    idempotencyKey.current = crypto.randomUUID();
    setError('');
  }

  function changeFile(event: ChangeEvent<HTMLInputElement>) {
    setFile(event.target.files?.[0] ?? null);
    idempotencyKey.current = crypto.randomUUID();
    setError('');
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    const invalid = validateTitle(title.trim()) ?? validateUploadFile(file);
    if (invalid || !file) {
      setError(invalid ?? '');
      return;
    }
    setSubmitting(true);
    setError('');
    try {
      const result = await uploadWorkflow({
        title: title.trim(),
        file,
        idempotencyKey: idempotencyKey.current,
      });
      void navigate(`/workflows/${result.workflowId}`);
    } catch (uploadError) {
      setError(describeWorkflowError(uploadError));
      setSubmitting(false);
    }
  }

  return (
    <>
      <PageHeader
        eyebrow="새 워크플로"
        title="워크플로 등록"
        description="n8n 편집기에서 내보낸 JSON 파일 하나를 올리면 v1로 등록됩니다."
      />
      <Card>
        <form className="upload-form" onSubmit={(event) => void submit(event)}>
          <Field label="제목">
            <input
              type="text"
              value={title}
              maxLength={MAX_TITLE_LENGTH}
              placeholder="비워 두면 워크플로 JSON의 이름을 사용합니다"
              onChange={changeTitle}
            />
          </Field>
          <Field label="워크플로 JSON 파일">
            <input
              type="file"
              accept=".json,application/json"
              onChange={changeFile}
            />
          </Field>
          <p className="muted upload-notice">
            <Icon name="lock" size={16} />
            {UPLOAD_NOTICE}
          </p>
          {error && <p role="alert">{error}</p>}
          <div>
            <Button type="submit" disabled={submitting}>
              <Icon name="upload" size={16} />
              {submitting ? '등록하는 중…' : '등록'}
            </Button>
          </div>
        </form>
      </Card>
    </>
  );
}
