ALTER TABLE workflow_hub.workflows ADD COLUMN created_at timestamptz;

-- 최초 업로드에서 함께 생성한 v1의 시각을 보존한다. v1이 없는 기존 행은 이관을 실패시킨다.
UPDATE workflow_hub.workflows w
SET created_at = v.created_at
FROM workflow_hub.workflow_versions v
WHERE v.workflow_id = w.id AND v.version = 'v1';

ALTER TABLE workflow_hub.workflows
    ALTER COLUMN created_at SET DEFAULT CURRENT_TIMESTAMP,
    ALTER COLUMN created_at SET NOT NULL;

CREATE INDEX workflows_owner_created_at_id_idx
    ON workflow_hub.workflows (owner_id, created_at DESC, id DESC);

CREATE INDEX workflow_versions_workflow_created_at_id_idx
    ON workflow_hub.workflow_versions (workflow_id, created_at DESC, id DESC);
