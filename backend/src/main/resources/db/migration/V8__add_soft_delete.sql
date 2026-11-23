-- 버전·워크플로 삭제(#37). 삭제는 행을 지우지 않고 표시만 하며, 버전 번호는 삭제 뒤에도 재사용하지 않는다.
--
-- 버전 상태
--   살아 있음  : deleted_at IS NULL
--   삭제됨     : deleted_at 있음, delete_started_at 없음. delete_after 전까지 소유자가 복구할 수 있다.
--   정리 중    : delete_started_at 있음, purged_at 없음. S3 삭제를 시작했으므로 복구할 수 없고, 실패하면 다시 시도한다.
--   정리 완료  : purged_at 있음. 원본을 지우고 객체 키·해시·크기를 비운다. 번호와 삭제 시각만 남는다.
ALTER TABLE workflow_hub.workflows
    ADD COLUMN deleted_at timestamptz,
    -- 모든 버전의 원본이 정리되면 제목도 비운다.
    ALTER COLUMN title DROP NOT NULL;

ALTER TABLE workflow_hub.workflow_versions
    ADD COLUMN deleted_at timestamptz,
    ADD COLUMN delete_after timestamptz,
    ADD COLUMN delete_started_at timestamptz,
    ADD COLUMN purged_at timestamptz,
    ALTER COLUMN s3_object_key DROP NOT NULL,
    ADD CONSTRAINT workflow_versions_delete_window_complete
        CHECK ((deleted_at IS NULL) = (delete_after IS NULL)),
    ADD CONSTRAINT workflow_versions_purge_requires_delete
        CHECK ((delete_started_at IS NULL AND purged_at IS NULL) OR deleted_at IS NOT NULL),
    -- 정리가 끝난 행에는 원본을 가리키는 값이 남지 않아야 하고, 끝나지 않은 행에는 키가 있어야 한다.
    ADD CONSTRAINT workflow_versions_purged_clears_file
        CHECK ((purged_at IS NULL AND s3_object_key IS NOT NULL)
            OR (purged_at IS NOT NULL AND s3_object_key IS NULL
                AND content_sha256 IS NULL AND size_bytes IS NULL));

-- 정리 작업이 기한이 지난 행을 찾는 데 쓴다.
CREATE INDEX workflow_versions_purge_idx
    ON workflow_hub.workflow_versions (delete_after, id)
    WHERE deleted_at IS NOT NULL AND purged_at IS NULL;
