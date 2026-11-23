-- S3에 쓰기 직전에 남기는 정리 대상 기록. 정상 커밋 때는 버전 INSERT와 같은 트랜잭션에서 지워지므로,
-- 남아 있는 행은 실패·커밋 결과 미확인·프로세스 중단으로 끝나지 않은 등록이다.
-- cleanup_after 전에는 진행 중인 요청일 수 있어 정리하지 않는다.
CREATE TABLE workflow_hub.pending_objects (
    object_key text PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    cleanup_after timestamptz NOT NULL,
    -- 정리 작업이 참조 없음을 확인하고 S3 삭제를 시작한 시각. 이 표시가 있으면 요청은 이 객체로 버전을 커밋하지 못한다.
    delete_started_at timestamptz
);

CREATE INDEX pending_objects_cleanup_idx
    ON workflow_hub.pending_objects (cleanup_after, object_key);

-- 정리 작업이 객체 키로 버전 참조를 확인한다.
CREATE INDEX workflow_versions_s3_object_key_idx
    ON workflow_hub.workflow_versions (s3_object_key);
