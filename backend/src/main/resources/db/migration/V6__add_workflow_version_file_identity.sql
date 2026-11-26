-- 서버가 S3에 저장한 원본 바이트의 SHA-256(소문자 hex)과 크기(바이트).
-- 기존 버전은 값을 알 수 없으므로 NULL(미확인)로 두고, 해시와 크기는 함께 있거나 함께 없어야 한다.
ALTER TABLE workflow_hub.workflow_versions
    ADD COLUMN content_sha256 text,
    ADD COLUMN size_bytes bigint,
    ADD CONSTRAINT workflow_versions_content_sha256_format
        CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
    ADD CONSTRAINT workflow_versions_size_bytes_nonnegative
        CHECK (size_bytes >= 0),
    ADD CONSTRAINT workflow_versions_file_identity_complete
        CHECK ((content_sha256 IS NULL) = (size_bytes IS NULL));
