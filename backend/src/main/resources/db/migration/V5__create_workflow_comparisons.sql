CREATE TABLE workflow_hub.workflow_comparisons (
    id uuid PRIMARY KEY,
    base_version_id uuid NOT NULL REFERENCES workflow_hub.workflow_versions (id),
    expires_at timestamptz NOT NULL,
    cleanup_after timestamptz NOT NULL
);

CREATE INDEX workflow_comparisons_cleanup_idx
    ON workflow_hub.workflow_comparisons (cleanup_after, id);
