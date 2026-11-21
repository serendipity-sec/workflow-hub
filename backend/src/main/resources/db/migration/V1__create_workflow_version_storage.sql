CREATE TABLE workflow_hub.workflows (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id text NOT NULL CONSTRAINT workflows_owner_id_nonblank CHECK (owner_id ~ '[^[:space:]]'),
    title text NOT NULL
);

CREATE TABLE workflow_hub.workflow_versions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id uuid NOT NULL,
    version text NOT NULL,
    s3_object_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT workflow_versions_workflow_fk
        FOREIGN KEY (workflow_id) REFERENCES workflow_hub.workflows (id),
    CONSTRAINT workflow_versions_workflow_id_version_key UNIQUE (workflow_id, version)
);
