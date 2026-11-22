CREATE TABLE workflow_hub.idempotency_keys (
    owner_id text NOT NULL,
    idempotency_key text NOT NULL
        CONSTRAINT idempotency_keys_key_length CHECK (char_length(idempotency_key) BETWEEN 1 AND 255),
    request_fingerprint text NOT NULL,
    workflow_id uuid NOT NULL,
    version_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT idempotency_keys_pkey PRIMARY KEY (owner_id, idempotency_key),
    CONSTRAINT idempotency_keys_workflow_fk
        FOREIGN KEY (workflow_id) REFERENCES workflow_hub.workflows (id),
    CONSTRAINT idempotency_keys_version_fk
        FOREIGN KEY (version_id) REFERENCES workflow_hub.workflow_versions (id)
);
