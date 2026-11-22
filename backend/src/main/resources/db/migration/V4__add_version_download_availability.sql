ALTER TABLE workflow_hub.workflow_versions
    ADD COLUMN download_enabled BOOLEAN NOT NULL DEFAULT TRUE;
