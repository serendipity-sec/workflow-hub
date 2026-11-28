-- 보안 검사 실행(scan_runs), 비동기 작업/시도(analysis_jobs, analysis_job_attempts),
-- 검사 요청 멱등성 키(scan_request_idempotency_keys) 저장 구조(#39, #57).
--
-- 4축 상태(execution_status, analysis_coverage, policy_*, publication_status)를 분리 저장한다.
-- 화면 구성에 필요한 요약·상태·오류는 DB에 두고, 대용량 serviceReport·assessment 원문은 비공개 S3에 저장한다.

CREATE TABLE workflow_hub.scan_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id uuid NOT NULL REFERENCES workflow_hub.workflows (id),
    workflow_version_id uuid NOT NULL REFERENCES workflow_hub.workflow_versions (id),
    input_sha256 text NOT NULL
        CONSTRAINT scan_runs_input_sha256_format CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL
        CONSTRAINT scan_runs_size_bytes_non_negative CHECK (size_bytes >= 0),

    -- 4축 상태 + LLM 보조 설명 상태
    execution_status text NOT NULL
        CONSTRAINT scan_runs_execution_status_valid
            CHECK (execution_status IN ('queued', 'running', 'completed', 'failed', 'timed_out', 'cancelled')),
    analysis_coverage text NOT NULL
        CONSTRAINT scan_runs_analysis_coverage_valid
            CHECK (analysis_coverage IN ('checked', 'partial', 'unsupported', 'unknown')),
    policy_evaluation_status text NOT NULL DEFAULT 'not_applicable'
        CONSTRAINT scan_runs_policy_eval_status_valid
            CHECK (policy_evaluation_status IN ('not_applicable', 'pending', 'completed', 'failed')),
    policy_decision text
        CONSTRAINT scan_runs_policy_decision_valid
            CHECK (policy_decision IS NULL OR policy_decision IN ('allow', 'review', 'block', 'inconclusive')),
    policy_advisory_decision text
        CONSTRAINT scan_runs_policy_advisory_decision_valid
            CHECK (policy_advisory_decision IS NULL OR policy_advisory_decision IN ('allow', 'review', 'block', 'inconclusive')),
    publication_status text NOT NULL DEFAULT 'private'
        CONSTRAINT scan_runs_publication_status_valid
            CHECK (publication_status IN ('private', 'submitted', 'published', 'withdrawn')),
    llm_status text NOT NULL DEFAULT 'not_requested'
        CONSTRAINT scan_runs_llm_status_valid
            CHECK (llm_status IN ('not_requested', 'generated', 'failed')),

    -- 결과 계약·엔진·규칙·어댑터 버전 (워커 결과 제출 시 기록)
    contract_version text,
    inspection_version text,
    assessment_version text,
    engine_version text,
    rules_version text,
    adapter_version text,

    -- 화면 기본 구성용 최소 요약 (completed 시 기록, S3 조회 없이 응답)
    summary_headline text,
    summary_analysis_status text
        CONSTRAINT scan_runs_summary_analysis_status_valid
            CHECK (summary_analysis_status IS NULL OR summary_analysis_status IN ('complete', 'review_required')),
    summary_finding_count integer,
    summary_high_risk_finding_count integer,
    summary_observation_count integer,
    summary_analysis_gap_count integer,
    summary_sink_reachable_gap_count integer,
    summary_environment_check_count integer,
    summary_security_review_required boolean,

    -- 비공개 S3 결과 객체 키 (브라우저에 직접 노출하지 않음)
    service_report_s3_key text,
    assessment_s3_key text,

    -- 실패·시간 초과 오류 정보
    error_code text,
    error_message text,
    error_retryable boolean,

    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    started_at timestamptz,
    finished_at timestamptz,

    CONSTRAINT scan_runs_result_keys_paired
        CHECK ((service_report_s3_key IS NULL) = (assessment_s3_key IS NULL)),
    CONSTRAINT scan_runs_result_keys_require_completed
        CHECK (execution_status = 'completed' OR (service_report_s3_key IS NULL AND assessment_s3_key IS NULL)),
    CONSTRAINT scan_runs_non_completed_coverage_unknown
        CHECK (execution_status = 'completed' OR analysis_coverage = 'unknown')
);

-- 같은 버전에 진행 중(queued/running) 검사는 최대 1건만 허용한다.
CREATE UNIQUE INDEX scan_runs_one_active_per_version_idx
    ON workflow_hub.scan_runs (workflow_version_id)
    WHERE execution_status IN ('queued', 'running');

-- 워크플로 삭제 시 진행 중 검사를 빠르게 취소하는 데 쓴다.
CREATE INDEX scan_runs_workflow_active_idx
    ON workflow_hub.scan_runs (workflow_id)
    WHERE execution_status IN ('queued', 'running');

-- 버전별 최신순 이력 커서 페이지네이션과 최신 단건 조회에 쓴다.
CREATE INDEX scan_runs_version_created_idx
    ON workflow_hub.scan_runs (workflow_version_id, created_at DESC, id DESC);

-- 정리 작업(pending_objects)이 결과 객체 참조를 확인할 때 쓴다.
CREATE INDEX scan_runs_service_report_s3_key_idx
    ON workflow_hub.scan_runs (service_report_s3_key)
    WHERE service_report_s3_key IS NOT NULL;

CREATE INDEX scan_runs_assessment_s3_key_idx
    ON workflow_hub.scan_runs (assessment_s3_key)
    WHERE assessment_s3_key IS NOT NULL;

CREATE TABLE workflow_hub.analysis_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_run_id uuid NOT NULL UNIQUE REFERENCES workflow_hub.scan_runs (id),
    workflow_version_id uuid NOT NULL REFERENCES workflow_hub.workflow_versions (id),
    input_sha256 text NOT NULL
        CONSTRAINT analysis_jobs_input_sha256_format CHECK (input_sha256 ~ '^[0-9a-f]{64}$'),
    size_bytes bigint NOT NULL
        CONSTRAINT analysis_jobs_size_bytes_non_negative CHECK (size_bytes >= 0),
    status text NOT NULL
        CONSTRAINT analysis_jobs_status_valid
            CHECK (status IN ('queued', 'running', 'completed', 'failed', 'timed_out', 'cancelled')),
    current_attempt_id uuid NOT NULL,
    attempt_number integer NOT NULL
        CONSTRAINT analysis_jobs_attempt_number_positive CHECK (attempt_number >= 1),
    max_attempts integer NOT NULL
        CONSTRAINT analysis_jobs_max_attempts_positive CHECK (max_attempts >= 1),
    lease_expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT analysis_jobs_attempt_within_max CHECK (attempt_number <= max_attempts)
);

-- 임대 만료 회수 스케줄러가 만료된 running 작업을 찾는 데 쓴다.
CREATE INDEX analysis_jobs_expired_lease_idx
    ON workflow_hub.analysis_jobs (lease_expires_at, id)
    WHERE status = 'running' AND lease_expires_at IS NOT NULL;

-- 미전달·DLQ 등으로 오래 queued에 머문 작업을 회수하는 데 쓴다.
CREATE INDEX analysis_jobs_stale_queued_idx
    ON workflow_hub.analysis_jobs (updated_at, id)
    WHERE status = 'queued';

CREATE INDEX analysis_jobs_version_active_idx
    ON workflow_hub.analysis_jobs (workflow_version_id)
    WHERE status IN ('queued', 'running');

CREATE TABLE workflow_hub.analysis_job_attempts (
    id uuid PRIMARY KEY,
    job_id uuid NOT NULL REFERENCES workflow_hub.analysis_jobs (id),
    attempt_number integer NOT NULL
        CONSTRAINT analysis_job_attempts_number_positive CHECK (attempt_number >= 1),
    status text NOT NULL
        CONSTRAINT analysis_job_attempts_status_valid
            CHECK (status IN ('queued', 'running', 'accepted', 'expired', 'cancelled')),
    started_at timestamptz,
    lease_expires_at timestamptz,
    finished_at timestamptz,
    result_idempotency_key text
        CONSTRAINT analysis_job_attempts_idempotency_format
            CHECK (result_idempotency_key IS NULL OR result_idempotency_key ~ '^[0-9a-f]{64}$'),
    accepted_execution_status text,
    accepted_analysis_coverage text,
    -- 마지막 SQS 발행 시도 시각과 발행 성공 확인 시각. 미확인 queued 시도는 회수기가 같은 attemptId로 다시 발행한다.
    dispatch_attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    dispatched_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT analysis_job_attempts_job_number_unique UNIQUE (job_id, attempt_number)
);

-- 발행이 확인되지 않은 queued 시도를 재발행할 때 쓴다.
CREATE INDEX analysis_job_attempts_undispatched_idx
    ON workflow_hub.analysis_job_attempts (dispatch_attempted_at, id)
    WHERE status = 'queued' AND dispatched_at IS NULL;

CREATE TABLE workflow_hub.scan_request_idempotency_keys (
    owner_id text NOT NULL,
    idempotency_key text NOT NULL
        CONSTRAINT scan_request_idempotency_key_length CHECK (char_length(idempotency_key) BETWEEN 1 AND 128),
    workflow_id uuid NOT NULL REFERENCES workflow_hub.workflows (id),
    workflow_version_id uuid NOT NULL REFERENCES workflow_hub.workflow_versions (id),
    scan_run_id uuid NOT NULL REFERENCES workflow_hub.scan_runs (id),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT scan_request_idempotency_keys_pkey PRIMARY KEY (owner_id, idempotency_key)
);

CREATE INDEX scan_request_idempotency_keys_scan_run_idx
    ON workflow_hub.scan_request_idempotency_keys (scan_run_id);
