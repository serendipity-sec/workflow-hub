package dev.workflowhub.analysis.service;

import dev.workflowhub.analysis.queue.ScanTaskMessage;
import dev.workflowhub.analysis.service.ScanModels.HeartbeatResult;
import dev.workflowhub.analysis.service.ScanModels.ResultSubmission;
import dev.workflowhub.analysis.service.ScanModels.ScanSummary;
import dev.workflowhub.analysis.service.ScanModels.ScanVersions;
import dev.workflowhub.analysis.service.ScanModels.WorkerFileDownload;
import dev.workflowhub.common.storage.PendingObjectRegistry;
import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * 워커 전용 내부 API(/internal/worker/v1/**) 처리 서비스(#39, #57).
 *
 * <p>원본 다운로드 시 queued -> running 전환과 60초 lease를 발급하고, heartbeat로 lease를 연장하며, 결과 제출 시
 * 멱등성·시도·임대·버전·해시 일치를 검증한 뒤 serviceReport와 assessment 원문을 비공개 S3에 저장한다.
 */
@Service
public class WorkerTaskService {
  private static final Logger log = LoggerFactory.getLogger(WorkerTaskService.class);
  private static final Pattern HEX_SHA256 = Pattern.compile("^[0-9a-f]{64}$");
  private static final Pattern ERROR_CODE_PATTERN = Pattern.compile("^[a-z][a-z0-9_]{0,79}$");
  private static final Set<String> ALLOWED_OUTCOMES = Set.of("completed", "failed", "timed_out");
  private static final Set<String> ALLOWED_INSPECTION_VERSIONS = Set.of("1.1.0");
  private static final Set<String> ALLOWED_ASSESSMENT_STATUSES =
      Set.of("analyzed", "partial", "unsupported");
  private static final Set<String> ALLOWED_DECISIONS =
      Set.of("allow", "review", "block", "inconclusive");
  private static final Set<String> ALLOWED_REPORT_EXECUTION_STATUSES =
      Set.of("completed", "completed_with_errors");
  private static final Set<String> ALLOWED_ANALYSIS_STATUSES =
      Set.of("complete", "review_required");
  private static final Set<String> NON_RETRYABLE_ERROR_CODES =
      Set.of(
          "hash_mismatch",
          "file_too_large",
          "invalid_utf8",
          "invalid_json",
          "duplicate_key",
          "depth_limit",
          "graph_limit",
          "invalid_workflow",
          "identity_collision",
          "broken_connection",
          "assessment_output_limit",
          "invalid_configuration",
          "cancelled",
          "assessment_timeout");

  private static final Map<String, String> SAFE_ERROR_MESSAGES =
      Map.ofEntries(
          Map.entry(
              "hash_mismatch",
              "Downloaded workflow bytes did not match the recorded version SHA-256"),
          Map.entry("file_too_large", "Workflow file exceeded the worker size limit"),
          Map.entry("invalid_utf8", "Workflow file is not valid UTF-8"),
          Map.entry("invalid_json", "Workflow file is not valid JSON"),
          Map.entry("duplicate_key", "Workflow JSON contains duplicate object keys"),
          Map.entry("depth_limit", "Workflow JSON exceeded the worker nesting depth limit"),
          Map.entry("graph_limit", "Workflow JSON exceeded the worker node or connection limit"),
          Map.entry("invalid_workflow", "Workflow structure could not be parsed by the worker"),
          Map.entry("identity_collision", "Workflow nodes contain conflicting identifiers"),
          Map.entry("broken_connection", "Workflow contains invalid node connections"),
          Map.entry("assessment_timeout", "Security scan exceeded the allowed execution time"),
          Map.entry("assessment_output_limit", "Security scan output exceeded the size limit"),
          Map.entry("sandbox_unavailable", "Security scan sandbox was temporarily unavailable"),
          Map.entry("sandbox_failed", "Security scan sandbox execution failed"),
          Map.entry("file_access", "Worker could not fetch the workflow file"),
          Map.entry("invalid_configuration", "Worker configuration error"),
          Map.entry("cancelled", "Security scan was cancelled"));

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final WorkflowObjectStore store;
  private final PendingObjectRegistry cleanup;
  private final ScanTaskDispatcher dispatcher;
  private final JsonMapper mapper;
  private final Duration leaseDuration;
  private final long maxResultBytes;

  public WorkerTaskService(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      WorkflowObjectStore store,
      PendingObjectRegistry cleanup,
      ScanTaskDispatcher dispatcher,
      JsonMapper mapper,
      @Value("${app.analysis.lease-duration}") Duration leaseDuration,
      @Value("${app.analysis.max-result-bytes}") long maxResultBytes) {
    if (leaseDuration.isZero() || leaseDuration.isNegative()) {
      throw new IllegalArgumentException("SCAN_LEASE_DURATION must be positive");
    }
    if (maxResultBytes <= 0) {
      throw new IllegalArgumentException("SCAN_MAX_RESULT_BYTES must be positive");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.store = store;
    this.cleanup = cleanup;
    this.dispatcher = dispatcher;
    this.mapper = mapper;
    this.leaseDuration = leaseDuration;
    this.maxResultBytes = maxResultBytes;
  }

  public long maxResultBytes() {
    return maxResultBytes;
  }

  public WorkerFileDownload fetchFile(String taskIdRaw, String attemptIdRaw) {
    UUID taskId = ScanService.parseId(taskIdRaw, ScanException::taskAttemptNotFound);
    UUID attemptId = ScanService.parseId(attemptIdRaw, ScanException::taskAttemptNotFound);

    // S3 읽기를 DB 잠금 밖에서 수행하기 위해 먼저 실행 가능 상태를 확인한다.
    TaskAttemptRow preCheck =
        readTaskAttempt(taskId, attemptId).orElseThrow(ScanException::taskAttemptNotFound);
    requireQueuedAndRunnable(preCheck);
    if (preCheck.versionObjectKey() == null) {
      throw ScanException.taskCancelled();
    }

    byte[] content;
    try {
      content = store.get(preCheck.versionObjectKey());
    } catch (RuntimeException e) {
      log.error(
          "event=analysis.worker.file_read_failed taskId={} attemptId={} objectKey={}",
          taskId,
          attemptId,
          preCheck.versionObjectKey(),
          e);
      throw ScanException.storageUnavailable();
    }

    OffsetDateTime leaseExpiresAt =
        transactions.execute(
            status -> {
              TaskAttemptRow locked =
                  lockTaskAttempt(taskId, attemptId)
                      .orElseThrow(ScanException::taskAttemptNotFound);
              requireQueuedAndRunnable(locked);
              OffsetDateTime now = databaseNow();
              OffsetDateTime expires = now.plus(leaseDuration);
              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_jobs
                      SET status = 'running', lease_expires_at = :expires, updated_at = :now
                      WHERE id = :taskId
                      """)
                  .param("expires", expires)
                  .param("now", now)
                  .param("taskId", taskId)
                  .update();
              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_job_attempts
                      SET status = 'running', started_at = :now, lease_expires_at = :expires
                      WHERE id = :attemptId
                      """)
                  .param("now", now)
                  .param("expires", expires)
                  .param("attemptId", attemptId)
                  .update();
              jdbc.sql(
                      """
                      UPDATE workflow_hub.scan_runs
                      SET execution_status = 'running', started_at = coalesce(started_at, :now)
                      WHERE id = :scanRunId
                      """)
                  .param("now", now)
                  .param("scanRunId", locked.scanRunId())
                  .update();
              return expires;
            });

    log.info(
        "event=analysis.worker.file_served taskId={} attemptId={} scanRunId={} leaseExpiresAt={}",
        taskId,
        attemptId,
        preCheck.scanRunId(),
        leaseExpiresAt.toInstant());
    return new WorkerFileDownload(content, preCheck.inputSha256(), leaseExpiresAt.toInstant());
  }

  public HeartbeatResult heartbeat(String taskIdRaw, String attemptIdRaw) {
    UUID taskId = ScanService.parseId(taskIdRaw, ScanException::taskAttemptNotFound);
    UUID attemptId = ScanService.parseId(attemptIdRaw, ScanException::taskAttemptNotFound);

    OffsetDateTime leaseExpiresAt =
        transactions.execute(
            status -> {
              TaskAttemptRow locked =
                  lockTaskAttempt(taskId, attemptId)
                      .orElseThrow(ScanException::taskAttemptNotFound);
              requireRunningAndLeaseValid(locked);
              OffsetDateTime now = databaseNow();
              OffsetDateTime extended = now.plus(leaseDuration);
              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_jobs
                      SET lease_expires_at = :expires, updated_at = :now
                      WHERE id = :taskId
                      """)
                  .param("expires", extended)
                  .param("now", now)
                  .param("taskId", taskId)
                  .update();
              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_job_attempts
                      SET lease_expires_at = :expires
                      WHERE id = :attemptId
                      """)
                  .param("expires", extended)
                  .param("attemptId", attemptId)
                  .update();
              return extended;
            });

    log.info(
        "event=analysis.worker.heartbeat taskId={} attemptId={} leaseExpiresAt={}",
        taskId,
        attemptId,
        leaseExpiresAt.toInstant());
    return new HeartbeatResult(taskId, attemptId, leaseExpiresAt.toInstant());
  }

  public ResultSubmission submitResult(
      String taskIdRaw, String attemptIdRaw, String idempotencyKey, byte[] rawBody) {
    UUID taskId = ScanService.parseId(taskIdRaw, ScanException::taskAttemptNotFound);
    UUID attemptId = ScanService.parseId(attemptIdRaw, ScanException::taskAttemptNotFound);

    validateWorkerIdempotencyKey(idempotencyKey, rawBody);
    ParsedResult payload = parseAndValidateResult(taskId, attemptId, rawBody);

    TaskAttemptRow preCheck =
        readTaskAttempt(taskId, attemptId).orElseThrow(ScanException::taskAttemptNotFound);
    ResultSubmission replayed = checkAcceptedReplay(preCheck, idempotencyKey);
    if (replayed != null) {
      return replayed;
    }
    requireRunningAndLeaseValid(preCheck);
    verifyResultIdentity(preCheck, payload);

    if ("completed".equals(payload.outcome())) {
      return persistCompletedResult(preCheck, payload, idempotencyKey);
    }
    return persistFailureOrTimeoutResult(taskId, attemptId, payload, idempotencyKey);
  }

  private ResultSubmission persistCompletedResult(
      TaskAttemptRow preCheck, ParsedResult payload, String idempotencyKey) {
    UUID uploadId = UUID.randomUUID();
    String prefix =
        "scan-results/"
            + preCheck.workflowId()
            + "/"
            + preCheck.workflowVersionId()
            + "/"
            + preCheck.scanRunId()
            + "/"
            + uploadId;
    String serviceReportKey = prefix + "/service-report.json";
    String assessmentKey = prefix + "/assessment.json";

    byte[] serviceReportBytes =
        mapper.writeValueAsString(payload.serviceReportNode()).getBytes(StandardCharsets.UTF_8);
    byte[] assessmentBytes =
        mapper.writeValueAsString(payload.assessmentNode()).getBytes(StandardCharsets.UTF_8);

    cleanup.recordPendingObject(serviceReportKey);
    cleanup.recordPendingObject(assessmentKey);

    boolean reportPut = false;
    boolean assessmentPut = false;
    try {
      store.put(serviceReportKey, serviceReportBytes);
      reportPut = true;
      store.put(assessmentKey, assessmentBytes);
      assessmentPut = true;
    } catch (RuntimeException e) {
      log.error(
          "event=analysis.worker.result_upload_failed taskId={} attemptId={} scanRunId={}",
          preCheck.taskId(),
          preCheck.attemptId(),
          preCheck.scanRunId(),
          e);
      if (reportPut) {
        cleanup.discardPendingObject(serviceReportKey);
      }
      if (assessmentPut) {
        cleanup.discardPendingObject(assessmentKey);
      }
      throw ScanException.storageUnavailable();
    }

    boolean[] bodyFinished = {false};
    try {
      ResultSubmission submission =
          transactions.execute(
              status -> {
                TaskAttemptRow locked =
                    lockTaskAttempt(preCheck.taskId(), preCheck.attemptId())
                        .orElseThrow(ScanException::taskAttemptNotFound);
                ResultSubmission replay = checkAcceptedReplay(locked, idempotencyKey);
                if (replay != null) {
                  bodyFinished[0] = true;
                  return replay;
                }
                requireRunningAndLeaseValid(locked);
                verifyResultIdentity(locked, payload);

                if (!cleanup.releasePendingObject(serviceReportKey)
                    || !cleanup.releasePendingObject(assessmentKey)) {
                  throw ScanException.storageUnavailable();
                }

                OffsetDateTime now = databaseNow();
                ScanVersions v = payload.versions();
                ScanSummary s = payload.summary();
                jdbc.sql(
                        """
                        UPDATE workflow_hub.scan_runs
                        SET execution_status = 'completed',
                            analysis_coverage = :coverage,
                            policy_advisory_decision = :advisoryDecision,
                            contract_version = :contractVersion,
                            inspection_version = :inspectionVersion,
                            assessment_version = :assessmentVersion,
                            engine_version = :engineVersion,
                            rules_version = :rulesVersion,
                            adapter_version = :adapterVersion,
                            summary_headline = :headline,
                            summary_analysis_status = :analysisStatus,
                            summary_finding_count = :findingCount,
                            summary_high_risk_finding_count = :highRiskFindingCount,
                            summary_observation_count = :observationCount,
                            summary_analysis_gap_count = :analysisGapCount,
                            summary_sink_reachable_gap_count = :sinkReachableGapCount,
                            summary_environment_check_count = :environmentCheckCount,
                            summary_security_review_required = :securityReviewRequired,
                            service_report_s3_key = :serviceReportKey,
                            assessment_s3_key = :assessmentKey,
                            error_code = NULL,
                            error_message = NULL,
                            error_retryable = NULL,
                            finished_at = :now
                        WHERE id = :scanRunId
                        """)
                    .param("coverage", payload.analysisCoverage())
                    .param("advisoryDecision", payload.advisoryDecision())
                    .param("contractVersion", v.contractVersion())
                    .param("inspectionVersion", v.inspectionVersion())
                    .param("assessmentVersion", v.assessmentVersion())
                    .param("engineVersion", v.engineVersion())
                    .param("rulesVersion", v.rulesVersion())
                    .param("adapterVersion", v.adapterVersion())
                    .param("headline", s.headline())
                    .param("analysisStatus", s.analysisStatus())
                    .param("findingCount", s.findingCount())
                    .param("highRiskFindingCount", s.highRiskFindingCount())
                    .param("observationCount", s.observationCount())
                    .param("analysisGapCount", s.analysisGapCount())
                    .param("sinkReachableGapCount", s.sinkReachableGapCount())
                    .param("environmentCheckCount", s.environmentCheckCount())
                    .param("securityReviewRequired", s.securityReviewRequired())
                    .param("serviceReportKey", serviceReportKey)
                    .param("assessmentKey", assessmentKey)
                    .param("now", now)
                    .param("scanRunId", locked.scanRunId())
                    .update();

                jdbc.sql(
                        """
                        UPDATE workflow_hub.analysis_jobs
                        SET status = 'completed', lease_expires_at = NULL, updated_at = :now
                        WHERE id = :taskId
                        """)
                    .param("now", now)
                    .param("taskId", locked.taskId())
                    .update();

                jdbc.sql(
                        """
                        UPDATE workflow_hub.analysis_job_attempts
                        SET status = 'accepted',
                            lease_expires_at = NULL,
                            finished_at = :now,
                            result_idempotency_key = :idempotencyKey,
                            accepted_execution_status = 'completed',
                            accepted_analysis_coverage = :coverage
                        WHERE id = :attemptId
                        """)
                    .param("now", now)
                    .param("idempotencyKey", idempotencyKey)
                    .param("coverage", payload.analysisCoverage())
                    .param("attemptId", locked.attemptId())
                    .update();

                bodyFinished[0] = true;
                return new ResultSubmission(
                    true, locked.scanRunId(), "completed", payload.analysisCoverage());
              });
      if (!submission.created()) {
        // 동시 재전송이 먼저 커밋됐으므로 방금 올린 미참조 객체는 즉시 정리한다.
        cleanup.discardPendingObject(serviceReportKey);
        cleanup.discardPendingObject(assessmentKey);
      } else {
        log.info(
            "event=analysis.worker.result_completed taskId={} attemptId={} scanRunId={} coverage={}",
            preCheck.taskId(),
            preCheck.attemptId(),
            submission.scanRunId(),
            submission.analysisCoverage());
      }
      return submission;
    } catch (RuntimeException e) {
      if (!bodyFinished[0]) {
        // 트랜잭션 본문에서 실패해 롤백이 확실하므로 미참조 객체를 즉시 정리한다.
        cleanup.discardPendingObject(serviceReportKey);
        cleanup.discardPendingObject(assessmentKey);
        throw e;
      }
      if (Boolean.TRUE.equals(isResultCommitted(preCheck.scanRunId(), serviceReportKey))) {
        log.warn(
            "event=analysis.worker.result_commit_confirmed taskId={} attemptId={} scanRunId={}",
            preCheck.taskId(),
            preCheck.attemptId(),
            preCheck.scanRunId());
        return new ResultSubmission(
            true, preCheck.scanRunId(), "completed", payload.analysisCoverage());
      }
      // 커밋 결과 미확인 상태에서는 객체를 보존하고 pending_objects 정리 작업이 참조 여부를 확인하게 둔다.
      log.error(
          "event=analysis.worker.result_commit_unknown taskId={} attemptId={} scanRunId={} serviceReportKey={} assessmentKey={}",
          preCheck.taskId(),
          preCheck.attemptId(),
          preCheck.scanRunId(),
          serviceReportKey,
          assessmentKey,
          e);
      throw e;
    }
  }

  private Boolean isResultCommitted(UUID scanRunId, String serviceReportKey) {
    try {
      return jdbc.sql(
              "SELECT EXISTS (SELECT 1 FROM workflow_hub.scan_runs WHERE id = :id AND service_report_s3_key = :key)")
          .param("id", scanRunId)
          .param("key", serviceReportKey)
          .query(Boolean.class)
          .single();
    } catch (RuntimeException e) {
      log.error("event=analysis.worker.commit_check_failed scanRunId={}", scanRunId, e);
      return null;
    }
  }

  private ResultSubmission persistFailureOrTimeoutResult(
      UUID taskId, UUID attemptId, ParsedResult payload, String idempotencyKey) {
    FailureTransition transition =
        transactions.execute(
            status -> {
              TaskAttemptRow locked =
                  lockTaskAttempt(taskId, attemptId)
                      .orElseThrow(ScanException::taskAttemptNotFound);
              ResultSubmission replay = checkAcceptedReplay(locked, idempotencyKey);
              if (replay != null) {
                return new FailureTransition(replay, null);
              }
              requireRunningAndLeaseValid(locked);
              verifyResultIdentity(locked, payload);

              OffsetDateTime now = databaseNow();
              ScanVersions v = payload.versions();
              boolean shouldRetry =
                  "failed".equals(payload.outcome())
                      && payload.errorRetryable()
                      && !NON_RETRYABLE_ERROR_CODES.contains(payload.errorCode())
                      && locked.attemptNumber() < locked.maxAttempts();

              if (shouldRetry) {
                UUID nextAttemptId = UUID.randomUUID();
                int nextAttemptNumber = locked.attemptNumber() + 1;

                jdbc.sql(
                        """
                        UPDATE workflow_hub.analysis_job_attempts
                        SET status = 'accepted',
                            lease_expires_at = NULL,
                            finished_at = :now,
                            result_idempotency_key = :idempotencyKey,
                            accepted_execution_status = 'queued',
                            accepted_analysis_coverage = 'unknown'
                        WHERE id = :attemptId
                        """)
                    .param("now", now)
                    .param("idempotencyKey", idempotencyKey)
                    .param("attemptId", attemptId)
                    .update();

                jdbc.sql(
                        """
                        INSERT INTO workflow_hub.analysis_job_attempts (
                            id, job_id, attempt_number, status, created_at, dispatch_attempted_at)
                        VALUES (:nextAttemptId, :taskId, :nextAttemptNumber, 'queued', :now, :now)
                        """)
                    .param("nextAttemptId", nextAttemptId)
                    .param("taskId", taskId)
                    .param("nextAttemptNumber", nextAttemptNumber)
                    .param("now", now)
                    .update();

                jdbc.sql(
                        """
                        UPDATE workflow_hub.analysis_jobs
                        SET status = 'queued',
                            current_attempt_id = :nextAttemptId,
                            attempt_number = :nextAttemptNumber,
                            lease_expires_at = NULL,
                            updated_at = :now
                        WHERE id = :taskId
                        """)
                    .param("nextAttemptId", nextAttemptId)
                    .param("nextAttemptNumber", nextAttemptNumber)
                    .param("now", now)
                    .param("taskId", taskId)
                    .update();

                jdbc.sql(
                        """
                        UPDATE workflow_hub.scan_runs
                        SET execution_status = 'queued',
                            analysis_coverage = 'unknown',
                            contract_version = :contractVersion,
                            inspection_version = :inspectionVersion,
                            assessment_version = :assessmentVersion,
                            engine_version = :engineVersion,
                            rules_version = :rulesVersion,
                            adapter_version = :adapterVersion
                        WHERE id = :scanRunId
                        """)
                    .param("contractVersion", v.contractVersion())
                    .param("inspectionVersion", v.inspectionVersion())
                    .param("assessmentVersion", v.assessmentVersion())
                    .param("engineVersion", v.engineVersion())
                    .param("rulesVersion", v.rulesVersion())
                    .param("adapterVersion", v.adapterVersion())
                    .param("scanRunId", locked.scanRunId())
                    .update();

                ScanTaskMessage retryMessage =
                    new ScanTaskMessage(
                        ScanModels.CONTRACT_VERSION,
                        taskId,
                        nextAttemptId,
                        locked.scanRunId(),
                        locked.workflowVersionId(),
                        locked.inputSha256(),
                        locked.sizeBytes(),
                        nextAttemptNumber,
                        locked.maxAttempts(),
                        now.toInstant());
                return new FailureTransition(
                    new ResultSubmission(true, locked.scanRunId(), "queued", "unknown"),
                    retryMessage);
              }

              String finalStatus =
                  "timed_out".equals(payload.outcome())
                          || "assessment_timeout".equals(payload.errorCode())
                      ? "timed_out"
                      : "failed";
              String safeMessage = safeErrorMessage(payload.errorCode(), finalStatus);

              jdbc.sql(
                      """
                      UPDATE workflow_hub.scan_runs
                      SET execution_status = :finalStatus,
                          analysis_coverage = 'unknown',
                          contract_version = :contractVersion,
                          inspection_version = :inspectionVersion,
                          assessment_version = :assessmentVersion,
                          engine_version = :engineVersion,
                          rules_version = :rulesVersion,
                          adapter_version = :adapterVersion,
                          error_code = :errorCode,
                          error_message = :errorMessage,
                          error_retryable = false,
                          finished_at = :now
                      WHERE id = :scanRunId
                      """)
                  .param("finalStatus", finalStatus)
                  .param("contractVersion", v.contractVersion())
                  .param("inspectionVersion", v.inspectionVersion())
                  .param("assessmentVersion", v.assessmentVersion())
                  .param("engineVersion", v.engineVersion())
                  .param("rulesVersion", v.rulesVersion())
                  .param("adapterVersion", v.adapterVersion())
                  .param("errorCode", payload.errorCode())
                  .param("errorMessage", safeMessage)
                  .param("now", now)
                  .param("scanRunId", locked.scanRunId())
                  .update();

              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_jobs
                      SET status = :finalStatus, lease_expires_at = NULL, updated_at = :now
                      WHERE id = :taskId
                      """)
                  .param("finalStatus", finalStatus)
                  .param("now", now)
                  .param("taskId", taskId)
                  .update();

              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_job_attempts
                      SET status = 'accepted',
                          lease_expires_at = NULL,
                          finished_at = :now,
                          result_idempotency_key = :idempotencyKey,
                          accepted_execution_status = :finalStatus,
                          accepted_analysis_coverage = 'unknown'
                      WHERE id = :attemptId
                      """)
                  .param("now", now)
                  .param("idempotencyKey", idempotencyKey)
                  .param("finalStatus", finalStatus)
                  .param("attemptId", attemptId)
                  .update();

              return new FailureTransition(
                  new ResultSubmission(true, locked.scanRunId(), finalStatus, "unknown"), null);
            });

    if (transition.retryMessage() != null) {
      ScanTaskMessage retryMessage = transition.retryMessage();
      log.warn(
          "event=analysis.worker.result_requeued taskId={} scanRunId={} nextAttemptId={} attemptNumber={} errorCode={}",
          taskId,
          retryMessage.scanRunId(),
          retryMessage.attemptId(),
          retryMessage.attemptNumber(),
          payload.errorCode());
      // 발행이 실패해도 수락한 응답(queued)은 바꾸지 않는다. 발행이 확인되지 않은 시도는 회수기가 같은 attemptId로 다시 보낸다.
      dispatcher.dispatch(retryMessage, "worker_retry");
    } else if (transition.submission().created()) {
      log.warn(
          "event=analysis.worker.result_failed taskId={} attemptId={} scanRunId={} status={} errorCode={}",
          taskId,
          attemptId,
          transition.submission().scanRunId(),
          transition.submission().executionStatus(),
          payload.errorCode());
    }
    return transition.submission();
  }

  private static ResultSubmission checkAcceptedReplay(TaskAttemptRow row, String idempotencyKey) {
    if (!"accepted".equals(row.attemptStatus())) {
      return null;
    }
    if (idempotencyKey.equals(row.resultIdempotencyKey())) {
      return new ResultSubmission(
          false, row.scanRunId(), row.acceptedExecutionStatus(), row.acceptedAnalysisCoverage());
    }
    throw ScanException.idempotencyConflict();
  }

  private static void requireQueuedAndRunnable(TaskAttemptRow row) {
    if (row.versionDeleted()
        || "cancelled".equals(row.jobStatus())
        || "cancelled".equals(row.attemptStatus())) {
      throw ScanException.taskCancelled();
    }
    if (!row.attemptId().equals(row.currentAttemptId()) || "expired".equals(row.attemptStatus())) {
      throw ScanException.attemptExpired();
    }
    if ("running".equals(row.attemptStatus()) && !row.leaseValid()) {
      throw ScanException.attemptExpired();
    }
    if (!"queued".equals(row.attemptStatus()) || !"queued".equals(row.jobStatus())) {
      throw ScanException.taskNotRunnable();
    }
  }

  private static void requireRunningAndLeaseValid(TaskAttemptRow row) {
    if (row.versionDeleted()
        || "cancelled".equals(row.jobStatus())
        || "cancelled".equals(row.attemptStatus())) {
      throw ScanException.taskCancelled();
    }
    if (!row.attemptId().equals(row.currentAttemptId()) || "expired".equals(row.attemptStatus())) {
      throw ScanException.attemptExpired();
    }
    if (!"running".equals(row.attemptStatus()) || !"running".equals(row.jobStatus())) {
      throw ScanException.attemptNotActive();
    }
    if (!row.leaseValid()) {
      throw ScanException.attemptExpired();
    }
  }

  private static void verifyResultIdentity(TaskAttemptRow row, ParsedResult payload) {
    if (!row.scanRunId().equals(payload.scanRunId())
        || !row.workflowVersionId().equals(payload.workflowVersionId())
        || !row.inputSha256().equals(payload.inputSha256())) {
      throw ScanException.resultIdentityMismatch();
    }
    if ("completed".equals(payload.outcome())) {
      for (String nestedHash : payload.nestedInputHashes()) {
        if (!row.inputSha256().equals(nestedHash)) {
          throw ScanException.resultIdentityMismatch();
        }
      }
    }
  }

  private void validateWorkerIdempotencyKey(String idempotencyKey, byte[] rawBody) {
    if (idempotencyKey == null || !HEX_SHA256.matcher(idempotencyKey).matches()) {
      throw ScanException.badRequest(
          "Idempotency-Key header is required and must be a 64-character lowercase hex SHA-256");
    }
    String computed = sha256Hex(rawBody);
    if (!computed.equals(idempotencyKey)) {
      throw ScanException.badRequest(
          "Idempotency-Key header must match the SHA-256 of the raw request body");
    }
  }

  private ParsedResult parseAndValidateResult(UUID pathTaskId, UUID pathAttemptId, byte[] rawBody) {
    JsonNode root;
    try {
      root = mapper.readTree(rawBody);
    } catch (RuntimeException e) {
      throw ScanException.badRequest("Request body is not valid JSON");
    }
    if (root == null || !root.isObject()) {
      throw ScanException.invalidResult("Result body must be a JSON object");
    }

    String contractVersion = requiredText(root, "contractVersion");
    if (!ScanModels.CONTRACT_VERSION.equals(contractVersion)) {
      throw ScanException.invalidResult("Unsupported contractVersion");
    }
    UUID bodyTaskId = requiredUuid(root, "taskId");
    UUID bodyAttemptId = requiredUuid(root, "attemptId");
    if (!pathTaskId.equals(bodyTaskId) || !pathAttemptId.equals(bodyAttemptId)) {
      throw ScanException.resultIdentityMismatch();
    }
    UUID scanRunId = requiredUuid(root, "scanRunId");
    UUID workflowVersionId = requiredUuid(root, "workflowVersionId");
    String inputSha256 = requiredSha256(root, "inputSha256");

    JsonNode versionsNode = requiredObject(root, "versions");
    ScanVersions versions =
        new ScanVersions(
            requiredText(versionsNode, "contractVersion"),
            requiredText(versionsNode, "inspectionVersion"),
            requiredText(versionsNode, "assessmentVersion"),
            requiredText(versionsNode, "engineVersion"),
            requiredText(versionsNode, "rulesVersion"),
            requiredText(versionsNode, "adapterVersion"));
    if (!contractVersion.equals(versions.contractVersion())) {
      throw ScanException.invalidResult("versions.contractVersion must match contractVersion");
    }

    String outcome = requiredText(root, "outcome");
    if (!ALLOWED_OUTCOMES.contains(outcome)) {
      throw ScanException.invalidResult("outcome must be completed, failed, or timed_out");
    }

    if ("completed".equals(outcome)) {
      JsonNode inspection = requiredObject(root, "inspection");
      String inspectionVersion = requiredText(inspection, "inspectionVersion");
      if (!ALLOWED_INSPECTION_VERSIONS.contains(inspectionVersion)) {
        throw ScanException.invalidResult("Unsupported inspectionVersion");
      }
      if (!inspectionVersion.equals(versions.inspectionVersion())) {
        throw ScanException.invalidResult(
            "inspection.inspectionVersion must match versions.inspectionVersion");
      }
      String inspectionHash = requiredSha256(inspection, "inputSha256");
      JsonNode assessment = requiredObject(inspection, "assessment");
      String assessmentVersion = requiredText(assessment, "assessmentVersion");
      String engineVersion = requiredText(assessment, "engineVersion");
      if (!assessmentVersion.equals(versions.assessmentVersion())
          || !engineVersion.equals(versions.engineVersion())) {
        throw ScanException.invalidResult(
            "inspection.assessment versions must match top-level versions");
      }
      String assessmentHash = requiredSha256(assessment, "inputSha256");
      String assessmentStatus = requiredText(assessment, "status");
      if (!ALLOWED_ASSESSMENT_STATUSES.contains(assessmentStatus)) {
        throw ScanException.invalidResult("Invalid inspection.assessment.status");
      }
      String advisoryDecision = requiredText(assessment, "decision");
      if (!ALLOWED_DECISIONS.contains(advisoryDecision)) {
        throw ScanException.invalidResult("Invalid inspection.assessment.decision");
      }

      JsonNode serviceReport = requiredObject(inspection, "serviceReport");
      String serviceReportVersion = requiredText(serviceReport, "serviceReportVersion");
      if (!inspectionVersion.equals(serviceReportVersion)) {
        throw ScanException.invalidResult(
            "inspection.serviceReport.serviceReportVersion must match inspectionVersion");
      }
      String serviceReportHash = requiredSha256(serviceReport, "inputSha256");
      String reportExecStatus = requiredText(serviceReport, "executionStatus");
      if (!ALLOWED_REPORT_EXECUTION_STATUSES.contains(reportExecStatus)) {
        throw ScanException.invalidResult("Invalid inspection.serviceReport.executionStatus");
      }
      String analysisStatus = requiredText(serviceReport, "analysisStatus");
      if (!ALLOWED_ANALYSIS_STATUSES.contains(analysisStatus)) {
        throw ScanException.invalidResult("Invalid inspection.serviceReport.analysisStatus");
      }
      String headline = requiredText(serviceReport, "headline");
      JsonNode counts = requiredObject(serviceReport, "counts");
      int findings = requiredNonNegativeInt(counts, "findings");
      int observations = requiredNonNegativeInt(counts, "observations");
      int analysisGaps = requiredNonNegativeInt(counts, "analysisGaps");
      int environmentChecks = requiredNonNegativeInt(counts, "environmentChecks");

      JsonNode serviceScope = requiredObject(serviceReport, "serviceScope");
      int highRiskFindings = requiredNonNegativeInt(serviceScope, "highRiskFindingCount");
      int sinkReachableGaps = requiredNonNegativeInt(serviceScope, "sinkReachableGapCount");
      boolean securityReviewRequired = requiredBoolean(serviceScope, "securityReviewRequired");

      JsonNode llm = requiredObject(inspection, "llm");
      String llmHash = requiredSha256(llm, "inputSha256");
      requiredText(llm, "status");

      String analysisCoverage =
          mapAnalysisCoverage(assessmentStatus, reportExecStatus, analysisGaps);
      ScanSummary summary =
          new ScanSummary(
              headline,
              analysisStatus,
              findings,
              highRiskFindings,
              observations,
              analysisGaps,
              sinkReachableGaps,
              environmentChecks,
              securityReviewRequired);
      return new ParsedResult(
          scanRunId,
          workflowVersionId,
          inputSha256,
          versions,
          outcome,
          analysisCoverage,
          advisoryDecision,
          summary,
          serviceReport,
          assessment,
          new String[] {inspectionHash, assessmentHash, serviceReportHash, llmHash},
          null,
          false);
    }

    JsonNode error = requiredObject(root, "error");
    String errorCode = requiredText(error, "code");
    if (!ERROR_CODE_PATTERN.matcher(errorCode).matches()) {
      throw ScanException.invalidResult("Invalid error.code format");
    }
    boolean retryable = requiredBoolean(error, "retryable");
    return new ParsedResult(
        scanRunId,
        workflowVersionId,
        inputSha256,
        versions,
        outcome,
        "unknown",
        null,
        null,
        null,
        null,
        new String[0],
        errorCode,
        retryable);
  }

  /** #39 §4.3 매핑 규칙: 워커 출력 -> analysisCoverage. */
  private static String mapAnalysisCoverage(
      String assessmentStatus, String reportExecutionStatus, int analysisGapCount) {
    if ("analyzed".equals(assessmentStatus)
        && "completed".equals(reportExecutionStatus)
        && analysisGapCount == 0) {
      return "checked";
    }
    if ("unsupported".equals(assessmentStatus)) {
      return "unsupported";
    }
    return "partial";
  }

  private static String safeErrorMessage(String errorCode, String finalStatus) {
    String mapped = SAFE_ERROR_MESSAGES.get(errorCode);
    if (mapped != null) {
      return mapped;
    }
    return "timed_out".equals(finalStatus)
        ? "Security scan exceeded the allowed execution time"
        : "Security scan failed";
  }

  private java.util.Optional<TaskAttemptRow> readTaskAttempt(UUID taskId, UUID attemptId) {
    return queryTaskAttempt(taskId, attemptId);
  }

  /**
   * 트랜잭션 안에서 작업 행을 먼저 잠근 뒤 별도 문장으로 시도 상태와 임대 유효성을 읽는다. READ COMMITTED에서 잠금과 조회를 한 문장으로 하면 잠금 대기 중
   * 커밋된 시도 행의 변경을 놓치고, 임대 유효성도 잠금을 얻기 전 시각으로 계산된다.
   */
  private java.util.Optional<TaskAttemptRow> lockTaskAttempt(UUID taskId, UUID attemptId) {
    var locked =
        jdbc.sql("SELECT id FROM workflow_hub.analysis_jobs WHERE id = :taskId FOR UPDATE")
            .param("taskId", taskId)
            .query(UUID.class)
            .optional();
    if (locked.isEmpty()) {
      return java.util.Optional.empty();
    }
    return queryTaskAttempt(taskId, attemptId);
  }

  private java.util.Optional<TaskAttemptRow> queryTaskAttempt(UUID taskId, UUID attemptId) {
    return jdbc.sql(
            """
            SELECT j.id AS task_id,
                   j.scan_run_id,
                   s.workflow_id,
                   j.workflow_version_id,
                   j.input_sha256,
                   j.size_bytes,
                   j.status AS job_status,
                   j.current_attempt_id,
                   j.attempt_number,
                   j.max_attempts,
                   a.id AS attempt_id,
                   a.status AS attempt_status,
                   a.result_idempotency_key,
                   a.accepted_execution_status,
                   a.accepted_analysis_coverage,
                   (a.lease_expires_at IS NOT NULL AND a.lease_expires_at > clock_timestamp()) AS lease_valid,
                   v.s3_object_key AS version_object_key,
                   (v.deleted_at IS NOT NULL OR w.deleted_at IS NOT NULL) AS version_deleted
            FROM workflow_hub.analysis_jobs j
            JOIN workflow_hub.analysis_job_attempts a ON a.job_id = j.id
            JOIN workflow_hub.scan_runs s ON s.id = j.scan_run_id
            JOIN workflow_hub.workflow_versions v ON v.id = j.workflow_version_id
            JOIN workflow_hub.workflows w ON w.id = v.workflow_id
            WHERE j.id = :taskId AND a.id = :attemptId
            """)
        .param("taskId", taskId)
        .param("attemptId", attemptId)
        .query(
            (rs, index) ->
                new TaskAttemptRow(
                    rs.getObject("task_id", UUID.class),
                    rs.getObject("scan_run_id", UUID.class),
                    rs.getObject("workflow_id", UUID.class),
                    rs.getObject("workflow_version_id", UUID.class),
                    rs.getString("input_sha256"),
                    rs.getLong("size_bytes"),
                    rs.getString("job_status"),
                    rs.getObject("current_attempt_id", UUID.class),
                    rs.getInt("attempt_number"),
                    rs.getInt("max_attempts"),
                    rs.getObject("attempt_id", UUID.class),
                    rs.getString("attempt_status"),
                    rs.getString("result_idempotency_key"),
                    rs.getString("accepted_execution_status"),
                    rs.getString("accepted_analysis_coverage"),
                    rs.getBoolean("lease_valid"),
                    rs.getString("version_object_key"),
                    rs.getBoolean("version_deleted")))
        .optional();
  }

  private OffsetDateTime databaseNow() {
    return jdbc.sql("SELECT clock_timestamp()")
        .query((rs, index) -> rs.getObject(1, OffsetDateTime.class))
        .single();
  }

  private static String sha256Hex(byte[] bytes) {
    try {
      return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  private static JsonNode requiredObject(JsonNode parent, String field) {
    JsonNode node = parent.get(field);
    if (node == null || !node.isObject()) {
      throw ScanException.invalidResult("Field '" + field + "' must be a JSON object");
    }
    return node;
  }

  private static String requiredText(JsonNode parent, String field) {
    JsonNode node = parent.get(field);
    if (node == null || !node.isString() || node.asString().isBlank()) {
      throw ScanException.invalidResult("Field '" + field + "' must be a non-blank string");
    }
    return node.asString();
  }

  private static UUID requiredUuid(JsonNode parent, String field) {
    String raw = requiredText(parent, field);
    try {
      return UUID.fromString(raw);
    } catch (IllegalArgumentException e) {
      throw ScanException.invalidResult("Field '" + field + "' must be a valid UUID");
    }
  }

  private static String requiredSha256(JsonNode parent, String field) {
    String raw = requiredText(parent, field);
    if (!HEX_SHA256.matcher(raw).matches()) {
      throw ScanException.invalidResult(
          "Field '" + field + "' must be a 64-character lowercase hex SHA-256");
    }
    return raw;
  }

  private static int requiredNonNegativeInt(JsonNode parent, String field) {
    JsonNode node = parent.get(field);
    if (node == null
        || !node.isIntegralNumber()
        || !node.canConvertToInt()
        || node.intValue() < 0) {
      throw ScanException.invalidResult("Field '" + field + "' must be a non-negative integer");
    }
    return node.intValue();
  }

  private static boolean requiredBoolean(JsonNode parent, String field) {
    JsonNode node = parent.get(field);
    if (node == null || !node.isBoolean()) {
      throw ScanException.invalidResult("Field '" + field + "' must be a boolean");
    }
    return node.booleanValue();
  }

  private record TaskAttemptRow(
      UUID taskId,
      UUID scanRunId,
      UUID workflowId,
      UUID workflowVersionId,
      String inputSha256,
      long sizeBytes,
      String jobStatus,
      UUID currentAttemptId,
      int attemptNumber,
      int maxAttempts,
      UUID attemptId,
      String attemptStatus,
      String resultIdempotencyKey,
      String acceptedExecutionStatus,
      String acceptedAnalysisCoverage,
      boolean leaseValid,
      String versionObjectKey,
      boolean versionDeleted) {}

  private record ParsedResult(
      UUID scanRunId,
      UUID workflowVersionId,
      String inputSha256,
      ScanVersions versions,
      String outcome,
      String analysisCoverage,
      String advisoryDecision,
      ScanSummary summary,
      JsonNode serviceReportNode,
      JsonNode assessmentNode,
      String[] nestedInputHashes,
      String errorCode,
      boolean errorRetryable) {}

  private record FailureTransition(ResultSubmission submission, ScanTaskMessage retryMessage) {}
}
