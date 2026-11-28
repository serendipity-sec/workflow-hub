package dev.workflowhub.analysis.service;

import dev.workflowhub.analysis.queue.ScanTaskMessage;
import dev.workflowhub.analysis.queue.ScanTaskQueue;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 임대(lease_expires_at)가 만료된 running 작업과 오래 미수신 상태로 남은 queued 작업을 회수한다.
 *
 * <p>최대 시도 횟수 미만이면 새 attemptId를 발급해 queued로 재발행하고, 소진 시 timed_out으로 마감한다.
 */
@Service
public class ScanLeaseRecovery {
  private static final Logger log = LoggerFactory.getLogger(ScanLeaseRecovery.class);
  private static final int MAX_PER_RUN = 100;
  private static final String LEASE_EXPIRED_CODE = "lease_expired";
  private static final String LEASE_EXPIRED_MESSAGE =
      "Security scan timed out after exhausting retry attempts";
  private static final String QUEUE_TIMEOUT_CODE = "queue_timeout";
  private static final String QUEUE_TIMEOUT_MESSAGE =
      "Security scan timed out waiting for a worker";
  private static final String DISPATCH_FAILED_CODE = "scan_dispatch_failed";
  private static final String DISPATCH_FAILED_MESSAGE =
      "Security scan retry could not be dispatched to the worker queue";

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final ScanTaskQueue queue;
  private final Duration queuedTimeout;

  public ScanLeaseRecovery(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      ScanTaskQueue queue,
      @Value("${app.analysis.queued-timeout}") Duration queuedTimeout) {
    if (queuedTimeout.isZero() || queuedTimeout.isNegative()) {
      throw new IllegalArgumentException("SCAN_QUEUED_TIMEOUT must be positive");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.queue = queue;
    this.queuedTimeout = queuedTimeout;
  }

  @Scheduled(fixedDelayString = "${app.analysis.lease-recovery-interval}")
  public void recoverExpired() {
    for (int processed = 0; processed < MAX_PER_RUN; processed++) {
      try {
        // 만료 대상이 없을 때는 불필요한 쓰기 트랜잭션을 열지 않는다.
        if (!hasExpiredCandidate()) {
          return;
        }
        Optional<RecoveryAction> action = transactions.execute(status -> claimAndTransitionOne());
        if (action == null || action.isEmpty()) {
          return;
        }
        RecoveryAction result = action.get();
        if (result.retryMessage() != null) {
          if (!dispatchRetry(result.retryMessage())) {
            return;
          }
        }
      } catch (RuntimeException e) {
        log.error("event=analysis.lease_recovery.run_failed", e);
        return;
      }
    }
  }

  private boolean hasExpiredCandidate() {
    return Boolean.TRUE.equals(
        jdbc.sql(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM workflow_hub.analysis_jobs j
                    WHERE (j.status = 'running'
                           AND j.lease_expires_at IS NOT NULL
                           AND j.lease_expires_at <= statement_timestamp())
                       OR (j.status = 'queued'
                           AND j.updated_at <= statement_timestamp() - make_interval(secs => :queuedTimeoutSeconds)))
                """)
            .param("queuedTimeoutSeconds", queuedTimeout.toMillis() / 1000.0)
            .query(Boolean.class)
            .single());
  }

  private Optional<RecoveryAction> claimAndTransitionOne() {
    var row =
        jdbc.sql(
                """
                SELECT j.id AS task_id,
                       j.scan_run_id,
                       j.workflow_version_id,
                       j.input_sha256,
                       j.size_bytes,
                       j.status AS job_status,
                       j.current_attempt_id,
                       j.attempt_number,
                       j.max_attempts,
                       (v.deleted_at IS NOT NULL OR w.deleted_at IS NOT NULL) AS version_deleted
                FROM workflow_hub.analysis_jobs j
                JOIN workflow_hub.workflow_versions v ON v.id = j.workflow_version_id
                JOIN workflow_hub.workflows w ON w.id = v.workflow_id
                WHERE (j.status = 'running'
                       AND j.lease_expires_at IS NOT NULL
                       AND j.lease_expires_at <= statement_timestamp())
                   OR (j.status = 'queued'
                       AND j.updated_at <= statement_timestamp() - make_interval(secs => :queuedTimeoutSeconds))
                ORDER BY coalesce(j.lease_expires_at, j.updated_at), j.id
                LIMIT 1
                FOR UPDATE OF j SKIP LOCKED
                """)
            .param("queuedTimeoutSeconds", queuedTimeout.toMillis() / 1000.0)
            .query(
                (rs, index) ->
                    new ExpiredJob(
                        rs.getObject("task_id", UUID.class),
                        rs.getObject("scan_run_id", UUID.class),
                        rs.getObject("workflow_version_id", UUID.class),
                        rs.getString("input_sha256"),
                        rs.getLong("size_bytes"),
                        rs.getString("job_status"),
                        rs.getObject("current_attempt_id", UUID.class),
                        rs.getInt("attempt_number"),
                        rs.getInt("max_attempts"),
                        rs.getBoolean("version_deleted")))
            .optional();
    if (row.isEmpty()) {
      return Optional.empty();
    }
    ExpiredJob job = row.get();
    OffsetDateTime now = databaseNow();

    if (job.versionDeleted()) {
      jdbc.sql(
              """
              UPDATE workflow_hub.analysis_job_attempts
              SET status = 'cancelled', lease_expires_at = NULL, finished_at = :now
              WHERE id = :attemptId
              """)
          .param("now", now)
          .param("attemptId", job.currentAttemptId())
          .update();
      jdbc.sql(
              """
              UPDATE workflow_hub.analysis_jobs
              SET status = 'cancelled', lease_expires_at = NULL, updated_at = :now
              WHERE id = :taskId
              """)
          .param("now", now)
          .param("taskId", job.taskId())
          .update();
      jdbc.sql(
              """
              UPDATE workflow_hub.scan_runs
              SET execution_status = 'cancelled', analysis_coverage = 'unknown', finished_at = :now
              WHERE id = :scanRunId
              """)
          .param("now", now)
          .param("scanRunId", job.scanRunId())
          .update();
      log.info(
          "event=analysis.lease_recovery.cancelled_deleted taskId={} scanRunId={}",
          job.taskId(),
          job.scanRunId());
      return Optional.of(new RecoveryAction(null));
    }

    jdbc.sql(
            """
            UPDATE workflow_hub.analysis_job_attempts
            SET status = 'expired', lease_expires_at = NULL, finished_at = :now
            WHERE id = :attemptId
            """)
        .param("now", now)
        .param("attemptId", job.currentAttemptId())
        .update();

    if (job.attemptNumber() < job.maxAttempts()) {
      UUID nextAttemptId = UUID.randomUUID();
      int nextAttemptNumber = job.attemptNumber() + 1;
      jdbc.sql(
              """
              INSERT INTO workflow_hub.analysis_job_attempts (id, job_id, attempt_number, status)
              VALUES (:attemptId, :jobId, :attemptNumber, 'queued')
              """)
          .param("attemptId", nextAttemptId)
          .param("jobId", job.taskId())
          .param("attemptNumber", nextAttemptNumber)
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
          .param("taskId", job.taskId())
          .update();
      jdbc.sql(
              """
              UPDATE workflow_hub.scan_runs
              SET execution_status = 'queued', analysis_coverage = 'unknown'
              WHERE id = :scanRunId
              """)
          .param("scanRunId", job.scanRunId())
          .update();
      log.warn(
          "event=analysis.lease_recovery.requeued taskId={} scanRunId={} priorStatus={} expiredAttemptId={} nextAttemptId={} attemptNumber={}",
          job.taskId(),
          job.scanRunId(),
          job.jobStatus(),
          job.currentAttemptId(),
          nextAttemptId,
          nextAttemptNumber);
      return Optional.of(
          new RecoveryAction(
              new ScanTaskMessage(
                  ScanModels.CONTRACT_VERSION,
                  job.taskId(),
                  nextAttemptId,
                  job.scanRunId(),
                  job.workflowVersionId(),
                  job.inputSha256(),
                  job.sizeBytes(),
                  nextAttemptNumber,
                  job.maxAttempts(),
                  now.toInstant())));
    }

    boolean wasQueued = "queued".equals(job.jobStatus());
    String errorCode = wasQueued ? QUEUE_TIMEOUT_CODE : LEASE_EXPIRED_CODE;
    String errorMessage = wasQueued ? QUEUE_TIMEOUT_MESSAGE : LEASE_EXPIRED_MESSAGE;

    jdbc.sql(
            """
            UPDATE workflow_hub.analysis_jobs
            SET status = 'timed_out', lease_expires_at = NULL, updated_at = :now
            WHERE id = :taskId
            """)
        .param("now", now)
        .param("taskId", job.taskId())
        .update();
    jdbc.sql(
            """
            UPDATE workflow_hub.scan_runs
            SET execution_status = 'timed_out',
                analysis_coverage = 'unknown',
                error_code = :code,
                error_message = :message,
                error_retryable = false,
                finished_at = :now
            WHERE id = :scanRunId
            """)
        .param("code", errorCode)
        .param("message", errorMessage)
        .param("now", now)
        .param("scanRunId", job.scanRunId())
        .update();
    log.warn(
        "event=analysis.lease_recovery.timed_out taskId={} scanRunId={} priorStatus={} attemptNumber={}",
        job.taskId(),
        job.scanRunId(),
        job.jobStatus(),
        job.attemptNumber());
    return Optional.of(new RecoveryAction(null));
  }

  private boolean dispatchRetry(ScanTaskMessage message) {
    try {
      queue.enqueue(message);
      return true;
    } catch (RuntimeException e) {
      log.error(
          "event=analysis.lease_recovery.dispatch_failed taskId={} scanRunId={} attemptId={}",
          message.taskId(),
          message.scanRunId(),
          message.attemptId(),
          e);
      markDispatchFailed(message.taskId(), message.scanRunId(), message.attemptId());
      return false;
    }
  }

  private void markDispatchFailed(UUID taskId, UUID scanRunId, UUID attemptId) {
    transactions.executeWithoutResult(
        status -> {
          OffsetDateTime now = databaseNow();
          int updated =
              jdbc.sql(
                      """
                      UPDATE workflow_hub.analysis_jobs
                      SET status = 'failed', lease_expires_at = NULL, updated_at = :now
                      WHERE id = :taskId AND current_attempt_id = :attemptId AND status = 'queued'
                      """)
                  .param("now", now)
                  .param("taskId", taskId)
                  .param("attemptId", attemptId)
                  .update();
          if (updated == 0) {
            return;
          }
          jdbc.sql(
                  """
                  UPDATE workflow_hub.analysis_job_attempts
                  SET status = 'expired', finished_at = :now
                  WHERE id = :attemptId AND status = 'queued'
                  """)
              .param("now", now)
              .param("attemptId", attemptId)
              .update();
          jdbc.sql(
                  """
                  UPDATE workflow_hub.scan_runs
                  SET execution_status = 'failed',
                      analysis_coverage = 'unknown',
                      error_code = :code,
                      error_message = :message,
                      error_retryable = false,
                      finished_at = :now
                  WHERE id = :scanRunId AND execution_status = 'queued'
                  """)
              .param("code", DISPATCH_FAILED_CODE)
              .param("message", DISPATCH_FAILED_MESSAGE)
              .param("now", now)
              .param("scanRunId", scanRunId)
              .update();
        });
  }

  private OffsetDateTime databaseNow() {
    return jdbc.sql("SELECT clock_timestamp()")
        .query((rs, index) -> rs.getObject(1, OffsetDateTime.class))
        .single();
  }

  private record ExpiredJob(
      UUID taskId,
      UUID scanRunId,
      UUID workflowVersionId,
      String inputSha256,
      long sizeBytes,
      String jobStatus,
      UUID currentAttemptId,
      int attemptNumber,
      int maxAttempts,
      boolean versionDeleted) {}

  private record RecoveryAction(ScanTaskMessage retryMessage) {}
}
