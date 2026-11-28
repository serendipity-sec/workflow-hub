package dev.workflowhub.analysis.service;

import dev.workflowhub.analysis.queue.ScanTaskMessage;
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
 * 임대(lease_expires_at)가 만료된 running 작업, 오래 미수신 상태로 남은 queued 작업, 발행이 확인되지 않은 queued 시도를 회수한다.
 *
 * <p>만료·미수신 작업은 최대 시도 횟수 미만이면 새 attemptId를 발급해 queued로 재발행하고, 소진 시 timed_out으로 마감한다. 발행이 확인되지 않은
 * 시도는 상태를 바꾸지 않고 같은 attemptId로 다시 발행한다. 일시적인 SQS 장애가 검사를 종료시키지 않으며, 장애가 길어지면 미수신 제한
 * 시간(SCAN_QUEUED_TIMEOUT)이 시도 횟수를 소모해 결국 timed_out으로 마감한다.
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

  private static final String EXPIRED_CONDITION =
      """
      ((j.status = 'running'
        AND j.lease_expires_at IS NOT NULL
        AND j.lease_expires_at <= statement_timestamp())
       OR (j.status = 'queued'
        AND j.updated_at <= statement_timestamp() - make_interval(secs => :queuedTimeoutSeconds)))
      """;
  private static final String UNDISPATCHED_CONDITION =
      """
      (j.status = 'queued'
       AND a.status = 'queued'
       AND a.dispatched_at IS NULL
       AND a.dispatch_attempted_at <= statement_timestamp() - make_interval(secs => :dispatchRetrySeconds))
      """;

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final ScanTaskDispatcher dispatcher;
  private final Duration queuedTimeout;
  private final Duration dispatchRetryDelay;

  public ScanLeaseRecovery(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      ScanTaskDispatcher dispatcher,
      @Value("${app.analysis.queued-timeout}") Duration queuedTimeout,
      @Value("${app.analysis.dispatch-retry-delay}") Duration dispatchRetryDelay,
      @Value("${app.analysis.queue-call-timeout}") Duration queueCallTimeout) {
    if (queuedTimeout.isZero() || queuedTimeout.isNegative()) {
      throw new IllegalArgumentException("SCAN_QUEUED_TIMEOUT must be positive");
    }
    // 요청 스레드의 첫 발행이 끝나기 전에 같은 시도를 다시 보내지 않도록 SQS 호출 제한보다 길어야 한다.
    if (dispatchRetryDelay.compareTo(queueCallTimeout) <= 0) {
      throw new IllegalArgumentException(
          "SCAN_DISPATCH_RETRY_DELAY must be longer than SQS_CALL_TIMEOUT");
    }
    // 미수신 제한 시간보다 길면 같은 시도 재발행이 일어나기 전에 시도가 만료돼 짧은 SQS 장애도 시도 횟수를 소모한다.
    if (dispatchRetryDelay.compareTo(queuedTimeout) >= 0) {
      throw new IllegalArgumentException(
          "SCAN_DISPATCH_RETRY_DELAY must be shorter than SCAN_QUEUED_TIMEOUT");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.dispatcher = dispatcher;
    this.queuedTimeout = queuedTimeout;
    this.dispatchRetryDelay = dispatchRetryDelay;
  }

  @Scheduled(fixedDelayString = "${app.analysis.lease-recovery-interval}")
  public void recoverExpired() {
    for (int processed = 0; processed < MAX_PER_RUN; processed++) {
      try {
        // 회수 대상이 없을 때는 불필요한 쓰기 트랜잭션을 열지 않는다.
        if (!hasCandidate()) {
          return;
        }
        Optional<RecoveryAction> action = transactions.execute(status -> claimAndTransitionOne());
        if (action == null || action.isEmpty()) {
          return;
        }
        ScanTaskMessage message = action.get().dispatchMessage();
        // SQS 장애 중에는 한 건만 시도하고 멈춰, 호출 제한 시간만큼 스케줄러를 붙잡지 않는다.
        if (message != null && !dispatcher.dispatch(message, "lease_recovery")) {
          return;
        }
      } catch (RuntimeException e) {
        log.error("event=analysis.lease_recovery.run_failed", e);
        return;
      }
    }
  }

  private boolean hasCandidate() {
    return Boolean.TRUE.equals(
        jdbc.sql(
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM workflow_hub.analysis_jobs j
                    JOIN workflow_hub.analysis_job_attempts a ON a.id = j.current_attempt_id
                    WHERE %s OR %s)
                """
                    .formatted(EXPIRED_CONDITION, UNDISPATCHED_CONDITION))
            .param("queuedTimeoutSeconds", seconds(queuedTimeout))
            .param("dispatchRetrySeconds", seconds(dispatchRetryDelay))
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
                       a.created_at AS attempt_created_at,
                       %s AS expired,
                       (v.deleted_at IS NOT NULL OR w.deleted_at IS NOT NULL) AS version_deleted
                FROM workflow_hub.analysis_jobs j
                JOIN workflow_hub.analysis_job_attempts a ON a.id = j.current_attempt_id
                JOIN workflow_hub.workflow_versions v ON v.id = j.workflow_version_id
                JOIN workflow_hub.workflows w ON w.id = v.workflow_id
                WHERE %s OR %s
                ORDER BY coalesce(j.lease_expires_at, j.updated_at), j.id
                LIMIT 1
                FOR UPDATE OF j SKIP LOCKED
                """
                    .formatted(EXPIRED_CONDITION, EXPIRED_CONDITION, UNDISPATCHED_CONDITION))
            .param("queuedTimeoutSeconds", seconds(queuedTimeout))
            .param("dispatchRetrySeconds", seconds(dispatchRetryDelay))
            .query(
                (rs, index) ->
                    new CandidateJob(
                        rs.getObject("task_id", UUID.class),
                        rs.getObject("scan_run_id", UUID.class),
                        rs.getObject("workflow_version_id", UUID.class),
                        rs.getString("input_sha256"),
                        rs.getLong("size_bytes"),
                        rs.getString("job_status"),
                        rs.getObject("current_attempt_id", UUID.class),
                        rs.getInt("attempt_number"),
                        rs.getInt("max_attempts"),
                        rs.getObject("attempt_created_at", OffsetDateTime.class),
                        rs.getBoolean("expired"),
                        rs.getBoolean("version_deleted")))
            .optional();
    if (row.isEmpty()) {
      return Optional.empty();
    }
    CandidateJob job = row.get();
    OffsetDateTime now = databaseNow();

    if (job.versionDeleted()) {
      return Optional.of(cancelDeleted(job, now));
    }
    if (!job.expired()) {
      return Optional.of(redispatchCurrentAttempt(job));
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
      return Optional.of(new RecoveryAction(message(job, nextAttemptId, nextAttemptNumber, now)));
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

  private RecoveryAction cancelDeleted(CandidateJob job, OffsetDateTime now) {
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
    return new RecoveryAction(null);
  }

  /**
   * 발행이 확인되지 않은 현재 시도를 같은 attemptId로 다시 보낸다. 발행 시도 시각을 먼저 커밋해 다른 인스턴스가 같은 시도를 곧바로 다시 집지 않게 한다. 작업
   * 상태와 updated_at은 바꾸지 않으므로 미수신 제한 시간은 그대로 흐른다.
   */
  private RecoveryAction redispatchCurrentAttempt(CandidateJob job) {
    jdbc.sql(
            """
            UPDATE workflow_hub.analysis_job_attempts
            SET dispatch_attempted_at = clock_timestamp()
            WHERE id = :attemptId
            """)
        .param("attemptId", job.currentAttemptId())
        .update();
    log.warn(
        "event=analysis.lease_recovery.redispatched taskId={} scanRunId={} attemptId={} attemptNumber={}",
        job.taskId(),
        job.scanRunId(),
        job.currentAttemptId(),
        job.attemptNumber());
    return new RecoveryAction(
        message(job, job.currentAttemptId(), job.attemptNumber(), job.attemptCreatedAt()));
  }

  private static ScanTaskMessage message(
      CandidateJob job, UUID attemptId, int attemptNumber, OffsetDateTime enqueuedAt) {
    return new ScanTaskMessage(
        ScanModels.CONTRACT_VERSION,
        job.taskId(),
        attemptId,
        job.scanRunId(),
        job.workflowVersionId(),
        job.inputSha256(),
        job.sizeBytes(),
        attemptNumber,
        job.maxAttempts(),
        enqueuedAt.toInstant());
  }

  private static double seconds(Duration duration) {
    return duration.toMillis() / 1000.0;
  }

  private OffsetDateTime databaseNow() {
    return jdbc.sql("SELECT clock_timestamp()")
        .query((rs, index) -> rs.getObject(1, OffsetDateTime.class))
        .single();
  }

  private record CandidateJob(
      UUID taskId,
      UUID scanRunId,
      UUID workflowVersionId,
      String inputSha256,
      long sizeBytes,
      String jobStatus,
      UUID currentAttemptId,
      int attemptNumber,
      int maxAttempts,
      OffsetDateTime attemptCreatedAt,
      boolean expired,
      boolean versionDeleted) {}

  private record RecoveryAction(ScanTaskMessage dispatchMessage) {}
}
