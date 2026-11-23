package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.time.Duration;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 업로드·버전 등록이 S3에 쓰기 전에 남기는 정리 대상 기록(pending_objects)을 관리하고, 끝나지 않은 기록의 객체를 정리한다.
 *
 * <p>정리 작업은 기록이 있는 객체만 다루며 버킷 전체를 훑지 않는다. versioning을 끈 버킷을 전제로 하며, DeleteObject는 없는 키에도 성공하므로
 * 재시도해도 안전하다.
 */
@Service
public class WorkflowObjectCleanup {
  private static final Logger log = LoggerFactory.getLogger(WorkflowObjectCleanup.class);
  private static final int MAX_PER_RUN = 100;

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final WorkflowObjectStore store;
  private final Duration grace;
  private final Duration retryDelay;

  public WorkflowObjectCleanup(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      WorkflowObjectStore store,
      @Value("${app.storage.pending-object-grace}") Duration grace,
      @Value("${app.storage.cleanup-retry-delay}") Duration retryDelay,
      @Value("${app.storage.call-timeout}") Duration callTimeout) {
    if (grace.isZero() || grace.isNegative() || retryDelay.isZero() || retryDelay.isNegative()) {
      throw new IllegalArgumentException(
          "PENDING_OBJECT_GRACE and CLEANUP_RETRY_DELAY must be positive");
    }
    // 진행 중인 요청의 객체를 지우지 않으려면 대기 시간이 S3 호출 제한보다 충분히 길어야 한다.
    if (grace.compareTo(callTimeout.multipliedBy(2)) < 0) {
      throw new IllegalArgumentException(
          "PENDING_OBJECT_GRACE must be at least twice S3_CALL_TIMEOUT");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.store = store;
    this.grace = grace;
    this.retryDelay = retryDelay;
  }

  /** S3에 쓰기 전에 호출한다. 요청 트랜잭션과 따로 커밋해야 롤백·재시작 뒤에도 남는다. */
  void record(String objectKey) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.pending_objects (object_key, cleanup_after)
            VALUES (:key, clock_timestamp() + make_interval(secs => :graceSeconds))
            """)
        .param("key", objectKey)
        .param("graceSeconds", grace.toMillis() / 1000.0)
        .update();
  }

  /**
   * 버전 INSERT와 같은 트랜잭션에서 호출한다. 커밋되면 기록이 사라지고 버전 행이 객체를 대신 가리킨다.
   *
   * <p>기록이 이미 없으면 정리 작업이 대기 시간 뒤 이 객체를 지웠다는 뜻이다. 삭제된 파일을 가리키는 버전을 만들지 않도록 실패시킨다. 정리 작업은 삭제가 끝날 때까지
   * 기록 행을 잠그므로 이 삭제는 그 완료를 기다린 뒤 결과를 본다.
   */
  void releaseForCommit(String objectKey) {
    int released =
        jdbc.sql(
                "DELETE FROM workflow_hub.pending_objects WHERE object_key = :key AND delete_started_at IS NULL")
            .param("key", objectKey)
            .update();
    if (released == 0) {
      log.error("event=workflow.object_cleanup.record_missing objectKey={}", objectKey);
      throw new WorkflowUploadException(
          HttpStatus.SERVICE_UNAVAILABLE,
          "STORAGE_UNAVAILABLE",
          "The stored file expired before registration finished. Retry with the same Idempotency-Key.");
    }
  }

  /**
   * 어떤 버전도 참조하지 않는 것이 확인된 객체를 즉시 지운다. 삭제가 확인되면 기록도 지우고, 실패하면 기록을 남겨 곧 다시 시도하게 한다. 요청 결과를 바꾸지 않도록
   * 예외를 던지지 않는다.
   */
  void discard(String objectKey) {
    try {
      store.delete(objectKey);
    } catch (RuntimeException e) {
      log.error("event=workflow.object_cleanup.discard_failed objectKey={}", objectKey, e);
      retrySoon(objectKey);
      return;
    }
    log.info("event=workflow.object_cleanup.discarded objectKey={}", objectKey);
    try {
      jdbc.sql("DELETE FROM workflow_hub.pending_objects WHERE object_key = :key")
          .param("key", objectKey)
          .update();
    } catch (RuntimeException e) {
      // 남은 기록은 정리 작업이 다시 확인한다.
      log.error("event=workflow.object_cleanup.forget_failed objectKey={}", objectKey, e);
    }
  }

  private void retrySoon(String objectKey) {
    try {
      jdbc.sql(
              """
              UPDATE workflow_hub.pending_objects
              SET cleanup_after = LEAST(cleanup_after,
                  clock_timestamp() + make_interval(secs => :delaySeconds))
              WHERE object_key = :key
              """)
          .param("key", objectKey)
          .param("delaySeconds", retryDelay.toMillis() / 1000.0)
          .update();
    } catch (RuntimeException e) {
      log.error("event=workflow.object_cleanup.retry_mark_failed objectKey={}", objectKey, e);
    }
  }

  @Scheduled(fixedDelayString = "${app.storage.cleanup-interval}")
  public void cleanDue() {
    for (int processed = 0; processed < MAX_PER_RUN; processed++) {
      try {
        Optional<String> due = claimDue();
        if (due.isEmpty()) {
          return;
        }
        // S3 장애 중에는 한 건만 시도하고 멈춰, 호출 제한 시간만큼 스케줄러를 붙잡지 않는다.
        if (!clean(due.get())) {
          return;
        }
      } catch (RuntimeException e) {
        // DB 상태를 확인하지 못하면 객체를 보존하고 다음 실행에서 다시 시도한다.
        log.error("event=workflow.object_cleanup.run_failed", e);
        return;
      }
    }
  }

  private Optional<String> claimDue() {
    // 처리 전에 한 행씩 선점하며, 이후 단계가 실패하거나 프로세스가 멈춰도 재시도 간격 뒤 다시 시도된다.
    return jdbc.sql(
            """
            WITH due AS (
                SELECT object_key
                FROM workflow_hub.pending_objects
                WHERE cleanup_after <= clock_timestamp()
                ORDER BY cleanup_after, object_key
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE workflow_hub.pending_objects p
            SET cleanup_after = clock_timestamp() + make_interval(secs => :delaySeconds)
            FROM due
            WHERE p.object_key = due.object_key
            RETURNING p.object_key
            """)
        .param("delaySeconds", retryDelay.toMillis() / 1000.0)
        .query(String.class)
        .optional();
  }

  /** 처리를 계속해도 되면 true. S3 삭제가 실패하면 false다. */
  private boolean clean(String objectKey) {
    if (!Boolean.TRUE.equals(transactions.execute(status -> markForDeletion(objectKey)))) {
      return true;
    }
    try {
      store.delete(objectKey);
    } catch (RuntimeException e) {
      // 삭제 시작 표시가 남아 있으므로 요청은 이 객체로 커밋할 수 없고, 다음 실행에서 다시 지운다.
      log.error("event=workflow.object_cleanup.delete_failed objectKey={}", objectKey, e);
      return false;
    }
    log.info("event=workflow.object_cleanup.deleted objectKey={}", objectKey);
    jdbc.sql("DELETE FROM workflow_hub.pending_objects WHERE object_key = :key")
        .param("key", objectKey)
        .update();
    return true;
  }

  /**
   * 참조가 없음을 확인한 같은 트랜잭션에서 삭제 시작을 표시한다. 같은 행을 버전 INSERT와 함께 지우려는 요청이 있으면 그 요청이 끝나기를 기다리지 않고 이번에는
   * 건너뛴다(선점으로 이미 재시도 시각이 미뤄져 있다). 삭제할 객체가 있으면 true.
   */
  private boolean markForDeletion(String objectKey) {
    var row =
        jdbc.sql(
                """
                SELECT delete_started_at IS NOT NULL
                FROM workflow_hub.pending_objects
                WHERE object_key = :key
                FOR UPDATE SKIP LOCKED
                """)
            .param("key", objectKey)
            .query(Boolean.class)
            .optional();
    if (row.isEmpty()) {
      return false;
    }
    if (row.get()) {
      return true;
    }
    boolean referenced =
        Boolean.TRUE.equals(
            jdbc.sql(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM workflow_hub.workflow_versions WHERE s3_object_key = :key)
                    """)
                .param("key", objectKey)
                .query(Boolean.class)
                .single());
    if (referenced) {
      // 커밋은 적용됐지만 요청이 결과를 확인하지 못한 경우다. 파일은 정상 버전의 원본이다.
      log.info("event=workflow.object_cleanup.kept_referenced objectKey={}", objectKey);
      jdbc.sql("DELETE FROM workflow_hub.pending_objects WHERE object_key = :key")
          .param("key", objectKey)
          .update();
      return false;
    }
    jdbc.sql(
            "UPDATE workflow_hub.pending_objects SET delete_started_at = clock_timestamp() WHERE object_key = :key")
        .param("key", objectKey)
        .update();
    return true;
  }
}
