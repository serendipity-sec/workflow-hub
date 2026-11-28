package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.time.Duration;
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
 * 삭제 기한(delete_after)이 지난 버전의 S3 원본을 지우고, 객체 키·해시·크기를 비워 정리 완료로 표시한다(#37).
 *
 * <p>정리 작업은 한 행씩 선점해 delete_started_at을 먼저 커밋한 뒤 S3를 호출한다. 이 표시가 있으면 복구를 거절하므로, 지워지는 중인 원본을 가리키는
 * 버전이 되살아나지 않는다. 삭제가 실패하면 표시가 남고, 재시도 간격이 지난 뒤 다시 지운다. versioning을 끈 버킷을 전제로 하며 DeleteObject는 없는
 * 키에도 성공하므로 재시도해도 안전하다.
 */
@Service
public class WorkflowVersionPurge {
  private static final Logger log = LoggerFactory.getLogger(WorkflowVersionPurge.class);
  private static final int MAX_PER_RUN = 100;

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final WorkflowObjectStore store;
  private final Duration retryDelay;

  public WorkflowVersionPurge(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      WorkflowObjectStore store,
      @Value("${app.storage.cleanup-retry-delay}") Duration retryDelay) {
    if (retryDelay.isZero() || retryDelay.isNegative()) {
      throw new IllegalArgumentException("CLEANUP_RETRY_DELAY must be positive");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.store = store;
    this.retryDelay = retryDelay;
  }

  @Scheduled(fixedDelayString = "${app.storage.cleanup-interval}")
  public void purgeDue() {
    for (int processed = 0; processed < MAX_PER_RUN; processed++) {
      try {
        Optional<Claim> due = claimDue();
        if (due.isEmpty()) {
          return;
        }
        // S3 장애 중에는 한 건만 시도하고 멈춰, 호출 제한 시간만큼 스케줄러를 붙잡지 않는다.
        if (!purge(due.get())) {
          return;
        }
      } catch (RuntimeException e) {
        // DB 상태를 확인하지 못하면 다음 실행에서 다시 시도한다. 원본은 지우지 않았다.
        log.error("event=workflow.version_purge.run_failed", e);
        return;
      }
    }
  }

  /**
   * 기한이 지났고 아직 정리하지 않은 행을 한 건 선점해 삭제 시작을 표시한다. 이전 시도가 실패했거나 중단된 행은 재시도 간격이 지나야 다시 집는다. 복구와 같은 행을 두고
   * 겹치면 복구가 끝나기를 기다리지 않고 건너뛴다.
   */
  private Optional<Claim> claimDue() {
    return jdbc.sql(
            """
            WITH due AS (
                SELECT id
                FROM workflow_hub.workflow_versions
                WHERE deleted_at IS NOT NULL AND purged_at IS NULL
                  AND delete_after <= statement_timestamp()
                  AND (delete_started_at IS NULL
                       OR delete_started_at <= statement_timestamp() - make_interval(secs => :retrySeconds))
                ORDER BY delete_after, id
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE workflow_hub.workflow_versions v
            SET delete_started_at = clock_timestamp()
            FROM due
            WHERE v.id = due.id
            RETURNING v.id, v.s3_object_key
            """)
        .param("retrySeconds", retryDelay.toMillis() / 1000.0)
        .query(
            (row, index) ->
                new Claim(row.getObject("id", UUID.class), row.getString("s3_object_key")))
        .optional();
  }

  /** 처리를 계속해도 되면 true. S3 삭제가 실패하면 false다. */
  private boolean purge(Claim claim) {
    try {
      store.delete(claim.objectKey());
      for (String scanObjectKey : scanObjectKeysForVersion(claim.versionId())) {
        store.delete(scanObjectKey);
      }
    } catch (RuntimeException e) {
      // 삭제 시작 표시가 남아 있으므로 복구는 거절되고, 재시도 간격 뒤 다시 지운다.
      log.error(
          "event=workflow.version_purge.delete_failed versionId={} objectKey={}",
          claim.versionId(),
          claim.objectKey(),
          e);
      return false;
    }
    transactions.executeWithoutResult(status -> markPurged(claim.versionId()));
    log.info(
        "event=workflow.version_purge.deleted versionId={} objectKey={}",
        claim.versionId(),
        claim.objectKey());
    return true;
  }

  private java.util.List<String> scanObjectKeysForVersion(UUID versionId) {
    return jdbc.sql(
            """
            SELECT service_report_s3_key AS key
            FROM workflow_hub.scan_runs
            WHERE workflow_version_id = :versionId AND service_report_s3_key IS NOT NULL
            UNION
            SELECT assessment_s3_key AS key
            FROM workflow_hub.scan_runs
            WHERE workflow_version_id = :versionId AND assessment_s3_key IS NOT NULL
            """)
        .param("versionId", versionId)
        .query(String.class)
        .list();
  }

  /**
   * 원본이 정리됐거나 이미 없는 것이 확인된 버전을 정리 완료로 표시한다. 호출하는 쪽의 트랜잭션 안에서 실행한다.
   *
   * <p>워크플로 행을 먼저 잠근 뒤 버전 행을 바꾼다. 삭제·복구·등록이 같은 순서로 잠그므로 서로 기다리다 교착하지 않는다. 워크플로의 모든 버전이 정리되면 제목도
   * 비운다.
   */
  void markPurged(UUID versionId) {
    var workflowId =
        jdbc.sql("SELECT workflow_id FROM workflow_hub.workflow_versions WHERE id = :id")
            .param("id", versionId)
            .query(UUID.class)
            .optional();
    if (workflowId.isEmpty()) {
      return;
    }
    jdbc.sql("SELECT id FROM workflow_hub.workflows WHERE id = :id FOR UPDATE")
        .param("id", workflowId.get())
        .query(UUID.class)
        .optional();
    int updated =
        jdbc.sql(
                """
                UPDATE workflow_hub.workflow_versions
                SET purged_at = clock_timestamp(),
                    delete_started_at = coalesce(delete_started_at, clock_timestamp()),
                    s3_object_key = NULL, content_sha256 = NULL, size_bytes = NULL
                WHERE id = :id AND deleted_at IS NOT NULL AND purged_at IS NULL
                """)
            .param("id", versionId)
            .update();
    if (updated == 0) {
      return;
    }
    jdbc.sql(
            """
            UPDATE workflow_hub.scan_runs
            SET service_report_s3_key = NULL, assessment_s3_key = NULL
            WHERE workflow_version_id = :versionId
              AND (service_report_s3_key IS NOT NULL OR assessment_s3_key IS NOT NULL)
            """)
        .param("versionId", versionId)
        .update();
    jdbc.sql(
            """
            UPDATE workflow_hub.workflows w
            SET title = NULL
            WHERE w.id = :workflowId AND w.deleted_at IS NOT NULL AND w.title IS NOT NULL
              AND NOT EXISTS (
                  SELECT 1 FROM workflow_hub.workflow_versions v
                  WHERE v.workflow_id = w.id AND v.purged_at IS NULL)
            """)
        .param("workflowId", workflowId.get())
        .update();
  }

  private record Claim(UUID versionId, String objectKey) {}
}
