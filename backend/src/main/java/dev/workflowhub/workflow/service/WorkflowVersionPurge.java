package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.time.Duration;
import java.util.List;
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
 * 삭제 기한(delete_after)이 지난 버전의 S3 원본과 보안 검사 결과 객체를 지우고, 객체 키·해시·크기를 비워 정리 완료로 표시한다(#37, #57).
 *
 * <p>정리 작업은 한 행씩 선점해 delete_started_at을 먼저 커밋한 뒤 S3를 호출한다. 이 표시가 있으면 복구를 거절하므로, 지워지는 중인 원본을 가리키는
 * 버전이 되살아나지 않는다. 삭제가 실패하면 표시가 남고, 재시도 간격이 지난 뒤 다시 지운다. versioning을 끈 버킷을 전제로 하며 DeleteObject는 없는
 * 키에도 성공하므로 재시도해도 안전하다.
 *
 * <p>한 실행의 S3 삭제 호출 수는 {@link #MAX_DELETE_CALLS_PER_RUN}으로 제한한다. 검사 결과 객체는 검사 실행 행 단위로 지운 뒤 그 행의 키를
 * 비워 진행 상태를 남기고, 모든 결과 객체와 원본을 지운 뒤에만 버전을 정리 완료로 표시한다. 한도에 걸린 버전은 다음 실행에서 이어서 지운다.
 */
@Service
public class WorkflowVersionPurge {
  private static final Logger log = LoggerFactory.getLogger(WorkflowVersionPurge.class);
  private static final int MAX_PER_RUN = 100;
  static final int MAX_DELETE_CALLS_PER_RUN = 200;
  private static final int SCAN_ROWS_PER_BATCH = 50;

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
    int deleteBudget = MAX_DELETE_CALLS_PER_RUN;
    for (int processed = 0; processed < MAX_PER_RUN && deleteBudget > 0; processed++) {
      try {
        Optional<Claim> due = claimDue();
        if (due.isEmpty()) {
          return;
        }
        PurgeResult result = purge(due.get(), deleteBudget);
        deleteBudget -= result.deleteCalls();
        // S3 장애 중에는 한 건만 시도하고 멈춰, 호출 제한 시간만큼 스케줄러를 붙잡지 않는다. 한도에 걸려 미룬 버전이 있어도 멈춘다.
        if (result.stopRun()) {
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
   *
   * <p>처음 정리하는 행을 재시도 행보다 먼저 집는다. 한 버전의 객체 삭제가 계속 실패해도 기한이 더 늦은 다른 버전의 정리를 막지 않는다.
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
                ORDER BY (delete_started_at IS NOT NULL), delete_after, id
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

  /** 선점한 버전의 객체를 삭제 호출 한도 안에서 지운다. */
  private PurgeResult purge(Claim claim, int deleteBudget) {
    int calls = 0;
    try {
      while (true) {
        int rowLimit = Math.min(SCAN_ROWS_PER_BATCH, (deleteBudget - calls) / 2);
        // 한도가 남지 않았어도 한 행을 읽어 남은 결과 객체가 있는지 확인한다.
        List<ScanObjects> batch = scanObjectsForVersion(claim.versionId(), Math.max(rowLimit, 1));
        if (batch.isEmpty()) {
          break;
        }
        if (rowLimit == 0) {
          deferRemaining(claim, calls);
          return new PurgeResult(calls, true);
        }
        for (ScanObjects scan : batch) {
          calls++;
          store.delete(scan.serviceReportKey());
          calls++;
          store.delete(scan.assessmentKey());
          clearScanObjects(scan.scanRunId());
        }
        if (batch.size() < rowLimit) {
          break;
        }
      }
      if (calls >= deleteBudget) {
        deferRemaining(claim, calls);
        return new PurgeResult(calls, true);
      }
      calls++;
      store.delete(claim.objectKey());
    } catch (RuntimeException e) {
      // 삭제 시작 표시가 남아 있으므로 복구는 거절되고, 재시도 간격 뒤 다시 지운다. 이미 지운 결과 객체는 키를 비워 두었다.
      log.error(
          "event=workflow.version_purge.delete_failed versionId={} objectKey={}",
          claim.versionId(),
          claim.objectKey(),
          e);
      return new PurgeResult(calls, true);
    }
    transactions.executeWithoutResult(status -> markPurged(claim.versionId()));
    log.info(
        "event=workflow.version_purge.deleted versionId={} objectKey={} deleteCalls={}",
        claim.versionId(),
        claim.objectKey(),
        calls);
    return new PurgeResult(calls, false);
  }

  /** 한도에 걸려 남은 객체가 있는 버전을 다음 실행이 곧바로 이어받게 한다. 삭제 시작 표시는 유지해 복구를 계속 거절하고, 시각만 재시도 간격만큼 앞당긴다. */
  private void deferRemaining(Claim claim, int calls) {
    jdbc.sql(
            """
            UPDATE workflow_hub.workflow_versions
            SET delete_started_at = clock_timestamp() - make_interval(secs => :retrySeconds)
            WHERE id = :id AND purged_at IS NULL
            """)
        .param("retrySeconds", retryDelay.toMillis() / 1000.0)
        .param("id", claim.versionId())
        .update();
    log.info(
        "event=workflow.version_purge.deferred versionId={} deleteCalls={}",
        claim.versionId(),
        calls);
  }

  private List<ScanObjects> scanObjectsForVersion(UUID versionId, int limit) {
    return jdbc.sql(
            """
            SELECT id, service_report_s3_key, assessment_s3_key
            FROM workflow_hub.scan_runs
            WHERE workflow_version_id = :versionId AND service_report_s3_key IS NOT NULL
            ORDER BY id
            LIMIT :limit
            """)
        .param("versionId", versionId)
        .param("limit", limit)
        .query(
            (row, index) ->
                new ScanObjects(
                    row.getObject("id", UUID.class),
                    row.getString("service_report_s3_key"),
                    row.getString("assessment_s3_key")))
        .list();
  }

  /** 두 결과 객체를 모두 지운 검사 실행의 키를 비워 진행 상태를 남긴다. 두 키는 제약으로 함께 있거나 함께 비어 있다. */
  private void clearScanObjects(UUID scanRunId) {
    jdbc.sql(
            """
            UPDATE workflow_hub.scan_runs
            SET service_report_s3_key = NULL, assessment_s3_key = NULL
            WHERE id = :id
            """)
        .param("id", scanRunId)
        .update();
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

  private record ScanObjects(UUID scanRunId, String serviceReportKey, String assessmentKey) {}

  /** stopRun은 S3 삭제가 실패했거나 한도에 걸려 남은 객체를 다음 실행으로 미뤘을 때 true다. */
  private record PurgeResult(int deleteCalls, boolean stopRun) {}
}
