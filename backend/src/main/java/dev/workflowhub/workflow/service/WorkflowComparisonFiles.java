package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

@Service
public class WorkflowComparisonFiles {
  private static final Logger log = LoggerFactory.getLogger(WorkflowComparisonFiles.class);
  private final JdbcClient jdbc;
  private final WorkflowObjectStore store;

  public WorkflowComparisonFiles(JdbcClient jdbc, WorkflowObjectStore store) {
    this.jdbc = jdbc;
    this.store = store;
  }

  StagedComparison stage(UUID baseVersionId, byte[] file) {
    UUID id = UUID.randomUUID();
    // PUT 응답 유실이나 프로세스 종료 뒤에도 만료 정리할 수 있도록 객체보다 행을 먼저 남긴다.
    Instant expiresAt =
        jdbc.sql(
                """
                WITH expiry AS (SELECT clock_timestamp() + interval '24 hours' AS time)
                INSERT INTO workflow_hub.workflow_comparisons
                    (id, base_version_id, expires_at, cleanup_after)
                SELECT :id, :baseVersionId, time, time FROM expiry
                RETURNING expires_at
                """)
            .param("id", id)
            .param("baseVersionId", baseVersionId)
            .query(OffsetDateTime.class)
            .single()
            .toInstant();
    try {
      store.put(objectKey(id), file);
    } catch (RuntimeException e) {
      log.error("event=workflow.comparison.storage_failed comparisonId={}", id, e);
      expireFailedUpload(id);
      throw new WorkflowUploadException(
          HttpStatus.SERVICE_UNAVAILABLE,
          "STORAGE_UNAVAILABLE",
          "Could not store the comparison file");
    }
    log.info(
        "event=workflow.comparison.staged comparisonId={} baseVersionId={} bytes={}",
        id,
        baseVersionId,
        file.length);
    return new StagedComparison(id, expiresAt);
  }

  byte[] read(UUID id) {
    return readObject(objectKey(id));
  }

  byte[] readObject(String objectKey) {
    try {
      return store.get(objectKey);
    } catch (RuntimeException e) {
      log.error("event=workflow.comparison.read_failed objectKey={}", objectKey, e);
      throw new WorkflowUploadException(
          HttpStatus.SERVICE_UNAVAILABLE,
          "STORAGE_UNAVAILABLE",
          "Could not read the workflow file");
    }
  }

  private void expireFailedUpload(UUID id) {
    // 타임아웃 뒤 PUT이 완료될 수 있어 즉시 삭제하지 않고 정리 기록을 유지한다.
    try {
      jdbc.sql(
              """
              UPDATE workflow_hub.workflow_comparisons
              SET expires_at = statement_timestamp(),
                  cleanup_after = statement_timestamp() + interval '5 minutes'
              WHERE id = :id
              """)
          .param("id", id)
          .update();
    } catch (RuntimeException e) {
      log.error("event=workflow.comparison.mark_failed_upload_failed comparisonId={}", id, e);
    }
  }

  @Scheduled(fixedDelay = 10, timeUnit = TimeUnit.SECONDS)
  void cleanExpired() {
    for (int processed = 0; processed < 100; processed++) {
      var due = claimExpired();
      if (due.isEmpty()) {
        return;
      }
      delete(due.get());
    }
  }

  private Optional<UUID> claimExpired() {
    // 삭제 직전에 한 행씩 선점하며 실패 시 유예 시간 뒤 다른 실행에서도 재시도할 수 있다.
    return jdbc.sql(
            """
            WITH due AS (
                SELECT id
                FROM workflow_hub.workflow_comparisons
                WHERE cleanup_after <= statement_timestamp()
                  AND expires_at <= statement_timestamp()
                ORDER BY cleanup_after, id
                LIMIT 1
                FOR UPDATE SKIP LOCKED
            )
            UPDATE workflow_hub.workflow_comparisons c
            SET cleanup_after = statement_timestamp() + interval '5 minutes'
            FROM due
            WHERE c.id = due.id
            RETURNING c.id
            """)
        .query(UUID.class)
        .optional();
  }

  private void delete(UUID comparisonId) {
    try {
      store.delete(objectKey(comparisonId));
      jdbc.sql("DELETE FROM workflow_hub.workflow_comparisons WHERE id = :id")
          .param("id", comparisonId)
          .update();
      log.info("event=workflow.comparison.deleted comparisonId={}", comparisonId);
    } catch (RuntimeException e) {
      log.error("event=workflow.comparison.cleanup_failed comparisonId={}", comparisonId, e);
    }
  }

  private static String objectKey(UUID id) {
    return "workflows/comparisons/" + id + ".json";
  }

  record StagedComparison(UUID id, Instant expiresAt) {}
}
