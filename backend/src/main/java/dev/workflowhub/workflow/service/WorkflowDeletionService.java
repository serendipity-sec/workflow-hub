package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Duration;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * 소유자의 버전·워크플로 삭제와 복구(#37).
 *
 * <p>삭제는 행을 지우지 않고 deleted_at을 표시하므로 버전 번호가 재사용되지 않는다. 삭제를 수락하는 즉시 조회·다운로드·비교에서 제외되고, 원본은 복구
 * 기간(delete_after) 뒤 {@link WorkflowVersionPurge}가 지운다. 버전마다 기한이 따로이므로 먼저 개별 삭제한 버전의 기한은 나중의 워크플로
 * 삭제와 무관하다.
 *
 * <p>삭제·복구는 워크플로 행을 먼저 잠근 뒤 버전 행을 바꾼다. 복구는 S3 확인을 잠금 밖에서 하고, 잠금 안에서 상태를 다시 확인한다. 정리 작업이 그 사이에 삭제를
 * 시작했다면 복구는 거절된다.
 */
@Service
public class WorkflowDeletionService {
  private static final Logger log = LoggerFactory.getLogger(WorkflowDeletionService.class);

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final WorkflowObjectStore store;
  private final Duration grace;

  public WorkflowDeletionService(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      WorkflowObjectStore store,
      @Value("${app.deletion.grace}") Duration grace) {
    if (grace.isZero() || grace.isNegative()) {
      throw new IllegalArgumentException("WORKFLOW_DELETE_GRACE must be positive");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.store = store;
    this.grace = grace;
  }

  /** 살아 있는 버전이 이 하나뿐이면 워크플로 전체를 삭제한다. */
  public Deletion deleteVersion(String owner, String workflowId, String versionId) {
    UUID workflow = parseId(workflowId, WorkflowQueryException::versionNotFound);
    UUID version = parseId(versionId, WorkflowQueryException::versionNotFound);
    Deletion result =
        transactions.execute(
            status -> {
              lockAliveWorkflow(owner, workflow, WorkflowQueryException::versionNotFound);
              requireAliveVersion(workflow, version);
              long alive =
                  jdbc.sql(
                          "SELECT count(*) FROM workflow_hub.workflow_versions WHERE workflow_id = :id AND deleted_at IS NULL")
                      .param("id", workflow)
                      .query(Long.class)
                      .single();
              OffsetDateTime now = databaseNow();
              OffsetDateTime after = now.plus(grace);
              if (alive > 1) {
                jdbc.sql(
                        "UPDATE workflow_hub.workflow_versions SET deleted_at = :now, delete_after = :after WHERE id = :id")
                    .param("now", now)
                    .param("after", after)
                    .param("id", version)
                    .update();
                return new Deletion(workflow, version, false, now.toInstant(), after.toInstant());
              }
              deleteWorkflowRows(workflow, now, after);
              return new Deletion(workflow, version, true, now.toInstant(), after.toInstant());
            });
    log.info(
        "event=workflow.version.deleted workflowId={} versionId={} workflowDeleted={} restoreUntil={}",
        workflow,
        version,
        result.workflowDeleted(),
        result.restoreUntil());
    return result;
  }

  /** 아직 살아 있는 버전을 모두 같은 시각에 삭제한다. 이미 개별 삭제한 버전은 자기 기한을 유지한다. */
  public Deletion deleteWorkflow(String owner, String workflowId) {
    UUID workflow = parseId(workflowId, WorkflowQueryException::workflowNotFound);
    Deletion result =
        transactions.execute(
            status -> {
              lockAliveWorkflow(owner, workflow, WorkflowQueryException::workflowNotFound);
              OffsetDateTime now = databaseNow();
              OffsetDateTime after = now.plus(grace);
              deleteWorkflowRows(workflow, now, after);
              return new Deletion(workflow, null, true, now.toInstant(), after.toInstant());
            });
    log.info(
        "event=workflow.deleted workflowId={} restoreUntil={}", workflow, result.restoreUntil());
    return result;
  }

  /** 삭제된 워크플로의 버전을 복구하면 워크플로도 함께 되살린다. 같이 삭제된 다른 버전은 삭제 상태로 둔다. */
  public Restoration restoreVersion(String owner, String workflowId, String versionId) {
    UUID workflow = parseId(workflowId, WorkflowQueryException::versionNotFound);
    UUID version = parseId(versionId, WorkflowQueryException::versionNotFound);
    var row =
        jdbc.sql(
                """
                SELECT v.s3_object_key, v.size_bytes, v.deleted_at, v.purged_at, v.delete_started_at,
                       v.delete_after > clock_timestamp() AS within_period
                FROM workflow_hub.workflow_versions v
                JOIN workflow_hub.workflows w ON w.id = v.workflow_id
                WHERE w.id = :workflowId AND w.owner_id = :owner AND v.id = :versionId
                """)
            .param("workflowId", workflow)
            .param("owner", owner)
            .param("versionId", version)
            .query(
                (rs, index) ->
                    new RestoreRow(
                        rs.getString("s3_object_key"),
                        nullableLong(rs, "size_bytes"),
                        rs.getObject("deleted_at") != null,
                        rs.getObject("purged_at") != null,
                        rs.getObject("delete_started_at") != null,
                        rs.getBoolean("within_period")))
            .optional()
            .orElseThrow(WorkflowQueryException::versionNotFound);
    if (!row.deleted()) {
      throw WorkflowQueryException.notDeleted();
    }
    if (row.purged()) {
      throw WorkflowQueryException.versionNotFound();
    }
    if (row.deleteStarted() || !row.withinPeriod()) {
      throw WorkflowQueryException.restoreUnavailable();
    }

    // S3가 객체가 없다고 답해도 행은 건드리지 않는다. 버킷·리전 설정 오류로 없는 것처럼 보이는 경우에도 복구할 수 있는 버전을 잃지 않도록, 기한 뒤 정리 작업에
    // 맡긴다.
    if (!originalIsAvailable(workflow, version, row.objectKey(), row.sizeBytes())) {
      throw WorkflowQueryException.restoreUnavailable();
    }

    boolean workflowRestored =
        Boolean.TRUE.equals(
            transactions.execute(
                status -> {
                  lockWorkflow(owner, workflow, WorkflowQueryException::versionNotFound);
                  if (!restoreRow(workflow, version, null)) {
                    // 확인하는 사이 다른 요청이 같은 버전을 이미 복구했다면 복구 불가가 아니라 삭제 상태가 아닌 것이다.
                    throw versionIsAlive(version)
                        ? WorkflowQueryException.notDeleted()
                        : WorkflowQueryException.restoreUnavailable();
                  }
                  return reviveWorkflow(workflow);
                }));
    log.info(
        "event=workflow.version.restored workflowId={} versionId={} workflowRestored={}",
        workflow,
        version,
        workflowRestored);
    return new Restoration(workflow, workflowRestored, List.of(version), List.of());
  }

  /**
   * 워크플로 삭제 때 함께 삭제된 버전 중 복구할 수 있는 것을 되살린다. 원본이 없거나 크기가 기록과 다른 버전은 행을 바꾸지 않고 응답에 복구하지 못한 버전으로
   * 알린다(기한이 지나면 정리 작업이 처리한다). 하나도 되살리지 못하면 워크플로도 복구하지 않는다.
   */
  public Restoration restoreWorkflow(String owner, String workflowId) {
    UUID workflow = parseId(workflowId, WorkflowQueryException::workflowNotFound);
    var header = readHeader(workflow, owner).orElseThrow(WorkflowQueryException::workflowNotFound);
    if (header.deletedAt() == null) {
      throw WorkflowQueryException.notDeleted();
    }
    if (header.scrubbed()) {
      throw WorkflowQueryException.workflowNotFound();
    }

    List<BatchVersion> batch =
        jdbc.sql(
                """
                SELECT v.id, v.s3_object_key, v.size_bytes, (%s) AS restorable
                FROM workflow_hub.workflow_versions v
                WHERE v.workflow_id = :workflowId AND v.deleted_at = :deletedAt
                ORDER BY v.created_at, v.id
                """
                    .formatted(WorkflowVersionStates.restorable("v")))
            .param("workflowId", workflow)
            .param("deletedAt", header.deletedAt())
            .query(
                (rs, index) ->
                    new BatchVersion(
                        rs.getObject("id", UUID.class),
                        rs.getString("s3_object_key"),
                        nullableLong(rs, "size_bytes"),
                        rs.getBoolean("restorable")))
            .list();

    List<UUID> candidates = new ArrayList<>();
    List<UUID> unavailable = new ArrayList<>();
    for (BatchVersion version : batch) {
      if (!version.restorable()) {
        unavailable.add(version.id());
        continue;
      }
      if (originalIsAvailable(workflow, version.id(), version.objectKey(), version.sizeBytes())) {
        candidates.add(version.id());
      } else {
        unavailable.add(version.id());
      }
    }
    if (candidates.isEmpty()) {
      throw WorkflowQueryException.restoreUnavailable();
    }

    Restoration result =
        transactions.execute(
            status -> {
              lockWorkflow(owner, workflow, WorkflowQueryException::workflowNotFound);
              // deleted_at이 NULL(이미 복구됨)이어도 행은 있으므로 NULL을 담을 수 있는 객체로 읽는다.
              OffsetDateTime current =
                  readHeader(workflow, owner)
                      .orElseThrow(WorkflowQueryException::workflowNotFound)
                      .deletedAt();
              // 확인하는 사이 다른 요청이 이미 워크플로를 되살렸거나, 되살린 뒤 다시 삭제한 경우다.
              if (current == null) {
                throw WorkflowQueryException.notDeleted();
              }
              if (!current.equals(header.deletedAt())) {
                throw WorkflowQueryException.restoreUnavailable();
              }
              List<UUID> restored = new ArrayList<>();
              List<UUID> notRestored = new ArrayList<>(unavailable);
              for (UUID id : candidates) {
                if (restoreRow(workflow, id, header.deletedAt())) {
                  restored.add(id);
                } else {
                  notRestored.add(id);
                }
              }
              if (restored.isEmpty()) {
                throw WorkflowQueryException.restoreUnavailable();
              }
              reviveWorkflow(workflow);
              return new Restoration(workflow, true, restored, notRestored);
            });
    log.info(
        "event=workflow.restored workflowId={} restored={} unavailable={}",
        workflow,
        result.restoredVersionIds().size(),
        result.unavailableVersionIds().size());
    return result;
  }

  /** 소유한 워크플로의 삭제 시각과 제목 정리 여부. deletedAt이 null이면 삭제 상태가 아니다. */
  private Optional<WorkflowHeader> readHeader(UUID workflow, String owner) {
    return jdbc.sql(
            "SELECT deleted_at, title IS NULL AS scrubbed FROM workflow_hub.workflows WHERE id = :id AND owner_id = :owner")
        .param("id", workflow)
        .param("owner", owner)
        .query(
            (rs, index) ->
                new WorkflowHeader(
                    rs.getObject("deleted_at", OffsetDateTime.class), rs.getBoolean("scrubbed")))
        .optional();
  }

  private void deleteWorkflowRows(UUID workflow, OffsetDateTime now, OffsetDateTime after) {
    jdbc.sql("UPDATE workflow_hub.workflows SET deleted_at = :now WHERE id = :id")
        .param("now", now)
        .param("id", workflow)
        .update();
    jdbc.sql(
            """
            UPDATE workflow_hub.workflow_versions
            SET deleted_at = :now, delete_after = :after
            WHERE workflow_id = :id AND deleted_at IS NULL
            """)
        .param("now", now)
        .param("after", after)
        .param("id", workflow)
        .update();
  }

  /**
   * 한 버전을 복구한다. batchDeletedAt이 있으면 그 워크플로 삭제 때 함께 삭제된 버전만 대상이다. 상태가 바뀌었다면(정리 시작, 기간 만료, 이미 복구)
   * false다.
   */
  private boolean restoreRow(UUID workflow, UUID version, OffsetDateTime batchDeletedAt) {
    String batchCondition = batchDeletedAt == null ? "" : "AND v.deleted_at = :batch";
    var update =
        jdbc.sql(
                """
                UPDATE workflow_hub.workflow_versions v
                SET deleted_at = NULL, delete_after = NULL
                WHERE v.id = :id AND v.workflow_id = :workflowId
                  AND %s %s
                """
                    .formatted(WorkflowVersionStates.restorable("v"), batchCondition))
            .param("id", version)
            .param("workflowId", workflow);
    if (batchDeletedAt != null) {
      update = update.param("batch", batchDeletedAt);
    }
    return update.update() > 0;
  }

  private boolean versionIsAlive(UUID version) {
    return Boolean.TRUE.equals(
        jdbc.sql("SELECT deleted_at IS NULL FROM workflow_hub.workflow_versions WHERE id = :id")
            .param("id", version)
            .query(Boolean.class)
            .optional()
            .orElse(false));
  }

  /** 삭제 상태였던 워크플로를 되살렸으면 true. */
  private boolean reviveWorkflow(UUID workflow) {
    return jdbc.sql(
                "UPDATE workflow_hub.workflows SET deleted_at = NULL WHERE id = :id AND deleted_at IS NOT NULL")
            .param("id", workflow)
            .update()
        > 0;
  }

  /**
   * 원본이 저장소에 있고 기록된 크기와 같으면 true. 없거나 크기가 다르면 false이며 어느 쪽이든 행을 바꾸지 않는다. 저장소를 확인하지 못하면 503으로 중단한다.
   */
  private boolean originalIsAvailable(UUID workflow, UUID version, String key, Long expectedSize) {
    OptionalLong size;
    try {
      size = store.size(key);
    } catch (RuntimeException e) {
      log.error(
          "event=workflow.restore.storage_failed workflowId={} versionId={} objectKey={}",
          workflow,
          version,
          key,
          e);
      throw WorkflowQueryException.storageUnavailable();
    }
    if (size.isEmpty()) {
      log.warn(
          "event=workflow.restore.object_missing workflowId={} versionId={} objectKey={}",
          workflow,
          version,
          key);
      return false;
    }
    if (expectedSize != null && expectedSize != size.getAsLong()) {
      log.error(
          "event=workflow.restore.size_mismatch workflowId={} versionId={} objectKey={} expected={} actual={}",
          workflow,
          version,
          key,
          expectedSize,
          size.getAsLong());
      return false;
    }
    return true;
  }

  private void lockAliveWorkflow(
      String owner, UUID workflow, Supplier<WorkflowQueryException> notFound) {
    jdbc.sql(
            "SELECT id FROM workflow_hub.workflows WHERE id = :id AND owner_id = :owner AND deleted_at IS NULL FOR UPDATE")
        .param("id", workflow)
        .param("owner", owner)
        .query(UUID.class)
        .optional()
        .orElseThrow(notFound);
  }

  private void lockWorkflow(
      String owner, UUID workflow, Supplier<WorkflowQueryException> notFound) {
    jdbc.sql(
            "SELECT id FROM workflow_hub.workflows WHERE id = :id AND owner_id = :owner FOR UPDATE")
        .param("id", workflow)
        .param("owner", owner)
        .query(UUID.class)
        .optional()
        .orElseThrow(notFound);
  }

  private void requireAliveVersion(UUID workflow, UUID version) {
    jdbc.sql(
            "SELECT id FROM workflow_hub.workflow_versions WHERE id = :id AND workflow_id = :workflowId AND deleted_at IS NULL")
        .param("id", version)
        .param("workflowId", workflow)
        .query(UUID.class)
        .optional()
        .orElseThrow(WorkflowQueryException::versionNotFound);
  }

  /** 한 트랜잭션 안의 모든 행에 같은 값을 쓰기 위해 시각을 한 번만 읽는다. */
  private OffsetDateTime databaseNow() {
    return jdbc.sql("SELECT clock_timestamp()")
        .query((rs, index) -> rs.getObject(1, OffsetDateTime.class))
        .single();
  }

  private static Long nullableLong(ResultSet rs, String column) throws SQLException {
    long value = rs.getLong(column);
    return rs.wasNull() ? null : value;
  }

  private static UUID parseId(String value, Supplier<WorkflowQueryException> notFound) {
    return WorkflowQueryService.parseId(value, notFound);
  }

  private record RestoreRow(
      String objectKey,
      Long sizeBytes,
      boolean deleted,
      boolean purged,
      boolean deleteStarted,
      boolean withinPeriod) {}

  private record WorkflowHeader(OffsetDateTime deletedAt, boolean scrubbed) {}

  private record BatchVersion(UUID id, String objectKey, Long sizeBytes, boolean restorable) {}

  /** versionId는 워크플로 전체를 삭제한 요청에서는 null이다. restoreUntil 이후에는 복구할 수 없다. */
  public record Deletion(
      UUID workflowId,
      UUID versionId,
      boolean workflowDeleted,
      Instant deletedAt,
      Instant restoreUntil) {}

  public record Restoration(
      UUID workflowId,
      boolean workflowRestored,
      List<UUID> restoredVersionIds,
      List<UUID> unavailableVersionIds) {}
}
