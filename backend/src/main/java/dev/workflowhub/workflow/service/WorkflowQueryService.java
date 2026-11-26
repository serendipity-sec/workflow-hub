package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

@Service
public class WorkflowQueryService {
  private static final Logger log = LoggerFactory.getLogger(WorkflowQueryService.class);
  private static final int DEFAULT_LIMIT = 20;
  private static final int MAX_LIMIT = 100;

  private static final String WORKFLOW_WITH_LATEST_VERSION =
      """
      SELECT w.id AS workflow_id, w.title, w.created_at AS workflow_created_at,
             w.deleted_at AS workflow_deleted_at, restore.restore_until,
             latest.version_id, latest.version_label, latest.version_created_at, latest.download_enabled,
             latest.content_sha256, latest.size_bytes,
             latest.version_deleted_at, latest.version_restore_until
      FROM workflow_hub.workflows w
      LEFT JOIN LATERAL (
          SELECT v.id AS version_id, v.version AS version_label, v.created_at AS version_created_at,
                 v.download_enabled, v.content_sha256, v.size_bytes,
                 v.deleted_at AS version_deleted_at, v.delete_after AS version_restore_until
          FROM workflow_hub.workflow_versions v
          WHERE v.workflow_id = w.id
            AND (v.deleted_at IS NULL OR (w.deleted_at IS NOT NULL AND (%1$s)))
          ORDER BY v.created_at DESC, v.id DESC
          LIMIT 1
      ) latest ON TRUE
      LEFT JOIN LATERAL (
          SELECT max(r.delete_after) AS restore_until
          FROM workflow_hub.workflow_versions r
          WHERE r.workflow_id = w.id AND w.deleted_at IS NOT NULL AND (%2$s)
      ) restore ON TRUE
      WHERE w.owner_id = :owner
        AND (w.deleted_at IS NULL OR (:includeDeleted AND restore.restore_until IS NOT NULL))
      """
          .formatted(WorkflowVersionStates.restorable("v"), WorkflowVersionStates.restorable("r"));
  private static final String WORKFLOW_CURSOR = "AND (w.created_at, w.id) < (:cursorAt, :cursorId)";
  private static final String VERSION_CURSOR = "AND (v.created_at, v.id) < (:cursorAt, :cursorId)";
  private static final String LIST_WORKFLOWS =
      WORKFLOW_WITH_LATEST_VERSION
          + """
      %s
      ORDER BY w.created_at DESC, w.id DESC
      LIMIT :fetchLimit
      """;
  private static final String LIST_VERSIONS =
      """
      SELECT page.version_id, page.version_label, page.version_created_at, page.download_enabled,
             page.content_sha256, page.size_bytes, page.version_deleted_at, page.version_restore_until
      FROM workflow_hub.workflows w
      LEFT JOIN LATERAL (
          SELECT v.id AS version_id, v.version AS version_label, v.created_at AS version_created_at,
                 v.download_enabled, v.content_sha256, v.size_bytes,
                 v.deleted_at AS version_deleted_at, v.delete_after AS version_restore_until
          FROM workflow_hub.workflow_versions v
          WHERE v.workflow_id = w.id
            AND (v.deleted_at IS NULL OR (:includeDeleted AND (%1$s)))
          %%s
          ORDER BY v.created_at DESC, v.id DESC
          LIMIT :fetchLimit
      ) page ON TRUE
      WHERE w.id = :workflowId AND w.owner_id = :owner
        AND (w.deleted_at IS NULL
             OR (:includeDeleted AND EXISTS (
                 SELECT 1 FROM workflow_hub.workflow_versions x
                 WHERE x.workflow_id = w.id AND (%2$s))))
      ORDER BY page.version_created_at DESC, page.version_id DESC
      """
          .formatted(WorkflowVersionStates.restorable("v"), WorkflowVersionStates.restorable("x"));
  private static final String FIND_DOWNLOAD =
      """
      SELECT w.title, v.version, v.s3_object_key, v.download_enabled
      FROM workflow_hub.workflows w
      JOIN workflow_hub.workflow_versions v ON v.workflow_id = w.id
      WHERE w.id = :workflowId AND w.owner_id = :owner AND v.id = :versionId
        AND w.deleted_at IS NULL AND v.deleted_at IS NULL
      """;
  private static final String UPDATE_DOWNLOAD_AVAILABILITY =
      """
      UPDATE workflow_hub.workflow_versions v
      SET download_enabled = :downloadEnabled
      FROM workflow_hub.workflows w
      WHERE v.workflow_id = w.id AND w.id = :workflowId AND w.owner_id = :owner
        AND v.id = :versionId AND w.deleted_at IS NULL AND v.deleted_at IS NULL
      """;

  private final JdbcClient jdbc;
  private final WorkflowObjectStore store;

  public WorkflowQueryService(JdbcClient jdbc, WorkflowObjectStore store) {
    this.jdbc = jdbc;
    this.store = store;
  }

  public WorkflowPage listWorkflows(
      String ownerId, Integer limit, String cursor, boolean includeDeleted) {
    int pageLimit = validateLimit(limit);
    List<WorkflowDetail> rows =
        pageQuery(LIST_WORKFLOWS, WORKFLOW_CURSOR, pageLimit, WorkflowCursor.decode(cursor))
            .param("owner", ownerId)
            .param("includeDeleted", includeDeleted)
            .query((rs, row) -> readWorkflow(rs))
            .list();
    List<WorkflowItem> items =
        rows.stream()
            .limit(pageLimit)
            .map(
                row ->
                    new WorkflowItem(
                        row.workflowId(),
                        row.title(),
                        row.latestVersion(),
                        row.deletedAt(),
                        row.restoreUntil()))
            .toList();
    String nextCursor = null;
    if (rows.size() > pageLimit) {
      WorkflowDetail last = rows.get(pageLimit - 1);
      nextCursor = new WorkflowCursor(last.createdAt(), last.workflowId()).encode();
    }
    log.debug("event=workflow.list.read count={} hasNext={}", items.size(), nextCursor != null);
    return new WorkflowPage(items, nextCursor);
  }

  public WorkflowDetail getWorkflow(String ownerId, String workflowId) {
    UUID id = parseId(workflowId, WorkflowQueryException::workflowNotFound);
    WorkflowDetail workflow =
        jdbc.sql(WORKFLOW_WITH_LATEST_VERSION + "AND w.id = :workflowId")
            .param("owner", ownerId)
            .param("includeDeleted", false)
            .param("workflowId", id)
            .query((rs, row) -> readWorkflow(rs))
            .optional()
            .orElseThrow(WorkflowQueryException::workflowNotFound);
    log.debug("event=workflow.detail.read workflowId={}", id);
    return workflow;
  }

  public VersionPage listVersions(
      String ownerId, String workflowId, Integer limit, String cursor, boolean includeDeleted) {
    UUID id = parseId(workflowId, WorkflowQueryException::workflowNotFound);
    int pageLimit = validateLimit(limit);
    List<VersionItem> rows =
        pageQuery(LIST_VERSIONS, VERSION_CURSOR, pageLimit, WorkflowCursor.decode(cursor))
            .param("workflowId", id)
            .param("owner", ownerId)
            .param("includeDeleted", includeDeleted)
            .query((rs, row) -> readVersion(rs))
            .list();
    if (rows.isEmpty()) {
      throw WorkflowQueryException.workflowNotFound();
    }
    // 소유한 워크플로에 해당 페이지의 버전이 없어도 조인은 워크플로 행을 남긴다.
    List<VersionItem> items =
        rows.getFirst() == null
            ? List.of()
            : List.copyOf(rows.subList(0, Math.min(pageLimit, rows.size())));
    String nextCursor = null;
    if (rows.size() > pageLimit) {
      VersionItem last = rows.get(pageLimit - 1);
      nextCursor = new WorkflowCursor(last.createdAt(), last.versionId()).encode();
    }
    log.debug(
        "event=workflow.versions.read workflowId={} count={} hasNext={}",
        id,
        items.size(),
        nextCursor != null);
    return new VersionPage(items, nextCursor);
  }

  public DownloadAvailability updateDownloadAvailability(
      String ownerId, String workflowId, String versionId, boolean downloadEnabled) {
    UUID workflow = parseId(workflowId, WorkflowQueryException::versionNotFound);
    UUID version = parseId(versionId, WorkflowQueryException::versionNotFound);
    int updated =
        jdbc.sql(UPDATE_DOWNLOAD_AVAILABILITY)
            .param("workflowId", workflow)
            .param("owner", ownerId)
            .param("versionId", version)
            .param("downloadEnabled", downloadEnabled)
            .update();
    if (updated == 0) {
      throw WorkflowQueryException.versionNotFound();
    }
    log.info(
        "event=workflow.download.availability_updated workflowId={} versionId={} downloadEnabled={}",
        workflow,
        version,
        downloadEnabled);
    return new DownloadAvailability(workflow, version, downloadEnabled);
  }

  public DownloadedVersion downloadVersion(String ownerId, String workflowId, String versionId) {
    UUID workflow = parseId(workflowId, WorkflowQueryException::versionNotFound);
    UUID version = parseId(versionId, WorkflowQueryException::versionNotFound);
    DownloadMetadata metadata =
        jdbc.sql(FIND_DOWNLOAD)
            .param("workflowId", workflow)
            .param("owner", ownerId)
            .param("versionId", version)
            .query(
                (rs, row) ->
                    new DownloadMetadata(
                        rs.getString("title"),
                        rs.getString("version"),
                        rs.getString("s3_object_key"),
                        rs.getBoolean("download_enabled")))
            .optional()
            .orElseThrow(WorkflowQueryException::versionNotFound);

    if (!metadata.downloadEnabled()) {
      throw WorkflowQueryException.downloadDisabled();
    }
    byte[] content;
    try {
      content = store.get(metadata.objectKey());
    } catch (RuntimeException e) {
      log.error(
          "event=workflow.download.storage_failed workflowId={} versionId={} objectKey={}",
          workflow,
          version,
          metadata.objectKey(),
          e);
      throw WorkflowQueryException.storageUnavailable();
    }
    log.debug(
        "event=workflow.download.read workflowId={} versionId={} size={}",
        workflow,
        version,
        content.length);
    return new DownloadedVersion(metadata.title(), metadata.versionLabel(), content);
  }

  private JdbcClient.StatementSpec pageQuery(
      String sql, String cursorCondition, int limit, WorkflowCursor cursor) {
    JdbcClient.StatementSpec query =
        jdbc.sql(sql.formatted(cursor == null ? "" : cursorCondition))
            .param("fetchLimit", limit + 1);
    if (cursor != null) {
      query
          .param("cursorAt", OffsetDateTime.ofInstant(cursor.createdAt(), ZoneOffset.UTC))
          .param("cursorId", cursor.id());
    }
    return query;
  }

  private static WorkflowDetail readWorkflow(ResultSet rs) throws SQLException {
    return new WorkflowDetail(
        rs.getObject("workflow_id", UUID.class),
        rs.getString("title"),
        readVersion(rs),
        rs.getObject("workflow_created_at", OffsetDateTime.class).toInstant(),
        instant(rs, "workflow_deleted_at"),
        instant(rs, "restore_until"));
  }

  private static VersionItem readVersion(ResultSet rs) throws SQLException {
    UUID id = rs.getObject("version_id", UUID.class);
    return id == null
        ? null
        : new VersionItem(
            id,
            rs.getString("version_label"),
            rs.getObject("version_created_at", OffsetDateTime.class).toInstant(),
            rs.getBoolean("download_enabled"),
            rs.getString("content_sha256"),
            sizeBytes(rs),
            instant(rs, "version_deleted_at"),
            instant(rs, "version_restore_until"));
  }

  private static Instant instant(ResultSet rs, String column) throws SQLException {
    OffsetDateTime value = rs.getObject(column, OffsetDateTime.class);
    return value == null ? null : value.toInstant();
  }

  /** 기존 버전은 크기가 NULL(미확인)이므로 0과 구분해 null로 읽는다. */
  private static Long sizeBytes(ResultSet rs) throws SQLException {
    long size = rs.getLong("size_bytes");
    return rs.wasNull() ? null : size;
  }

  static UUID parseId(String value, Supplier<WorkflowQueryException> notFound) {
    if (value != null && value.length() == 36) {
      try {
        UUID id = UUID.fromString(value);
        if (id.toString().equalsIgnoreCase(value)) {
          return id;
        }
      } catch (IllegalArgumentException e) {
        throw notFound.get();
      }
    }
    throw notFound.get();
  }

  private static int validateLimit(Integer limit) {
    if (limit == null) {
      return DEFAULT_LIMIT;
    }
    if (limit < 1 || limit > MAX_LIMIT) {
      throw WorkflowQueryException.invalidLimit();
    }
    return limit;
  }

  public record WorkflowPage(List<WorkflowItem> items, String nextCursor) {}

  public record VersionPage(List<VersionItem> items, String nextCursor) {}

  /**
   * deletedAt·restoreUntil은 삭제된 워크플로에만 있다. 그 latestVersion은 복구할 수 있는 버전 중 가장 최근 것이고, restoreUntil은
   * 복구할 수 있는 버전 중 가장 늦은 기한이다.
   */
  public record WorkflowItem(
      UUID workflowId,
      String title,
      VersionItem latestVersion,
      Instant deletedAt,
      Instant restoreUntil) {}

  public record WorkflowDetail(
      UUID workflowId,
      String title,
      VersionItem latestVersion,
      Instant createdAt,
      Instant deletedAt,
      Instant restoreUntil) {}

  /** sha256과 sizeBytes는 서버가 저장한 원본 바이트 기준이며, 기록하기 전의 버전은 null이다. */
  public record VersionItem(
      UUID versionId,
      String versionLabel,
      Instant createdAt,
      boolean downloadEnabled,
      String sha256,
      Long sizeBytes,
      Instant deletedAt,
      Instant restoreUntil) {}

  public record DownloadAvailability(UUID workflowId, UUID versionId, boolean downloadEnabled) {}

  public record DownloadedVersion(String title, String versionLabel, byte[] content) {}

  private record DownloadMetadata(
      String title, String versionLabel, String objectKey, boolean downloadEnabled) {}
}
