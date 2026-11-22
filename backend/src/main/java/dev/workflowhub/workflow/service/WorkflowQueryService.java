package dev.workflowhub.workflow.service;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
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
             latest.version_id, latest.version_label, latest.version_created_at
      FROM workflow_hub.workflows w
      LEFT JOIN LATERAL (
          SELECT id AS version_id, version AS version_label, created_at AS version_created_at
          FROM workflow_hub.workflow_versions
          WHERE workflow_id = w.id
          ORDER BY created_at DESC, id DESC
          LIMIT 1
      ) latest ON TRUE
      WHERE w.owner_id = :owner
      """;
  private static final String CURSOR_CONDITION = "AND (created_at, id) < (:cursorAt, :cursorId)";
  private static final String LIST_WORKFLOWS =
      WORKFLOW_WITH_LATEST_VERSION
          + """
      %s
      ORDER BY w.created_at DESC, w.id DESC
      LIMIT :fetchLimit
      """;
  private static final String LIST_VERSIONS =
      """
      SELECT page.version_id, page.version_label, page.version_created_at
      FROM workflow_hub.workflows w
      LEFT JOIN LATERAL (
          SELECT id AS version_id, version AS version_label, created_at AS version_created_at
          FROM workflow_hub.workflow_versions
          WHERE workflow_id = w.id
          %s
          ORDER BY created_at DESC, id DESC
          LIMIT :fetchLimit
      ) page ON TRUE
      WHERE w.id = :workflowId AND w.owner_id = :owner
      ORDER BY page.version_created_at DESC, page.version_id DESC
      """;

  private final JdbcClient jdbc;

  public WorkflowQueryService(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  public WorkflowPage listWorkflows(String ownerId, Integer limit, String cursor) {
    int pageLimit = validateLimit(limit);
    List<WorkflowDetail> rows =
        pageQuery(LIST_WORKFLOWS, pageLimit, WorkflowCursor.decode(cursor))
            .param("owner", ownerId)
            .query((rs, row) -> readWorkflow(rs))
            .list();
    List<WorkflowItem> items =
        rows.stream()
            .limit(pageLimit)
            .map(row -> new WorkflowItem(row.workflowId(), row.title(), row.latestVersion()))
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
    UUID id = parseWorkflowId(workflowId);
    WorkflowDetail workflow =
        jdbc.sql(WORKFLOW_WITH_LATEST_VERSION + "AND w.id = :workflowId")
            .param("owner", ownerId)
            .param("workflowId", id)
            .query((rs, row) -> readWorkflow(rs))
            .optional()
            .orElseThrow(WorkflowQueryException::workflowNotFound);
    log.debug("event=workflow.detail.read workflowId={}", id);
    return workflow;
  }

  public VersionPage listVersions(String ownerId, String workflowId, Integer limit, String cursor) {
    UUID id = parseWorkflowId(workflowId);
    int pageLimit = validateLimit(limit);
    List<VersionItem> rows =
        pageQuery(LIST_VERSIONS, pageLimit, WorkflowCursor.decode(cursor))
            .param("workflowId", id)
            .param("owner", ownerId)
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

  private JdbcClient.StatementSpec pageQuery(String sql, int limit, WorkflowCursor cursor) {
    JdbcClient.StatementSpec query =
        jdbc.sql(sql.formatted(cursor == null ? "" : CURSOR_CONDITION))
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
        rs.getObject("workflow_created_at", OffsetDateTime.class).toInstant());
  }

  private static VersionItem readVersion(ResultSet rs) throws SQLException {
    UUID id = rs.getObject("version_id", UUID.class);
    return id == null
        ? null
        : new VersionItem(
            id,
            rs.getString("version_label"),
            rs.getObject("version_created_at", OffsetDateTime.class).toInstant());
  }

  private static UUID parseWorkflowId(String workflowId) {
    if (workflowId != null && workflowId.length() == 36) {
      try {
        UUID id = UUID.fromString(workflowId);
        if (id.toString().equalsIgnoreCase(workflowId)) {
          return id;
        }
      } catch (IllegalArgumentException e) {
        throw WorkflowQueryException.workflowNotFound();
      }
    }
    throw WorkflowQueryException.workflowNotFound();
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

  public record WorkflowItem(UUID workflowId, String title, VersionItem latestVersion) {}

  public record WorkflowDetail(
      UUID workflowId, String title, VersionItem latestVersion, Instant createdAt) {}

  public record VersionItem(UUID versionId, String versionLabel, Instant createdAt) {}
}
