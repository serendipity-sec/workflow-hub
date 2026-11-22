package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.service.WorkflowUploadService.UploadResult;
import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

@Service
public class WorkflowVersionService {
  private static final Logger log = LoggerFactory.getLogger(WorkflowVersionService.class);
  private static final Pattern VERSION_LABEL =
      Pattern.compile("v([1-9][0-9]*)(?:[.]([1-9][0-9]*))?");
  private static final String OWNED_WORKFLOW =
      "SELECT id FROM workflow_hub.workflows WHERE id = :id AND owner_id = :owner";
  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final WorkflowObjectStore store;
  private final WorkflowComparisonFiles files;
  private final WorkflowGraphComparison graphs;

  public WorkflowVersionService(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      WorkflowObjectStore store,
      WorkflowComparisonFiles files,
      WorkflowGraphComparison graphs) {
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.store = store;
    this.files = files;
    this.graphs = graphs;
  }

  public Comparison compare(String owner, String workflowPath, String versionPath, byte[] file) {
    UUID workflowId =
        resourceId(workflowPath, "WORKFLOW_VERSION_NOT_FOUND", "Workflow version not found");
    UUID versionId =
        resourceId(versionPath, "WORKFLOW_VERSION_NOT_FOUND", "Workflow version not found");
    var base =
        jdbc.sql(
                """
                SELECT v.id, v.version, v.created_at, v.s3_object_key
                FROM workflow_hub.workflow_versions v
                JOIN workflow_hub.workflows w ON w.id = v.workflow_id
                WHERE w.owner_id = :owner AND v.workflow_id = :workflowId AND v.id = :versionId
                """)
            .param("owner", owner)
            .param("workflowId", workflowId)
            .param("versionId", versionId)
            .query((row, index) -> new StoredVersion(version(row), row.getString("s3_object_key")))
            .optional()
            .orElseThrow(
                () -> notFound("WORKFLOW_VERSION_NOT_FOUND", "Workflow version not found"));
    requireCurrentBase(workflowId, base.version(), UpdateType.MINOR);
    var diff = graphs.compare(() -> files.readObject(base.objectKey()), file);
    var staged = files.stage(versionId, file);
    return new Comparison(staged.id(), base.version(), staged.expiresAt(), diff);
  }

  public UploadResult register(
      String owner, String workflowPath, String key, UUID comparisonId, UpdateType updateType) {
    WorkflowUploadService.requireValidKey(key);
    UUID workflowId = resourceId(workflowPath, "WORKFLOW_NOT_FOUND", "Workflow not found");
    requireOwnedWorkflow(owner, workflowId, false);
    String fingerprint = "register-version:" + workflowId + ":" + comparisonId + ":" + updateType;
    var previous = replay(owner, key, fingerprint);
    if (previous.isPresent()) {
      return previous.get();
    }

    byte[] bytes;
    try {
      bytes = readRegistrationFile(workflowId, comparisonId, updateType);
    } catch (WorkflowUploadException e) {
      // 첫 조회 뒤 같은 요청이 커밋됐다면 기준 변경이나 만료보다 그 결과가 우선한다.
      return replay(owner, key, fingerprint).orElseThrow(() -> e);
    }
    UUID versionId = UUID.randomUUID();
    String objectKey = "workflows/" + workflowId + "/" + versionId + ".json";
    try {
      store.put(objectKey, bytes);
    } catch (RuntimeException e) {
      log.error("event=workflow.version.storage_failed objectKey={}", objectKey, e);
      discardVersionObject(objectKey);
      return replay(owner, key, fingerprint)
          .orElseThrow(
              () ->
                  new WorkflowUploadException(
                      HttpStatus.SERVICE_UNAVAILABLE,
                      "STORAGE_UNAVAILABLE",
                      "Could not store the version file"));
    }

    var wroteRows = new AtomicBoolean(false);
    UploadResult result;
    try {
      result =
          transactions.execute(
              status -> {
                // 객체 쓰기는 잠금 전에 끝내고, 잠금 아래 기준과 재시도 여부를 다시 확인한다.
                requireOwnedWorkflow(owner, workflowId, true);
                var alreadySaved = replay(owner, key, fingerprint);
                if (alreadySaved.isPresent()) {
                  return alreadySaved.get();
                }
                var base = findComparisonBase(workflowId, comparisonId);
                VersionNumber number = requireCurrentBase(workflowId, base, updateType);
                String label = number.next(updateType).label();
                insertVersion(workflowId, versionId, label, objectKey);
                recordRequest(owner, key, fingerprint, workflowId, versionId);
                wroteRows.set(true);
                return new UploadResult(workflowId, versionId, label);
              });
    } catch (RuntimeException e) {
      if (wroteRows.get()) {
        // 커밋 응답이 유실되었을 수 있으므로 이 단계에서는 등록 파일을 보존한다.
        log.error("event=workflow.version.commit_unknown objectKey={}", objectKey, e);
        Optional<UploadResult> committed;
        try {
          committed = confirmCommit(owner, key, fingerprint);
        } catch (WorkflowUploadException conflict) {
          // 같은 키가 다른 입력으로 이미 커밋되어 있으면 이 요청의 행은 남지 않았다.
          discardVersionObject(objectKey);
          throw conflict;
        }
        if (committed.isPresent()) {
          if (!committed.get().versionId().equals(versionId)) {
            // 같은 키의 다른 요청이 먼저 커밋했으므로 이 요청의 객체는 어떤 행도 가리키지 않는다.
            discardVersionObject(objectKey);
          }
          return committed.get();
        }
      } else {
        discardVersionObject(objectKey);
        if (e instanceof DuplicateKeyException) {
          var winner = replay(owner, key, fingerprint);
          if (winner.isPresent()) {
            return winner.get();
          }
        }
      }
      throw e;
    }

    if (!wroteRows.get()) {
      discardVersionObject(objectKey);
    } else {
      log.info(
          "event=workflow.version.committed workflowId={} versionId={} version={} comparisonId={}",
          workflowId,
          versionId,
          result.versionLabel(),
          comparisonId);
    }
    return result;
  }

  private byte[] readRegistrationFile(UUID workflowId, UUID comparisonId, UpdateType type) {
    requireCurrentBase(workflowId, findComparisonBase(workflowId, comparisonId), type);
    try {
      return files.read(comparisonId);
    } catch (WorkflowUploadException e) {
      // 보관 기간이 읽기 도중 끝난 경우에도 만료로 응답한다.
      findComparisonBase(workflowId, comparisonId);
      throw e;
    }
  }

  private void requireOwnedWorkflow(String owner, UUID workflowId, boolean lock) {
    jdbc.sql(lock ? OWNED_WORKFLOW + " FOR UPDATE" : OWNED_WORKFLOW)
        .param("id", workflowId)
        .param("owner", owner)
        .query(UUID.class)
        .optional()
        .orElseThrow(() -> notFound("WORKFLOW_NOT_FOUND", "Workflow not found"));
  }

  private VersionReference findComparisonBase(UUID workflowId, UUID comparisonId) {
    return jdbc.sql(
            """
            SELECT v.id, v.version, v.created_at
            FROM workflow_hub.workflow_comparisons c
            JOIN workflow_hub.workflow_versions v ON v.id = c.base_version_id
            WHERE c.id = :comparisonId AND v.workflow_id = :workflowId
              AND c.expires_at > clock_timestamp()
            """)
        .param("comparisonId", comparisonId)
        .param("workflowId", workflowId)
        .query((row, index) -> version(row))
        .optional()
        .orElseThrow(() -> notFound("COMPARISON_NOT_FOUND", "Comparison not found or expired"));
  }

  private VersionNumber requireCurrentBase(
      UUID workflowId, VersionReference base, UpdateType type) {
    VersionNumber number = VersionNumber.parse(base.versionLabel());
    BigDecimal major = type == UpdateType.MINOR ? new BigDecimal(number.major()) : null;
    var current =
        jdbc.sql(
                """
                SELECT id, version, created_at FROM (
                    SELECT id, version, created_at,
                        substring(version FROM '^v([1-9][0-9]*)(?:[.][1-9][0-9]*)?$')::numeric AS major,
                        coalesce(substring(version FROM '[.]([1-9][0-9]*)$')::numeric, 0) AS minor
                    FROM workflow_hub.workflow_versions
                    WHERE workflow_id = :workflowId
                ) numbered
                WHERE major IS NOT NULL AND (:major IS NULL OR major = :major)
                ORDER BY major DESC, minor DESC
                LIMIT 1
                """)
            .param("workflowId", workflowId)
            .param("major", major, Types.NUMERIC)
            .query((row, index) -> version(row))
            .single();
    if (!current.versionId().equals(base.versionId())) {
      throw new LatestVersionChanged(current);
    }
    return number;
  }

  private void insertVersion(UUID workflowId, UUID versionId, String label, String objectKey) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflow_versions (id, workflow_id, version, s3_object_key, created_at)
            VALUES (:id, :workflowId, :label, :objectKey, clock_timestamp())
            """)
        .param("id", versionId)
        .param("workflowId", workflowId)
        .param("label", label)
        .param("objectKey", objectKey)
        .update();
  }

  private void recordRequest(
      String owner, String key, String fingerprint, UUID workflowId, UUID versionId) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.idempotency_keys
                (owner_id, idempotency_key, request_fingerprint, workflow_id, version_id)
            VALUES (:owner, :key, :fingerprint, :workflowId, :versionId)
            """)
        .param("owner", owner)
        .param("key", key)
        .param("fingerprint", fingerprint)
        .param("workflowId", workflowId)
        .param("versionId", versionId)
        .update();
  }

  private Optional<UploadResult> replay(String owner, String key, String fingerprint) {
    return jdbc.sql(
            """
            SELECT k.request_fingerprint, k.workflow_id, k.version_id, v.version
            FROM workflow_hub.idempotency_keys k
            JOIN workflow_hub.workflow_versions v ON v.id = k.version_id
            WHERE k.owner_id = :owner AND k.idempotency_key = :key
            """)
        .param("owner", owner)
        .param("key", key)
        .query(
            (row, index) -> {
              if (!fingerprint.equals(row.getString("request_fingerprint"))) {
                throw new WorkflowUploadException(
                    HttpStatus.CONFLICT,
                    "IDEMPOTENCY_KEY_REUSED",
                    "Idempotency-Key was already used with a different request");
              }
              return new UploadResult(
                  row.getObject("workflow_id", UUID.class),
                  row.getObject("version_id", UUID.class),
                  row.getString("version"));
            })
        .optional();
  }

  private Optional<UploadResult> confirmCommit(String owner, String key, String fingerprint) {
    try {
      return replay(owner, key, fingerprint);
    } catch (WorkflowUploadException e) {
      // 확인된 키 충돌은 확인 불가가 아니므로 호출자가 응답으로 전달한다.
      throw e;
    } catch (RuntimeException e) {
      log.error("event=workflow.version.commit_check_failed", e);
      return Optional.empty();
    }
  }

  private void discardVersionObject(String objectKey) {
    try {
      store.delete(objectKey);
    } catch (RuntimeException e) {
      log.error("event=workflow.version.orphan_delete_failed objectKey={}", objectKey, e);
    }
  }

  private static UUID resourceId(String path, String code, String message) {
    try {
      UUID parsed = UUID.fromString(path);
      if (parsed.toString().equalsIgnoreCase(path)) {
        return parsed;
      }
    } catch (IllegalArgumentException ignored) {
      // 형식이 잘못된 ID도 같은 404로 응답한다.
    }
    throw notFound(code, message);
  }

  private static WorkflowUploadException notFound(String code, String message) {
    return new WorkflowUploadException(HttpStatus.NOT_FOUND, code, message);
  }

  private static VersionReference version(ResultSet row) throws SQLException {
    return new VersionReference(
        row.getObject("id", UUID.class),
        row.getString("version"),
        row.getObject("created_at", OffsetDateTime.class).toInstant());
  }

  private record StoredVersion(VersionReference version, String objectKey) {}

  private record VersionNumber(BigInteger major, BigInteger minor) {
    static VersionNumber parse(String label) {
      var parts = VERSION_LABEL.matcher(label);
      if (!parts.matches()) {
        throw notFound("WORKFLOW_VERSION_NOT_FOUND", "Workflow version not found");
      }
      return new VersionNumber(
          new BigInteger(parts.group(1)),
          parts.group(2) == null ? BigInteger.ZERO : new BigInteger(parts.group(2)));
    }

    VersionNumber next(UpdateType type) {
      return type == UpdateType.MINOR
          ? new VersionNumber(major, minor.add(BigInteger.ONE))
          : new VersionNumber(major.add(BigInteger.ONE), BigInteger.ZERO);
    }

    String label() {
      return "v" + major + (minor.signum() == 0 ? "" : "." + minor);
    }
  }

  public enum UpdateType {
    MINOR,
    MAJOR
  }

  public record VersionReference(UUID versionId, String versionLabel, Instant createdAt) {}

  public record Comparison(
      UUID comparisonId,
      VersionReference baseVersion,
      Instant expiresAt,
      WorkflowGraphComparison.Result diff) {}

  public static final class LatestVersionChanged extends WorkflowUploadException {
    private final VersionReference latestVersion;

    LatestVersionChanged(VersionReference latestVersion) {
      super(
          HttpStatus.CONFLICT,
          "LATEST_VERSION_CHANGED",
          "Compare again with the current base version");
      this.latestVersion = latestVersion;
    }

    public VersionReference latestVersion() {
      return latestVersion;
    }
  }
}
