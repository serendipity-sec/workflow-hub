package dev.workflowhub.workflow.service;

import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

/** 로그 규칙: 모든 줄은 event=... key=value 형식이다. 파일 내용과 제목은 기록하지 않고, 추적은 requestId(MDC)와 ID 값으로 한다. */
@Service
public class WorkflowUploadService {
  static final String FIRST_VERSION = "v1";
  private static final int MAX_TITLE_LENGTH = 200;
  private static final int MAX_KEY_LENGTH = 255;
  private static final Logger log = LoggerFactory.getLogger(WorkflowUploadService.class);

  private final N8nWorkflowValidator validator;
  private final WorkflowObjectStore store;
  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final WorkflowObjectCleanup cleanup;

  public WorkflowUploadService(
      N8nWorkflowValidator validator,
      WorkflowObjectStore store,
      JdbcClient jdbc,
      TransactionTemplate transactions,
      WorkflowObjectCleanup cleanup) {
    this.validator = validator;
    this.store = store;
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.cleanup = cleanup;
  }

  /** 같은 소유자·키·입력으로 다시 호출하면 최초 결과를 돌려주고 워크플로는 한 번만 만든다. */
  public UploadResult upload(
      String ownerId, String idempotencyKey, String titleInput, byte[] file) {
    requireValidKey(idempotencyKey);
    log.info(
        "event=workflow.upload.start owner={} idempotencyKey={} bytes={}",
        ownerId,
        idempotencyKey,
        file.length);
    String fingerprint = fingerprint(titleInput, file);

    // 재시도는 JSON을 다시 파싱하지 않고 저장된 결과로 처리한다. 같은 키에 다른 입력이면 409다.
    Optional<Existing> existing = findExisting(ownerId, idempotencyKey);
    if (existing.isPresent()) {
      return replay(ownerId, idempotencyKey, existing.get(), fingerprint);
    }

    var workflow = validator.validate(file);
    String title = resolveTitle(titleInput, workflow.name());

    UUID workflowId = UUID.randomUUID();
    UUID versionId = UUID.randomUUID();
    String objectKey = "workflows/" + workflowId + "/" + versionId + ".json";
    // 저장소에 넘기는 같은 배열로 계산한다.
    var identity = WorkflowFileIdentity.of(file);

    // S3에 쓰기 전에 정리 대상으로 남긴다. 저장과 커밋 사이에 프로세스가 중단돼도 재시작 후 찾을 수 있다.
    cleanup.record(objectKey);
    long storeStart = System.nanoTime();
    try {
      store.put(objectKey, file);
    } catch (RuntimeException e) {
      log.error(
          "event=workflow.upload.storage_failed objectKey={} owner={}", objectKey, ownerId, e);
      // 응답만 유실되고 저장은 끝났거나 늦게 끝날 수 있다. 기록을 남겨 두면 대기 시간 뒤 정리 작업이 지운다.
      throw new WorkflowUploadException(
          HttpStatus.SERVICE_UNAVAILABLE,
          "STORAGE_UNAVAILABLE",
          "Could not store the file. Retry with the same Idempotency-Key.");
    }
    log.info(
        "event=workflow.upload.object_stored objectKey={} bytes={} durationMs={}",
        objectKey,
        file.length,
        (System.nanoTime() - storeStart) / 1_000_000);

    // 본문(INSERT)이 끝난 뒤의 실패는 커밋 단계다. 예외 타입만으로는 둘을 구분할 수 없어 표시로 가른다.
    AtomicBoolean bodyCompleted = new AtomicBoolean(false);
    try {
      transactions.executeWithoutResult(
          status -> {
            record(
                ownerId,
                idempotencyKey,
                fingerprint,
                title,
                workflowId,
                versionId,
                objectKey,
                identity);
            bodyCompleted.set(true);
          });
    } catch (DuplicateKeyException e) {
      // 같은 키의 동시 요청이 먼저 커밋됐다. 이 요청이 올린 객체는 참조되지 않으므로 지운다.
      log.info(
          "event=workflow.upload.concurrent_duplicate owner={} idempotencyKey={} objectKey={}",
          ownerId,
          idempotencyKey,
          objectKey);
      cleanup.discard(objectKey);
      Optional<Existing> winner = findExisting(ownerId, idempotencyKey);
      if (winner.isPresent()) {
        return replay(ownerId, idempotencyKey, winner.get(), fingerprint);
      }
      throw e;
    } catch (RuntimeException e) {
      if (!bodyCompleted.get()) {
        // 커밋 전의 실패(트랜잭션 시작 실패 포함)는 롤백이 확실하므로 객체를 지워도 안전하다.
        log.error(
            "event=workflow.upload.db_failed owner={} workflowId={} objectKey={}",
            ownerId,
            workflowId,
            objectKey,
            e);
        cleanup.discard(objectKey);
        throw e;
      }
      // 커밋 단계의 실패는 응답만 유실되고 커밋은 적용됐을 수 있다. 행이 있으면 성공으로 처리하고,
      // 없거나 확인하지 못하면 이후 커밋될 가능성이 있으므로 객체를 지우지 않는다.
      log.error(
          "event=workflow.upload.commit_failed owner={} workflowId={} objectKey={}",
          ownerId,
          workflowId,
          objectKey,
          e);
      if (Boolean.TRUE.equals(isCommitted(versionId))) {
        log.warn(
            "event=workflow.upload.commit_confirmed owner={} workflowId={} versionId={}",
            ownerId,
            workflowId,
            versionId);
        return new UploadResult(workflowId, versionId, FIRST_VERSION);
      }
      // 객체는 보존한다. 정리 대상 기록이 남아 있으면 대기 시간 뒤 정리 작업이 버전 참조 여부를 확인해 처리한다.
      log.error(
          "event=workflow.upload.commit_unknown owner={} workflowId={} versionId={} objectKey={}",
          ownerId,
          workflowId,
          versionId,
          objectKey);
      throw e;
    }
    log.info(
        "event=workflow.upload.committed owner={} workflowId={} versionId={} version={} objectKey={}",
        ownerId,
        workflowId,
        versionId,
        FIRST_VERSION,
        objectKey);
    return new UploadResult(workflowId, versionId, FIRST_VERSION);
  }

  /** 버전 행이 있으면 true, 없으면 false, 확인에 실패하면 null. */
  private Boolean isCommitted(UUID versionId) {
    try {
      return jdbc.sql("SELECT EXISTS (SELECT 1 FROM workflow_hub.workflow_versions WHERE id = :id)")
          .param("id", versionId)
          .query(Boolean.class)
          .single();
    } catch (RuntimeException e) {
      log.error("event=workflow.upload.commit_check_failed versionId={}", versionId, e);
      return null;
    }
  }

  private void record(
      String ownerId,
      String idempotencyKey,
      String fingerprint,
      String title,
      UUID workflowId,
      UUID versionId,
      String objectKey,
      WorkflowFileIdentity identity) {
    jdbc.sql(
            "INSERT INTO workflow_hub.workflows (id, owner_id, title) VALUES (:id, :owner, :title)")
        .param("id", workflowId)
        .param("owner", ownerId)
        .param("title", title)
        .update();
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflow_versions
                (id, workflow_id, version, s3_object_key, content_sha256, size_bytes)
            VALUES (:id, :workflowId, :version, :objectKey, :sha256, :sizeBytes)
            """)
        .param("id", versionId)
        .param("workflowId", workflowId)
        .param("version", FIRST_VERSION)
        .param("objectKey", objectKey)
        .param("sha256", identity.sha256())
        .param("sizeBytes", identity.sizeBytes())
        .update();
    jdbc.sql(
            """
            INSERT INTO workflow_hub.idempotency_keys
                (owner_id, idempotency_key, request_fingerprint, workflow_id, version_id)
            VALUES (:owner, :key, :fingerprint, :workflowId, :versionId)
            """)
        .param("owner", ownerId)
        .param("key", idempotencyKey)
        .param("fingerprint", fingerprint)
        .param("workflowId", workflowId)
        .param("versionId", versionId)
        .update();
    // 커밋되면 버전 행이 객체를 가리키므로 정리 대상에서 뺀다. 롤백되면 이 삭제도 취소돼 기록이 남는다.
    cleanup.releaseForCommit(objectKey);
  }

  private Optional<Existing> findExisting(String ownerId, String idempotencyKey) {
    return jdbc.sql(
            """
            SELECT k.request_fingerprint, k.workflow_id, k.version_id, v.version
            FROM workflow_hub.idempotency_keys k
            JOIN workflow_hub.workflow_versions v ON v.id = k.version_id
            WHERE k.owner_id = :owner AND k.idempotency_key = :key
            """)
        .param("owner", ownerId)
        .param("key", idempotencyKey)
        .query(
            (rs, row) ->
                new Existing(
                    rs.getString("request_fingerprint"),
                    new UploadResult(
                        rs.getObject("workflow_id", UUID.class),
                        rs.getObject("version_id", UUID.class),
                        rs.getString("version"))))
        .optional();
  }

  private static UploadResult replay(
      String ownerId, String idempotencyKey, Existing existing, String fingerprint) {
    if (!existing.fingerprint().equals(fingerprint)) {
      log.warn(
          "event=workflow.upload.key_reused owner={} idempotencyKey={}", ownerId, idempotencyKey);
      throw new WorkflowUploadException(
          HttpStatus.CONFLICT,
          "IDEMPOTENCY_KEY_REUSED",
          "Idempotency-Key was already used with a different request");
    }
    log.info(
        "event=workflow.upload.replayed owner={} idempotencyKey={} workflowId={} versionId={}",
        ownerId,
        idempotencyKey,
        existing.result().workflowId(),
        existing.result().versionId());
    return existing.result();
  }

  static void requireValidKey(String key) {
    if (key == null || key.isBlank()) {
      throw new WorkflowUploadException(
          HttpStatus.BAD_REQUEST, "IDEMPOTENCY_KEY_REQUIRED", "Idempotency-Key header is required");
    }
    if (key.length() > MAX_KEY_LENGTH || key.chars().anyMatch(c -> c < 0x20 || c > 0x7e)) {
      throw new WorkflowUploadException(
          HttpStatus.BAD_REQUEST,
          "IDEMPOTENCY_KEY_INVALID",
          "Idempotency-Key must be 1-255 printable ASCII characters");
    }
  }

  private static String resolveTitle(String input, String workflowName) {
    String title = input != null && !input.isBlank() ? input.strip() : null;
    if (title == null && workflowName != null && !workflowName.isBlank()) {
      title = workflowName.strip();
    }
    if (title == null) {
      throw new WorkflowUploadException(
          HttpStatus.UNPROCESSABLE_CONTENT, "TITLE_REQUIRED", "A title is required");
    }
    // PostgreSQL text는 NUL을 저장하지 못한다. S3 저장 전에 422로 막는다.
    if (title.indexOf('\u0000') >= 0) {
      throw new WorkflowUploadException(
          HttpStatus.UNPROCESSABLE_CONTENT, "TITLE_INVALID", "Title must not contain NUL");
    }
    if (title.codePointCount(0, title.length()) > MAX_TITLE_LENGTH) {
      throw new WorkflowUploadException(
          HttpStatus.UNPROCESSABLE_CONTENT,
          "TITLE_TOO_LONG",
          "Title must be at most " + MAX_TITLE_LENGTH + " characters");
    }
    return title;
  }

  /** 제출된 제목과 파일 바이트의 SHA-256. 둘 사이에 길이를 넣어 경계를 구분한다. */
  static String fingerprint(String titleInput, byte[] file) {
    try {
      MessageDigest digest = MessageDigest.getInstance("SHA-256");
      byte[] title = (titleInput == null ? "" : titleInput).getBytes(StandardCharsets.UTF_8);
      digest.update(ByteBuffer.allocate(Integer.BYTES).putInt(title.length).array());
      digest.update(title);
      digest.update(file);
      return HexFormat.of().formatHex(digest.digest());
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }

  public record UploadResult(UUID workflowId, UUID versionId, String versionLabel) {}

  private record Existing(String fingerprint, UploadResult result) {}
}
