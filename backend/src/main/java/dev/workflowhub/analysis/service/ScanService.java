package dev.workflowhub.analysis.service;

import dev.workflowhub.analysis.queue.ScanTaskMessage;
import dev.workflowhub.analysis.service.ScanModels.ScanError;
import dev.workflowhub.analysis.service.ScanModels.ScanLlm;
import dev.workflowhub.analysis.service.ScanModels.ScanPage;
import dev.workflowhub.analysis.service.ScanModels.ScanPolicy;
import dev.workflowhub.analysis.service.ScanModels.ScanReportView;
import dev.workflowhub.analysis.service.ScanModels.ScanRunView;
import dev.workflowhub.analysis.service.ScanModels.ScanSummary;
import dev.workflowhub.analysis.service.ScanModels.ScanVersions;
import dev.workflowhub.workflow.storage.WorkflowObjectStore;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.core.simple.JdbcClient.StatementSpec;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * 소유자용 보안 검사 요청·이력·최신·상세·리포트 조회 서비스(#39, #57).
 *
 * <p>상태·요약 조회(목록/최신/단건)는 DB만 읽어 빠르게 응답하고, 상세 리포트(serviceReport)는 별도 요청에서 소유권 확인 후 비공개 S3에서 읽어 반환한다.
 */
@Service
public class ScanService {
  private static final Logger log = LoggerFactory.getLogger(ScanService.class);
  private static final int DEFAULT_LIMIT = 20;
  private static final int MAX_LIMIT = 100;
  private static final int MAX_IDEMPOTENCY_KEY_LENGTH = 128;
  private static final String DISPATCH_FAILED_CODE = "scan_dispatch_failed";
  private static final String DISPATCH_FAILED_MESSAGE =
      "Security scan task could not be dispatched to the worker queue. Request a new scan.";

  private final JdbcClient jdbc;
  private final TransactionTemplate transactions;
  private final ScanTaskDispatcher dispatcher;
  private final WorkflowObjectStore store;
  private final JsonMapper mapper;
  private final long maxFileBytes;
  private final int maxAttempts;

  public ScanService(
      JdbcClient jdbc,
      TransactionTemplate transactions,
      ScanTaskDispatcher dispatcher,
      WorkflowObjectStore store,
      JsonMapper mapper,
      @Value("${app.analysis.max-file-bytes}") long maxFileBytes,
      @Value("${app.analysis.max-attempts}") int maxAttempts) {
    if (maxFileBytes <= 0 || maxAttempts < 1) {
      throw new IllegalArgumentException(
          "SCAN_MAX_FILE_BYTES and SCAN_MAX_ATTEMPTS must be positive");
    }
    this.jdbc = jdbc;
    this.transactions = transactions;
    this.dispatcher = dispatcher;
    this.store = store;
    this.mapper = mapper;
    this.maxFileBytes = maxFileBytes;
    this.maxAttempts = maxAttempts;
  }

  public ScanRunView requestScan(
      String owner, String workflowIdRaw, String versionIdRaw, String rawIdempotencyKey) {
    String idempotencyKey = validateOptionalIdempotencyKey(rawIdempotencyKey);
    UUID workflowId = parseId(workflowIdRaw, ScanException::versionNotFound);
    UUID versionId = parseId(versionIdRaw, ScanException::versionNotFound);

    CreationOutcome outcome;
    try {
      outcome =
          transactions.execute(
              status -> createOrReplayScan(owner, workflowId, versionId, idempotencyKey));
    } catch (DuplicateKeyException e) {
      // 서로 다른 워크플로로 동시에 같은 Idempotency-Key가 들어오면 충돌로 변환한다.
      if (idempotencyKey != null) {
        outcome = resolveConcurrentIdempotency(owner, versionId, idempotencyKey);
      } else {
        throw e;
      }
    }
    if (outcome.message() == null) {
      log.info(
          "event=analysis.scan.request_replayed workflowId={} versionId={} scanRunId={}",
          workflowId,
          versionId,
          outcome.view().scanRunId());
      return outcome.view();
    }

    ScanTaskMessage message = outcome.message();
    ScanTaskDispatcher.Outcome dispatched = dispatcher.dispatch(message, "scan_request");
    if (dispatched == ScanTaskDispatcher.Outcome.UNKNOWN) {
      // 메시지가 이미 큐에 있을 수 있으므로 실행을 보존한다. 발행이 확인되지 않은 시도는 회수기가 같은 attemptId로 다시 보낸다.
      log.warn(
          "event=analysis.scan.dispatch_unconfirmed workflowId={} versionId={} scanRunId={} taskId={}",
          workflowId,
          versionId,
          message.scanRunId(),
          message.taskId());
      return readPreservedRun(message.scanRunId());
    }
    if (dispatched == ScanTaskDispatcher.Outcome.REJECTED) {
      RejectionOutcome rejection = failRejectedFirstDispatch(message);
      if (rejection == RejectionOutcome.FAILED) {
        throw ScanException.dispatchUnavailable();
      }
      if (rejection == RejectionOutcome.CANCELLED) {
        throw ScanException.versionNotFound();
      }
      // 워커가 이미 시작했거나 회수기가 발행을 넘겨받은 실행은 그대로 두고 최신 DB 상태를 반환한다.
      log.warn(
          "event=analysis.scan.dispatch_rejected_preserved workflowId={} versionId={} scanRunId={} taskId={}",
          workflowId,
          versionId,
          message.scanRunId(),
          message.taskId());
      return readPreservedRun(message.scanRunId());
    }

    log.info(
        "event=analysis.scan.requested workflowId={} versionId={} scanRunId={} taskId={} attemptId={}",
        workflowId,
        versionId,
        message.scanRunId(),
        message.taskId(),
        message.attemptId());
    return outcome.view();
  }

  public ScanPage listScans(
      String owner, String workflowIdRaw, String versionIdRaw, Integer limitParam, String cursor) {
    int limit = resolveLimit(limitParam);
    ScanCursor decoded = ScanCursor.decode(cursor);
    UUID workflowId = parseId(workflowIdRaw, ScanException::versionNotFound);
    UUID versionId = parseId(versionIdRaw, ScanException::versionNotFound);

    String cursorClause =
        decoded == null
            ? ""
            : "AND (s.created_at < :cursorCreatedAt OR (s.created_at = :cursorCreatedAt AND s.id < :cursorId))";
    var query =
        aliveVersionScans(owner, workflowId, versionId, cursorClause, "LIMIT :limitPlusOne")
            .param("limitPlusOne", limit + 1);
    if (decoded != null) {
      query =
          query
              .param(
                  "cursorCreatedAt",
                  OffsetDateTime.ofInstant(decoded.createdAt(), java.time.ZoneOffset.UTC))
              .param("cursorId", decoded.id());
    }

    List<Optional<ScanRunView>> versionRows = query.query(ScanService::mapAliveVersionScan).list();
    if (versionRows.isEmpty()) {
      throw ScanException.versionNotFound();
    }
    List<ScanRunView> rows = versionRows.stream().flatMap(Optional::stream).toList();
    boolean hasMore = rows.size() > limit;
    List<ScanRunView> items = hasMore ? rows.subList(0, limit) : rows;
    String nextCursor =
        hasMore
            ? new ScanCursor(items.getLast().createdAt(), items.getLast().scanRunId()).encode()
            : null;
    return new ScanPage(items, nextCursor);
  }

  public Optional<ScanRunView> getLatestScan(
      String owner, String workflowIdRaw, String versionIdRaw) {
    UUID workflowId = parseId(workflowIdRaw, ScanException::versionNotFound);
    UUID versionId = parseId(versionIdRaw, ScanException::versionNotFound);

    return aliveVersionScans(owner, workflowId, versionId, "", "LIMIT 1")
        .query(ScanService::mapAliveVersionScan)
        .optional()
        .orElseThrow(ScanException::versionNotFound);
  }

  /**
   * 살아 있는 소유 버전과 그 검사 이력을 한 SQL 문(같은 스냅샷)에서 읽는다. 버전이 없거나 삭제됐으면 행이 없고, 버전은 있지만 검사 이력이 없으면 검사 열이 모두
   * NULL인 행 하나가 나온다. 확인과 조회 사이에 삭제가 커밋돼 삭제된 버전의 이력을 돌려주는 일을 막는다.
   */
  private StatementSpec aliveVersionScans(
      String owner, UUID workflowId, UUID versionId, String cursorClause, String limitClause) {
    return jdbc.sql(
            """
            SELECT s.*, v.version AS version_label
            FROM workflow_hub.workflow_versions v
            JOIN workflow_hub.workflows w ON w.id = v.workflow_id
            LEFT JOIN workflow_hub.scan_runs s ON s.workflow_version_id = v.id %s
            WHERE w.id = :workflowId
              AND w.owner_id = :owner
              AND w.deleted_at IS NULL
              AND v.id = :versionId
              AND v.deleted_at IS NULL
            ORDER BY s.created_at DESC, s.id DESC
            %s
            """
                .formatted(cursorClause, limitClause))
        .param("workflowId", workflowId)
        .param("owner", owner)
        .param("versionId", versionId);
  }

  public ScanRunView getScan(
      String owner, String workflowIdRaw, String versionIdRaw, String scanRunIdRaw) {
    UUID workflowId = parseId(workflowIdRaw, ScanException::scanRunNotFound);
    UUID versionId = parseId(versionIdRaw, ScanException::scanRunNotFound);
    UUID scanRunId = parseId(scanRunIdRaw, ScanException::scanRunNotFound);

    return jdbc.sql(
            """
            SELECT s.*, v.version AS version_label
            FROM workflow_hub.scan_runs s
            JOIN workflow_hub.workflow_versions v ON v.id = s.workflow_version_id
            JOIN workflow_hub.workflows w ON w.id = v.workflow_id
            WHERE w.id = :workflowId
              AND w.owner_id = :owner
              AND w.deleted_at IS NULL
              AND v.id = :versionId
              AND v.deleted_at IS NULL
              AND s.id = :scanRunId
            """)
        .param("workflowId", workflowId)
        .param("owner", owner)
        .param("versionId", versionId)
        .param("scanRunId", scanRunId)
        .query(ScanService::mapScanRun)
        .optional()
        .orElseThrow(ScanException::scanRunNotFound);
  }

  public ScanReportView getScanReport(
      String owner, String workflowIdRaw, String versionIdRaw, String scanRunIdRaw) {
    UUID workflowId = parseId(workflowIdRaw, ScanException::scanRunNotFound);
    UUID versionId = parseId(versionIdRaw, ScanException::scanRunNotFound);
    UUID scanRunId = parseId(scanRunIdRaw, ScanException::scanRunNotFound);

    ReportMeta meta =
        jdbc.sql(
                """
                SELECT s.id,
                       s.workflow_id,
                       s.workflow_version_id,
                       v.version AS version_label,
                       s.input_sha256,
                       s.contract_version,
                       s.inspection_version,
                       s.assessment_version,
                       s.engine_version,
                       s.rules_version,
                       s.adapter_version,
                       s.service_report_s3_key
                FROM workflow_hub.scan_runs s
                JOIN workflow_hub.workflow_versions v ON v.id = s.workflow_version_id
                JOIN workflow_hub.workflows w ON w.id = v.workflow_id
                WHERE w.id = :workflowId
                  AND w.owner_id = :owner
                  AND w.deleted_at IS NULL
                  AND v.id = :versionId
                  AND v.deleted_at IS NULL
                  AND s.id = :scanRunId
                """)
            .param("workflowId", workflowId)
            .param("owner", owner)
            .param("versionId", versionId)
            .param("scanRunId", scanRunId)
            .query(
                (rs, index) ->
                    new ReportMeta(
                        rs.getObject("id", UUID.class),
                        rs.getObject("workflow_id", UUID.class),
                        rs.getObject("workflow_version_id", UUID.class),
                        rs.getString("version_label"),
                        rs.getString("input_sha256"),
                        mapVersions(rs),
                        rs.getString("service_report_s3_key")))
            .optional()
            .orElseThrow(ScanException::scanRunNotFound);

    if (meta.serviceReportKey() == null) {
      throw ScanException.reportNotAvailable();
    }

    byte[] rawBytes;
    try {
      rawBytes = store.get(meta.serviceReportKey());
    } catch (RuntimeException e) {
      log.error(
          "event=analysis.scan.report_read_failed scanRunId={} objectKey={}",
          scanRunId,
          meta.serviceReportKey(),
          e);
      throw ScanException.storageUnavailable();
    }

    JsonNode serviceReport;
    try {
      serviceReport = mapper.readTree(rawBytes);
    } catch (RuntimeException e) {
      log.error(
          "event=analysis.scan.report_parse_failed scanRunId={} objectKey={}",
          scanRunId,
          meta.serviceReportKey(),
          e);
      throw ScanException.storageUnavailable();
    }

    return new ScanReportView(
        meta.scanRunId(),
        meta.workflowId(),
        meta.workflowVersionId(),
        meta.versionLabel(),
        meta.inputSha256(),
        meta.versions(),
        serviceReport);
  }

  private CreationOutcome createOrReplayScan(
      String owner, UUID workflowId, UUID versionId, String idempotencyKey) {
    // 삭제·버전 등록과 같은 잠금 순서(workflows 행 선잠금)를 지켜 교착을 막는다.
    jdbc.sql(
            """
            SELECT id
            FROM workflow_hub.workflows
            WHERE id = :workflowId AND owner_id = :owner AND deleted_at IS NULL
            FOR UPDATE
            """)
        .param("workflowId", workflowId)
        .param("owner", owner)
        .query(UUID.class)
        .optional()
        .orElseThrow(ScanException::versionNotFound);

    VersionRow version =
        jdbc.sql(
                """
                SELECT version, content_sha256, size_bytes
                FROM workflow_hub.workflow_versions
                WHERE id = :versionId AND workflow_id = :workflowId AND deleted_at IS NULL
                """)
            .param("versionId", versionId)
            .param("workflowId", workflowId)
            .query(
                (rs, index) ->
                    new VersionRow(
                        rs.getString("version"),
                        rs.getString("content_sha256"),
                        nullableLong(rs, "size_bytes")))
            .optional()
            .orElseThrow(ScanException::versionNotFound);

    if (idempotencyKey != null) {
      var existing =
          jdbc.sql(
                  """
                  SELECT workflow_version_id, scan_run_id
                  FROM workflow_hub.scan_request_idempotency_keys
                  WHERE owner_id = :owner AND idempotency_key = :key
                  """)
              .param("owner", owner)
              .param("key", idempotencyKey)
              .query(
                  (rs, index) ->
                      new IdempotencyRow(
                          rs.getObject("workflow_version_id", UUID.class),
                          rs.getObject("scan_run_id", UUID.class)))
              .optional();
      if (existing.isPresent()) {
        if (!existing.get().workflowVersionId().equals(versionId)) {
          throw ScanException.idempotencyConflict();
        }
        rejectIfFirstDispatchPending(existing.get().scanRunId());
        ScanRunView existingRun =
            jdbc.sql(
                    """
                    SELECT s.*, v.version AS version_label
                    FROM workflow_hub.scan_runs s
                    JOIN workflow_hub.workflow_versions v ON v.id = s.workflow_version_id
                    WHERE s.id = :scanRunId
                    """)
                .param("scanRunId", existing.get().scanRunId())
                .query(ScanService::mapScanRun)
                .single();
        return new CreationOutcome(existingRun, null);
      }
    }

    if (version.contentSha256() == null || version.sizeBytes() == null) {
      throw ScanException.versionHashUnavailable();
    }
    if (version.sizeBytes() > maxFileBytes) {
      throw ScanException.fileTooLarge(maxFileBytes);
    }

    var active =
        jdbc.sql(
                """
                SELECT id, execution_status
                FROM workflow_hub.scan_runs
                WHERE workflow_version_id = :versionId
                  AND execution_status IN ('queued', 'running')
                LIMIT 1
                """)
            .param("versionId", versionId)
            .query(
                (rs, index) ->
                    new ActiveScan(
                        rs.getObject("id", UUID.class), rs.getString("execution_status")))
            .optional();
    if (active.isPresent()) {
      throw ScanException.alreadyInProgress(active.get().scanRunId(), active.get().status());
    }

    OffsetDateTime now = databaseNow();
    UUID scanRunId = UUID.randomUUID();
    UUID taskId = UUID.randomUUID();
    UUID attemptId = UUID.randomUUID();

    jdbc.sql(
            """
            INSERT INTO workflow_hub.scan_runs (
                id, workflow_id, workflow_version_id, input_sha256, size_bytes,
                execution_status, analysis_coverage, policy_evaluation_status,
                publication_status, llm_status, created_at)
            VALUES (
                :id, :workflowId, :versionId, :sha256, :sizeBytes,
                'queued', 'unknown', 'not_applicable',
                'private', 'not_requested', :now)
            """)
        .param("id", scanRunId)
        .param("workflowId", workflowId)
        .param("versionId", versionId)
        .param("sha256", version.contentSha256())
        .param("sizeBytes", version.sizeBytes())
        .param("now", now)
        .update();

    jdbc.sql(
            """
            INSERT INTO workflow_hub.analysis_jobs (
                id, scan_run_id, workflow_version_id, input_sha256, size_bytes,
                status, current_attempt_id, attempt_number, max_attempts,
                created_at, updated_at)
            VALUES (
                :taskId, :scanRunId, :versionId, :sha256, :sizeBytes,
                'queued', :attemptId, 1, :maxAttempts,
                :now, :now)
            """)
        .param("taskId", taskId)
        .param("scanRunId", scanRunId)
        .param("versionId", versionId)
        .param("sha256", version.contentSha256())
        .param("sizeBytes", version.sizeBytes())
        .param("attemptId", attemptId)
        .param("maxAttempts", maxAttempts)
        .param("now", now)
        .update();

    jdbc.sql(
            """
            INSERT INTO workflow_hub.analysis_job_attempts (
                id, job_id, attempt_number, status, created_at, dispatch_attempted_at)
            VALUES (:attemptId, :taskId, 1, 'queued', :now, :now)
            """)
        .param("attemptId", attemptId)
        .param("taskId", taskId)
        .param("now", now)
        .update();

    if (idempotencyKey != null) {
      jdbc.sql(
              """
              INSERT INTO workflow_hub.scan_request_idempotency_keys (
                  owner_id, idempotency_key, workflow_id, workflow_version_id, scan_run_id, created_at)
              VALUES (:owner, :key, :workflowId, :versionId, :scanRunId, :now)
              """)
          .param("owner", owner)
          .param("key", idempotencyKey)
          .param("workflowId", workflowId)
          .param("versionId", versionId)
          .param("scanRunId", scanRunId)
          .param("now", now)
          .update();
    }

    ScanRunView view =
        new ScanRunView(
            scanRunId,
            workflowId,
            versionId,
            version.versionLabel(),
            version.contentSha256(),
            null,
            "queued",
            "unknown",
            new ScanPolicy("not_applicable", null, null),
            "private",
            new ScanLlm("not_requested"),
            null,
            false,
            null,
            now.toInstant(),
            null,
            null);
    ScanTaskMessage message =
        new ScanTaskMessage(
            ScanModels.CONTRACT_VERSION,
            taskId,
            attemptId,
            scanRunId,
            versionId,
            version.contentSha256(),
            version.sizeBytes(),
            1,
            maxAttempts,
            now.toInstant());
    return new CreationOutcome(view, message);
  }

  private CreationOutcome resolveConcurrentIdempotency(
      String owner, UUID versionId, String idempotencyKey) {
    var existing =
        jdbc.sql(
                """
                SELECT workflow_version_id, scan_run_id
                FROM workflow_hub.scan_request_idempotency_keys
                WHERE owner_id = :owner AND idempotency_key = :key
                """)
            .param("owner", owner)
            .param("key", idempotencyKey)
            .query(
                (rs, index) ->
                    new IdempotencyRow(
                        rs.getObject("workflow_version_id", UUID.class),
                        rs.getObject("scan_run_id", UUID.class)))
            .optional();
    if (existing.isEmpty() || !existing.get().workflowVersionId().equals(versionId)) {
      throw ScanException.idempotencyConflict();
    }
    rejectIfFirstDispatchPending(existing.get().scanRunId());
    return new CreationOutcome(readScanRunById(existing.get().scanRunId()), null);
  }

  /**
   * 최초 요청이 아직 첫 발행 결과를 기다리는 실행(시도 1이 queued이고 발행이 확인되지 않았으며 회수기가 넘겨받지 않음)은 곧 failed로 마감될 수 있으므로, 같은
   * 키 재전송에 202 대신 재시도 가능한 503을 준다. 실행은 지우지 않으므로 다시 요청하면 결과가 정해진 뒤의 상태를 받는다.
   */
  private void rejectIfFirstDispatchPending(UUID scanRunId) {
    boolean pending =
        Boolean.TRUE.equals(
            jdbc.sql(
                    """
                    SELECT EXISTS (
                        SELECT 1
                        FROM workflow_hub.analysis_jobs j
                        JOIN workflow_hub.analysis_job_attempts a ON a.id = j.current_attempt_id
                        WHERE j.scan_run_id = :scanRunId
                          AND j.status = 'queued'
                          AND j.attempt_number = 1
                          AND a.status = 'queued'
                          AND a.dispatched_at IS NULL
                          AND a.dispatch_attempted_at = a.created_at)
                    """)
                .param("scanRunId", scanRunId)
                .query(Boolean.class)
                .single());
    if (pending) {
      log.warn("event=analysis.scan.replay_dispatch_pending scanRunId={}", scanRunId);
      throw ScanException.dispatchUnavailable();
    }
  }

  /** 발행 실패 뒤 보존한 실행을 돌려준다. 그사이 버전·워크플로 삭제로 취소됐으면 다른 삭제 경합과 같게 404로 답한다. */
  private ScanRunView readPreservedRun(UUID scanRunId) {
    ScanRunView view = readScanRunById(scanRunId);
    if ("cancelled".equals(view.executionStatus())) {
      throw ScanException.versionNotFound();
    }
    return view;
  }

  private ScanRunView readScanRunById(UUID scanRunId) {
    return jdbc.sql(
            """
            SELECT s.*, v.version AS version_label
            FROM workflow_hub.scan_runs s
            JOIN workflow_hub.workflow_versions v ON v.id = s.workflow_version_id
            WHERE s.id = :scanRunId
            """)
        .param("scanRunId", scanRunId)
        .query(ScanService::mapScanRun)
        .single();
  }

  /**
   * SQS가 최초 발행을 명확히 거부하면 실행을 지우지 않고 failed(scan_dispatch_failed)로 마감한다. 이미 조회한 화면도 404 대신 실패 상태를
   * 보고, 같은 버전에 새 검사를 바로 요청할 수 있다. 멱등성 키는 해제해 같은 키로 다시 요청하면 새 검사를 만든다.
   *
   * <p>작업이 여전히 이 요청이 만든 시도를 가리키고, 그 시도가 queued이며, 발행이 확인되지 않았고, 회수기가 발행을 넘겨받지 않았을 때만 마감한다
   * (dispatch_attempted_at이 created_at과 같다). 그 밖에는 워커나 회수기가 처리 중이므로 그대로 둔다.
   */
  private RejectionOutcome failRejectedFirstDispatch(ScanTaskMessage message) {
    UUID taskId = message.taskId();
    UUID scanRunId = message.scanRunId();
    return transactions.execute(
        status -> {
          // 잠금을 얻은 뒤 별도 문장으로 읽어야 READ COMMITTED에서 잠금 대기 중 커밋된 시도 상태를 본다.
          jdbc.sql("SELECT id FROM workflow_hub.analysis_jobs WHERE id = :taskId FOR UPDATE")
              .param("taskId", taskId)
              .query(UUID.class)
              .single();
          JobDispatchState state =
              jdbc.sql(
                      """
                      SELECT j.status, j.current_attempt_id, a.status AS attempt_status,
                             a.dispatched_at IS NOT NULL AS dispatched,
                             a.dispatch_attempted_at > a.created_at AS taken_over
                      FROM workflow_hub.analysis_jobs j
                      JOIN workflow_hub.analysis_job_attempts a ON a.id = j.current_attempt_id
                      WHERE j.id = :taskId
                      """)
                  .param("taskId", taskId)
                  .query(
                      (rs, index) ->
                          new JobDispatchState(
                              rs.getString("status"),
                              rs.getObject("current_attempt_id", UUID.class),
                              rs.getString("attempt_status"),
                              rs.getBoolean("dispatched"),
                              rs.getBoolean("taken_over")))
                  .single();
          if ("cancelled".equals(state.jobStatus())) {
            return RejectionOutcome.CANCELLED;
          }
          if (!"queued".equals(state.jobStatus())
              || !message.attemptId().equals(state.currentAttemptId())
              || !"queued".equals(state.attemptStatus())
              || state.dispatched()
              || state.takenOver()) {
            return RejectionOutcome.PRESERVED;
          }
          OffsetDateTime now = databaseNow();
          jdbc.sql(
                  """
                  UPDATE workflow_hub.analysis_job_attempts
                  SET status = 'expired', finished_at = :now
                  WHERE id = :attemptId
                  """)
              .param("now", now)
              .param("attemptId", message.attemptId())
              .update();
          jdbc.sql(
                  """
                  UPDATE workflow_hub.analysis_jobs
                  SET status = 'failed', lease_expires_at = NULL, updated_at = :now
                  WHERE id = :taskId
                  """)
              .param("now", now)
              .param("taskId", taskId)
              .update();
          jdbc.sql(
                  """
                  UPDATE workflow_hub.scan_runs
                  SET execution_status = 'failed',
                      analysis_coverage = 'unknown',
                      error_code = :code,
                      error_message = :message,
                      error_retryable = false,
                      finished_at = :now
                  WHERE id = :scanRunId
                  """)
              .param("code", DISPATCH_FAILED_CODE)
              .param("message", DISPATCH_FAILED_MESSAGE)
              .param("now", now)
              .param("scanRunId", scanRunId)
              .update();
          jdbc.sql(
                  "DELETE FROM workflow_hub.scan_request_idempotency_keys WHERE scan_run_id = :scanRunId")
              .param("scanRunId", scanRunId)
              .update();
          log.warn(
              "event=analysis.scan.dispatch_rejected scanRunId={} taskId={}", scanRunId, taskId);
          return RejectionOutcome.FAILED;
        });
  }

  private enum RejectionOutcome {
    FAILED,
    CANCELLED,
    PRESERVED
  }

  private record JobDispatchState(
      String jobStatus,
      UUID currentAttemptId,
      String attemptStatus,
      boolean dispatched,
      boolean takenOver) {}

  private OffsetDateTime databaseNow() {
    return jdbc.sql("SELECT clock_timestamp()")
        .query((rs, index) -> rs.getObject(1, OffsetDateTime.class))
        .single();
  }

  private static String validateOptionalIdempotencyKey(String key) {
    if (key == null) {
      return null;
    }
    if (key.isBlank() || key.length() > MAX_IDEMPOTENCY_KEY_LENGTH || !key.equals(key.trim())) {
      throw ScanException.invalidIdempotencyKey(
          "Idempotency-Key must be a non-blank string up to 128 characters");
    }
    return key;
  }

  private static int resolveLimit(Integer limit) {
    if (limit == null) {
      return DEFAULT_LIMIT;
    }
    if (limit < 1 || limit > MAX_LIMIT) {
      throw ScanException.invalidLimit();
    }
    return limit;
  }

  static UUID parseId(String value, Supplier<ScanException> notFound) {
    if (value == null || value.isBlank()) {
      throw notFound.get();
    }
    try {
      return UUID.fromString(value);
    } catch (IllegalArgumentException e) {
      throw notFound.get();
    }
  }

  /** 검사 이력이 없는 살아 있는 버전 행(LEFT JOIN의 NULL 검사 열)은 빈 값으로 매핑한다. */
  private static Optional<ScanRunView> mapAliveVersionScan(ResultSet rs, int index)
      throws SQLException {
    if (rs.getObject("id") == null) {
      return Optional.empty();
    }
    return Optional.of(mapScanRun(rs, index));
  }

  private static ScanRunView mapScanRun(ResultSet rs, int index) throws SQLException {
    ScanVersions versions = mapVersions(rs);
    ScanSummary summary = mapSummary(rs);
    ScanError error = mapError(rs);
    OffsetDateTime createdAt = rs.getObject("created_at", OffsetDateTime.class);
    OffsetDateTime startedAt = rs.getObject("started_at", OffsetDateTime.class);
    OffsetDateTime finishedAt = rs.getObject("finished_at", OffsetDateTime.class);
    return new ScanRunView(
        rs.getObject("id", UUID.class),
        rs.getObject("workflow_id", UUID.class),
        rs.getObject("workflow_version_id", UUID.class),
        rs.getString("version_label"),
        rs.getString("input_sha256"),
        versions,
        rs.getString("execution_status"),
        rs.getString("analysis_coverage"),
        new ScanPolicy(
            rs.getString("policy_evaluation_status"),
            rs.getString("policy_decision"),
            rs.getString("policy_advisory_decision")),
        rs.getString("publication_status"),
        new ScanLlm(rs.getString("llm_status")),
        summary,
        rs.getString("service_report_s3_key") != null,
        error,
        createdAt.toInstant(),
        startedAt == null ? null : startedAt.toInstant(),
        finishedAt == null ? null : finishedAt.toInstant());
  }

  private static ScanVersions mapVersions(ResultSet rs) throws SQLException {
    String contractVersion = rs.getString("contract_version");
    if (contractVersion == null) {
      return null;
    }
    return new ScanVersions(
        contractVersion,
        rs.getString("inspection_version"),
        rs.getString("assessment_version"),
        rs.getString("engine_version"),
        rs.getString("rules_version"),
        rs.getString("adapter_version"));
  }

  private static ScanSummary mapSummary(ResultSet rs) throws SQLException {
    String headline = rs.getString("summary_headline");
    if (headline == null) {
      return null;
    }
    return new ScanSummary(
        headline,
        rs.getString("summary_analysis_status"),
        rs.getInt("summary_finding_count"),
        rs.getInt("summary_high_risk_finding_count"),
        rs.getInt("summary_observation_count"),
        rs.getInt("summary_analysis_gap_count"),
        rs.getInt("summary_sink_reachable_gap_count"),
        rs.getInt("summary_environment_check_count"),
        rs.getBoolean("summary_security_review_required"));
  }

  private static ScanError mapError(ResultSet rs) throws SQLException {
    String code = rs.getString("error_code");
    if (code == null) {
      return null;
    }
    return new ScanError(code, rs.getString("error_message"), rs.getBoolean("error_retryable"));
  }

  private static Long nullableLong(ResultSet rs, String column) throws SQLException {
    long value = rs.getLong(column);
    return rs.wasNull() ? null : value;
  }

  private record VersionRow(String versionLabel, String contentSha256, Long sizeBytes) {}

  private record IdempotencyRow(UUID workflowVersionId, UUID scanRunId) {}

  private record ActiveScan(UUID scanRunId, String status) {}

  private record CreationOutcome(ScanRunView view, ScanTaskMessage message) {}

  private record ReportMeta(
      UUID scanRunId,
      UUID workflowId,
      UUID workflowVersionId,
      String versionLabel,
      String inputSha256,
      ScanVersions versions,
      String serviceReportKey) {}
}
