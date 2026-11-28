package dev.workflowhub.analysis.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.analysis.queue.InMemoryScanTaskQueue;
import dev.workflowhub.analysis.queue.ScanTaskMessage;
import dev.workflowhub.analysis.service.ScanLeaseRecovery;
import dev.workflowhub.workflow.service.WorkflowObjectCleanup;
import dev.workflowhub.workflow.service.WorkflowVersionPurge;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** 소유자용 보안 검사 API, 지연 리포트 조회, 삭제 취소, 정리 통합 테스트(#57). */
@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfiguration.class, ScanApiTests.TestDoublesConfiguration.class})
class ScanApiTests {
  private static final String OWNER = "scan-owner-a";
  private static final String OTHER = "scan-owner-b";
  private static final String WORKER_TOKEN = "test-worker-token-primary";
  private static final byte[] WORKFLOW_BYTES =
      """
      {
        "name": "Synthetic scan target",
        "nodes": [
          {"id":"n1","name":"Start","type":"n8n-nodes-base.manualTrigger","parameters":{}}
        ],
        "connections": {}
      }
      """
          .getBytes(StandardCharsets.UTF_8);

  @TestConfiguration(proxyBeanMethods = false)
  public static class TestDoublesConfiguration {
    @Bean
    @Primary
    InMemoryWorkflowObjectStore inMemoryWorkflowObjectStore() {
      return new InMemoryWorkflowObjectStore();
    }

    @Bean
    @Primary
    InMemoryScanTaskQueue inMemoryScanTaskQueue() {
      return new InMemoryScanTaskQueue();
    }
  }

  @Autowired MockMvc mvc;
  @Autowired JdbcClient jdbc;
  @Autowired InMemoryWorkflowObjectStore store;
  @Autowired InMemoryScanTaskQueue queue;
  @Autowired WorkflowVersionPurge purge;
  @Autowired WorkflowObjectCleanup cleanup;
  @Autowired ScanLeaseRecovery leaseRecovery;

  @BeforeEach
  void reset() {
    jdbc.sql("DELETE FROM workflow_hub.scan_request_idempotency_keys").update();
    jdbc.sql("DELETE FROM workflow_hub.analysis_job_attempts").update();
    jdbc.sql("DELETE FROM workflow_hub.analysis_jobs").update();
    jdbc.sql("DELETE FROM workflow_hub.scan_runs").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_comparisons").update();
    jdbc.sql("DELETE FROM workflow_hub.idempotency_keys").update();
    jdbc.sql("DELETE FROM workflow_hub.pending_objects").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_versions").update();
    jdbc.sql("DELETE FROM workflow_hub.workflows").update();
    store.reset();
    queue.reset();
  }

  @Test
  void requiresAuthenticationAndBlocksWorkerTokenOnUserScanEndpoints() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-auth");
    String base = scansUrl(target);

    mvc.perform(post(base))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    mvc.perform(get(base))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    mvc.perform(get(base + "/latest"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    mvc.perform(get(base + "/" + UUID.randomUUID()))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    mvc.perform(get(base + "/" + UUID.randomUUID() + "/report"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

    // 워커 전용 토큰으로는 사용자 API에 접근할 수 없다.
    mvc.perform(get(base + "/latest").header("Authorization", "Bearer " + WORKER_TOKEN))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
  }

  @Test
  void enforcesOwnershipAndHidesMissingInvalidOrDeletedVersions() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-owner");
    String base = scansUrl(target);

    // 타인 소유 버전
    mvc.perform(post(base).with(user(OTHER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(get(base).with(user(OTHER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(get(base + "/latest").with(user(OTHER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));

    // 잘못된 UUID
    mvc.perform(post("/api/workflows/bad-uuid/versions/bad-uuid/scans").with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(get(base + "/bad-uuid").with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("SCAN_RUN_NOT_FOUND"));

    // 삭제된 버전
    mvc.perform(
            delete("/api/workflows/{w}/versions/{v}", target.workflowId(), target.versionId())
                .with(user(OWNER)))
        .andExpect(status().isOk());
    mvc.perform(post(base).with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(get(base + "/latest").with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
  }

  @Test
  void rejectsVersionWithoutHashOrOverScanFileSizeLimit() throws Exception {
    UploadedVersion missingHash = uploadWorkflow(OWNER, "k-nohash");
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET content_sha256 = NULL, size_bytes = NULL WHERE id = :id")
        .param("id", UUID.fromString(missingHash.versionId()))
        .update();

    mvc.perform(post(scansUrl(missingHash)).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("VERSION_HASH_UNAVAILABLE"));

    UploadedVersion tooLarge = uploadWorkflow(OWNER, "k-large");
    jdbc.sql("UPDATE workflow_hub.workflow_versions SET size_bytes = 262145 WHERE id = :id")
        .param("id", UUID.fromString(tooLarge.versionId()))
        .update();

    mvc.perform(post(scansUrl(tooLarge)).with(user(OWNER)))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("SCAN_FILE_TOO_LARGE"));
    assertThat(queue.messages()).isEmpty();
  }

  @Test
  void handlesLatestNullBeforeScanRequestIdempotencyActiveConflictAndSqsRollback()
      throws Exception {
    UploadedVersion first = uploadWorkflow(OWNER, "k-flow-1");
    UploadedVersion second = uploadWorkflow(OWNER, "k-flow-2");
    String base = scansUrl(first);

    // 아직 검사 이력이 없는 살아 있는 버전은 200 OK + data: null
    mvc.perform(get(base + "/latest").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data").value(nullValue()));

    // SQS가 발행을 명확히 거부하면 503을 반환하고 실행은 지우지 않고 failed로 마감한다. 멱등성 키는 해제된다.
    queue.rejectEnqueue = true;
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-001"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.code").value("SCAN_DISPATCH_UNAVAILABLE"));
    String rejectedId =
        jdbc.sql("SELECT id::text FROM workflow_hub.scan_runs").query(String.class).single();
    mvc.perform(get(base + "/" + rejectedId).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.executionStatus").value("failed"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unknown"))
        .andExpect(jsonPath("$.data.error.code").value("scan_dispatch_failed"))
        .andExpect(jsonPath("$.data.error.retryable").value(false));

    // 같은 키로 다시 요청하면 새 검사가 만들어진다.
    queue.rejectEnqueue = false;
    MvcResult created =
        mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-001"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.data.executionStatus").value("queued"))
            .andExpect(jsonPath("$.data.analysisCoverage").value("unknown"))
            .andExpect(jsonPath("$.data.policy.evaluationStatus").value("not_applicable"))
            .andExpect(jsonPath("$.data.publicationStatus").value("private"))
            .andExpect(jsonPath("$.data.llm.status").value("not_requested"))
            .andExpect(jsonPath("$.data.reportAvailable").value(false))
            .andReturn();
    String scanRunId =
        JsonPath.read(created.getResponse().getContentAsString(), "$.data.scanRunId");
    assertThat(scanRunId).isNotEqualTo(rejectedId);
    assertThat(queue.messages()).hasSize(1);

    // 같은 Idempotency-Key 재전송은 202와 동일 scanRunId를 돌려주고 SQS에 중복 발행하지 않는다.
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-001"))
        .andExpect(status().isAccepted())
        .andExpect(jsonPath("$.data.scanRunId").value(scanRunId));
    assertThat(queue.messages()).hasSize(1);

    // 같은 키를 다른 버전에 재사용하면 409 IDEMPOTENCY_KEY_CONFLICT
    mvc.perform(post(scansUrl(second)).with(user(OWNER)).header("Idempotency-Key", "req-001"))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_CONFLICT"));

    // 진행 중(queued) 검사가 있는 버전에 새 요청을 보내면 409 SCAN_ALREADY_IN_PROGRESS + details
    mvc.perform(post(base).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("SCAN_ALREADY_IN_PROGRESS"))
        .andExpect(jsonPath("$.details.scanRunId").value(scanRunId))
        .andExpect(jsonPath("$.details.executionStatus").value("queued"));

    // 완료 전에는 report 조회 불가(409 SCAN_REPORT_NOT_AVAILABLE)
    mvc.perform(get(base + "/" + scanRunId + "/report").with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("SCAN_REPORT_NOT_AVAILABLE"));

    // 잘못된 Idempotency-Key 형식은 400 INVALID_IDEMPOTENCY_KEY
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "   "))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_IDEMPOTENCY_KEY"));
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "x".repeat(129)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_IDEMPOTENCY_KEY"));
  }

  @Test
  void objectCleanupKeepsReferencedScanResultObjectsAndDeletesOrphans() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-cleanup");
    String base = scansUrl(target);

    mvc.perform(post(base).with(user(OWNER))).andExpect(status().isAccepted());
    ScanTaskMessage task = queue.lastMessage();
    completeScan(task, "analyzed", "completed", "complete", "allow", 0, 0, false);

    String referencedReportKey =
        jdbc.sql("SELECT service_report_s3_key FROM workflow_hub.scan_runs WHERE id = :id")
            .param("id", task.scanRunId())
            .query(String.class)
            .single();
    String orphanKey = "scan-results/orphan/service-report.json";
    store.put(orphanKey, "{}".getBytes(StandardCharsets.UTF_8));

    // 참조 중인 결과 키와 미참조 고아 키 모두 만료된 pending_objects에 넣고 정리 실행
    jdbc.sql(
            "INSERT INTO workflow_hub.pending_objects (object_key, cleanup_after) VALUES (:k, clock_timestamp() - interval '1 minute')")
        .param("k", referencedReportKey)
        .update();
    jdbc.sql(
            "INSERT INTO workflow_hub.pending_objects (object_key, cleanup_after) VALUES (:k, clock_timestamp() - interval '1 minute')")
        .param("k", orphanKey)
        .update();

    cleanup.cleanDue();

    assertThat(store.objects()).containsKey(referencedReportKey);
    assertThat(store.objects()).doesNotContainKey(orphanKey);
    assertThat(
            jdbc.sql("SELECT count(*) FROM workflow_hub.pending_objects")
                .query(Long.class)
                .single())
        .isZero();
  }

  @Test
  void servesDbOnlySummaryOnDetailAndLazyLoadsServiceReportFromPrivateS3() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-report");
    String base = scansUrl(target);

    mvc.perform(post(base).with(user(OWNER))).andExpect(status().isAccepted());
    ScanTaskMessage task = queue.lastMessage();

    // 워커가 파일을 받아 완료 결과 제출 (checked + findings 0)
    completeScan(task, "analyzed", "completed", "complete", "allow", 0, 0, false);

    // 단건 상세와 latest는 DB 요약만 반환하고 reportAvailable=true를 표시 (S3 키 노출 없음)
    MvcResult detail =
        mvc.perform(get(base + "/" + task.scanRunId()).with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.executionStatus").value("completed"))
            .andExpect(jsonPath("$.data.analysisCoverage").value("checked"))
            .andExpect(jsonPath("$.data.policy.advisoryDecision").value("allow"))
            .andExpect(jsonPath("$.data.summary.findingCount").value(0))
            .andExpect(jsonPath("$.data.summary.analysisGapCount").value(0))
            .andExpect(jsonPath("$.data.summary.analysisStatus").value("complete"))
            .andExpect(jsonPath("$.data.summary.securityReviewRequired").value(false))
            .andExpect(jsonPath("$.data.reportAvailable").value(true))
            .andExpect(jsonPath("$.data.serviceReport").doesNotExist())
            .andReturn();
    assertThat(detail.getResponse().getContentAsString()).doesNotContain("scan-results/");

    mvc.perform(get(base + "/latest").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.scanRunId").value(task.scanRunId().toString()))
        .andExpect(jsonPath("$.data.reportAvailable").value(true));

    // 자세히 보기: 별도 /report 경로에서 비공개 S3의 serviceReport를 소유권 확인 후 반환
    MvcResult report =
        mvc.perform(get(base + "/" + task.scanRunId() + "/report").with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.scanRunId").value(task.scanRunId().toString()))
            .andExpect(jsonPath("$.data.inputSha256").value(task.inputSha256()))
            .andExpect(jsonPath("$.data.serviceReport.serviceReportVersion").value("1.1.0"))
            .andExpect(jsonPath("$.data.serviceReport.analysisStatus").value("complete"))
            .andReturn();
    assertThat(report.getResponse().getContentAsString()).doesNotContain("scan-results/");

    // 타인 소유자는 /report 조회 불가(404)
    mvc.perform(get(base + "/" + task.scanRunId() + "/report").with(user(OTHER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("SCAN_RUN_NOT_FOUND"));

    // 목록 커서 페이지네이션 검증: 두 번째 검사(partial) 생성 후 limit=1로 2페이지 순회
    mvc.perform(post(base).with(user(OWNER))).andExpect(status().isAccepted());
    ScanTaskMessage secondTask = queue.lastMessage();
    completeScan(secondTask, "partial", "completed", "review_required", "inconclusive", 1, 2, true);

    MvcResult page1 =
        mvc.perform(get(base).param("limit", "1").with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.items", hasSize(1)))
            .andExpect(
                jsonPath("$.data.items[0].scanRunId").value(secondTask.scanRunId().toString()))
            .andExpect(jsonPath("$.data.items[0].analysisCoverage").value("partial"))
            .andExpect(jsonPath("$.data.items[0].summary.securityReviewRequired").value(true))
            .andExpect(jsonPath("$.data.nextCursor").isString())
            .andReturn();
    String nextCursor =
        JsonPath.read(page1.getResponse().getContentAsString(), "$.data.nextCursor");

    mvc.perform(get(base).param("limit", "1").param("cursor", nextCursor).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items", hasSize(1)))
        .andExpect(jsonPath("$.data.items[0].scanRunId").value(task.scanRunId().toString()))
        .andExpect(jsonPath("$.data.nextCursor").value(nullValue()));

    // 잘못된 페이지네이션 파라미터
    mvc.perform(get(base).param("limit", "0").with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_LIMIT"));
    mvc.perform(get(base).param("cursor", "broken").with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_CURSOR"));
  }

  @Test
  void cancelsInProgressScanOnDeletionAndPurgesStoredScanObjectsAfterGrace() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-delete");
    String base = scansUrl(target);

    // 첫 검사 완료 후 S3에 결과 객체 저장 확인
    mvc.perform(post(base).with(user(OWNER))).andExpect(status().isAccepted());
    ScanTaskMessage completedTask = queue.lastMessage();
    completeScan(completedTask, "analyzed", "completed", "complete", "allow", 0, 0, false);
    assertThat(store.objects().keySet().stream().filter(k -> k.startsWith("scan-results/")).count())
        .isEqualTo(2);

    // 두 번째 검사 시작(running)
    mvc.perform(post(base).with(user(OWNER))).andExpect(status().isAccepted());
    ScanTaskMessage runningTask = queue.lastMessage();
    mvc.perform(
            get(
                    "/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/file",
                    runningTask.taskId(),
                    runningTask.attemptId())
                .header("Authorization", "Bearer " + WORKER_TOKEN))
        .andExpect(status().isOk());

    // 워크플로 삭제 시 진행 중 검사가 같은 트랜잭션에서 cancelled로 전환된다.
    mvc.perform(delete("/api/workflows/{workflowId}", target.workflowId()).with(user(OWNER)))
        .andExpect(status().isOk());

    String runningScanStatus =
        jdbc.sql("SELECT execution_status FROM workflow_hub.scan_runs WHERE id = :id")
            .param("id", runningTask.scanRunId())
            .query(String.class)
            .single();
    assertThat(runningScanStatus).isEqualTo("cancelled");

    // 삭제 후 복구 기한 경과 시 purge가 원본과 함께 S3 결과 객체도 정리한다.
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET delete_after = clock_timestamp() - interval '1 minute' WHERE id = :id")
        .param("id", UUID.fromString(target.versionId()))
        .update();
    purge.purgeDue();

    assertThat(store.objects()).isEmpty();
    Long remainingKeys =
        jdbc.sql(
                "SELECT count(*) FROM workflow_hub.scan_runs WHERE service_report_s3_key IS NOT NULL OR assessment_s3_key IS NOT NULL")
            .query(Long.class)
            .single();
    assertThat(remainingKeys).isZero();
  }

  @Test
  void unknownFirstDispatchFailureKeepsTheRunAndRecoveryResendsTheSameAttempt() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-dispatch-unknown");
    String base = scansUrl(target);

    // 시간 초과처럼 결과를 알 수 없는 실패는 메시지가 이미 큐에 있을 수 있으므로 실행을 보존하고 202를 준다.
    queue.failEnqueue = true;
    MvcResult created =
        mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-unknown"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.data.executionStatus").value("queued"))
            .andReturn();
    String scanRunId =
        JsonPath.read(created.getResponse().getContentAsString(), "$.data.scanRunId");
    UUID attempt1 = currentAttempt(scanRunId);
    assertThat(dispatched(attempt1)).isFalse();

    // 목록·최신은 보존된 같은 실행을 보여 준다. 첫 발행 결과가 정해지기 전 같은 키 재전송은 재시도 가능한 503이다.
    mvc.perform(get(base + "/latest").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.scanRunId").value(scanRunId));
    queue.failEnqueue = false;
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-unknown"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.code").value("SCAN_DISPATCH_UNAVAILABLE"));
    assertThat(queue.messages()).isEmpty();

    // 재발행 간격이 지나면 회수기가 같은 attemptId로 다시 보내고, 이후 재전송은 같은 scanRunId로 202를 받는다.
    backdateDispatchAttempt(attempt1);
    leaseRecovery.recoverExpired();
    assertThat(queue.messages()).hasSize(1);
    assertThat(queue.lastMessage().attemptId()).isEqualTo(attempt1);
    assertThat(queue.lastMessage().attemptNumber()).isEqualTo(1);
    assertThat(dispatched(attempt1)).isTrue();
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-unknown"))
        .andExpect(status().isAccepted())
        .andExpect(jsonPath("$.data.scanRunId").value(scanRunId));
    assertThat(queue.messages()).hasSize(1);
  }

  @Test
  void unknownFirstDispatchFailureAfterConcurrentDeletionAnswersNotFound() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-dispatch-deleted");
    // 첫 발행을 기다리는 사이 버전 삭제가 진행 중 검사를 취소한 상태를 만든다.
    queue.failEnqueue = true;
    queue.beforeEnqueue =
        () -> {
          jdbc.sql(
                  "UPDATE workflow_hub.analysis_job_attempts SET status = 'cancelled', finished_at = clock_timestamp()")
              .update();
          jdbc.sql("UPDATE workflow_hub.analysis_jobs SET status = 'cancelled'").update();
          jdbc.sql(
                  "UPDATE workflow_hub.scan_runs SET execution_status = 'cancelled', finished_at = clock_timestamp()")
              .update();
        };
    mvc.perform(post(scansUrl(target)).with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
  }

  @Test
  void rejectedFirstDispatchKeepsTheRunWhenRecoveryAlreadyTookOverTheAttempt() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-reject-takeover");
    String base = scansUrl(target);

    // 최초 SQS 호출이 오래 걸리는 사이 회수기가 같은 시도의 발행을 넘겨받는다(회수기의 발행도 거부됨).
    queue.rejectEnqueue = true;
    queue.beforeEnqueue =
        () -> {
          jdbc.sql(
                  "UPDATE workflow_hub.analysis_job_attempts SET dispatch_attempted_at = clock_timestamp() - interval '10 minutes'")
              .update();
          leaseRecovery.recoverExpired();
        };
    MvcResult created =
        mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-takeover"))
            .andExpect(status().isAccepted())
            .andExpect(jsonPath("$.data.executionStatus").value("queued"))
            .andReturn();
    String scanRunId =
        JsonPath.read(created.getResponse().getContentAsString(), "$.data.scanRunId");
    UUID attempt1 = currentAttempt(scanRunId);

    // 최초 요청의 거부가 회수기가 넘겨받은 시도를 failed로 마감하지 않는다.
    mvc.perform(get(base + "/" + scanRunId).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.executionStatus").value("queued"));
    mvc.perform(post(base).with(user(OWNER)).header("Idempotency-Key", "req-takeover"))
        .andExpect(status().isAccepted())
        .andExpect(jsonPath("$.data.scanRunId").value(scanRunId));

    // SQS가 복구되면 회수기가 같은 attemptId로 발행한다.
    queue.rejectEnqueue = false;
    backdateDispatchAttempt(attempt1);
    leaseRecovery.recoverExpired();
    assertThat(queue.messages()).hasSize(1);
    assertThat(queue.lastMessage().attemptId()).isEqualTo(attempt1);
  }

  @Test
  void queuedTimeoutResendsAnUnconfirmedAttemptOnceBeforeConsumingAnAttempt() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-window");
    String base = scansUrl(target);
    queue.failEnqueue = true;
    MvcResult created =
        mvc.perform(post(base).with(user(OWNER))).andExpect(status().isAccepted()).andReturn();
    String scanRunId =
        JsonPath.read(created.getResponse().getContentAsString(), "$.data.scanRunId");
    UUID attempt1 = currentAttempt(scanRunId);

    // 회수 주기 때문에 재발행 구간을 건너뛰어 미수신 제한 시간까지 지난 상태를 만든다.
    queue.failEnqueue = false;
    jdbc.sql(
            "UPDATE workflow_hub.analysis_jobs SET updated_at = clock_timestamp() - interval '10 minutes'")
        .update();
    backdateDispatchAttempt(attempt1);

    // 시도를 만료하지 않고 같은 attemptId를 먼저 다시 보낸다.
    leaseRecovery.recoverExpired();
    assertThat(queue.messages()).hasSize(1);
    assertThat(queue.lastMessage().attemptId()).isEqualTo(attempt1);
    assertThat(queue.lastMessage().attemptNumber()).isEqualTo(1);
    assertThat(currentAttempt(scanRunId)).isEqualTo(attempt1);

    // 재발행 직후에는 만료하지 않는다. 발행 시각부터 미수신 제한 시간이 지나도 워커가 시작하지 않으면 그때 다음 시도로 넘긴다.
    leaseRecovery.recoverExpired();
    assertThat(queue.messages()).hasSize(1);
    jdbc.sql(
            "UPDATE workflow_hub.analysis_job_attempts SET dispatched_at = clock_timestamp() - interval '10 minutes' WHERE id = :id")
        .param("id", attempt1)
        .update();
    leaseRecovery.recoverExpired();
    assertThat(queue.messages()).hasSize(2);
    assertThat(queue.lastMessage().attemptNumber()).isEqualTo(2);
  }

  private UUID currentAttempt(String scanRunId) {
    return jdbc.sql(
            "SELECT current_attempt_id FROM workflow_hub.analysis_jobs WHERE scan_run_id = :id")
        .param("id", UUID.fromString(scanRunId))
        .query(UUID.class)
        .single();
  }

  private void backdateDispatchAttempt(UUID attemptId) {
    jdbc.sql(
            "UPDATE workflow_hub.analysis_job_attempts SET dispatch_attempted_at = clock_timestamp() - interval '10 minutes' WHERE id = :id")
        .param("id", attemptId)
        .update();
  }

  @Test
  void purgeDoesNotLetOneFailingVersionBlockOtherDueVersions() throws Exception {
    UploadedVersion stuck = uploadWorkflow(OWNER, "k-purge-stuck");
    UploadedVersion later = uploadWorkflow(OWNER, "k-purge-later");
    mvc.perform(post(scansUrl(stuck)).with(user(OWNER))).andExpect(status().isAccepted());
    completeScan(queue.lastMessage(), "analyzed", "completed", "complete", "allow", 0, 0, false);
    String stuckReportKey =
        jdbc.sql(
                "SELECT service_report_s3_key FROM workflow_hub.scan_runs WHERE workflow_version_id = :id")
            .param("id", UUID.fromString(stuck.versionId()))
            .query(String.class)
            .single();
    store.failDeleteKeys.add(stuckReportKey);

    for (UploadedVersion v : new UploadedVersion[] {stuck, later}) {
      mvc.perform(delete("/api/workflows/{workflowId}", v.workflowId()).with(user(OWNER)))
          .andExpect(status().isOk());
    }
    expireVersion(stuck, "2 minutes");
    expireVersion(later, "1 minute");

    // 기한이 먼저인 버전의 결과 객체 삭제가 실패하면 이번 실행은 멈춘다.
    purge.purgeDue();
    assertThat(purged(stuck)).isFalse();
    assertThat(purged(later)).isFalse();

    // 재시도 간격이 실행 간격보다 짧아 실패한 버전이 바로 다시 대상이 되어도, 처음 정리하는 버전을 먼저 처리한다.
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET delete_started_at = clock_timestamp() - interval '1 hour' WHERE id = :id")
        .param("id", UUID.fromString(stuck.versionId()))
        .update();
    purge.purgeDue();
    assertThat(purged(later)).isTrue();
    assertThat(purged(stuck)).isFalse();

    // 원인이 사라지면 재시도에서 마저 정리한다.
    store.failDeleteKeys.clear();
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET delete_started_at = clock_timestamp() - interval '1 hour' WHERE id = :id")
        .param("id", UUID.fromString(stuck.versionId()))
        .update();
    purge.purgeDue();
    assertThat(purged(stuck)).isTrue();
    assertThat(store.objects()).isEmpty();
  }

  @Test
  void purgeLimitsDeleteCallsPerRunAndResumesFromRecordedProgress() throws Exception {
    UploadedVersion target = uploadWorkflow(OWNER, "k-purge-budget");
    UUID versionId = UUID.fromString(target.versionId());
    // 결과 객체 두 개씩을 가진 완료 검사 150건(객체 300개)을 만든다.
    jdbc.sql(
            """
            INSERT INTO workflow_hub.scan_runs (
                workflow_id, workflow_version_id, input_sha256, size_bytes,
                execution_status, analysis_coverage, service_report_s3_key, assessment_s3_key)
            SELECT :workflowId, :versionId, repeat('a', 64), 10, 'completed', 'checked',
                   'scan-results/budget/' || g || '/service-report.json',
                   'scan-results/budget/' || g || '/assessment.json'
            FROM generate_series(1, 150) AS g
            """)
        .param("workflowId", UUID.fromString(target.workflowId()))
        .param("versionId", versionId)
        .update();
    for (int i = 1; i <= 150; i++) {
      store.objects().put("scan-results/budget/" + i + "/service-report.json", new byte[] {1});
      store.objects().put("scan-results/budget/" + i + "/assessment.json", new byte[] {1});
    }
    mvc.perform(delete("/api/workflows/{workflowId}", target.workflowId()).with(user(OWNER)))
        .andExpect(status().isOk());
    expireVersion(target, "1 minute");
    store.deleteCalls.set(0);

    // 한 실행의 삭제 호출은 200회를 넘지 않고, 지운 검사 행의 키를 비워 진행 상태를 남긴다.
    purge.purgeDue();
    assertThat(store.deleteCalls.get()).isEqualTo(200);
    assertThat(purged(target)).isFalse();
    assertThat(remainingScanKeys(versionId)).isEqualTo(50L);
    assertThat(
            jdbc.sql(
                    "SELECT delete_started_at IS NOT NULL FROM workflow_hub.workflow_versions WHERE id = :id")
                .param("id", versionId)
                .query(Boolean.class)
                .single())
        .isTrue();

    // 다음 실행은 남은 객체와 원본을 지운 뒤에만 정리 완료로 표시한다.
    purge.purgeDue();
    assertThat(store.deleteCalls.get()).isEqualTo(301);
    assertThat(purged(target)).isTrue();
    assertThat(remainingScanKeys(versionId)).isZero();
    assertThat(store.objects()).isEmpty();
  }

  private boolean dispatched(UUID attemptId) {
    return jdbc.sql(
            "SELECT dispatched_at IS NOT NULL FROM workflow_hub.analysis_job_attempts WHERE id = :id")
        .param("id", attemptId)
        .query(Boolean.class)
        .single();
  }

  private void expireVersion(UploadedVersion v, String ago) {
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET delete_after = clock_timestamp() - CAST(:ago AS interval) WHERE id = :id")
        .param("ago", ago)
        .param("id", UUID.fromString(v.versionId()))
        .update();
  }

  private boolean purged(UploadedVersion v) {
    return jdbc.sql(
            "SELECT purged_at IS NOT NULL FROM workflow_hub.workflow_versions WHERE id = :id")
        .param("id", UUID.fromString(v.versionId()))
        .query(Boolean.class)
        .single();
  }

  private Long remainingScanKeys(UUID versionId) {
    return jdbc.sql(
            "SELECT count(*) FROM workflow_hub.scan_runs WHERE workflow_version_id = :id AND service_report_s3_key IS NOT NULL")
        .param("id", versionId)
        .query(Long.class)
        .single();
  }

  private void completeScan(
      ScanTaskMessage task,
      String assessmentStatus,
      String reportExecStatus,
      String analysisStatus,
      String decision,
      int findings,
      int analysisGaps,
      boolean reviewRequired)
      throws Exception {
    mvc.perform(
            get(
                    "/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/file",
                    task.taskId(),
                    task.attemptId())
                .header("Authorization", "Bearer " + WORKER_TOKEN))
        .andExpect(status().isOk());

    String body =
        """
        {
          "contractVersion": "1.0.0",
          "taskId": "%s",
          "attemptId": "%s",
          "scanRunId": "%s",
          "workflowVersionId": "%s",
          "inputSha256": "%s",
          "versions": {
            "contractVersion": "1.0.0",
            "inspectionVersion": "1.1.0",
            "assessmentVersion": "1.0.0",
            "engineVersion": "0.10.0",
            "rulesVersion": "0.10.0",
            "adapterVersion": "n8n@2.48.7/workflow-json@1"
          },
          "outcome": "completed",
          "inspection": {
            "inspectionVersion": "1.1.0",
            "inputSha256": "%s",
            "assessment": {
              "assessmentVersion": "1.0.0",
              "engineVersion": "0.10.0",
              "inputSha256": "%s",
              "execution": "not_run",
              "status": "%s",
              "decision": "%s"
            },
            "serviceReport": {
              "serviceReportVersion": "1.1.0",
              "inputSha256": "%s",
              "executionStatus": "%s",
              "analysisStatus": "%s",
              "headline": "지원 범위의 검사 결과와 사용 조건을 확인하세요",
              "counts": {
                "findings": %d,
                "observations": 0,
                "analysisGaps": %d,
                "environmentChecks": 1,
                "scopeNotes": 0
              },
              "serviceScope": {
                "highRiskFindingCount": %d,
                "sinkReachableGapCount": %d,
                "isolatedGapCount": 0,
                "usageNoticeCount": 1,
                "excludedScopeNoticeCount": 0,
                "securityReviewRequired": %s
              },
              "findings": [],
              "analysisGaps": [],
              "environmentChecks": [],
              "scopeNotes": [],
              "truncated": false
            },
            "llm": {
              "status": "unavailable",
              "code": "disabled",
              "inputSha256": "%s"
            }
          }
        }
        """
            .formatted(
                task.taskId(),
                task.attemptId(),
                task.scanRunId(),
                task.workflowVersionId(),
                task.inputSha256(),
                task.inputSha256(),
                task.inputSha256(),
                assessmentStatus,
                decision,
                task.inputSha256(),
                reportExecStatus,
                analysisStatus,
                findings,
                analysisGaps,
                findings,
                analysisGaps,
                reviewRequired,
                task.inputSha256());

    byte[] raw = body.getBytes(StandardCharsets.UTF_8);
    mvc.perform(
            put(
                    "/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/result",
                    task.taskId(),
                    task.attemptId())
                .header("Authorization", "Bearer " + WORKER_TOKEN)
                .header("Idempotency-Key", sha256(raw))
                .contentType(MediaType.APPLICATION_JSON)
                .content(raw))
        .andExpect(status().isCreated());
  }

  private UploadedVersion uploadWorkflow(String owner, String key) throws Exception {
    MockMultipartFile file =
        new MockMultipartFile(
            "file", "workflow.json", MediaType.APPLICATION_JSON_VALUE, WORKFLOW_BYTES);
    MvcResult result =
        mvc.perform(
                multipart("/api/workflows")
                    .file(file)
                    .header("Idempotency-Key", key)
                    .with(user(owner)))
            .andExpect(status().isCreated())
            .andReturn();
    String json = result.getResponse().getContentAsString();
    return new UploadedVersion(
        JsonPath.read(json, "$.data.workflowId"), JsonPath.read(json, "$.data.versionId"));
  }

  private static String scansUrl(UploadedVersion v) {
    return "/api/workflows/" + v.workflowId() + "/versions/" + v.versionId() + "/scans";
  }

  private static RequestPostProcessor user(String subject) {
    return jwt().jwt(token -> token.subject(subject));
  }

  private static String sha256(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }

  private record UploadedVersion(String workflowId, String versionId) {}
}
