package dev.workflowhub.analysis.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.analysis.queue.InMemoryScanTaskQueue;
import dev.workflowhub.analysis.queue.ScanTaskMessage;
import dev.workflowhub.analysis.service.ScanLeaseRecovery;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

/** 워커 내부 API 인증 분리, 파일 다운로드·임대·하트비트·결과 제출·멱등성·만료 회수 테스트(#57). */
@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfiguration.class, ScanApiTests.TestDoublesConfiguration.class})
class WorkerTaskApiTests {
  private static final String OWNER = "worker-test-owner";
  private static final String PRIMARY_TOKEN = "test-worker-token-primary";
  private static final String SECONDARY_TOKEN = "test-worker-token-secondary";
  private static final byte[] WORKFLOW_BYTES =
      """
      {
        "name": "Worker test flow",
        "nodes": [
          {"id":"n1","name":"Start","type":"n8n-nodes-base.manualTrigger","parameters":{}}
        ],
        "connections": {}
      }
      """
          .getBytes(StandardCharsets.UTF_8);

  @Autowired MockMvc mvc;
  @Autowired JdbcClient jdbc;
  @Autowired InMemoryWorkflowObjectStore store;
  @Autowired InMemoryScanTaskQueue queue;
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
  void isolatesWorkerInternalAuthFromUserJwtAndSupportsTokenRotation() throws Exception {
    ScanTaskMessage task = enqueueNewScan("k-worker-auth");
    String fileUrl = workerBase(task) + "/file";

    // 토큰 없음 -> 401 WORKER_UNAUTHORIZED
    mvc.perform(get(fileUrl))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("WORKER_UNAUTHORIZED"));

    // 잘못된 토큰 / 사용자 JWT 형태의 Bearer 헤더 -> 401 WORKER_UNAUTHORIZED
    mvc.perform(get(fileUrl).header("Authorization", "Bearer eyJhbGciOiJFUzI1NiJ9.user.jwt"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("WORKER_UNAUTHORIZED"));

    // 사용자 JWT Principal(ROLE_WORKER 없음) -> 403 WORKER_FORBIDDEN
    mvc.perform(get(fileUrl).with(jwt().jwt(token -> token.subject(OWNER))))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("WORKER_FORBIDDEN"));

    // 회전용 2차 활성 토큰으로 정상 인증
    mvc.perform(get(fileUrl).header("Authorization", "Bearer " + SECONDARY_TOKEN))
        .andExpect(status().isOk())
        .andExpect(header().string("X-Input-Sha256", task.inputSha256()))
        .andExpect(header().exists("X-Lease-Expires-At"))
        .andExpect(content().bytes(WORKFLOW_BYTES));
  }

  @Test
  void validatesFileFetchHeartbeatIdempotencyIdentityMismatchAndUnsupportedCoverage()
      throws Exception {
    ScanTaskMessage task = enqueueNewScan("k-worker-flow");
    String base = workerBase(task);

    // 아직 queued일 때 heartbeat는 409 ATTEMPT_NOT_ACTIVE
    mvc.perform(post(base + "/heartbeat").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("ATTEMPT_NOT_ACTIVE"));

    // GET /file 정상 수락 -> running + 60초 lease
    mvc.perform(get(base + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk())
        .andExpect(header().string("X-Input-Sha256", task.inputSha256()));

    // 이미 running인 시도에 GET /file 재호출 -> 409 TASK_NOT_RUNNABLE
    mvc.perform(get(base + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("TASK_NOT_RUNNABLE"));

    // POST /heartbeat -> 200 OK
    mvc.perform(post(base + "/heartbeat").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.taskId").value(task.taskId().toString()))
        .andExpect(jsonPath("$.data.attemptId").value(task.attemptId().toString()))
        .andExpect(jsonPath("$.data.leaseExpiresAt").isString());

    // 해시 불일치 제출 -> 409 RESULT_IDENTITY_MISMATCH
    byte[] badHashBody =
        completedBody(
            task, "0".repeat(64), "unsupported", "completed", "review_required", "inconclusive");
    mvc.perform(
            put(base + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(badHashBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(badHashBody))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("RESULT_IDENTITY_MISMATCH"));

    // scanRunId 불일치 제출 -> 409 RESULT_IDENTITY_MISMATCH
    byte[] wrongScanRunBody =
        completedBodyWithIds(
            task.taskId(),
            task.attemptId(),
            UUID.randomUUID(),
            task.workflowVersionId(),
            task.inputSha256(),
            "unsupported",
            "completed",
            "review_required",
            "inconclusive");
    mvc.perform(
            put(base + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(wrongScanRunBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(wrongScanRunBody))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("RESULT_IDENTITY_MISMATCH"));

    // 정상 제출(unsupported) -> 201 Created + analysisCoverage=unsupported
    byte[] validBody =
        completedBody(
            task,
            task.inputSha256(),
            "unsupported",
            "completed",
            "review_required",
            "inconclusive");
    String validKey = sha256(validBody);
    mvc.perform(
            put(base + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", validKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validBody))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.scanRunId").value(task.scanRunId().toString()))
        .andExpect(jsonPath("$.data.executionStatus").value("completed"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unsupported"));

    // 동일 Idempotency-Key 재전송 -> 200 OK (멱등)
    mvc.perform(
            put(base + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", validKey)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validBody))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.executionStatus").value("completed"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unsupported"));

    // 다른 본문·다른 Idempotency-Key 재전송 -> 409 IDEMPOTENCY_KEY_CONFLICT
    byte[] differentBody =
        completedBody(task, task.inputSha256(), "analyzed", "completed", "complete", "allow");
    mvc.perform(
            put(base + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(differentBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(differentBody))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_CONFLICT"));

    // pending_objects에 남은 고아 기록이 없어야 한다.
    assertThat(
            jdbc.sql("SELECT count(*) FROM workflow_hub.pending_objects")
                .query(Long.class)
                .single())
        .isZero();
  }

  @Test
  void rejectsExpiredAndSupersededAttemptsAndRecoversLeasesUpToMaxAttempts() throws Exception {
    ScanTaskMessage attempt1 = enqueueNewScan("k-lease-expiry");

    // 시도 1 시작
    mvc.perform(
            get(workerBase(attempt1) + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());

    // 임대 만료 시뮬레이션 (회수 스케줄러 실행 전에도 410 ATTEMPT_EXPIRED 거절)
    expireLease(attempt1.taskId(), attempt1.attemptId());

    mvc.perform(
            post(workerBase(attempt1) + "/heartbeat")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isGone())
        .andExpect(jsonPath("$.code").value("ATTEMPT_EXPIRED"));

    byte[] lateBody =
        completedBody(
            attempt1, attempt1.inputSha256(), "analyzed", "completed", "complete", "allow");
    mvc.perform(
            put(workerBase(attempt1) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(lateBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(lateBody))
        .andExpect(status().isGone())
        .andExpect(jsonPath("$.code").value("ATTEMPT_EXPIRED"));

    // 만료 회수 스케줄러 실행 -> 시도 2로 재발행
    leaseRecovery.recoverExpired();
    assertThat(queue.messages()).hasSize(2);
    ScanTaskMessage attempt2 = queue.lastMessage();
    assertThat(attempt2.attemptNumber()).isEqualTo(2);
    assertThat(attempt2.attemptId()).isNotEqualTo(attempt1.attemptId());

    // 시도 2 시작 후에도 이전 시도 1의 지연 결과는 410으로 거절되고 최신 상태를 덮어쓰지 못한다.
    mvc.perform(
            get(workerBase(attempt2) + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());
    mvc.perform(
            put(workerBase(attempt1) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(lateBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(lateBody))
        .andExpect(status().isGone())
        .andExpect(jsonPath("$.code").value("ATTEMPT_EXPIRED"));

    // 시도 2 만료 -> 회수 스케줄러 -> 시도 3 발행
    expireLease(attempt2.taskId(), attempt2.attemptId());
    leaseRecovery.recoverExpired();
    ScanTaskMessage attempt3 = queue.lastMessage();
    assertThat(attempt3.attemptNumber()).isEqualTo(3);

    // 시도 3 시작 후 만료 -> 최대 3회 소진 -> timed_out 마감
    mvc.perform(
            get(workerBase(attempt3) + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());
    expireLease(attempt3.taskId(), attempt3.attemptId());
    leaseRecovery.recoverExpired();

    String workflowId =
        jdbc.sql("SELECT workflow_id::text FROM workflow_hub.scan_runs WHERE id = :id")
            .param("id", attempt1.scanRunId())
            .query(String.class)
            .single();
    mvc.perform(
            get(
                    "/api/workflows/{w}/versions/{v}/scans/{s}",
                    workflowId,
                    attempt1.workflowVersionId(),
                    attempt1.scanRunId())
                .with(jwt().jwt(token -> token.subject(OWNER))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.executionStatus").value("timed_out"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unknown"))
        .andExpect(jsonPath("$.data.error.code").value("lease_expired"))
        .andExpect(jsonPath("$.data.error.retryable").value(false));
  }

  @Test
  void handlesNonRetryableFailureRetryableFailureAndCancelledSubmission() throws Exception {
    // 1) 비재시도 실패(hash_mismatch) -> 즉시 failed + unknown
    ScanTaskMessage hashTask = enqueueNewScan("k-hash-fail");
    mvc.perform(
            get(workerBase(hashTask) + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());
    byte[] hashMismatchBody = failureBody(hashTask, "failed", "hash_mismatch", false);
    mvc.perform(
            put(workerBase(hashTask) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(hashMismatchBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(hashMismatchBody))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.executionStatus").value("failed"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unknown"));

    // 2) 일시 오류(sandbox_unavailable, retryable=true) -> 재발행(attempt 2)
    ScanTaskMessage retryTask = enqueueNewScan("k-retry-fail");
    mvc.perform(
            get(workerBase(retryTask) + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());
    byte[] transientBody = failureBody(retryTask, "failed", "sandbox_unavailable", true);
    mvc.perform(
            put(workerBase(retryTask) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(transientBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(transientBody))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.executionStatus").value("queued"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unknown"));
    assertThat(queue.lastMessage().attemptNumber()).isEqualTo(2);

    // 3) 실행 중 버전 삭제 후 워커의 heartbeat와 PUT /result는 409 TASK_CANCELLED
    ScanTaskMessage cancelTask = enqueueNewScan("k-cancel-submit");
    mvc.perform(
            get(workerBase(cancelTask) + "/file")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());
    String workflowId =
        jdbc.sql("SELECT workflow_id::text FROM workflow_hub.scan_runs WHERE id = :id")
            .param("id", cancelTask.scanRunId())
            .query(String.class)
            .single();
    mvc.perform(
            delete("/api/workflows/{w}/versions/{v}", workflowId, cancelTask.workflowVersionId())
                .with(jwt().jwt(token -> token.subject(OWNER))))
        .andExpect(status().isOk());

    mvc.perform(
            post(workerBase(cancelTask) + "/heartbeat")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("TASK_CANCELLED"));

    byte[] cancelledBody =
        completedBody(
            cancelTask, cancelTask.inputSha256(), "analyzed", "completed", "complete", "allow");
    mvc.perform(
            put(workerBase(cancelTask) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(cancelledBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(cancelledBody))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("TASK_CANCELLED"));
  }

  @Test
  void rejectsInvalidHeadersSchemaOverflowUnknownAttemptsAndHandlesTimeoutAndStaleQueued()
      throws Exception {
    // 존재하지 않는 task/attempt -> 404 TASK_ATTEMPT_NOT_FOUND
    String missingBase =
        "/internal/worker/v1/tasks/" + UUID.randomUUID() + "/attempts/" + UUID.randomUUID();
    mvc.perform(get(missingBase + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("TASK_ATTEMPT_NOT_FOUND"));
    mvc.perform(post(missingBase + "/heartbeat").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("TASK_ATTEMPT_NOT_FOUND"));

    // Idempotency-Key 누락·불일치 -> 400 BAD_REQUEST, 정수 오버플로/버전 불일치 -> 422 INVALID_RESULT
    ScanTaskMessage task = enqueueNewScan("k-invalid-result");
    mvc.perform(get(workerBase(task) + "/file").header("Authorization", "Bearer " + PRIMARY_TOKEN))
        .andExpect(status().isOk());

    byte[] validBody =
        completedBody(task, task.inputSha256(), "analyzed", "completed", "complete", "allow");
    mvc.perform(
            put(workerBase(task) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(validBody))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
    mvc.perform(
            put(workerBase(task) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", "0".repeat(64))
                .contentType(MediaType.APPLICATION_JSON)
                .content(validBody))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

    byte[] overflowBody =
        new String(validBody, StandardCharsets.UTF_8)
            .replace("\"findings\": 0", "\"findings\": 4294967296")
            .getBytes(StandardCharsets.UTF_8);
    mvc.perform(
            put(workerBase(task) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(overflowBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(overflowBody))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("INVALID_RESULT"));

    // outcome=timed_out -> 즉시 timed_out + unknown 마감
    byte[] timeoutBody = failureBody(task, "timed_out", "assessment_timeout", false);
    mvc.perform(
            put(workerBase(task) + "/result")
                .header("Authorization", "Bearer " + PRIMARY_TOKEN)
                .header("Idempotency-Key", sha256(timeoutBody))
                .contentType(MediaType.APPLICATION_JSON)
                .content(timeoutBody))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.executionStatus").value("timed_out"))
        .andExpect(jsonPath("$.data.analysisCoverage").value("unknown"));

    // 오래 미수신 상태로 남은 queued 작업도 ScanLeaseRecovery가 재발행한다.
    ScanTaskMessage staleQueued = enqueueNewScan("k-stale-queued");
    jdbc.sql(
            "UPDATE workflow_hub.analysis_jobs SET updated_at = clock_timestamp() - interval '10 minutes' WHERE id = :id")
        .param("id", staleQueued.taskId())
        .update();
    leaseRecovery.recoverExpired();
    assertThat(queue.lastMessage().taskId()).isEqualTo(staleQueued.taskId());
    assertThat(queue.lastMessage().attemptNumber()).isEqualTo(2);
  }

  private void expireLease(UUID taskId, UUID attemptId) {
    jdbc.sql(
            "UPDATE workflow_hub.analysis_jobs SET lease_expires_at = clock_timestamp() - interval '5 seconds' WHERE id = :taskId")
        .param("taskId", taskId)
        .update();
    jdbc.sql(
            "UPDATE workflow_hub.analysis_job_attempts SET lease_expires_at = clock_timestamp() - interval '5 seconds' WHERE id = :attemptId")
        .param("attemptId", attemptId)
        .update();
  }

  private ScanTaskMessage enqueueNewScan(String uploadKey) throws Exception {
    MockMultipartFile file =
        new MockMultipartFile(
            "file", "workflow.json", MediaType.APPLICATION_JSON_VALUE, WORKFLOW_BYTES);
    MvcResult upload =
        mvc.perform(
                multipart("/api/workflows")
                    .file(file)
                    .header("Idempotency-Key", uploadKey)
                    .with(jwt().jwt(token -> token.subject(OWNER))))
            .andExpect(status().isCreated())
            .andReturn();
    String workflowId =
        JsonPath.read(upload.getResponse().getContentAsString(), "$.data.workflowId");
    String versionId = JsonPath.read(upload.getResponse().getContentAsString(), "$.data.versionId");

    mvc.perform(
            post("/api/workflows/{w}/versions/{v}/scans", workflowId, versionId)
                .with(jwt().jwt(token -> token.subject(OWNER))))
        .andExpect(status().isAccepted());
    return queue.lastMessage();
  }

  private static String workerBase(ScanTaskMessage task) {
    return "/internal/worker/v1/tasks/" + task.taskId() + "/attempts/" + task.attemptId();
  }

  private static byte[] completedBody(
      ScanTaskMessage task,
      String sha,
      String assessmentStatus,
      String reportExecStatus,
      String analysisStatus,
      String decision) {
    return completedBodyWithIds(
        task.taskId(),
        task.attemptId(),
        task.scanRunId(),
        task.workflowVersionId(),
        sha,
        assessmentStatus,
        reportExecStatus,
        analysisStatus,
        decision);
  }

  private static byte[] completedBodyWithIds(
      UUID taskId,
      UUID attemptId,
      UUID scanRunId,
      UUID versionId,
      String sha,
      String assessmentStatus,
      String reportExecStatus,
      String analysisStatus,
      String decision) {
    String json =
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
                "findings": 0,
                "observations": 0,
                "analysisGaps": 0,
                "environmentChecks": 1,
                "scopeNotes": 0
              },
              "serviceScope": {
                "highRiskFindingCount": 0,
                "sinkReachableGapCount": 0,
                "isolatedGapCount": 0,
                "usageNoticeCount": 1,
                "excludedScopeNoticeCount": 0,
                "securityReviewRequired": false
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
                taskId,
                attemptId,
                scanRunId,
                versionId,
                sha,
                sha,
                sha,
                assessmentStatus,
                decision,
                sha,
                reportExecStatus,
                analysisStatus,
                sha);
    return json.getBytes(StandardCharsets.UTF_8);
  }

  private static byte[] failureBody(
      ScanTaskMessage task, String outcome, String errorCode, boolean retryable) {
    String json =
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
          "outcome": "%s",
          "error": {
            "code": "%s",
            "retryable": %s
          }
        }
        """
            .formatted(
                task.taskId(),
                task.attemptId(),
                task.scanRunId(),
                task.workflowVersionId(),
                task.inputSha256(),
                outcome,
                errorCode,
                retryable);
    return json.getBytes(StandardCharsets.UTF_8);
  }

  private static String sha256(byte[] bytes) throws Exception {
    return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
  }
}
