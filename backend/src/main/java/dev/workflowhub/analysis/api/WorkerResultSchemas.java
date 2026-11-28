package dev.workflowhub.analysis.api;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.UUID;

/**
 * PUT .../result 요청 본문의 OpenAPI 문서용 스키마. 서버는 Idempotency-Key 검증을 위해 원본 바이트를 그대로 읽어 {@code
 * WorkerTaskService}에서 검증하며, 이 레코드로 역직렬화하지 않는다. 필수 필드와 허용 값은 그 검증과 같게 유지한다. 문서에 없는 추가 필드는 허용한다.
 */
public final class WorkerResultSchemas {
  private static final String TASK_ID = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
  private static final String ATTEMPT_ID = "11111111-2222-4333-8444-555555555555";
  private static final String SCAN_RUN_ID = "9f8e7d6c-5b4a-4321-9876-543210fedcba";
  private static final String VERSION_ID = "5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33";
  private static final String SHA256 =
      "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
  private static final String SHA256_PATTERN = "^[0-9a-f]{64}$";
  private static final String SAME_HASH = "작업의 inputSha256과 같아야 한다";

  private WorkerResultSchemas() {}

  @Schema(
      name = "WorkerCompletedResult",
      description = "outcome=completed 결과. 공통 해시와 inspection 하위 해시를 모두 작업 기록과 대조한다",
      requiredProperties = {
        "contractVersion",
        "taskId",
        "attemptId",
        "scanRunId",
        "workflowVersionId",
        "inputSha256",
        "versions",
        "outcome",
        "inspection"
      })
  public record CompletedResult(
      @Schema(allowableValues = "1.0.0", example = "1.0.0") String contractVersion,
      @Schema(description = "경로의 taskId와 같아야 한다", example = TASK_ID) UUID taskId,
      @Schema(description = "경로의 attemptId와 같아야 한다", example = ATTEMPT_ID) UUID attemptId,
      @Schema(example = SCAN_RUN_ID) UUID scanRunId,
      @Schema(example = VERSION_ID) UUID workflowVersionId,
      @Schema(description = SAME_HASH, pattern = SHA256_PATTERN, example = SHA256)
          String inputSha256,
      ResultVersions versions,
      @Schema(allowableValues = "completed") String outcome,
      Inspection inspection) {}

  @Schema(
      name = "WorkerFailedResult",
      description = "outcome=failed 또는 timed_out 결과. 공통 해시만 대조하며 inspection은 없다",
      requiredProperties = {
        "contractVersion",
        "taskId",
        "attemptId",
        "scanRunId",
        "workflowVersionId",
        "inputSha256",
        "versions",
        "outcome",
        "error"
      })
  public record FailedResult(
      @Schema(allowableValues = "1.0.0", example = "1.0.0") String contractVersion,
      @Schema(description = "경로의 taskId와 같아야 한다", example = TASK_ID) UUID taskId,
      @Schema(description = "경로의 attemptId와 같아야 한다", example = ATTEMPT_ID) UUID attemptId,
      @Schema(example = SCAN_RUN_ID) UUID scanRunId,
      @Schema(example = VERSION_ID) UUID workflowVersionId,
      @Schema(description = SAME_HASH, pattern = SHA256_PATTERN, example = SHA256)
          String inputSha256,
      ResultVersions versions,
      @Schema(allowableValues = {"failed", "timed_out"}) String outcome,
      ResultError error) {}

  @Schema(
      name = "WorkerResultVersions",
      description = "contractVersion은 최상위 contractVersion과 같아야 한다",
      requiredProperties = {
        "contractVersion",
        "inspectionVersion",
        "assessmentVersion",
        "engineVersion",
        "rulesVersion",
        "adapterVersion"
      })
  public record ResultVersions(
      @Schema(example = "1.0.0") String contractVersion,
      @Schema(example = "1.1.0") String inspectionVersion,
      @Schema(example = "1.0.0") String assessmentVersion,
      @Schema(example = "0.10.0") String engineVersion,
      @Schema(example = "0.10.0") String rulesVersion,
      @Schema(example = "n8n@2.48.7/workflow-json@1") String adapterVersion) {}

  @Schema(
      name = "WorkerResultError",
      requiredProperties = {"code", "retryable"})
  public record ResultError(
      @Schema(
              description = "소문자 오류 코드",
              pattern = "^[a-z][a-z0-9_]{0,79}$",
              example = "hash_mismatch")
          String code,
      @Schema(description = "재시도 가능 여부. 재시도하지 않는 코드는 true여도 재시도하지 않는다") boolean retryable) {}

  @Schema(
      name = "WorkerInspection",
      description = "inspectionVersion은 versions.inspectionVersion과 같아야 한다",
      requiredProperties = {
        "inspectionVersion",
        "inputSha256",
        "assessment",
        "serviceReport",
        "llm"
      })
  public record Inspection(
      @Schema(allowableValues = "1.1.0") String inspectionVersion,
      @Schema(description = SAME_HASH, pattern = SHA256_PATTERN) String inputSha256,
      Assessment assessment,
      ServiceReport serviceReport,
      Llm llm) {}

  @Schema(
      name = "WorkerAssessment",
      description = "assessmentVersion·engineVersion은 versions의 같은 값과 같아야 한다. 원문은 비공개 S3에 저장한다",
      requiredProperties = {
        "assessmentVersion",
        "engineVersion",
        "inputSha256",
        "status",
        "decision"
      })
  public record Assessment(
      String assessmentVersion,
      String engineVersion,
      @Schema(description = SAME_HASH, pattern = SHA256_PATTERN) String inputSha256,
      @Schema(allowableValues = {"analyzed", "partial", "unsupported"}) String status,
      @Schema(allowableValues = {"allow", "review", "block", "inconclusive"}) String decision) {}

  @Schema(
      name = "WorkerServiceReport",
      description = "serviceReportVersion은 inspectionVersion과 같아야 한다. 원문은 비공개 S3에 저장한다",
      requiredProperties = {
        "serviceReportVersion",
        "inputSha256",
        "executionStatus",
        "analysisStatus",
        "headline",
        "counts",
        "serviceScope"
      })
  public record ServiceReport(
      String serviceReportVersion,
      @Schema(description = SAME_HASH, pattern = SHA256_PATTERN) String inputSha256,
      @Schema(allowableValues = {"completed", "completed_with_errors"}) String executionStatus,
      @Schema(allowableValues = {"complete", "review_required"}) String analysisStatus,
      String headline,
      Counts counts,
      ServiceScope serviceScope) {}

  @Schema(
      name = "WorkerServiceReportCounts",
      description = "모든 값은 0 이상의 32비트 정수",
      requiredProperties = {"findings", "observations", "analysisGaps", "environmentChecks"})
  public record Counts(
      @Schema(minimum = "0") int findings,
      @Schema(minimum = "0") int observations,
      @Schema(minimum = "0") int analysisGaps,
      @Schema(minimum = "0") int environmentChecks) {}

  @Schema(
      name = "WorkerServiceScope",
      requiredProperties = {
        "highRiskFindingCount",
        "sinkReachableGapCount",
        "securityReviewRequired"
      })
  public record ServiceScope(
      @Schema(minimum = "0") int highRiskFindingCount,
      @Schema(minimum = "0") int sinkReachableGapCount,
      boolean securityReviewRequired) {}

  @Schema(
      name = "WorkerLlm",
      requiredProperties = {"status", "inputSha256"})
  public record Llm(
      String status,
      @Schema(description = SAME_HASH, pattern = SHA256_PATTERN) String inputSha256) {}
}
