package dev.workflowhub.analysis.service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import tools.jackson.databind.JsonNode;

/** 보안 검사 도메인의 조회·제출 결과 모델. */
public final class ScanModels {
  public static final String CONTRACT_VERSION = "1.0.0";

  private ScanModels() {}

  public record ScanVersions(
      String contractVersion,
      String inspectionVersion,
      String assessmentVersion,
      String engineVersion,
      String rulesVersion,
      String adapterVersion) {}

  public record ScanPolicy(String evaluationStatus, String decision, String advisoryDecision) {}

  public record ScanLlm(String status) {}

  public record ScanSummary(
      String headline,
      String analysisStatus,
      int findingCount,
      int highRiskFindingCount,
      int observationCount,
      int analysisGapCount,
      int sinkReachableGapCount,
      int environmentCheckCount,
      boolean securityReviewRequired) {}

  public record ScanError(String code, String message, boolean retryable) {}

  public record ScanRunView(
      UUID scanRunId,
      UUID workflowId,
      UUID workflowVersionId,
      String versionLabel,
      String inputSha256,
      ScanVersions versions,
      String executionStatus,
      String analysisCoverage,
      ScanPolicy policy,
      String publicationStatus,
      ScanLlm llm,
      ScanSummary summary,
      boolean reportAvailable,
      ScanError error,
      Instant createdAt,
      Instant startedAt,
      Instant finishedAt) {}

  public record ScanPage(List<ScanRunView> items, String nextCursor) {}

  public record ScanReportView(
      UUID scanRunId,
      UUID workflowId,
      UUID workflowVersionId,
      String versionLabel,
      String inputSha256,
      ScanVersions versions,
      JsonNode serviceReport) {}

  public record WorkerFileDownload(byte[] content, String inputSha256, Instant leaseExpiresAt) {}

  public record HeartbeatResult(UUID taskId, UUID attemptId, Instant leaseExpiresAt) {}

  public record ResultSubmission(
      boolean created, UUID scanRunId, String executionStatus, String analysisCoverage) {}
}
