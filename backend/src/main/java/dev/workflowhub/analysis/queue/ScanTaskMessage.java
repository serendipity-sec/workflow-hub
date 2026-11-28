package dev.workflowhub.analysis.queue;

import java.time.Instant;
import java.util.UUID;

/** 백엔드가 SQS에 발행하는 보안 검사 작업 메시지(#39 §6.1). */
public record ScanTaskMessage(
    String contractVersion,
    UUID taskId,
    UUID attemptId,
    UUID scanRunId,
    UUID workflowVersionId,
    String inputSha256,
    long sizeBytes,
    int attemptNumber,
    int maxAttempts,
    Instant enqueuedAt) {}
