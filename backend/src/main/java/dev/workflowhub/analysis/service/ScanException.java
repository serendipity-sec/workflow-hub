package dev.workflowhub.analysis.service;

import java.util.Map;
import java.util.UUID;
import org.springframework.http.HttpStatus;

public class ScanException extends RuntimeException {
  private final HttpStatus status;
  private final String code;
  private final Map<String, Object> details;

  public ScanException(HttpStatus status, String code, String message) {
    this(status, code, message, null);
  }

  public ScanException(
      HttpStatus status, String code, String message, Map<String, Object> details) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }

  public HttpStatus status() {
    return status;
  }

  public String code() {
    return code;
  }

  public Map<String, Object> details() {
    return details;
  }

  public static ScanException versionNotFound() {
    return new ScanException(
        HttpStatus.NOT_FOUND, "WORKFLOW_VERSION_NOT_FOUND", "Workflow version not found");
  }

  public static ScanException scanRunNotFound() {
    return new ScanException(HttpStatus.NOT_FOUND, "SCAN_RUN_NOT_FOUND", "Scan run not found");
  }

  public static ScanException taskAttemptNotFound() {
    return new ScanException(
        HttpStatus.NOT_FOUND, "TASK_ATTEMPT_NOT_FOUND", "Task attempt not found");
  }

  public static ScanException invalidLimit() {
    return new ScanException(
        HttpStatus.BAD_REQUEST, "INVALID_LIMIT", "limit must be an integer between 1 and 100");
  }

  public static ScanException invalidCursor() {
    return new ScanException(
        HttpStatus.BAD_REQUEST, "INVALID_CURSOR", "cursor is not a valid pagination token");
  }

  public static ScanException invalidIdempotencyKey(String message) {
    return new ScanException(HttpStatus.BAD_REQUEST, "INVALID_IDEMPOTENCY_KEY", message);
  }

  public static ScanException badRequest(String message) {
    return new ScanException(HttpStatus.BAD_REQUEST, "BAD_REQUEST", message);
  }

  public static ScanException versionHashUnavailable() {
    return new ScanException(
        HttpStatus.CONFLICT,
        "VERSION_HASH_UNAVAILABLE",
        "Workflow version has no recorded SHA-256 hash");
  }

  public static ScanException alreadyInProgress(UUID scanRunId, String executionStatus) {
    return new ScanException(
        HttpStatus.CONFLICT,
        "SCAN_ALREADY_IN_PROGRESS",
        "A security scan is already queued or running for this version",
        Map.of("scanRunId", scanRunId.toString(), "executionStatus", executionStatus));
  }

  public static ScanException idempotencyConflict() {
    return new ScanException(
        HttpStatus.CONFLICT,
        "IDEMPOTENCY_KEY_CONFLICT",
        "Idempotency-Key was already used with a different request");
  }

  public static ScanException reportNotAvailable() {
    return new ScanException(
        HttpStatus.CONFLICT,
        "SCAN_REPORT_NOT_AVAILABLE",
        "Scan report is only available for completed scans");
  }

  public static ScanException taskCancelled() {
    return new ScanException(HttpStatus.CONFLICT, "TASK_CANCELLED", "Scan task has been cancelled");
  }

  public static ScanException taskNotRunnable() {
    return new ScanException(
        HttpStatus.CONFLICT, "TASK_NOT_RUNNABLE", "Task attempt is not in a runnable state");
  }

  public static ScanException attemptNotActive() {
    return new ScanException(
        HttpStatus.CONFLICT, "ATTEMPT_NOT_ACTIVE", "Task attempt is not currently running");
  }

  public static ScanException resultIdentityMismatch() {
    return new ScanException(
        HttpStatus.CONFLICT,
        "RESULT_IDENTITY_MISMATCH",
        "Submitted result identity or inputSha256 does not match the recorded task");
  }

  public static ScanException attemptExpired() {
    return new ScanException(
        HttpStatus.GONE, "ATTEMPT_EXPIRED", "Task attempt lease has expired or been superseded");
  }

  public static ScanException fileTooLarge(long maxBytes) {
    return new ScanException(
        HttpStatus.UNPROCESSABLE_CONTENT,
        "SCAN_FILE_TOO_LARGE",
        "Workflow file exceeds the security scan size limit of " + maxBytes + " bytes");
  }

  public static ScanException resultTooLarge(long maxBytes) {
    return new ScanException(
        HttpStatus.CONTENT_TOO_LARGE,
        "PAYLOAD_TOO_LARGE",
        "Worker result payload exceeds the maximum size of " + maxBytes + " bytes");
  }

  public static ScanException invalidResult(String message) {
    return new ScanException(HttpStatus.UNPROCESSABLE_CONTENT, "INVALID_RESULT", message);
  }

  public static ScanException dispatchUnavailable() {
    return new ScanException(
        HttpStatus.SERVICE_UNAVAILABLE,
        "SCAN_DISPATCH_UNAVAILABLE",
        "Failed to dispatch security scan task. Please try again later.");
  }

  public static ScanException storageUnavailable() {
    return new ScanException(
        HttpStatus.SERVICE_UNAVAILABLE,
        "STORAGE_UNAVAILABLE",
        "Storage is temporarily unavailable. Please try again later.");
  }
}
