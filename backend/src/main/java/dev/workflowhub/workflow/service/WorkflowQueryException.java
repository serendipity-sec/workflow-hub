package dev.workflowhub.workflow.service;

import org.springframework.http.HttpStatus;

public class WorkflowQueryException extends RuntimeException {
  private final HttpStatus status;
  private final String code;

  private WorkflowQueryException(HttpStatus status, String code, String message) {
    super(message);
    this.status = status;
    this.code = code;
  }

  public static WorkflowQueryException invalidLimit() {
    return new WorkflowQueryException(
        HttpStatus.BAD_REQUEST, "INVALID_LIMIT", "limit must be an integer between 1 and 100");
  }

  public static WorkflowQueryException invalidDownloadAvailability() {
    return new WorkflowQueryException(
        HttpStatus.BAD_REQUEST, "BAD_REQUEST", "downloadEnabled must be a boolean");
  }

  static WorkflowQueryException invalidCursor() {
    return new WorkflowQueryException(HttpStatus.BAD_REQUEST, "INVALID_CURSOR", "Invalid cursor");
  }

  static WorkflowQueryException workflowNotFound() {
    return new WorkflowQueryException(
        HttpStatus.NOT_FOUND, "WORKFLOW_NOT_FOUND", "Workflow not found");
  }

  static WorkflowQueryException versionNotFound() {
    return new WorkflowQueryException(
        HttpStatus.NOT_FOUND, "WORKFLOW_VERSION_NOT_FOUND", "Workflow version not found");
  }

  static WorkflowQueryException downloadDisabled() {
    return new WorkflowQueryException(
        HttpStatus.FORBIDDEN, "VERSION_DOWNLOAD_DISABLED", "Version download is disabled");
  }

  static WorkflowQueryException storageUnavailable() {
    return new WorkflowQueryException(
        HttpStatus.SERVICE_UNAVAILABLE, "STORAGE_UNAVAILABLE", "Could not read the file");
  }

  public HttpStatus status() {
    return status;
  }

  public String code() {
    return code;
  }
}
