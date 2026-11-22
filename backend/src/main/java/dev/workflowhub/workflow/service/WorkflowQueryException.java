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

  static WorkflowQueryException invalidCursor() {
    return new WorkflowQueryException(HttpStatus.BAD_REQUEST, "INVALID_CURSOR", "Invalid cursor");
  }

  static WorkflowQueryException workflowNotFound() {
    return new WorkflowQueryException(
        HttpStatus.NOT_FOUND, "WORKFLOW_NOT_FOUND", "Workflow not found");
  }

  public HttpStatus status() {
    return status;
  }

  public String code() {
    return code;
  }
}
