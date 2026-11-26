package dev.workflowhub.workflow.service;

import org.springframework.http.HttpStatus;

/** API 오류 응답으로 바로 바뀌는 예외. message는 그대로 응답에 실린다. */
public class WorkflowUploadException extends RuntimeException {
  private final HttpStatus status;
  private final String code;

  public WorkflowUploadException(HttpStatus status, String code, String message) {
    super(message);
    this.status = status;
    this.code = code;
  }

  public HttpStatus status() {
    return status;
  }

  public String code() {
    return code;
  }
}
