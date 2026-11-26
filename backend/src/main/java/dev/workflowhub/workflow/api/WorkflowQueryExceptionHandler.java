package dev.workflowhub.workflow.api;

import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.workflow.service.WorkflowQueryException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(
    assignableTypes = {WorkflowQueryController.class, WorkflowDeletionController.class})
@Order(Ordered.HIGHEST_PRECEDENCE)
class WorkflowQueryExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(WorkflowQueryExceptionHandler.class);

  @ExceptionHandler(WorkflowQueryException.class)
  ResponseEntity<ApiError> rejected(WorkflowQueryException e) {
    log.warn("event=workflow.query.rejected status={} code={}", e.status().value(), e.code());
    return ResponseEntity.status(e.status()).body(ApiError.of(e.code(), e.getMessage()));
  }
}
