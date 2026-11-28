package dev.workflowhub.analysis.api;

import dev.workflowhub.analysis.service.ScanException;
import dev.workflowhub.common.api.ApiError;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice(assignableTypes = {ScanController.class, WorkerTaskController.class})
@Order(Ordered.HIGHEST_PRECEDENCE)
class ScanExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(ScanExceptionHandler.class);

  @ExceptionHandler(ScanException.class)
  ResponseEntity<ApiError> rejected(ScanException e) {
    if (e.status().is4xxClientError()) {
      log.warn("event=analysis.request.rejected status={} code={}", e.status().value(), e.code());
    }
    return ResponseEntity.status(e.status())
        .body(ApiError.of(e.code(), e.getMessage(), e.details()));
  }
}
