package dev.workflowhub.workflow.api;

import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.workflow.service.WorkflowUploadException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.support.MissingServletRequestPartException;

/** 업로드 거절은 클라이언트 오류이므로 WARN으로 사유 코드만 남긴다. */
@RestControllerAdvice(assignableTypes = WorkflowUploadController.class)
@Order(Ordered.HIGHEST_PRECEDENCE)
class WorkflowUploadExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(WorkflowUploadExceptionHandler.class);

  @ExceptionHandler(WorkflowUploadException.class)
  ResponseEntity<ApiError> upload(WorkflowUploadException e) {
    // 5xx(저장소 장애)는 서비스에서 원인과 함께 ERROR로 이미 기록했다.
    log.warn("event=workflow.upload.rejected status={} code={}", e.status().value(), e.code());
    return ResponseEntity.status(e.status()).body(ApiError.of(e.code(), e.getMessage()));
  }

  @ExceptionHandler({
    MissingServletRequestPartException.class,
    MissingServletRequestParameterException.class
  })
  ResponseEntity<ApiError> missingFile() {
    log.warn("event=workflow.upload.rejected status=400 code=FILE_REQUIRED");
    return ResponseEntity.badRequest()
        .body(ApiError.of("FILE_REQUIRED", "A file part named 'file' is required"));
  }
}
