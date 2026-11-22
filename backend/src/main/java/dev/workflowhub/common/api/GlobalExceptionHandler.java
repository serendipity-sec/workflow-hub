package dev.workflowhub.common.api;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.TypeMismatchException;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.multipart.MaxUploadSizeExceededException;
import org.springframework.web.multipart.MultipartException;

/** 도메인 핸들러가 처리하지 않은 예외를 ApiError로 바꾸고 원인을 로그에 남긴다. */
@RestControllerAdvice
@Order(Ordered.LOWEST_PRECEDENCE)
class GlobalExceptionHandler {
  private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);
  private final UploadLimit limit;

  GlobalExceptionHandler(UploadLimit limit) {
    this.limit = limit;
  }

  /** 서블릿 단계에서 던져져 컨트롤러 전용 핸들러가 닿지 않으므로 여기서 처리한다. */
  @ExceptionHandler(MaxUploadSizeExceededException.class)
  ResponseEntity<ApiError> tooLarge() {
    log.warn("event=http.error status=413 code=FILE_TOO_LARGE");
    return ResponseEntity.status(HttpStatus.CONTENT_TOO_LARGE)
        .body(ApiError.of("FILE_TOO_LARGE", limit.tooLargeMessage()));
  }

  /** 깨진 multipart 본문이나 잘못된 파라미터 타입은 클라이언트 오류다. */
  @ExceptionHandler({
    MultipartException.class,
    HttpMessageNotReadableException.class,
    TypeMismatchException.class
  })
  ResponseEntity<ApiError> malformed(Exception e) {
    // 끊긴 업로드와 서버 임시 파일 오류는 같은 예외로 감싸져 구분할 수 없다. 클라이언트 중단이 대부분이라
    // 400으로 답하고, 원인 종류를 남겨 디스크 문제는 로그와 인프라 알림으로 확인한다.
    log.warn(
        "event=http.error status=400 type={} cause={}",
        e.getClass().getSimpleName(),
        e.getCause() == null ? "none" : e.getCause().getClass().getSimpleName());
    return ResponseEntity.badRequest().body(ApiError.of("BAD_REQUEST", "Malformed request"));
  }

  @ExceptionHandler(Exception.class)
  ResponseEntity<ApiError> handle(Exception e) throws Exception {
    // 인증·인가 예외는 보안 필터의 401/403 처리에 맡긴다.
    if (e instanceof AccessDeniedException || e instanceof AuthenticationException) {
      throw e;
    }
    // 404, 405, 415 같은 Spring MVC의 표준 오류는 원래 상태 코드를 유지한다.
    if (e instanceof ErrorResponse errorResponse) {
      HttpStatusCode status = errorResponse.getStatusCode();
      log.warn("event=http.error status={} type={}", status.value(), e.getClass().getSimpleName());
      String reason =
          HttpStatus.resolve(status.value()) != null
              ? HttpStatus.resolve(status.value()).name()
              : "ERROR";
      return ResponseEntity.status(status)
          .body(ApiError.of(reason, errorResponse.getBody().getDetail()));
    }
    log.error("event=http.unhandled", e);
    return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
        .body(ApiError.of("INTERNAL_ERROR", "Unexpected server error"));
  }
}
