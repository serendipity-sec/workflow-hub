package dev.workflowhub.common.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.workflowhub.common.logging.RequestIdFilter;
import io.swagger.v3.oas.annotations.media.Schema;
import java.util.Map;
import org.slf4j.MDC;

/** 모든 API 오류 응답의 공통 본문. requestId는 서버 로그와 대조하는 데 쓴다. */
@JsonInclude(JsonInclude.Include.NON_NULL)
@Schema(description = "API 오류 응답")
public record ApiError(
    @Schema(description = "오류 코드", example = "INVALID_WORKFLOW") String code,
    @Schema(
            description = "사용자에게 보여줄 수 있는 설명",
            example = "Workflow must have a non-empty nodes array")
        String message,
    @Schema(
            description = "요청 추적 ID. 응답 헤더 X-Request-Id와 같다",
            example = "3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11")
        String requestId,
    @Schema(description = "충돌 등 추가 문맥이 필요한 오류의 부가 정보") Map<String, Object> details) {

  public static ApiError of(String code, String message) {
    return new ApiError(code, message, MDC.get(RequestIdFilter.MDC_KEY), null);
  }

  public static ApiError of(String code, String message, Map<String, Object> details) {
    return new ApiError(code, message, MDC.get(RequestIdFilter.MDC_KEY), details);
  }
}
