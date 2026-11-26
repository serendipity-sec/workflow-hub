package dev.workflowhub.common.api;

import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import org.springframework.stereotype.Component;
import tools.jackson.core.StreamWriteFeature;
import tools.jackson.databind.ObjectWriter;
import tools.jackson.databind.json.JsonMapper;

/** 컨트롤러 밖(보안 필터)에서도 애플리케이션의 JsonMapper로 ApiError를 내려 오류 형식을 하나로 유지한다. */
@Component
public class ApiErrorWriter {
  private final ObjectWriter writer;

  ApiErrorWriter(JsonMapper mapper) {
    // 응답 writer를 닫으면 뒤따르는 필터가 쓸 수 없으므로 자동 닫기를 끈다.
    this.writer = mapper.writer().without(StreamWriteFeature.AUTO_CLOSE_TARGET);
  }

  public void write(HttpServletResponse response, int status, String code, String message)
      throws IOException {
    response.setStatus(status);
    response.setCharacterEncoding(StandardCharsets.UTF_8.name());
    response.setContentType("application/json;charset=UTF-8");
    writer.writeValue(response.getWriter(), ApiError.of(code, message));
  }
}
