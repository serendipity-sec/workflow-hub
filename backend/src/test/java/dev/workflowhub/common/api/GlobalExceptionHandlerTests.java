package dev.workflowhub.common.api;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;
import org.springframework.boot.servlet.autoconfigure.MultipartProperties;
import org.springframework.util.unit.DataSize;
import org.springframework.web.multipart.MultipartException;

class GlobalExceptionHandlerTests {
  private final GlobalExceptionHandler handler = new GlobalExceptionHandler(limit());

  @Test
  void malformedMultipartIsA400() {
    var response = handler.malformed(new MultipartException("Current request is not multipart"));

    assertThat(response.getStatusCode().value()).isEqualTo(400);
    assertThat(response.getBody().code()).isEqualTo("BAD_REQUEST");
  }

  @Test
  void multipartFailureCausedByAnIoErrorIsStillA400() {
    var response =
        handler.malformed(new MultipartException("Failed to parse", new IOException("aborted")));

    assertThat(response.getStatusCode().value()).isEqualTo(400);
  }

  @Test
  void sizeLimitMessageFollowsTheConfiguredLimit() {
    assertThat(handler.tooLarge().getBody().message())
        .isEqualTo("Upload exceeds the size limit (5 MiB per file)");
  }

  private static UploadLimit limit() {
    MultipartProperties properties = new MultipartProperties();
    properties.setMaxFileSize(DataSize.ofMegabytes(5));
    return new UploadLimit(properties);
  }
}
