package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;

import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;

/** MockMvc는 서블릿의 멀티파트 크기 제한과 본문 파싱을 거치지 않으므로, 크기 상한과 깨진 본문은 실제 서버에 요청해서 확인한다. */
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@Import({PostgresTestConfiguration.class, LargeUploadLimitTests.TestBeans.class})
class LargeUploadLimitTests {
  private static final String BOUNDARY = "----upload-test-boundary";
  private static final long LIMIT = 5L * 1024 * 1024;

  @TestConfiguration(proxyBeanMethods = false)
  static class TestBeans {
    @Bean
    @Primary
    InMemoryWorkflowObjectStore inMemoryStore() {
      return new InMemoryWorkflowObjectStore();
    }

    @Bean
    @Primary
    JwtDecoder testJwtDecoder() {
      return token ->
          Jwt.withTokenValue(token)
              .header("alg", "none")
              .subject("user-large")
              .issuedAt(Instant.now())
              .expiresAt(Instant.now().plusSeconds(300))
              .claims(claims -> claims.putAll(Map.of("role", "authenticated")))
              .build();
    }
  }

  @LocalServerPort int port;
  @Autowired InMemoryWorkflowObjectStore store;

  @BeforeEach
  void reset() {
    store.reset();
  }

  @Test
  void fileOverTheLimitReturnsFileTooLarge() throws Exception {
    HttpResponse<String> response = send("key-large", filePart(new byte[(int) LIMIT + 1024]));

    assertThat(response.statusCode()).isEqualTo(413);
    assertThat(response.body()).contains("\"code\":\"FILE_TOO_LARGE\"").contains("requestId");
    assertThat(store.objects()).isEmpty();
  }

  @Test
  void fileExactlyAtTheLimitIsAccepted() throws Exception {
    String prefix = "{\"name\":\"Big\",\"pad\":\"";
    String suffix = "\",\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}";
    int padding = (int) LIMIT - prefix.length() - suffix.length();
    byte[] atLimit = (prefix + "x".repeat(padding) + suffix).getBytes(StandardCharsets.UTF_8);
    assertThat(atLimit).hasSize((int) LIMIT);

    HttpResponse<String> response = send("key-limit", filePart(atLimit));

    assertThat(response.statusCode()).isEqualTo(201);
    assertThat(store.objects()).hasSize(1);
  }

  @Test
  void garbageMultipartBodyIsAClientError() throws Exception {
    HttpResponse<String> response = send("key-garbage", "garbage".getBytes(StandardCharsets.UTF_8));

    assertThat(response.statusCode()).isEqualTo(400);
    assertThat(response.body()).contains("requestId");
    assertThat(store.objects()).isEmpty();
  }

  private byte[] filePart(byte[] content) throws Exception {
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    body.write(
        ("--"
                + BOUNDARY
                + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"w.json\"\r\n"
                + "Content-Type: application/json\r\n\r\n")
            .getBytes(StandardCharsets.UTF_8));
    body.write(content);
    body.write(("\r\n--" + BOUNDARY + "--\r\n").getBytes(StandardCharsets.UTF_8));
    return body.toByteArray();
  }

  private HttpResponse<String> send(String key, byte[] body) throws Exception {
    return HttpClient.newHttpClient()
        .send(
            HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/api/workflows"))
                .header("Authorization", "Bearer test-token")
                .header("Idempotency-Key", key)
                .header("Content-Type", "multipart/form-data; boundary=" + BOUNDARY)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body))
                .build(),
            HttpResponse.BodyHandlers.ofString());
  }
}
