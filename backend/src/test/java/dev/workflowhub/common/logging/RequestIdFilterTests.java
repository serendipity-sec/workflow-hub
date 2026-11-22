package dev.workflowhub.common.logging;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.workflowhub.PostgresTestConfiguration;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
@Import(PostgresTestConfiguration.class)
@ExtendWith(OutputCaptureExtension.class)
class RequestIdFilterTests {
  @Autowired MockMvc mvc;

  @Test
  void generatesRequestIdAndLogsTheRequest(CapturedOutput output) throws Exception {
    String id =
        mvc.perform(get("/api/me").with(jwt().jwt(t -> t.subject("user-1"))))
            .andExpect(status().isOk())
            .andExpect(header().exists("X-Request-Id"))
            .andReturn()
            .getResponse()
            .getHeader("X-Request-Id");

    assertThat(output.getAll())
        .contains("[" + id + "]")
        .contains("event=http.request method=GET path=/api/me status=200");
  }

  @Test
  void keepsAValidClientRequestId() throws Exception {
    mvc.perform(
            get("/api/me")
                .header("X-Request-Id", "client-req-0001")
                .with(jwt().jwt(t -> t.subject("user-1"))))
        .andExpect(header().string("X-Request-Id", "client-req-0001"));
  }

  @Test
  void replacesAnUnsafeClientRequestId() throws Exception {
    String id =
        mvc.perform(
                get("/api/me")
                    .header("X-Request-Id", "bad id\nforged-log-line")
                    .with(jwt().jwt(t -> t.subject("user-1"))))
            .andReturn()
            .getResponse()
            .getHeader("X-Request-Id");

    assertThat(id).matches("[0-9a-f-]{36}");
  }

  @Test
  void unauthorizedResponseCarriesTheSameRequestId() throws Exception {
    String id =
        mvc.perform(get("/api/me"))
            .andExpect(status().isUnauthorized())
            .andReturn()
            .getResponse()
            .getHeader("X-Request-Id");

    mvc.perform(get("/api/me").header("X-Request-Id", "trace-abcdef01"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.requestId").value("trace-abcdef01"))
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
    assertThat(id).isNotBlank();
  }

  @Test
  void methodNotAllowedKeepsTheAllowHeader() throws Exception {
    mvc.perform(get("/api/workflows").with(jwt().jwt(t -> t.subject("user-1"))))
        .andExpect(status().isMethodNotAllowed())
        .andExpect(header().string("Allow", org.hamcrest.Matchers.containsString("POST")))
        .andExpect(jsonPath("$.requestId").isNotEmpty());
  }

  @Test
  void unknownPathKeepsItsStatusInsteadOfBecoming500() throws Exception {
    mvc.perform(get("/api/does-not-exist").with(jwt().jwt(t -> t.subject("user-1"))))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.requestId").isNotEmpty());
  }
}
