package dev.workflowhub.auth;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityTests {
  @Autowired MockMvc mvc;

  @Test
  void healthIsPublic() throws Exception {
    mvc.perform(get("/api/health"))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.status").value("UP"));
  }

  @Test
  void identityRequiresAuthentication() throws Exception {
    mvc.perform(get("/api/me"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"))
        .andExpect(header().doesNotExist("Set-Cookie"));
  }

  @Test
  void identityUsesAuthenticatedSubject() throws Exception {
    mvc.perform(get("/api/me").with(jwt().jwt(token -> token.subject("user-123"))))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.id").value("user-123"))
        .andExpect(header().doesNotExist("Set-Cookie"));
  }

  @Test
  void malformedBearerTokenIsRejected() throws Exception {
    mvc.perform(get("/api/me").header("Authorization", "Bearer invalid"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
  }

  @Test
  void configuredOriginCanSendBearerToken() throws Exception {
    mvc.perform(
            options("/api/me")
                .header("Origin", "http://localhost:5173")
                .header("Access-Control-Request-Method", "GET")
                .header("Access-Control-Request-Headers", "Authorization"))
        .andExpect(status().isOk())
        .andExpect(header().string("Access-Control-Allow-Origin", "http://localhost:5173"));
  }

  @Test
  void unconfiguredOriginIsRejected() throws Exception {
    mvc.perform(
            options("/api/me")
                .header("Origin", "https://untrusted.example")
                .header("Access-Control-Request-Method", "GET"))
        .andExpect(status().isForbidden());
  }
}
