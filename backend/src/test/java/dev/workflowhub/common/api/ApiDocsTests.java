package dev.workflowhub.common.api;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.workflowhub.PostgresTestConfiguration;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.test.web.servlet.MockMvc;

/** 컨트롤러 어노테이션이 이 API의 유일한 명세이므로, 문서에 핵심 내용이 빠지지 않았는지 확인한다. */
class ApiDocsTests {
  private static final String POST = "$.paths['/api/workflows'].post";

  @Nested
  @SpringBootTest(properties = "app.docs.enabled=true")
  @AutoConfigureMockMvc
  @Import(PostgresTestConfiguration.class)
  class Enabled {
    @Autowired MockMvc mvc;

    @Test
    void documentsTheUploadEndpointWithoutAToken() throws Exception {
      mvc.perform(get("/v3/api-docs"))
          .andExpect(status().isOk())
          .andExpect(jsonPath("$.components.securitySchemes.bearerAuth.scheme").value("bearer"))
          .andExpect(jsonPath(POST + ".operationId").exists())
          .andExpect(jsonPath(POST + ".requestBody.content['multipart/form-data']").exists())
          .andExpect(
              jsonPath(POST + ".parameters[?(@.name=='Idempotency-Key')].required").value(true))
          .andExpect(
              jsonPath(POST + ".parameters[?(@.name=='Idempotency-Key')].example")
                  .value("7c9e6679-7425-40de-944b-e07fc1f90ae7"));
    }

    @Test
    void documentsEverySuccessAndErrorStatus() throws Exception {
      for (String code : new String[] {"201", "400", "401", "409", "413", "422", "500", "503"}) {
        mvc.perform(get("/v3/api-docs"))
            .andExpect(jsonPath(POST + ".responses['" + code + "']").exists());
      }
    }

    @Test
    void servesSwaggerUiWithoutAToken() throws Exception {
      mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
    }
  }

  @Nested
  @SpringBootTest
  @AutoConfigureMockMvc
  @Import(PostgresTestConfiguration.class)
  class DisabledByDefault {
    @Autowired MockMvc mvc;

    @Test
    void doesNotExposeDocsAnonymously() throws Exception {
      mvc.perform(get("/v3/api-docs")).andExpect(status().isUnauthorized());
      mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isUnauthorized());
    }
  }
}
