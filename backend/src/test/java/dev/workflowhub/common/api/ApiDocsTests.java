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
  private static final String LIST = "$.paths['/api/me/workflows'].get";
  private static final String DETAIL = "$.paths['/api/workflows/{workflowId}'].get";
  private static final String VERSIONS = "$.paths['/api/workflows/{workflowId}/versions'].get";
  private static final String SCHEMAS = "$.components.schemas.";

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
    void documentsQueryStatusesAndParameters() throws Exception {
      var docs = mvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
      docs.andExpect(jsonPath("$.security[0].bearerAuth").isArray());

      for (String operation : new String[] {LIST, DETAIL, VERSIONS}) {
        for (String code : new String[] {"200", "401", "500"}) {
          docs.andExpect(jsonPath(operation + ".responses['" + code + "']").exists());
        }
      }

      for (String operation : new String[] {LIST, VERSIONS}) {
        String limit = operation + ".parameters[?(@.name=='limit')]";
        String cursor = operation + ".parameters[?(@.name=='cursor')]";
        docs.andExpect(jsonPath(operation + ".responses['400']").exists())
            .andExpect(jsonPath(limit + ".in").value("query"))
            .andExpect(jsonPath(limit + ".required").value(false))
            .andExpect(jsonPath(limit + ".schema.type").value("integer"))
            .andExpect(jsonPath(limit + ".schema.default").value(20))
            .andExpect(jsonPath(limit + ".schema.minimum").value(1))
            .andExpect(jsonPath(limit + ".schema.maximum").value(100))
            .andExpect(jsonPath(cursor + ".in").value("query"))
            .andExpect(jsonPath(cursor + ".required").value(false));
      }

      for (String operation : new String[] {DETAIL, VERSIONS}) {
        String workflowId = operation + ".parameters[?(@.name=='workflowId')]";
        docs.andExpect(jsonPath(operation + ".responses['404']").exists())
            .andExpect(jsonPath(workflowId + ".in").value("path"))
            .andExpect(jsonPath(workflowId + ".required").value(true))
            .andExpect(jsonPath(workflowId + ".schema.format").value("uuid"));
      }
    }

    @Test
    void documentsQueryResponseEnvelopes() throws Exception {
      mvc.perform(get("/v3/api-docs"))
          .andExpect(status().isOk())
          .andExpect(jsonPath(successSchema(LIST)).value(schemaRef("WorkflowListResponse")))
          .andExpect(jsonPath(successSchema(DETAIL)).value(schemaRef("WorkflowDetailResponse")))
          .andExpect(jsonPath(successSchema(VERSIONS)).value(schemaRef("VersionListResponse")))
          .andExpect(
              jsonPath(SCHEMAS + "WorkflowListResponse.properties.data['$ref']")
                  .value(schemaRef("WorkflowListData")))
          .andExpect(
              jsonPath(SCHEMAS + "WorkflowDetailResponse.properties.data['$ref']")
                  .value(schemaRef("WorkflowDetailData")))
          .andExpect(
              jsonPath(SCHEMAS + "VersionListResponse.properties.data['$ref']")
                  .value(schemaRef("VersionListData")))
          .andExpect(
              jsonPath(SCHEMAS + "WorkflowListData.properties.items.items['$ref']")
                  .value(schemaRef("WorkflowSummary")))
          .andExpect(jsonPath(SCHEMAS + "WorkflowListData.properties.nextCursor").exists())
          .andExpect(
              jsonPath(SCHEMAS + "WorkflowSummary.properties.workflowId.format").value("uuid"))
          .andExpect(jsonPath(SCHEMAS + "WorkflowSummary.properties.title").exists())
          .andExpect(jsonPath(SCHEMAS + "WorkflowSummary.properties.latestVersion").exists())
          .andExpect(jsonPath(SCHEMAS + "WorkflowDetailData.properties.workflowId").exists())
          .andExpect(jsonPath(SCHEMAS + "WorkflowDetailData.properties.title").exists())
          .andExpect(jsonPath(SCHEMAS + "WorkflowDetailData.properties.latestVersion").exists())
          .andExpect(
              jsonPath(SCHEMAS + "WorkflowDetailData.properties.createdAt.format")
                  .value("date-time"))
          .andExpect(
              jsonPath(SCHEMAS + "VersionListData.properties.items.items['$ref']")
                  .value(schemaRef("VersionMetadata")))
          .andExpect(jsonPath(SCHEMAS + "VersionListData.properties.nextCursor").exists())
          .andExpect(
              jsonPath(SCHEMAS + "VersionMetadata.properties.versionId.format").value("uuid"))
          .andExpect(jsonPath(SCHEMAS + "VersionMetadata.properties.versionLabel").exists())
          .andExpect(
              jsonPath(SCHEMAS + "VersionMetadata.properties.createdAt.format").value("date-time"));
    }

    @Test
    void servesSwaggerUiWithoutAToken() throws Exception {
      mvc.perform(get("/swagger-ui/index.html")).andExpect(status().isOk());
    }
  }

  private static String successSchema(String operation) {
    return operation + ".responses['200'].content['application/json'].schema['$ref']";
  }

  private static String schemaRef(String name) {
    return "#/components/schemas/" + name;
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
