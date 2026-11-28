package dev.workflowhub.common.api;

import static org.hamcrest.Matchers.containsString;
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
  private static final String REGISTER = "$.paths['/api/workflows/{workflowId}/versions'].post";
  private static final String COMPARE =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/comparisons'].post";
  private static final String DOWNLOAD =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/download'].get";
  private static final String AVAILABILITY =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/download-availability'].patch";
  private static final String DELETE_VERSION =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}'].delete";
  private static final String DELETE_WORKFLOW = "$.paths['/api/workflows/{workflowId}'].delete";
  private static final String RESTORE_VERSION =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/restore'].post";
  private static final String RESTORE_WORKFLOW =
      "$.paths['/api/workflows/{workflowId}/restore'].post";
  private static final String SCAN_REQUEST =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/scans'].post";
  private static final String SCAN_LIST =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/scans'].get";
  private static final String SCAN_LATEST =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/scans/latest'].get";
  private static final String SCAN_DETAIL =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/scans/{scanRunId}'].get";
  private static final String SCAN_REPORT =
      "$.paths['/api/workflows/{workflowId}/versions/{versionId}/scans/{scanRunId}/report'].get";
  private static final String WORKER_FILE =
      "$.paths['/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/file'].get";
  private static final String WORKER_HEARTBEAT =
      "$.paths['/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/heartbeat'].post";
  private static final String WORKER_RESULT =
      "$.paths['/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}/result'].put";
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
    void documentsComparisonRegistrationAndDownloadControl() throws Exception {
      var docs = mvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
      docs.andExpect(jsonPath(COMPARE + ".requestBody.content['multipart/form-data']").exists())
          .andExpect(
              jsonPath(COMPARE + ".requestBody.content['multipart/form-data'].schema.$ref")
                  .value(schemaRef("ComparisonRequest")))
          .andExpect(jsonPath(SCHEMAS + "ComparisonRequest.required[0]").value("file"))
          .andExpect(jsonPath(SCHEMAS + "ComparisonRequest.properties.file.format").value("binary"))
          .andExpect(jsonPath(successSchema(COMPARE)).value(schemaRef("ComparisonResponse")))
          .andExpect(
              jsonPath(REGISTER + ".parameters[?(@.name=='Idempotency-Key')].required").value(true))
          .andExpect(
              jsonPath(
                      REGISTER
                          + ".responses['409'].content['application/json'].schema.anyOf.length()")
                  .value(2))
          .andExpect(jsonPath(AVAILABILITY + ".requestBody.content['application/json']").exists())
          .andExpect(jsonPath(DOWNLOAD + ".responses['403'].description").exists())
          .andExpect(
              jsonPath(SCHEMAS + "DownloadAvailabilityRequest.properties.downloadEnabled.type")
                  .value("boolean"))
          .andExpect(
              jsonPath(SCHEMAS + "VersionMetadata.properties.downloadEnabled.type")
                  .value("boolean"));
    }

    @Test
    void documentsDeletionRestoreAndTheIncludeDeletedOption() throws Exception {
      var docs = mvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
      for (String operation : new String[] {DELETE_VERSION, DELETE_WORKFLOW}) {
        for (String code : new String[] {"200", "401", "404", "500"}) {
          docs.andExpect(jsonPath(operation + ".responses['" + code + "']").exists());
        }
        docs.andExpect(jsonPath(successSchema(operation)).value(schemaRef("DeletionResponse")));
      }
      for (String operation : new String[] {RESTORE_VERSION, RESTORE_WORKFLOW}) {
        for (String code : new String[] {"200", "401", "404", "409", "500", "503"}) {
          docs.andExpect(jsonPath(operation + ".responses['" + code + "']").exists());
        }
        docs.andExpect(jsonPath(successSchema(operation)).value(schemaRef("RestoreResponse")));
      }
      docs.andExpect(
              jsonPath(SCHEMAS + "DeletionResponse.properties.data['$ref']")
                  .value(schemaRef("DeletionData")))
          .andExpect(
              jsonPath(SCHEMAS + "DeletionData.properties.restoreUntil.format").value("date-time"))
          .andExpect(
              jsonPath(SCHEMAS + "DeletionData.properties.workflowDeleted.type").value("boolean"))
          .andExpect(jsonPath(SCHEMAS + "RestoreData.properties.restoredVersionIds").exists())
          .andExpect(jsonPath(SCHEMAS + "RestoreData.properties.unavailableVersionIds").exists())
          .andExpect(jsonPath(SCHEMAS + "VersionMetadata.properties.deletedAt").exists())
          .andExpect(jsonPath(SCHEMAS + "VersionMetadata.properties.restoreUntil").exists())
          .andExpect(jsonPath(SCHEMAS + "WorkflowSummary.properties.deletedAt").exists())
          .andExpect(jsonPath(SCHEMAS + "WorkflowSummary.properties.restoreUntil").exists());
      for (String operation : new String[] {LIST, VERSIONS}) {
        String include = operation + ".parameters[?(@.name=='includeDeleted')]";
        docs.andExpect(jsonPath(include + ".in").value("query"))
            .andExpect(jsonPath(include + ".required").value(false))
            .andExpect(jsonPath(include + ".schema.default").value(false));
      }
    }

    @Test
    void documentsTheOptionThatRefusesDeletingTheLastVersion() throws Exception {
      String allow = DELETE_VERSION + ".parameters[?(@.name=='allowWorkflowDelete')]";
      mvc.perform(get("/v3/api-docs"))
          .andExpect(status().isOk())
          .andExpect(jsonPath(allow + ".in").value("query"))
          .andExpect(jsonPath(allow + ".required").value(false))
          .andExpect(jsonPath(allow + ".schema.type").value("boolean"))
          .andExpect(jsonPath(allow + ".schema.default").value(true))
          .andExpect(jsonPath(DELETE_VERSION + ".responses['400']").exists())
          .andExpect(
              jsonPath(DELETE_VERSION + ".responses['409'].description")
                  .value(containsString("LAST_VERSION_REMAINING")));
    }

    @Test
    void documentsSecurityScanAndWorkerInternalEndpoints() throws Exception {
      var docs = mvc.perform(get("/v3/api-docs")).andExpect(status().isOk());
      docs.andExpect(
              jsonPath("$.components.securitySchemes.workerBearerAuth.scheme").value("bearer"))
          .andExpect(jsonPath(SCAN_REQUEST + ".responses['202']").exists())
          .andExpect(jsonPath(SCAN_REQUEST + ".responses['409']").exists())
          .andExpect(jsonPath(SCAN_REQUEST + ".responses['422']").exists())
          .andExpect(jsonPath(SCAN_REQUEST + ".responses['503']").exists())
          .andExpect(jsonPath(SCAN_LIST + ".responses['200']").exists())
          .andExpect(jsonPath(SCAN_LATEST + ".responses['200']").exists())
          .andExpect(jsonPath(SCAN_DETAIL + ".responses['200']").exists())
          .andExpect(jsonPath(SCAN_REPORT + ".responses['200']").exists())
          .andExpect(jsonPath(SCAN_REPORT + ".responses['409']").exists())
          .andExpect(jsonPath(WORKER_FILE + ".responses['200']").exists())
          .andExpect(jsonPath(WORKER_FILE + ".responses['410']").exists())
          .andExpect(jsonPath(WORKER_FILE + ".responses['500']").exists())
          .andExpect(jsonPath(WORKER_FILE + ".security[0].workerBearerAuth").isArray())
          .andExpect(jsonPath(WORKER_HEARTBEAT + ".responses['200']").exists())
          .andExpect(jsonPath(WORKER_HEARTBEAT + ".responses['410']").exists())
          .andExpect(jsonPath(WORKER_HEARTBEAT + ".responses['500']").exists())
          .andExpect(jsonPath(WORKER_HEARTBEAT + ".security[0].workerBearerAuth").isArray())
          .andExpect(jsonPath(WORKER_RESULT + ".requestBody.content['application/json']").exists())
          .andExpect(jsonPath(WORKER_RESULT + ".responses['201']").exists())
          .andExpect(jsonPath(WORKER_RESULT + ".responses['200']").exists())
          .andExpect(jsonPath(WORKER_RESULT + ".responses['410']").exists())
          .andExpect(jsonPath(WORKER_RESULT + ".responses['500']").exists())
          .andExpect(jsonPath(WORKER_RESULT + ".security[0].workerBearerAuth").isArray());
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
