package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@SpringBootTest(properties = "app.docs.enabled=true")
@AutoConfigureMockMvc
@Import({PostgresTestConfiguration.class, WorkflowUploadTests.StoreConfiguration.class})
class WorkflowDownloadTests {
  private static final String DOWNLOAD =
      "/api/workflows/{workflowId}/versions/{versionId}/download";
  private static final String AVAILABILITY =
      "/api/workflows/{workflowId}/versions/{versionId}/download-availability";
  private static final String OWNER = "user-a";
  private static final String OTHER_USER = "user-b";
  private static final UUID WORKFLOW_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
  private static final UUID VERSION_ID = UUID.fromString("00000000-0000-0000-0000-000000000002");
  private static final UUID OTHER_WORKFLOW_ID =
      UUID.fromString("00000000-0000-0000-0000-000000000003");
  private static final UUID OTHER_VERSION_ID =
      UUID.fromString("00000000-0000-0000-0000-000000000004");
  private static final UUID UNKNOWN_ID = UUID.fromString("00000000-0000-0000-0000-000000000005");
  private static final String OBJECT_KEY = "test-fixtures/selected-version.json";
  private static final byte[] ORIGINAL =
      ("{\r\n  \"name\" : \"원본 이름\", \"nodes\": [], \"connections\": {}, \"settings\": {}\r\n}\r\n")
          .getBytes(StandardCharsets.UTF_8);

  @Autowired MockMvc mvc;
  @Autowired JdbcClient jdbc;
  @MockitoSpyBean InMemoryWorkflowObjectStore store;

  @BeforeEach
  void clean() {
    jdbc.sql("DELETE FROM workflow_hub.idempotency_keys").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_versions").update();
    jdbc.sql("DELETE FROM workflow_hub.workflows").update();
    store.reset();
    clearInvocations(store);
  }

  @Test
  void downloadsTheSameBytesSentToTheUploadEndpoint() throws Exception {
    byte[] uploaded =
        """
        {
          "name" : "합성 워크플로",
          "nodes": [{"name": "Start", "type": "n8n-nodes-base.manualTrigger"}],
          "connections": {}
        }
        """
            .replace("\n", "\r\n")
            .getBytes(StandardCharsets.UTF_8);
    var upload =
        mvc.perform(
                multipart("/api/workflows")
                    .file(
                        new MockMultipartFile(
                            "file", "synthetic.json", MediaType.APPLICATION_JSON_VALUE, uploaded))
                    .header("Idempotency-Key", "download-round-trip")
                    .with(user(OWNER)))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse();
    var data = JsonPath.parse(upload.getContentAsString());
    String workflowId = data.read("$.data.workflowId");
    String versionId = data.read("$.data.versionId");

    mvc.perform(get(DOWNLOAD, workflowId, versionId).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(content().bytes(uploaded));
  }

  @Test
  void disablingAVersionBlocksStorageReadsAndReenablingRestoresTheOriginalBytes() throws Exception {
    insertWorkflow(WORKFLOW_ID, "Private workflow");
    insertVersion(OTHER_VERSION_ID, WORKFLOW_ID, "v1", "test-fixtures/older-version.json");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v2", OBJECT_KEY);
    byte[] older = "{}".getBytes(StandardCharsets.UTF_8);
    store.put("test-fixtures/older-version.json", older);
    store.put(OBJECT_KEY, ORIGINAL);
    clearInvocations(store);

    mvc.perform(
            availability(WORKFLOW_ID, VERSION_ID, "{\"downloadEnabled\":false}").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowId").value(WORKFLOW_ID.toString()))
        .andExpect(jsonPath("$.data.versionId").value(VERSION_ID.toString()))
        .andExpect(jsonPath("$.data.downloadEnabled").value(false));
    mvc.perform(get(DOWNLOAD, WORKFLOW_ID, VERSION_ID).with(user(OWNER)))
        .andExpect(status().isForbidden())
        .andExpect(header().doesNotExist(HttpHeaders.CONTENT_DISPOSITION))
        .andExpect(jsonPath("$.code").value("VERSION_DOWNLOAD_DISABLED"));
    mvc.perform(get("/api/workflows/{workflowId}/versions", WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[0].versionId").value(VERSION_ID.toString()))
        .andExpect(jsonPath("$.data.items[0].downloadEnabled").value(false))
        .andExpect(jsonPath("$.data.items[1].downloadEnabled").value(true));
    verifyNoInteractions(store);

    mvc.perform(get(DOWNLOAD, WORKFLOW_ID, OTHER_VERSION_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(content().bytes(older));
    mvc.perform(
            availability(WORKFLOW_ID, VERSION_ID, "{\"downloadEnabled\":true}").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.downloadEnabled").value(true));
    mvc.perform(get(DOWNLOAD, WORKFLOW_ID, VERSION_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(content().bytes(ORIGINAL));
  }

  @Test
  void onlyTheOwnerCanSetAvailabilityForAVersionOfTheRequestedWorkflow() throws Exception {
    insertWorkflow(WORKFLOW_ID, "First workflow");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1", OBJECT_KEY);
    insertWorkflow(OTHER_WORKFLOW_ID, "Second workflow");
    insertVersion(OTHER_VERSION_ID, OTHER_WORKFLOW_ID, "v1", "test-fixtures/other.json");
    String disabled = "{\"downloadEnabled\":false}";

    mvc.perform(availability(WORKFLOW_ID, VERSION_ID, disabled))
        .andExpect(status().isUnauthorized());
    mvc.perform(availability(WORKFLOW_ID, VERSION_ID, disabled).with(user(OTHER_USER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(availability(WORKFLOW_ID, OTHER_VERSION_ID, disabled).with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(availability(WORKFLOW_ID, "0-0-0-0-2", disabled).with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    verifyNoInteractions(store);

    mvc.perform(get("/api/workflows/{workflowId}/versions", WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[0].downloadEnabled").value(true));
    mvc.perform(get("/api/workflows/{workflowId}/versions", OTHER_WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[0].downloadEnabled").value(true));
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "null",
        "{}",
        "{\"downloadEnabled\":null}",
        "{\"downloadEnabled\":\"false\"}",
        "{\"downloadEnabled\":0}",
        "{\"downloadEnabled\":[]}",
        "{\"downloadEnabled\":{}}"
      })
  void rejectsABodyWithoutAJsonBoolean(String body) throws Exception {
    insertWorkflow(WORKFLOW_ID, "Private workflow");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1", OBJECT_KEY);

    mvc.perform(availability(WORKFLOW_ID, VERSION_ID, body).with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
    mvc.perform(get("/api/workflows/{workflowId}/versions", WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[0].downloadEnabled").value(true));
    verifyNoInteractions(store);
  }

  @Test
  void downloadsTheSelectedVersionBytesUsingTheCurrentTitleAndStoredVersionLabel()
      throws Exception {
    insertWorkflow(WORKFLOW_ID, "Initial title");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1.3", OBJECT_KEY);
    insertVersion(OTHER_VERSION_ID, WORKFLOW_ID, "v2", "test-fixtures/latest-version.json");
    jdbc.sql("UPDATE workflow_hub.workflows SET title = :title WHERE id = :id")
        .param("title", "주간 보고서")
        .param("id", WORKFLOW_ID)
        .update();
    store.put(OBJECT_KEY, ORIGINAL);

    var response =
        mvc.perform(get(DOWNLOAD, WORKFLOW_ID, VERSION_ID).with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(content().contentType(MediaType.APPLICATION_JSON))
            .andExpect(content().bytes(ORIGINAL))
            .andReturn()
            .getResponse();

    String disposition = response.getHeader(HttpHeaders.CONTENT_DISPOSITION);
    assertThat(disposition).contains("filename*=UTF-8''");
    ContentDisposition attachment = ContentDisposition.parse(disposition);
    assertThat(attachment.isAttachment()).isTrue();
    assertThat(attachment.getFilename()).isEqualTo("주간 보고서-v1.3.json");
    verify(store).get(OBJECT_KEY);
  }

  @Test
  void removesPathSeparatorsAndUnsafeCharactersFromTheAttachmentName() throws Exception {
    insertWorkflow(WORKFLOW_ID, "ops/reports\\weekly\r\n\"summary\"");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1", OBJECT_KEY);
    store.put(OBJECT_KEY, ORIGINAL);

    var response =
        mvc.perform(get(DOWNLOAD, WORKFLOW_ID, VERSION_ID).with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(content().bytes(ORIGINAL))
            .andReturn()
            .getResponse();

    ContentDisposition attachment =
        ContentDisposition.parse(response.getHeader(HttpHeaders.CONTENT_DISPOSITION));
    assertThat(attachment.isAttachment()).isTrue();
    assertThat(attachment.getFilename())
        .doesNotContain("/", "\\", "\r", "\n", "\"")
        .endsWith("-v1.json");
  }

  @Test
  void rejectsUnknownMalformedMismatchedAndForeignIdsBeforeReadingStorage() throws Exception {
    insertWorkflow(WORKFLOW_ID, "First workflow");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1", OBJECT_KEY);
    insertWorkflow(OTHER_WORKFLOW_ID, "Second workflow");
    insertVersion(OTHER_VERSION_ID, OTHER_WORKFLOW_ID, "v1", "test-fixtures/other-workflow.json");

    expectNotFound(WORKFLOW_ID, VERSION_ID, OTHER_USER);
    expectNotFound(WORKFLOW_ID, OTHER_VERSION_ID, OWNER);
    expectNotFound(UNKNOWN_ID, VERSION_ID, OWNER);
    expectNotFound(WORKFLOW_ID, UNKNOWN_ID, OWNER);
    expectNotFound("invalid", VERSION_ID, OWNER);
    expectNotFound(WORKFLOW_ID, "invalid", OWNER);
    expectNotFound("0-0-0-0-1", VERSION_ID, OWNER);
    expectNotFound(WORKFLOW_ID, "0-0-0-0-2", OWNER);

    verifyNoInteractions(store);
  }

  @Test
  void requiresAuthenticationBeforeReadingStorage() throws Exception {
    insertWorkflow(WORKFLOW_ID, "Private workflow");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1", OBJECT_KEY);

    mvc.perform(get(DOWNLOAD, WORKFLOW_ID, VERSION_ID)).andExpect(status().isUnauthorized());
    verifyNoInteractions(store);
  }

  @Test
  void returnsAServiceUnavailableErrorWhenReadingTheObjectFails() throws Exception {
    insertWorkflow(WORKFLOW_ID, "Private workflow");
    insertVersion(VERSION_ID, WORKFLOW_ID, "v1", OBJECT_KEY);
    doThrow(new IllegalStateException("simulated read failure")).when(store).get(OBJECT_KEY);

    mvc.perform(get(DOWNLOAD, WORKFLOW_ID, VERSION_ID).with(user(OWNER)))
        .andExpect(status().isServiceUnavailable())
        .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
        .andExpect(header().doesNotExist(HttpHeaders.CONTENT_DISPOSITION))
        .andExpect(jsonPath("$.code").value("STORAGE_UNAVAILABLE"));

    verify(store).get(OBJECT_KEY);
  }

  @Test
  void documentsTheGetOperationAndItsDownloadAndErrorResponses() throws Exception {
    String operation = "$.paths['" + DOWNLOAD + "'].get";
    var docs =
        mvc.perform(get("/v3/api-docs"))
            .andExpect(status().isOk())
            .andExpect(jsonPath(operation + ".operationId").isNotEmpty())
            .andExpect(
                jsonPath(operation + ".responses['200'].content['application/json'].schema.format")
                    .value("binary"))
            .andExpect(
                jsonPath(operation + ".responses['200'].headers['Content-Disposition']").exists());

    for (String parameter : new String[] {"workflowId", "versionId"}) {
      String path = operation + ".parameters[?(@.name=='" + parameter + "')]";
      docs.andExpect(jsonPath(path + ".in").value("path"))
          .andExpect(jsonPath(path + ".required").value(true))
          .andExpect(jsonPath(path + ".schema.format").value("uuid"));
    }

    for (String code : new String[] {"401", "403", "404", "500", "503"}) {
      docs.andExpect(
          jsonPath(operation + ".responses['" + code + "'].content['application/json']").exists());
    }
  }

  private static MockHttpServletRequestBuilder availability(
      Object workflowId, Object versionId, String body) {
    return patch(AVAILABILITY, workflowId, versionId)
        .contentType(MediaType.APPLICATION_JSON)
        .content(body);
  }

  private void insertWorkflow(UUID id, String title) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflows (id, owner_id, title)
            VALUES (:id, :owner, :title)
            """)
        .param("id", id)
        .param("owner", OWNER)
        .param("title", title)
        .update();
  }

  private void insertVersion(UUID id, UUID workflowId, String version, String objectKey) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflow_versions (id, workflow_id, version, s3_object_key)
            VALUES (:id, :workflowId, :version, :objectKey)
            """)
        .param("id", id)
        .param("workflowId", workflowId)
        .param("version", version)
        .param("objectKey", objectKey)
        .update();
  }

  private void expectNotFound(Object workflowId, Object versionId, String subject)
      throws Exception {
    mvc.perform(get(DOWNLOAD, workflowId, versionId).with(user(subject)))
        .andExpect(status().isNotFound())
        .andExpect(header().doesNotExist(HttpHeaders.CONTENT_DISPOSITION))
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
  }

  private static RequestPostProcessor user(String subject) {
    return jwt().jwt(token -> token.subject(subject));
  }
}
