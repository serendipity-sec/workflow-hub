package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.aMapWithSize;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.json.JsonCompareMode;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfiguration.class, WorkflowUploadTests.StoreConfiguration.class})
class WorkflowQueryTests {
  private static final String MY_WORKFLOWS = "/api/me/workflows";
  private static final String WORKFLOW = "/api/workflows/{workflowId}";
  private static final String VERSIONS = WORKFLOW + "/versions";
  private static final String OWNER = "user-a";
  private static final String OTHER_USER = "user-b";
  private static final UUID WORKFLOW_ID = UUID.fromString("00000000-0000-0000-0000-000000000001");
  private static final OffsetDateTime FIRST = OffsetDateTime.parse("2026-10-01T00:00:00.123456Z");
  private static final OffsetDateTime SECOND = FIRST.plusDays(1);
  private static final OffsetDateTime THIRD = FIRST.plusDays(2);

  @Autowired MockMvc mvc;
  @Autowired JdbcClient jdbc;
  @Autowired InMemoryWorkflowObjectStore store;

  @BeforeEach
  void clean() {
    jdbc.sql("DELETE FROM workflow_hub.idempotency_keys").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_versions").update();
    jdbc.sql("DELETE FROM workflow_hub.workflows").update();
    store.reset();
  }

  @Test
  void ownerCanFindAnUploadedWorkflowAndItsFirstVersion() throws Exception {
    byte[] json = new ClassPathResource("samples/minimal-workflow.json").getContentAsByteArray();
    MockMultipartFile file =
        new MockMultipartFile("file", "workflow.json", "application/json", json);
    MvcResult upload =
        mvc.perform(
                multipart("/api/workflows")
                    .file(file)
                    .header("Idempotency-Key", "read-after-upload")
                    .with(user(OWNER)))
            .andExpect(status().isCreated())
            .andReturn();
    String workflowId = stringAt(upload, "$.data.workflowId");
    String versionId = stringAt(upload, "$.data.versionId");

    mvc.perform(get(MY_WORKFLOWS).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items", hasSize(1)))
        .andExpect(jsonPath("$.data.items[0].workflowId").value(workflowId))
        .andExpect(jsonPath("$.data.items[0].title").value("Synthetic manual workflow"))
        .andExpect(jsonPath("$.data.items[0].latestVersion.versionId").value(versionId))
        .andExpect(jsonPath("$.data.items[0].latestVersion.versionLabel").value("v1"))
        .andExpect(jsonPath("$.data.nextCursor").value(nullValue()));
    mvc.perform(get(WORKFLOW, workflowId).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowId").value(workflowId))
        .andExpect(jsonPath("$.data.title").value("Synthetic manual workflow"))
        .andExpect(jsonPath("$.data.createdAt").isNotEmpty())
        .andExpect(jsonPath("$.data.latestVersion.versionId").value(versionId))
        .andExpect(jsonPath("$.data.latestVersion.versionLabel").value("v1"));
    mvc.perform(get(VERSIONS, workflowId).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items", hasSize(1)))
        .andExpect(jsonPath("$.data.items[0].versionId").value(versionId))
        .andExpect(jsonPath("$.data.items[0].versionLabel").value("v1"))
        .andExpect(jsonPath("$.data.items[0].createdAt").isNotEmpty())
        .andExpect(jsonPath("$.data.nextCursor").value(nullValue()));
  }

  @Test
  void unauthorizedRequestsRequireAuthentication() throws Exception {
    mvc.perform(get(MY_WORKFLOWS)).andExpect(status().isUnauthorized());
    mvc.perform(get(WORKFLOW, WORKFLOW_ID)).andExpect(status().isUnauthorized());
    mvc.perform(get(VERSIONS, WORKFLOW_ID)).andExpect(status().isUnauthorized());
  }

  @Test
  void anotherUserGetsAnEmptyListAndCannotAccessTheWorkflowById() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Private workflow", FIRST);
    insertVersion(UUID.randomUUID(), WORKFLOW_ID, "v1", FIRST);

    mvc.perform(get(MY_WORKFLOWS).param("ownerId", OWNER).with(user(OTHER_USER)))
        .andExpect(status().isOk())
        .andExpect(
            content()
                .json("{\"data\":{\"items\":[],\"nextCursor\":null}}", JsonCompareMode.STRICT));
    expectNotFound(WORKFLOW_ID.toString(), OTHER_USER);
  }

  @Test
  void unknownAndMalformedWorkflowIdsReturnNotFound() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Existing workflow", FIRST);
    insertVersion(UUID.randomUUID(), WORKFLOW_ID, "v1", FIRST);

    expectNotFound("00000000-0000-0000-0000-000000000002", OWNER);
    expectNotFound("not-a-uuid", OWNER);
    // UUID.fromString이 기존 워크플로 ID로 해석할 수 있는 축약 입력도 거절해야 한다.
    expectNotFound("0-0-0-0-1", OWNER);
  }

  @Test
  void listAndDetailUseTheNewestVersionAndReturnOnlyPublicMetadata() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Synthetic workflow", FIRST);
    UUID latest = UUID.fromString("80000000-0000-0000-0000-000000000001");
    UUID tied = UUID.fromString("70000000-0000-0000-0000-000000000001");
    UUID older = UUID.fromString("f0000000-0000-0000-0000-000000000001");
    insertVersion(latest, WORKFLOW_ID, "v1.10", THIRD);
    insertVersion(tied, WORKFLOW_ID, "v1.8", THIRD);
    insertVersion(older, WORKFLOW_ID, "v1.9", SECOND);

    String latestVersion =
        """
        {"versionId":"%s","versionLabel":"v1.10","createdAt":"2026-10-03T00:00:00.123456Z","downloadEnabled":true,"sha256":null,"sizeBytes":null}
        """
            .formatted(latest);
    mvc.perform(get(MY_WORKFLOWS).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(
            content()
                .json(
                    """
                    {"data":{"items":[{"workflowId":"%s","title":"Synthetic workflow","latestVersion":%s}],"nextCursor":null}}
                    """
                        .formatted(WORKFLOW_ID, latestVersion),
                    JsonCompareMode.STRICT));
    mvc.perform(get(WORKFLOW, WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(
            content()
                .json(
                    """
                    {"data":{"workflowId":"%s","title":"Synthetic workflow","createdAt":"2026-10-01T00:00:00.123456Z","latestVersion":%s}}
                    """
                        .formatted(WORKFLOW_ID, latestVersion),
                    JsonCompareMode.STRICT));
    mvc.perform(get(VERSIONS, WORKFLOW_ID).param("limit", "1").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[0].versionId").value(latest.toString()))
        .andExpect(jsonPath("$.data.items[0].versionLabel").value("v1.10"))
        .andExpect(jsonPath("$.data.items[0].createdAt").value("2026-10-03T00:00:00.123456Z"))
        .andExpect(jsonPath("$.data.items[0].downloadEnabled").value(true))
        .andExpect(jsonPath("$.data.items[0].sha256").value(nullValue()))
        .andExpect(jsonPath("$.data.items[0].sizeBytes").value(nullValue()))
        .andExpect(jsonPath("$.data.items[0]", aMapWithSize(6)))
        .andExpect(jsonPath("$.data.nextCursor").isNotEmpty());
  }

  @Test
  void exposesTheRecordedHashAndSizeInListDetailAndVersionQueries() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Synthetic workflow", FIRST);
    UUID version = UUID.fromString("80000000-0000-0000-0000-000000000002");
    insertVersion(version, WORKFLOW_ID, "v1", FIRST);
    String sha256 = "a".repeat(64);
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET content_sha256 = :sha, size_bytes = 0 WHERE id = :id")
        .param("sha", sha256)
        .param("id", version)
        .update();

    // 크기 0은 미확인(null)과 구분되어 0으로 나온다.
    mvc.perform(get(MY_WORKFLOWS).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[0].latestVersion.sha256").value(sha256))
        .andExpect(jsonPath("$.data.items[0].latestVersion.sizeBytes").value(0));
    mvc.perform(get(WORKFLOW, WORKFLOW_ID).with(user(OWNER)))
        .andExpect(jsonPath("$.data.latestVersion.sha256").value(sha256))
        .andExpect(jsonPath("$.data.latestVersion.sizeBytes").value(0));
    mvc.perform(get(VERSIONS, WORKFLOW_ID).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[0].sha256").value(sha256))
        .andExpect(jsonPath("$.data.items[0].sizeBytes").value(0));
  }

  @Test
  void rejectsIncompleteOrMalformedFileIdentityAtTheDatabase() {
    insertWorkflow(WORKFLOW_ID, OWNER, "Synthetic workflow", FIRST);
    UUID version = UUID.fromString("80000000-0000-0000-0000-000000000003");
    insertVersion(version, WORKFLOW_ID, "v1", FIRST);

    for (String assignment :
        new String[] {
          "content_sha256 = '" + "a".repeat(64) + "'", // 크기 없이 해시만
          "size_bytes = 1", // 해시 없이 크기만
          "content_sha256 = '" + "A".repeat(64) + "', size_bytes = 1", // 대문자
          "content_sha256 = 'abc', size_bytes = 1", // 길이 부족
          "content_sha256 = '" + "a".repeat(64) + "', size_bytes = -1"
        }) {
      assertThatThrownBy(
              () ->
                  jdbc.sql(
                          "UPDATE workflow_hub.workflow_versions SET "
                              + assignment
                              + " WHERE id = :id")
                      .param("id", version)
                      .update())
          .as(assignment)
          .isInstanceOf(DataIntegrityViolationException.class);
    }
  }

  @Test
  void workflowPagesCrossATimestampTieAndExcludeAnotherOwnersRows() throws Exception {
    UUID newest = UUID.fromString("10000000-0000-0000-0000-000000000001");
    UUID tiedHigher = UUID.fromString("80000000-0000-0000-0000-000000000001");
    UUID foreign = UUID.fromString("75000000-0000-0000-0000-000000000001");
    UUID tiedLower = UUID.fromString("70000000-0000-0000-0000-000000000001");
    UUID oldest = UUID.fromString("f0000000-0000-0000-0000-000000000001");
    insertWorkflowWithVersion(tiedLower, OWNER, SECOND);
    insertWorkflowWithVersion(oldest, OWNER, FIRST);
    insertWorkflowWithVersion(foreign, OTHER_USER, SECOND);
    insertWorkflowWithVersion(newest, OWNER, THIRD);
    insertWorkflowWithVersion(tiedHigher, OWNER, SECOND);
    insertVersion(UUID.randomUUID(), oldest, "v1.1", THIRD.plusDays(1));

    MvcResult firstPage =
        mvc.perform(get(MY_WORKFLOWS).param("limit", "2").with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(
                jsonPath(
                    "$.data.items[*].workflowId",
                    contains(newest.toString(), tiedHigher.toString())))
            .andExpect(jsonPath("$.data.nextCursor").isNotEmpty())
            .andReturn();

    mvc.perform(
            get(MY_WORKFLOWS)
                .param("limit", "2")
                .param("cursor", stringAt(firstPage, "$.data.nextCursor"))
                .with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.data.items[*].workflowId", contains(tiedLower.toString(), oldest.toString())))
        .andExpect(jsonPath("$.data.nextCursor").value(nullValue()));
  }

  @Test
  void versionPagesCrossATimestampTieAndExcludeVersionsOfOtherWorkflows() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Workflow", FIRST);
    UUID otherWorkflow = UUID.randomUUID();
    insertWorkflowWithVersion(otherWorkflow, OWNER, SECOND);
    UUID newest = UUID.fromString("10000000-0000-0000-0000-000000000001");
    UUID tiedHigher = UUID.fromString("80000000-0000-0000-0000-000000000001");
    UUID tiedLower = UUID.fromString("70000000-0000-0000-0000-000000000001");
    UUID oldest = UUID.fromString("f0000000-0000-0000-0000-000000000001");
    insertVersion(tiedLower, WORKFLOW_ID, "v1.1", SECOND);
    insertVersion(oldest, WORKFLOW_ID, "v1", FIRST);
    insertVersion(newest, WORKFLOW_ID, "v2", THIRD);
    insertVersion(tiedHigher, WORKFLOW_ID, "v1.2", SECOND);

    MvcResult firstPage =
        mvc.perform(get(VERSIONS, WORKFLOW_ID).param("limit", "2").with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(
                jsonPath(
                    "$.data.items[*].versionId",
                    contains(newest.toString(), tiedHigher.toString())))
            .andExpect(jsonPath("$.data.nextCursor").isNotEmpty())
            .andReturn();

    mvc.perform(
            get(VERSIONS, WORKFLOW_ID)
                .param("limit", "2")
                .param("cursor", stringAt(firstPage, "$.data.nextCursor"))
                .with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(
            jsonPath(
                "$.data.items[*].versionId", contains(tiedLower.toString(), oldest.toString())))
        .andExpect(jsonPath("$.data.nextCursor").value(nullValue()));
  }

  @Test
  void workflowWithoutVersionsHasNullLatestVersionAndEmptyVersionList() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Workflow without versions", FIRST);

    mvc.perform(get(WORKFLOW, WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.latestVersion").value(nullValue()));
    mvc.perform(get(MY_WORKFLOWS).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[0].latestVersion").value(nullValue()));
    mvc.perform(get(VERSIONS, WORKFLOW_ID).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(
            content()
                .json("{\"data\":{\"items\":[],\"nextCursor\":null}}", JsonCompareMode.STRICT));
  }

  @Test
  void bothListsDefaultToTwentyAndAcceptTheLimitBounds() throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Workflow with many versions", FIRST);
    for (int i = 1; i <= 100; i++) {
      insertWorkflowWithVersion(UUID.randomUUID(), OWNER, FIRST);
    }
    for (int i = 0; i <= 100; i++) {
      insertVersion(UUID.randomUUID(), WORKFLOW_ID, "v" + (i + 1), FIRST);
    }

    expectPageSize(mvc.perform(get(MY_WORKFLOWS).with(user(OWNER))), 20);
    expectPageSize(mvc.perform(get(VERSIONS, WORKFLOW_ID).with(user(OWNER))), 20);
    expectPageSize(mvc.perform(get(MY_WORKFLOWS).param("limit", "1").with(user(OWNER))), 1);
    expectPageSize(
        mvc.perform(get(VERSIONS, WORKFLOW_ID).param("limit", "1").with(user(OWNER))), 1);
    expectPageSize(mvc.perform(get(MY_WORKFLOWS).param("limit", "100").with(user(OWNER))), 100);
    expectPageSize(
        mvc.perform(get(VERSIONS, WORKFLOW_ID).param("limit", "100").with(user(OWNER))), 100);
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "0", "-1", "101", "2147483648", "0x10", "1.5", "invalid"})
  void bothListsRejectInvalidLimits(String limit) throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Workflow", FIRST);

    expectBadRequest(
        mvc.perform(get(MY_WORKFLOWS).param("limit", limit).with(user(OWNER))), "INVALID_LIMIT");
    expectBadRequest(
        mvc.perform(get(VERSIONS, WORKFLOW_ID).param("limit", limit).with(user(OWNER))),
        "INVALID_LIMIT");
  }

  @ParameterizedTest
  @ValueSource(strings = {"", "invalid%cursor", "eA"})
  void bothListsRejectInvalidCursors(String cursor) throws Exception {
    insertWorkflow(WORKFLOW_ID, OWNER, "Workflow", FIRST);

    expectBadRequest(
        mvc.perform(get(MY_WORKFLOWS).param("cursor", cursor).with(user(OWNER))), "INVALID_CURSOR");
    expectBadRequest(
        mvc.perform(get(VERSIONS, WORKFLOW_ID).param("cursor", cursor).with(user(OWNER))),
        "INVALID_CURSOR");
  }

  private void insertWorkflowWithVersion(UUID id, String owner, OffsetDateTime createdAt) {
    insertWorkflow(id, owner, "Workflow", createdAt);
    insertVersion(UUID.randomUUID(), id, "v1", createdAt);
  }

  private void insertWorkflow(UUID id, String owner, String title, OffsetDateTime createdAt) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflows (id, owner_id, title, created_at)
            VALUES (:id, :owner, :title, :createdAt)
            """)
        .param("id", id)
        .param("owner", owner)
        .param("title", title)
        .param("createdAt", createdAt)
        .update();
  }

  private void insertVersion(UUID id, UUID workflowId, String version, OffsetDateTime createdAt) {
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflow_versions (id, workflow_id, version, s3_object_key, created_at)
            VALUES (:id, :workflowId, :version, :objectKey, :createdAt)
            """)
        .param("id", id)
        .param("workflowId", workflowId)
        .param("version", version)
        .param("objectKey", "workflows/" + workflowId + "/" + id + ".json")
        .param("createdAt", createdAt)
        .update();
  }

  private void expectNotFound(String workflowId, String subject) throws Exception {
    mvc.perform(get(WORKFLOW, workflowId).with(user(subject)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_NOT_FOUND"));
    mvc.perform(get(VERSIONS, workflowId).with(user(subject)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_NOT_FOUND"));
  }

  private static void expectBadRequest(ResultActions result, String code) throws Exception {
    result.andExpect(status().isBadRequest()).andExpect(jsonPath("$.code").value(code));
  }

  private static void expectPageSize(ResultActions result, int size) throws Exception {
    result
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items", hasSize(size)))
        .andExpect(jsonPath("$.data.nextCursor").isNotEmpty());
  }

  private static String stringAt(MvcResult result, String path) throws Exception {
    String value = JsonPath.read(result.getResponse().getContentAsString(), path);
    assertThat(value).isNotBlank();
    return value;
  }

  private static RequestPostProcessor user(String subject) {
    return jwt().jwt(token -> token.subject(subject));
  }
}
