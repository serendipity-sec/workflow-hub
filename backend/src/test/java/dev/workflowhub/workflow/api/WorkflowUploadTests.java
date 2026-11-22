package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** 로컬 테스트: Testcontainers PostgreSQL과 인메모리 저장소를 쓰며 실제 S3에는 접속하지 않는다. */
@SpringBootTest
@AutoConfigureMockMvc
@ExtendWith(OutputCaptureExtension.class)
@Import({PostgresTestConfiguration.class, WorkflowUploadTests.StoreConfiguration.class})
class WorkflowUploadTests {
  private static final String VALID =
      """
      {"name":"Synthetic flow",
       "nodes":[{"name":"Start","type":"n8n-nodes-base.manualTrigger","parameters":{}}],
       "connections":{},"settings":{}}
      """;

  @TestConfiguration(proxyBeanMethods = false)
  static class StoreConfiguration {
    @Bean
    @Primary
    InMemoryWorkflowObjectStore inMemoryStore() {
      return new InMemoryWorkflowObjectStore();
    }
  }

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
  void createsWorkflowAndV1WithOriginalBytesAndTokenOwner() throws Exception {
    byte[] original = VALID.getBytes(StandardCharsets.UTF_8);

    MvcResult result =
        mvc.perform(upload("key-1", "My title", original, "user-1"))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.data.versionLabel").value("v1"))
            .andExpect(jsonPath("$.data.workflowId").isNotEmpty())
            .andExpect(jsonPath("$.data.versionId").isNotEmpty())
            .andReturn();
    UUID workflowId = idFrom(result, "workflowId");
    UUID versionId = idFrom(result, "versionId");

    var workflow =
        jdbc.sql("SELECT owner_id, title FROM workflow_hub.workflows WHERE id = :id")
            .param("id", workflowId)
            .query()
            .singleRow();
    assertThat(workflow).containsEntry("owner_id", "user-1").containsEntry("title", "My title");
    var version =
        jdbc.sql(
                "SELECT workflow_id, version, s3_object_key FROM workflow_hub.workflow_versions WHERE id = :id")
            .param("id", versionId)
            .query()
            .singleRow();
    assertThat(version.get("workflow_id")).isEqualTo(workflowId);
    assertThat(version.get("version")).isEqualTo("v1");
    String objectKey = (String) version.get("s3_object_key");
    assertThat(objectKey).isEqualTo("workflows/" + workflowId + "/" + versionId + ".json");
    assertThat(store.objects()).containsOnlyKeys(objectKey);
    assertThat(store.objects().get(objectKey)).isEqualTo(original);
  }

  @Test
  void ignoresOwnerValuesSentByTheClient() throws Exception {
    MockMultipartHttpServletRequestBuilder request =
        upload("key-owner", "T", VALID.getBytes(StandardCharsets.UTF_8), "real-user");
    request.param("ownerId", "attacker").param("owner_id", "attacker");
    request.header("X-Owner-Id", "attacker");

    mvc.perform(request).andExpect(status().isCreated());

    assertThat(jdbc.sql("SELECT owner_id FROM workflow_hub.workflows").query(String.class).list())
        .containsExactly("real-user");
  }

  @Test
  void rejectsUnauthenticatedRequestsBeforeStoringAnything() throws Exception {
    mvc.perform(
            multipart("/api/workflows")
                .file(file(VALID.getBytes(StandardCharsets.UTF_8)))
                .header("Idempotency-Key", "key-anon"))
        .andExpect(status().isUnauthorized())
        .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));

    assertNothingCreated();
  }

  @Test
  void usesWorkflowNameWhenTitleIsOmittedOrBlank() throws Exception {
    byte[] bytes = VALID.getBytes(StandardCharsets.UTF_8);
    mvc.perform(upload("key-a", null, bytes, "u")).andExpect(status().isCreated());
    mvc.perform(upload("key-b", "   ", bytes, "u")).andExpect(status().isCreated());

    assertThat(jdbc.sql("SELECT title FROM workflow_hub.workflows").query(String.class).list())
        .containsExactly("Synthetic flow", "Synthetic flow");
  }

  @Test
  void trimsTitle() throws Exception {
    mvc.perform(upload("key-trim", "  Padded  ", VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isCreated());

    assertThat(jdbc.sql("SELECT title FROM workflow_hub.workflows").query(String.class).single())
        .isEqualTo("Padded");
  }

  @Test
  void rejectsMissingTitleWhenWorkflowHasNoName() throws Exception {
    String noName = "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}";

    mvc.perform(upload("key-noname", null, noName.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("TITLE_REQUIRED"));

    assertNothingCreated();
  }

  @Test
  void rejectsTitleLongerThan200Characters() throws Exception {
    mvc.perform(upload("key-long", "x".repeat(201), VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("TITLE_TOO_LONG"));

    assertNothingCreated();
  }

  @Test
  void rejectsMissingIdempotencyKey() throws Exception {
    mvc.perform(upload(null, "T", VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_REQUIRED"));

    assertNothingCreated();
  }

  @Test
  void rejectsMissingFilePart() throws Exception {
    mvc.perform(
            multipart("/api/workflows")
                .param("title", "T")
                .header("Idempotency-Key", "key-nofile")
                .with(user("u")))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("FILE_REQUIRED"));
  }

  @Test
  void rejectsControlCharactersInTheTitleBeforeStoringAnything() throws Exception {
    mvc.perform(upload("key-nul", "a\u0000b", VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("TITLE_INVALID"));
    String nulName =
        "{\"name\":\"a\\u0000b\",\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}";
    mvc.perform(upload("key-nul2", null, nulName.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("TITLE_INVALID"));

    assertNothingCreated();
  }

  @Test
  void acceptsATitleWithAnUnpairedSurrogateBecauseOnlyNulIsRejectedByTheDatabase()
      throws Exception {
    mvc.perform(upload("key-surrogate", "a\uD800b", VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isCreated());
  }

  @Test
  void reusedKeyWithAnInvalidFileIsStillA409() throws Exception {
    mvc.perform(upload("key-409", "T", VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isCreated());

    mvc.perform(upload("key-409", "T", "not json".getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_REUSED"));
  }

  @Test
  void rejectsInvalidN8nJsonWith422() throws Exception {
    mvc.perform(upload("key-bad", "T", "not json".getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("INVALID_WORKFLOW"));
    mvc.perform(upload("key-bad2", "T", "{\"nodes\":[]}".getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isUnprocessableContent());

    assertNothingCreated();
  }

  @Test
  void createsNothingWhenObjectStorageFails() throws Exception {
    store.failPuts = true;

    mvc.perform(upload("key-s3", "T", VALID.getBytes(StandardCharsets.UTF_8), "u"))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.code").value("STORAGE_UNAVAILABLE"));

    assertNothingCreated();
  }

  @Test
  void deletesTheStoredObjectWhenTheDatabaseWriteFails() throws Exception {
    // 소유자가 공백이면 workflows_owner_id_nonblank 제약에 걸려 S3 저장 뒤에 DB 기록이 실패한다.
    mvc.perform(upload("key-db", "T", VALID.getBytes(StandardCharsets.UTF_8), " "))
        .andExpect(status().isInternalServerError())
        .andExpect(jsonPath("$.code").value("INTERNAL_ERROR"))
        .andExpect(jsonPath("$.requestId").isNotEmpty());

    assertNothingCreated();
  }

  @Test
  void survivesCleanupFailureAfterDatabaseFailure() throws Exception {
    store.failDeletes = true;

    mvc.perform(upload("key-db2", "T", VALID.getBytes(StandardCharsets.UTF_8), " "))
        .andExpect(status().isInternalServerError());

    assertThat(count("workflow_hub.workflows")).isZero();
    assertThat(store.objects()).hasSize(1); // 삭제 실패로 남은 객체. 후속 정리 대상
  }

  @Test
  void logsUploadStepsWithIdsButNeverTheFileContentOrTitle(CapturedOutput output) throws Exception {
    String secret = "SECRET-TOKEN-VALUE";
    String json =
        "{\"name\":\"n\",\"nodes\":[{\"name\":\"A\",\"type\":\"t\",\"parameters\":{\"token\":\""
            + secret
            + "\"}}],\"connections\":{}}";

    MvcResult result =
        mvc.perform(upload("key-log", "비밀 제목", json.getBytes(StandardCharsets.UTF_8), "user-log"))
            .andExpect(status().isCreated())
            .andReturn();

    String logs = output.getAll();
    assertThat(logs)
        .contains("event=workflow.upload.start owner=user-log idempotencyKey=key-log")
        .contains("event=workflow.upload.object_stored")
        .contains("event=workflow.upload.committed")
        .contains("workflowId=" + idFrom(result, "workflowId"))
        .doesNotContain(secret)
        .doesNotContain("비밀 제목");
  }

  @Test
  void logsTheObjectKeyWhenCleanupFails(CapturedOutput output) throws Exception {
    store.failDeletes = true;

    mvc.perform(upload("key-clean", "T", VALID.getBytes(StandardCharsets.UTF_8), " "))
        .andExpect(status().isInternalServerError());

    assertThat(output.getAll())
        .contains("event=workflow.upload.db_failed")
        .contains("event=workflow.upload.orphan_delete_failed objectKey=workflows/");
  }

  @Test
  void retryWithSameKeyAndInputReturnsTheFirstResponseWithoutCreatingAgain() throws Exception {
    byte[] bytes = VALID.getBytes(StandardCharsets.UTF_8);
    String first =
        mvc.perform(upload("key-retry", "T", bytes, "u"))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();

    // 저장소가 장애여도 저장된 최초 결과를 돌려준다.
    store.failPuts = true;
    String second =
        mvc.perform(upload("key-retry", "T", bytes, "u"))
            .andExpect(status().isCreated())
            .andReturn()
            .getResponse()
            .getContentAsString();

    assertThat(second).isEqualTo(first);
    assertThat(count("workflow_hub.workflows")).isEqualTo(1);
    assertThat(count("workflow_hub.workflow_versions")).isEqualTo(1);
    assertThat(store.objects()).hasSize(1);
  }

  @Test
  void sameKeyWithDifferentInputIsRejectedWith409() throws Exception {
    byte[] bytes = VALID.getBytes(StandardCharsets.UTF_8);
    mvc.perform(upload("key-reuse", "T", bytes, "u")).andExpect(status().isCreated());

    mvc.perform(upload("key-reuse", "Other title", bytes, "u"))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_REUSED"));
    mvc.perform(upload("key-reuse", "T", VALID.replace("Synthetic", "Changed").getBytes(), "u"))
        .andExpect(status().isConflict());

    assertThat(count("workflow_hub.workflows")).isEqualTo(1);
    assertThat(store.objects()).hasSize(1);
  }

  @Test
  void sameKeyFromDifferentOwnersCreatesSeparateWorkflows() throws Exception {
    byte[] bytes = VALID.getBytes(StandardCharsets.UTF_8);
    mvc.perform(upload("shared-key", "T", bytes, "user-a")).andExpect(status().isCreated());
    mvc.perform(upload("shared-key", "T", bytes, "user-b")).andExpect(status().isCreated());

    assertThat(count("workflow_hub.workflows")).isEqualTo(2);
  }

  @Test
  void concurrentRequestsWithTheSameKeyCreateOneWorkflow() throws Exception {
    byte[] bytes = VALID.getBytes(StandardCharsets.UTF_8);
    int threads = 4;
    ExecutorService pool = Executors.newFixedThreadPool(threads);
    CountDownLatch ready = new CountDownLatch(threads);
    CountDownLatch go = new CountDownLatch(1);
    List<Future<String>> bodies = new ArrayList<>();
    try {
      for (int i = 0; i < threads; i++) {
        bodies.add(
            pool.submit(
                () -> {
                  ready.countDown();
                  go.await();
                  return mvc.perform(upload("key-race", "T", bytes, "u"))
                      .andExpect(status().isCreated())
                      .andReturn()
                      .getResponse()
                      .getContentAsString();
                }));
      }
      ready.await();
      go.countDown();
      List<String> results = new ArrayList<>();
      for (Future<String> body : bodies) {
        results.add(body.get());
      }
      assertThat(results).allMatch(results.get(0)::equals);
    } finally {
      pool.shutdownNow();
    }

    assertThat(count("workflow_hub.workflows")).isEqualTo(1);
    assertThat(count("workflow_hub.workflow_versions")).isEqualTo(1);
    assertThat(store.objects()).hasSize(1); // 진 요청은 자기 객체를 지웠다
  }

  private MockMultipartHttpServletRequestBuilder upload(
      String key, String title, byte[] content, String subject) {
    MockMultipartHttpServletRequestBuilder request =
        multipart("/api/workflows").file(file(content)).with(user(subject));
    if (key != null) {
      request.header("Idempotency-Key", key);
    }
    if (title != null) {
      request.param("title", title);
    }
    return request;
  }

  private static MockMultipartFile file(byte[] content) {
    return new MockMultipartFile("file", "workflow.json", "application/json", content);
  }

  private static RequestPostProcessor user(String subject) {
    return jwt().jwt(token -> token.subject(subject));
  }

  private UUID idFrom(MvcResult result, String field) throws Exception {
    String body = result.getResponse().getContentAsString();
    java.util.regex.Matcher m =
        java.util.regex.Pattern.compile("\"" + field + "\":\"([0-9a-f-]{36})\"").matcher(body);
    assertThat(m.find()).isTrue();
    return UUID.fromString(m.group(1));
  }

  private long count(String table) {
    return jdbc.sql("SELECT count(*) FROM " + table).query(Long.class).single();
  }

  private void assertNothingCreated() {
    assertThat(count("workflow_hub.workflows")).isZero();
    assertThat(count("workflow_hub.workflow_versions")).isZero();
    assertThat(count("workflow_hub.idempotency_keys")).isZero();
    assertThat(store.objects()).isEmpty();
  }
}
