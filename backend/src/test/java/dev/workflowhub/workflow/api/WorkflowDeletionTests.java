package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.empty;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.nullValue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.service.WorkflowVersionPurge;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/** 버전·워크플로 삭제, 복구, 원본 정리(#37). 합성 파일과 인메모리 저장소를 쓰며 실제 S3의 동작은 검증하지 못한다. */
@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfiguration.class, WorkflowUploadTests.StoreConfiguration.class})
class WorkflowDeletionTests {
  private static final String WORKFLOWS = "/api/workflows";
  private static final String WORKFLOW = WORKFLOWS + "/{workflowId}";
  private static final String VERSIONS = WORKFLOW + "/versions";
  private static final String VERSION = VERSIONS + "/{versionId}";
  private static final String OWNER = "user-a";
  private static final String OTHER_USER = "user-b";
  private static final byte[] BASE =
      """
      {
        "name": "Synthetic flow",
        "nodes": [
          {"id":"a","name":"Start","type":"n8n-nodes-base.manualTrigger","parameters":{}},
          {"id":"b","name":"Old step","type":"n8n-nodes-base.noOp","parameters":{}}
        ],
        "connections": {"Start":{"main":[[{"node":"Old step","type":"main","index":0}]]}}
      }
      """
          .getBytes(StandardCharsets.UTF_8);
  private static final byte[] CANDIDATE =
      """
      {
        "name": "Changed synthetic flow",
        "nodes": [
          {"id":"a","name":"Start","type":"n8n-nodes-base.manualTrigger","parameters":{}},
          {"id":"c","name":"New step","type":"n8n-nodes-base.noOp","parameters":{}}
        ],
        "connections": {"Start":{"main":[[{"node":"New step","type":"main","index":0}]]}}
      }
      """
          .getBytes(StandardCharsets.UTF_8);

  @Autowired MockMvc mvc;
  @Autowired JdbcClient jdbc;
  @Autowired InMemoryWorkflowObjectStore store;
  @Autowired WorkflowVersionPurge purge;

  @BeforeEach
  void clean() {
    jdbc.sql("TRUNCATE workflow_hub.workflows CASCADE").update();
    jdbc.sql("DELETE FROM workflow_hub.pending_objects").update();
    store.reset();
  }

  /** 비교 기록이 버전을 참조하므로, 다음 테스트 클래스가 버전 행을 지울 수 있게 정리해 둔다. */
  @AfterEach
  void cleanUp() {
    jdbc.sql("TRUNCATE workflow_hub.workflows CASCADE").update();
    jdbc.sql("DELETE FROM workflow_hub.pending_objects").update();
  }

  // ---- 삭제 ----

  @Test
  void deletingTheNewestVersionMakesTheNewestRemainingVersionTheDefault() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");

    MvcResult result =
        mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.data.workflowId").value(w.id().toString()))
            .andExpect(jsonPath("$.data.versionId").value(w.version("v1.2").toString()))
            .andExpect(jsonPath("$.data.workflowDeleted").value(false))
            .andReturn();

    Instant deletedAt = Instant.parse(JsonPath.read(body(result), "$.data.deletedAt"));
    Instant restoreUntil = Instant.parse(JsonPath.read(body(result), "$.data.restoreUntil"));
    assertThat(Duration.between(deletedAt, restoreUntil)).isEqualTo(Duration.ofDays(7));
    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.latestVersion.versionLabel").value("v1.1"));
    mvc.perform(get("/api/me/workflows").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[0].latestVersion.versionLabel").value("v1.1"));
    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1", "v1")));
  }

  @Test
  void deletedVersionsAreExcludedFromDownloadDownloadStateAndComparison() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    UUID deleted = w.version("v1.1");
    mvc.perform(delete(VERSION, w.id(), deleted).with(user(OWNER))).andExpect(status().isOk());

    mvc.perform(get(VERSION + "/download", w.id(), deleted).with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(
            patch(VERSION + "/download-availability", w.id(), deleted)
                .with(user(OWNER))
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"downloadEnabled\":false}"))
        .andExpect(status().isNotFound());
    mvc.perform(
            multipart(VERSION + "/comparisons", w.id(), deleted)
                .file(file(CANDIDATE))
                .with(user(OWNER)))
        .andExpect(status().isNotFound());
  }

  @Test
  void aDeletedVersionNumberIsNeverReused() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());

    // 삭제된 v1.2를 건너뛰고 v1.1이 기준이지만 번호는 v1.3이다.
    String next = register(w.id(), w.version("v1.1"), "MINOR");

    assertThat(next).isEqualTo("v1.3");
  }

  @Test
  void aMajorUpdateAfterDeletingTheHighestSeriesSkipsItsNumber() throws Exception {
    Workflow w = workflow("v1");
    UUID v2 = w.add(registerId(w.id(), w.version("v1"), "MAJOR"), "v2");
    mvc.perform(delete(VERSION, w.id(), v2).with(user(OWNER))).andExpect(status().isOk());

    assertThat(register(w.id(), w.version("v1"), "MAJOR")).isEqualTo("v3");
  }

  @Test
  void deletingAnEarlierVersionDoesNotAffectLaterOnesOrTheirFiles() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    String keep = objectKeyOf(w.version("v1.1"));

    mvc.perform(delete(VERSION, w.id(), w.version("v1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(false));
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(false));

    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1")));
    // 삭제를 수락했을 뿐 원본은 복구 기간 동안 모두 남아 있다.
    assertThat(versionObjects()).hasSize(3).contains(keep);
  }

  @Test
  void deletingTheLastVersionDeletesTheWholeWorkflow() throws Exception {
    Workflow w = workflow("v1");

    mvc.perform(delete(VERSION, w.id(), w.version("v1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(true));

    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isNotFound());
    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER))).andExpect(status().isNotFound());
    mvc.perform(get("/api/me/workflows").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", empty()));
  }

  @Test
  void anExplicitlyAllowedDeleteOfTheLastVersionStillDeletesTheWholeWorkflow() throws Exception {
    Workflow w = workflow("v1");

    mvc.perform(
            delete(VERSION, w.id(), w.version("v1"))
                .param("allowWorkflowDelete", "true")
                .with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(true));

    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isNotFound());
  }

  @Test
  void aDeleteThatMustKeepTheWorkflowIsRefusedForTheLastVersionAndChangesNothing()
      throws Exception {
    Workflow w = workflow("v1");
    List<String> objects = versionObjects();

    mvc.perform(
            delete(VERSION, w.id(), w.version("v1"))
                .param("allowWorkflowDelete", "false")
                .with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("LAST_VERSION_REMAINING"));

    assertThat(deletedCount(w.id())).isZero();
    assertThat(workflowIsDeleted(w.id())).isFalse();
    assertThat(versionRow(w.version("v1")).get("delete_after")).isNull();
    assertThat(versionObjects()).isEqualTo(objects);
    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", hasSize(1)));
  }

  @Test
  void aDeleteThatMustKeepTheWorkflowIsRefusedWhenAnotherTabDeletedTheOtherVersionsFirst()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    // 화면은 v1을 "버전만 삭제"로 확인했지만, 그사이 다른 탭이 v1.1을 지웠다.
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(false));

    mvc.perform(
            delete(VERSION, w.id(), w.version("v1"))
                .param("allowWorkflowDelete", "false")
                .with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("LAST_VERSION_REMAINING"));

    assertThat(deletedCount(w.id())).isEqualTo(1);
    assertThat(workflowIsDeleted(w.id())).isFalse();
    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.latestVersion.versionId").value(w.version("v1").toString()));

    // 사용자가 워크플로 전체 삭제를 다시 확인하면 조건 없이 삭제할 수 있다.
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(true));
  }

  @Test
  void aDeleteThatMustKeepTheWorkflowDeletesOnlyTheVersionWhileOthersRemain() throws Exception {
    Workflow w = workflow("v1", "v1.1");

    mvc.perform(
            delete(VERSION, w.id(), w.version("v1.1"))
                .param("allowWorkflowDelete", "false")
                .with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(false))
        .andExpect(jsonPath("$.data.versionId").value(w.version("v1.1").toString()));

    assertThat(deletedCount(w.id())).isEqualTo(1);
    assertThat(workflowIsDeleted(w.id())).isFalse();
  }

  @Test
  void aDeleteThatMustKeepTheWorkflowAnswersNotFoundForOtherUsersBeforeTheLastVersionCheck()
      throws Exception {
    Workflow w = workflow("v1");

    // 남의 워크플로가 마지막 버전인지 409로 드러나지 않아야 한다.
    mvc.perform(
            delete(VERSION, w.id(), w.version("v1"))
                .param("allowWorkflowDelete", "false")
                .with(user(OTHER_USER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));

    assertThat(deletedCount(w.id())).isZero();
    assertThat(workflowIsDeleted(w.id())).isFalse();
  }

  // 빈 값과 1·yes는 Spring이 참으로 바꾸지만, 더 많이 지우는 기본값으로 처리되지 않게 거절한다.
  @ParameterizedTest
  @ValueSource(strings = {"", "maybe", "2", "1", "yes", "TRUE"})
  void rejectsAnAllowWorkflowDeleteThatIsNotABooleanWithoutDeleting(String value) throws Exception {
    Workflow w = workflow("v1");

    mvc.perform(
            delete(VERSION, w.id(), w.version("v1"))
                .param("allowWorkflowDelete", value)
                .with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("BAD_REQUEST"));

    assertThat(deletedCount(w.id())).isZero();
    assertThat(workflowIsDeleted(w.id())).isFalse();
  }

  @Test
  void deletingAWorkflowKeepsTheEarlierDeadlineOfAnAlreadyDeletedVersion() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());
    // 이틀 전에 삭제한 것으로 만들어 남은 기간이 5일이 되게 한다.
    jdbc.sql(
            """
            UPDATE workflow_hub.workflow_versions
            SET deleted_at = deleted_at - interval '2 days', delete_after = delete_after - interval '2 days'
            WHERE id = :id
            """)
        .param("id", w.version("v1.2"))
        .update();
    Instant individual = deleteAfter(w.version("v1.2"));

    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(true))
        .andExpect(jsonPath("$.data.versionId").value(nullValue()));

    assertThat(deleteAfter(w.version("v1.2"))).isEqualTo(individual);
    assertThat(deleteAfter(w.version("v1"))).isAfter(individual.plus(Duration.ofDays(1)));
    assertThat(deleteAfter(w.version("v1.1"))).isEqualTo(deleteAfter(w.version("v1")));
  }

  @Test
  void otherUsersCannotDeleteAndNothingChanges() throws Exception {
    Workflow w = workflow("v1", "v1.1");

    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OTHER_USER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_VERSION_NOT_FOUND"));
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OTHER_USER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_NOT_FOUND"));

    assertThat(deletedCount(w.id())).isZero();
    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", hasSize(2)));
  }

  @Test
  void aVersionOfAnotherWorkflowCannotBeDeletedThroughThisWorkflow() throws Exception {
    Workflow mine = workflow("v1", "v1.1");
    Workflow other = workflow("v1", "v1.1");

    mvc.perform(delete(VERSION, mine.id(), other.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isNotFound());

    assertThat(deletedCount(other.id())).isZero();
  }

  @Test
  void deletingTwiceAndMalformedIdsReturnNotFound() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());

    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isNotFound());
    mvc.perform(delete(VERSION, w.id(), "not-a-uuid").with(user(OWNER)))
        .andExpect(status().isNotFound());
    mvc.perform(delete(WORKFLOW, "not-a-uuid").with(user(OWNER))).andExpect(status().isNotFound());
  }

  @Test
  void deletionAndRestoreRequireAuthentication() throws Exception {
    UUID id = UUID.randomUUID();
    mvc.perform(delete(VERSION, id, id)).andExpect(status().isUnauthorized());
    mvc.perform(delete(WORKFLOW, id)).andExpect(status().isUnauthorized());
    mvc.perform(post(VERSION + "/restore", id, id)).andExpect(status().isUnauthorized());
    mvc.perform(post(WORKFLOW + "/restore", id)).andExpect(status().isUnauthorized());
  }

  @Test
  void twoConcurrentDeletesOfTheLastTwoVersionsNeverLeaveAnAliveWorkflowWithoutVersions()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    List<Callable<Boolean>> calls = new ArrayList<>();
    for (String label : List.of("v1", "v1.1")) {
      calls.add(
          () ->
              Boolean.parseBoolean(
                  JsonPath.read(
                          mvc.perform(delete(VERSION, w.id(), w.version(label)).with(user(OWNER)))
                              .andExpect(status().isOk())
                              .andReturn()
                              .getResponse()
                              .getContentAsString(),
                          "$.data.workflowDeleted")
                      .toString()));
    }
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      List<Boolean> deletedWorkflow = new ArrayList<>();
      // 제한 시간 안에 끝나지 않은 작업은 취소되고, 그 결과를 읽을 때 CancellationException으로 테스트가 실패한다.
      for (Future<Boolean> future : pool.invokeAll(calls, 30, TimeUnit.SECONDS)) {
        deletedWorkflow.add(future.get());
      }
      // 한 요청은 개별 삭제, 다른 요청은 마지막 버전이라 워크플로 전체 삭제가 된다.
      assertThat(deletedWorkflow).containsExactlyInAnyOrder(true, false);
    } finally {
      pool.shutdownNow();
    }
    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isNotFound());
  }

  @Test
  void twoConcurrentDeletesThatMustKeepTheWorkflowLeaveOneVersionAndTheWorkflowAlive()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    List<Callable<Integer>> calls = new ArrayList<>();
    for (String label : List.of("v1", "v1.1")) {
      calls.add(
          () ->
              mvc.perform(
                      delete(VERSION, w.id(), w.version(label))
                          .param("allowWorkflowDelete", "false")
                          .with(user(OWNER)))
                  .andReturn()
                  .getResponse()
                  .getStatus());
    }
    ExecutorService pool = Executors.newFixedThreadPool(2);
    try {
      List<Integer> statuses = new ArrayList<>();
      // 제한 시간 안에 끝나지 않은 작업은 취소되고, 그 결과를 읽을 때 CancellationException으로 테스트가 실패한다.
      for (Future<Integer> future : pool.invokeAll(calls, 30, TimeUnit.SECONDS)) {
        statuses.add(future.get());
      }
      // 워크플로 행 잠금으로 순서가 정해져, 먼저 들어간 요청만 버전을 지우고 나중 요청은 마지막 버전이라 거절된다.
      assertThat(statuses).containsExactlyInAnyOrder(200, 409);
    } finally {
      pool.shutdownNow();
    }
    assertThat(deletedCount(w.id())).isEqualTo(1);
    assertThat(workflowIsDeleted(w.id())).isFalse();
    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", hasSize(1)));
  }

  // ---- 삭제 목록 ----

  @Test
  void includeDeletedListsRestorableDeletedVersionsAndWorkflowsOnly() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());

    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.2", "v1.1", "v1")))
        .andExpect(jsonPath("$.data.items[0].deletedAt").isNotEmpty())
        .andExpect(jsonPath("$.data.items[0].restoreUntil").isNotEmpty())
        .andExpect(jsonPath("$.data.items[1].deletedAt").doesNotExist());

    // 복구 기간이 끝난 버전은 목록에서도 빠진다.
    expire(w.version("v1.2"));
    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1", "v1")));
  }

  @Test
  void includeDeletedListsADeletedWorkflowAndItsVersionsForItsOwnerOnly() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());

    mvc.perform(get("/api/me/workflows").param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", hasSize(1)))
        .andExpect(jsonPath("$.data.items[0].workflowId").value(w.id().toString()))
        .andExpect(jsonPath("$.data.items[0].deletedAt").isNotEmpty())
        .andExpect(jsonPath("$.data.items[0].restoreUntil").isNotEmpty())
        .andExpect(jsonPath("$.data.items[0].latestVersion.versionLabel").value("v1.1"));
    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1", "v1")));
    mvc.perform(get("/api/me/workflows").param("includeDeleted", "true").with(user(OTHER_USER)))
        .andExpect(jsonPath("$.data.items", empty()));
    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OTHER_USER)))
        .andExpect(status().isNotFound());
    // 옵션 없이는 삭제된 워크플로가 보이지 않는다.
    mvc.perform(get("/api/me/workflows").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", empty()));
  }

  @ParameterizedTest
  @ValueSource(strings = {"maybe", "2"})
  void rejectsAnIncludeDeletedThatIsNotABoolean(String value) throws Exception {
    mvc.perform(get("/api/me/workflows").param("includeDeleted", value).with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("BAD_REQUEST"));
  }

  @Test
  void retryOfACommittedRegistrationAfterTheWorkflowWasDeletedReturnsTheOriginalResult()
      throws Exception {
    Workflow w = workflow("v1");
    MvcResult comparison =
        mvc.perform(
                multipart(VERSION + "/comparisons", w.id(), w.version("v1"))
                    .file(file(CANDIDATE))
                    .with(user(OWNER)))
            .andExpect(status().isOk())
            .andReturn();
    String comparisonId = JsonPath.read(body(comparison), "$.data.comparisonId");
    String key = UUID.randomUUID().toString();
    String request = "{\"comparisonId\":\"%s\",\"updateType\":\"MINOR\"}".formatted(comparisonId);
    MvcResult first =
        mvc.perform(
                post(VERSIONS, w.id())
                    .header("Idempotency-Key", key)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content(request)
                    .with(user(OWNER)))
            .andExpect(status().isCreated())
            .andReturn();
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());

    // 응답을 받지 못한 클라이언트의 재시도는 그 사이 삭제가 있었어도 처음 결과를 돌려준다.
    mvc.perform(
            post(VERSIONS, w.id())
                .header("Idempotency-Key", key)
                .contentType(MediaType.APPLICATION_JSON)
                .content(request)
                .with(user(OWNER)))
        .andExpect(status().isCreated())
        .andExpect(
            jsonPath("$.data.versionId")
                .value((String) JsonPath.read(body(first), "$.data.versionId")));
    // 새 키로는 삭제된 워크플로에 버전을 등록할 수 없다.
    mvc.perform(
            post(VERSIONS, w.id())
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(request)
                .with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_NOT_FOUND"));
  }

  @Test
  void includeDeletedStillListsADeletedWorkflowWhenOnlyAnEarlierDeletedVersionIsRestorable()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(VERSION, w.id(), w.version("v1")).with(user(OWNER)))
        .andExpect(status().isOk());
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowDeleted").value(true));
    // 워크플로 삭제 때 함께 삭제된 v1.1의 원본은 정리되고, 먼저 삭제한 v1만 복구할 수 있다.
    expire(w.version("v1.1"));
    purge.purgeDue();

    mvc.perform(get("/api/me/workflows").param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", hasSize(1)))
        .andExpect(jsonPath("$.data.items[0].latestVersion.versionLabel").value("v1"))
        .andExpect(jsonPath("$.data.items[0].restoreUntil").isNotEmpty());
    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1")));
    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowRestored").value(true));
  }

  @Test
  void aDeletedWorkflowWithoutRestorableVersionsIsNotFoundEvenBeforeTheOriginalIsPurged()
      throws Exception {
    Workflow w = workflow("v1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    // 복구 기간은 끝났지만 정리 작업은 아직 실행되기 전이다. 워크플로 목록과 버전 목록이 같은 결과여야 한다.
    expire(w.version("v1"));

    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(status().isNotFound());
    mvc.perform(get("/api/me/workflows").param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", empty()));
  }

  // ---- 복구 ----

  @Test
  void ownerRestoresADeletedVersionWithinThePeriod() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());

    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowRestored").value(false))
        .andExpect(jsonPath("$.data.restoredVersionIds[0]").value(w.version("v1.1").toString()))
        .andExpect(jsonPath("$.data.unavailableVersionIds", empty()));

    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1", "v1")));
    mvc.perform(get(VERSION + "/download", w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());
  }

  @Test
  void restoreIsRefusedForOtherUsersAndForTargetsThatAreNotDeleted() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());

    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1.1")).with(user(OTHER_USER)))
        .andExpect(status().isNotFound());
    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1")).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("NOT_DELETED"));
    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("NOT_DELETED"));
    assertThat(deletedCount(w.id())).isEqualTo(1);
  }

  @Test
  void restoreIsRefusedAfterThePeriodEndedOrTheStorageDeletionStarted() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());
    expire(w.version("v1.1"));
    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET delete_started_at = clock_timestamp() WHERE id = :id")
        .param("id", w.version("v1.2"))
        .update();

    for (String label : List.of("v1.1", "v1.2")) {
      mvc.perform(post(VERSION + "/restore", w.id(), w.version(label)).with(user(OWNER)))
          .andExpect(status().isConflict())
          .andExpect(jsonPath("$.code").value("RESTORE_UNAVAILABLE"));
    }
    assertThat(deletedCount(w.id())).isEqualTo(2);
  }

  @Test
  void restoreFailsWithoutChangingTheRowWhenTheOriginalIsGone() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    UUID version = w.version("v1.1");
    mvc.perform(delete(VERSION, w.id(), version).with(user(OWNER))).andExpect(status().isOk());
    String key = objectKeyOf(version);
    store.objects().remove(key);

    // S3가 없다고 답해도 설정 오류일 수 있으므로 행은 그대로 두고 기한 뒤 정리 작업에 맡긴다.
    for (int attempt = 0; attempt < 2; attempt++) {
      mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
          .andExpect(status().isConflict())
          .andExpect(jsonPath("$.code").value("RESTORE_UNAVAILABLE"));
    }
    Map<String, Object> row = versionRow(version);
    assertThat(row.get("deleted_at")).isNotNull();
    assertThat(row.get("purged_at")).isNull();
    assertThat(row.get("s3_object_key")).isEqualTo(key);

    // 기한이 지나면 정리 작업이 없는 객체도 정상으로 처리하고 정리 완료로 표시한다.
    expire(version);
    purge.purgeDue();
    assertThat(versionRow(version).get("purged_at")).isNotNull();
    mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
        .andExpect(status().isNotFound());
  }

  @Test
  void restoreFailsWithoutChangesWhenTheSizeDiffersFromTheRecordedOne() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    UUID version = w.version("v1.1");
    mvc.perform(delete(VERSION, w.id(), version).with(user(OWNER))).andExpect(status().isOk());
    store.objects().put(objectKeyOf(version), new byte[] {1, 2, 3});

    mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("RESTORE_UNAVAILABLE"));

    assertThat(versionRow(version).get("deleted_at")).isNotNull();
    assertThat(versionRow(version).get("purged_at")).isNull();
  }

  @Test
  void restoreReturnsServiceUnavailableWithoutChangesWhenStorageCannotBeChecked() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    UUID version = w.version("v1.1");
    mvc.perform(delete(VERSION, w.id(), version).with(user(OWNER))).andExpect(status().isOk());
    store.failSizes = true;

    mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.code").value("STORAGE_UNAVAILABLE"));

    assertThat(versionRow(version).get("deleted_at")).isNotNull();
    assertThat(versionRow(version).get("purged_at")).isNull();
  }

  @Test
  void restoringAWorkflowRestoresOnlyTheVersionsDeletedWithIt() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());

    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowRestored").value(true))
        .andExpect(jsonPath("$.data.restoredVersionIds", hasSize(2)))
        .andExpect(jsonPath("$.data.unavailableVersionIds", empty()));

    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.latestVersion.versionLabel").value("v1.1"));
    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.2", "v1.1", "v1")))
        .andExpect(jsonPath("$.data.items[0].restoreUntil").isNotEmpty());
    // 먼저 개별 삭제한 버전은 되살아나지 않았고, 따로 복구할 수 있다.
    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());
  }

  @Test
  void restoringOneVersionOfADeletedWorkflowRevivesTheWorkflowButNotTheOtherVersions()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());

    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.workflowRestored").value(true));

    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.latestVersion.versionLabel").value("v1.1"));
    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1")));
    // 워크플로가 살아 있으므로 같이 삭제됐던 나머지는 버전 단위로 복구한다.
    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isConflict());
    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1")).with(user(OWNER)))
        .andExpect(status().isOk());
  }

  @Test
  void aSecondDeleteAndRestoreCycleDoesNotRevivePreviouslyDeletedVersions() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());

    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.restoredVersionIds", hasSize(1)))
        .andExpect(jsonPath("$.data.restoredVersionIds[0]").value(w.version("v1.1").toString()));
  }

  @Test
  void restoringAWorkflowReportsVersionsWhoseOriginalIsGone() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    store.objects().remove(objectKeyOf(w.version("v1.1")));

    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.restoredVersionIds[0]").value(w.version("v1").toString()))
        .andExpect(jsonPath("$.data.unavailableVersionIds[0]").value(w.version("v1.1").toString()));

    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1")));
    // 없는 것으로 보이는 버전도 행은 그대로 두고, 기한이 지난 뒤 정리 작업이 처리한다.
    assertThat(versionRow(w.version("v1.1")).get("deleted_at")).isNotNull();
    assertThat(versionRow(w.version("v1.1")).get("purged_at")).isNull();
  }

  @Test
  void restoringAWorkflowFailsAndStaysDeletedWhenNoVersionCanBeRestored() throws Exception {
    Workflow w = workflow("v1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    store.objects().remove(objectKeyOf(w.version("v1")));

    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("RESTORE_UNAVAILABLE"));

    mvc.perform(get(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isNotFound());
  }

  @Test
  void restoringAWorkflowNeverRevivesVersionsOfAnotherWorkflowOrOtherOwners() throws Exception {
    Workflow mine = workflow("v1");
    Workflow other = workflow("v1");
    mvc.perform(delete(WORKFLOW, mine.id()).with(user(OWNER))).andExpect(status().isOk());
    mvc.perform(delete(WORKFLOW, other.id()).with(user(OWNER))).andExpect(status().isOk());

    mvc.perform(post(WORKFLOW + "/restore", mine.id()).with(user(OTHER_USER)))
        .andExpect(status().isNotFound());
    mvc.perform(post(WORKFLOW + "/restore", mine.id()).with(user(OWNER)))
        .andExpect(status().isOk());

    assertThat(deletedCount(other.id())).isEqualTo(1);
  }

  @Test
  void restoringAWorkflowAnswersNotDeletedWhenAnotherRequestRestoredItWhileStorageWasChecked()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    // 저장소를 확인하는 사이(잠금 밖) 다른 요청이 같은 워크플로를 먼저 복구한다.
    store.afterSize =
        () -> {
          try {
            mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
                .andExpect(status().isOk());
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
        };

    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("NOT_DELETED"));

    mvc.perform(get(VERSIONS, w.id()).with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", hasSize(2)));
  }

  @Test
  void restoringAVersionAnswersNotDeletedWhenAnotherRequestRestoredItWhileStorageWasChecked()
      throws Exception {
    Workflow w = workflow("v1", "v1.1");
    UUID version = w.version("v1.1");
    mvc.perform(delete(VERSION, w.id(), version).with(user(OWNER))).andExpect(status().isOk());
    store.afterSize =
        () -> {
          try {
            mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
                .andExpect(status().isOk());
          } catch (Exception e) {
            throw new IllegalStateException(e);
          }
        };

    mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("NOT_DELETED"));

    assertThat(versionRow(version).get("deleted_at")).isNull();
  }

  // ---- 원본 정리 ----

  @Test
  void purgeKeepsTheOriginalUntilTheRestorePeriodEnds() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());

    purge.purgeDue();

    assertThat(versionObjects()).hasSize(2);
    assertThat(versionRow(w.version("v1.1")).get("delete_started_at")).isNull();
  }

  @Test
  void purgeDeletesOnlyTheExpiredVersionsOriginalAndClearsItsFileData() throws Exception {
    Workflow w = workflow("v1", "v1.1", "v1.2");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isOk());
    String purged = objectKeyOf(w.version("v1.2"));
    expire(w.version("v1.2"));

    purge.purgeDue();

    assertThat(versionObjects()).hasSize(2).doesNotContain(purged);
    Map<String, Object> row = versionRow(w.version("v1.2"));
    assertThat(row.get("purged_at")).isNotNull();
    assertThat(row.get("s3_object_key")).isNull();
    assertThat(row.get("content_sha256")).isNull();
    assertThat(row.get("size_bytes")).isNull();
    // 번호는 행에 남아 재사용되지 않는다.
    assertThat(row.get("version")).isEqualTo("v1.2");
    mvc.perform(post(VERSION + "/restore", w.id(), w.version("v1.2")).with(user(OWNER)))
        .andExpect(status().isNotFound());
    mvc.perform(get(VERSIONS, w.id()).param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items[*].versionLabel", contains("v1.1", "v1")));
  }

  @Test
  void purgeKeepsBlockingAccessAndRetriesAfterAStorageFailure() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    UUID version = w.version("v1.1");
    // 정리가 끝나면 행의 s3_object_key가 비워지므로, 정리 전에 실제 객체 키를 저장해 둔다.
    String key = objectKeyOf(version);
    mvc.perform(delete(VERSION, w.id(), version).with(user(OWNER))).andExpect(status().isOk());
    expire(version);

    store.failDeletes = true;
    purge.purgeDue();

    // 삭제된 버전의 접근은 계속 막히고, 삭제를 시작했으므로 복구도 거절된다.
    assertThat(versionObjects()).contains(key);
    assertThat(versionRow(version).get("delete_started_at")).isNotNull();
    assertThat(versionRow(version).get("purged_at")).isNull();
    mvc.perform(get(VERSION + "/download", w.id(), version).with(user(OWNER)))
        .andExpect(status().isNotFound());
    mvc.perform(post(VERSION + "/restore", w.id(), version).with(user(OWNER)))
        .andExpect(status().isConflict());

    // 재시도 간격 안에서는 다시 집지 않는다.
    store.failDeletes = false;
    purge.purgeDue();
    assertThat(versionObjects()).contains(key);

    jdbc.sql(
            "UPDATE workflow_hub.workflow_versions SET delete_started_at = clock_timestamp() - interval '1 hour' WHERE id = :id")
        .param("id", version)
        .update();
    purge.purgeDue();

    assertThat(versionObjects()).doesNotContain(key);
    assertThat(versionRow(version).get("purged_at")).isNotNull();
  }

  @Test
  void purgeClearsTheTitleOnlyAfterEveryVersionOfADeletedWorkflowIsPurged() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(WORKFLOW, w.id()).with(user(OWNER))).andExpect(status().isOk());
    expire(w.version("v1"));

    purge.purgeDue();
    assertThat(title(w.id())).isNotNull();

    expire(w.version("v1.1"));
    purge.purgeDue();

    assertThat(title(w.id())).isNull();
    mvc.perform(get("/api/me/workflows").param("includeDeleted", "true").with(user(OWNER)))
        .andExpect(jsonPath("$.data.items", empty()));
    mvc.perform(post(WORKFLOW + "/restore", w.id()).with(user(OWNER)))
        .andExpect(status().isNotFound());
    assertThat(versionObjects()).isEmpty();
  }

  @Test
  void purgeNeverTouchesAliveVersions() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    // 살아 있는 버전의 기한을 건드릴 수 없도록 제약이 막는다.
    assertThatThrownBy(
            () ->
                jdbc.sql(
                        "UPDATE workflow_hub.workflow_versions SET delete_after = clock_timestamp() WHERE id = :id")
                    .param("id", w.version("v1"))
                    .update())
        .isInstanceOf(DataIntegrityViolationException.class);

    purge.purgeDue();

    assertThat(versionObjects()).hasSize(2);
  }

  @Test
  void theDatabaseRejectsAPurgedRowThatStillPointsToAFile() throws Exception {
    Workflow w = workflow("v1", "v1.1");
    mvc.perform(delete(VERSION, w.id(), w.version("v1.1")).with(user(OWNER)))
        .andExpect(status().isOk());

    assertThatThrownBy(
            () ->
                jdbc.sql(
                        "UPDATE workflow_hub.workflow_versions SET purged_at = clock_timestamp() WHERE id = :id")
                    .param("id", w.version("v1.1"))
                    .update())
        .isInstanceOf(DataIntegrityViolationException.class);
  }

  // ---- 도우미 ----

  /** 최초 업로드와 MINOR 등록으로 합성 워크플로를 만든다. 라벨 순서대로 v1, v1.1, v1.2...를 기대한다. */
  private Workflow workflow(String... labels) throws Exception {
    MvcResult upload =
        mvc.perform(
                multipart(WORKFLOWS)
                    .file(file(BASE))
                    .header("Idempotency-Key", UUID.randomUUID().toString())
                    .with(user(OWNER)))
            .andExpect(status().isCreated())
            .andReturn();
    Workflow workflow =
        new Workflow(UUID.fromString(JsonPath.read(body(upload), "$.data.workflowId")));
    UUID previous = UUID.fromString(JsonPath.read(body(upload), "$.data.versionId"));
    workflow.add(previous, "v1");
    for (int i = 1; i < labels.length; i++) {
      previous = workflow.add(registerId(workflow.id(), previous, "MINOR"), labels[i]);
    }
    return workflow;
  }

  private String register(UUID workflowId, UUID baseVersion, String updateType) throws Exception {
    return JsonPath.read(
        body(registerResult(workflowId, baseVersion, updateType)), "$.data.versionLabel");
  }

  private UUID registerId(UUID workflowId, UUID baseVersion, String updateType) throws Exception {
    return UUID.fromString(
        JsonPath.read(
            body(registerResult(workflowId, baseVersion, updateType)), "$.data.versionId"));
  }

  private MvcResult registerResult(UUID workflowId, UUID baseVersion, String updateType)
      throws Exception {
    MvcResult comparison =
        mvc.perform(
                multipart(VERSION + "/comparisons", workflowId, baseVersion)
                    .file(file(CANDIDATE))
                    .with(user(OWNER)))
            .andExpect(status().isOk())
            .andReturn();
    String comparisonId = JsonPath.read(body(comparison), "$.data.comparisonId");
    return mvc.perform(
            post(VERSIONS, workflowId)
                .header("Idempotency-Key", UUID.randomUUID().toString())
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    "{\"comparisonId\":\"%s\",\"updateType\":\"%s\"}"
                        .formatted(comparisonId, updateType))
                .with(user(OWNER)))
        .andExpect(status().isCreated())
        .andReturn();
  }

  /** 버전 원본 객체의 키. 비교용 임시 파일은 제외한다. */
  private List<String> versionObjects() {
    return store.objects().keySet().stream()
        .filter(key -> !key.startsWith("workflows/comparisons/"))
        .toList();
  }

  private void expire(UUID versionId) {
    jdbc.sql(
            """
            UPDATE workflow_hub.workflow_versions
            SET delete_after = clock_timestamp() - interval '1 second'
            WHERE id = :id AND deleted_at IS NOT NULL
            """)
        .param("id", versionId)
        .update();
  }

  private Instant deleteAfter(UUID versionId) {
    return jdbc.sql("SELECT delete_after FROM workflow_hub.workflow_versions WHERE id = :id")
        .param("id", versionId)
        .query((rs, i) -> rs.getObject(1, java.time.OffsetDateTime.class).toInstant())
        .single();
  }

  private long deletedCount(UUID workflowId) {
    return jdbc.sql(
            "SELECT count(*) FROM workflow_hub.workflow_versions WHERE workflow_id = :id AND deleted_at IS NOT NULL")
        .param("id", workflowId)
        .query(Long.class)
        .single();
  }

  private boolean workflowIsDeleted(UUID workflowId) {
    return jdbc.sql("SELECT deleted_at IS NOT NULL FROM workflow_hub.workflows WHERE id = :id")
        .param("id", workflowId)
        .query(Boolean.class)
        .single();
  }

  private Map<String, Object> versionRow(UUID versionId) {
    return jdbc.sql("SELECT * FROM workflow_hub.workflow_versions WHERE id = :id")
        .param("id", versionId)
        .query()
        .singleRow();
  }

  private String objectKeyOf(UUID versionId) {
    return (String) versionRow(versionId).get("s3_object_key");
  }

  private String title(UUID workflowId) {
    return jdbc.sql("SELECT title FROM workflow_hub.workflows WHERE id = :id")
        .param("id", workflowId)
        .query(String.class)
        .optional()
        .orElse(null);
  }

  private static String body(MvcResult result) throws Exception {
    return result.getResponse().getContentAsString();
  }

  private static MockMultipartFile file(byte[] bytes) {
    return new MockMultipartFile("file", "synthetic.json", MediaType.APPLICATION_JSON_VALUE, bytes);
  }

  private static RequestPostProcessor user(String subject) {
    return jwt().jwt(token -> token.subject(subject));
  }

  private static final class Workflow {
    private final UUID id;
    private final Map<String, UUID> versions = new java.util.LinkedHashMap<>();

    Workflow(UUID id) {
      this.id = id;
    }

    UUID id() {
      return id;
    }

    UUID add(UUID versionId, String label) {
      versions.put(label, versionId);
      return versionId;
    }

    UUID version(String label) {
      UUID versionId = versions.get(label);
      assertThat(versionId).as("version %s", label).isNotNull();
      return versionId;
    }
  }
}
