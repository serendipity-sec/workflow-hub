package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.clearInvocations;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

@SpringBootTest
@AutoConfigureMockMvc
@Import({PostgresTestConfiguration.class, WorkflowUploadTests.StoreConfiguration.class})
class WorkflowVersionTests {
  private static final String WORKFLOWS = "/api/workflows";
  private static final String VERSIONS = WORKFLOWS + "/{workflowId}/versions";
  private static final String VERSION_PATH = VERSIONS + "/{versionId}";
  private static final String COMPARISONS = VERSION_PATH + "/comparisons";
  private static final String IDEMPOTENCY_KEY = "Idempotency-Key";
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
        "name" : "수정한 합성 워크플로",
        "nodes" : [
          {"id":"a","name":"Start","type":"n8n-nodes-base.manualTrigger","disabled":true,"parameters":{}},
          {"id":"c","name":"New step","type":"n8n-nodes-base.noOp","parameters":{}}
        ],
        "connections" : {"Start":{"main":[[{"node":"New step","type":"main","index":0}]]}}
      }
      """
          .replace("\n", "\r\n")
          .getBytes(StandardCharsets.UTF_8);

  @Autowired MockMvc mvc;
  @Autowired JdbcClient jdbc;
  @MockitoSpyBean InMemoryWorkflowObjectStore store;

  @BeforeEach
  void clean() {
    jdbc.sql("TRUNCATE workflow_hub.workflows CASCADE").update();
    store.reset();
    clearInvocations(store);
  }

  @Test
  void comparesGraphsAndReturnsTheBaseVersionAndChangeSummary() throws Exception {
    Version initial = upload();

    MvcResult result =
        mvc.perform(comparison(initial).with(user(OWNER)))
            .andExpect(status().isOk())
            .andExpect(
                jsonPath("$.data.baseVersion.versionId").value(initial.versionId().toString()))
            .andExpect(jsonPath("$.data.baseVersion.versionLabel").value("v1"))
            .andExpect(jsonPath("$.data.baseVersion.createdAt").isNotEmpty())
            .andExpect(jsonPath("$.data.expiresAt").isNotEmpty())
            .andExpect(jsonPath("$.data.summary.nodesAdded").value(1))
            .andExpect(jsonPath("$.data.summary.nodesRemoved").value(1))
            .andExpect(jsonPath("$.data.summary.nodesModified").value(1))
            .andExpect(jsonPath("$.data.summary.connectionsAdded").value(1))
            .andExpect(jsonPath("$.data.summary.connectionsRemoved").value(1))
            .andExpect(jsonPath("$.data.graphs.base.nodes.length()").value(2))
            .andExpect(jsonPath("$.data.graphs.base.connections.length()").value(1))
            .andExpect(jsonPath("$.data.graphs.candidate.nodes.length()").value(2))
            .andExpect(jsonPath("$.data.graphs.candidate.connections.length()").value(1))
            .andExpect(jsonPath("$.data.changes.length()").value(5))
            .andReturn();
    idFrom(result, "comparisonId");
  }

  @Test
  void rejectsMultipleComparisonFilesWithoutStaging() throws Exception {
    Version base = upload();
    clearInvocations(store);

    mvc.perform(comparison(base).file(file(BASE)).with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_FILE_COUNT"));
    verifyNoInteractions(store);
  }

  @Test
  void rejectsMissingOrDifferentlyNamedComparisonFilesWithoutStaging() throws Exception {
    Version base = upload();
    clearInvocations(store);

    mvc.perform(multipart(COMPARISONS, base.workflowId(), base.versionId()).with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_FILE_COUNT"));
    mvc.perform(
            comparison(base)
                .file(new MockMultipartFile("other", "o.json", "application/json", BASE))
                .with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_FILE_COUNT"));
    mvc.perform(
            multipart(COMPARISONS, base.workflowId(), base.versionId())
                .file(new MockMultipartFile("other", "o.json", "application/json", BASE))
                .with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_FILE_COUNT"));
    mvc.perform(
            multipart(COMPARISONS, base.workflowId(), base.versionId())
                .param("file", "text")
                .with(user(OWNER)))
        .andExpect(status().isBadRequest())
        .andExpect(jsonPath("$.code").value("INVALID_FILE_COUNT"));
    verifyNoInteractions(store);
  }

  @Test
  void rejectsInvalidWorkflowJsonBeforeStaging() throws Exception {
    Version base = upload();

    mvc.perform(
            multipart(COMPARISONS, base.workflowId(), base.versionId())
                .file(file("{}".getBytes(StandardCharsets.UTF_8)))
                .with(user(OWNER)))
        .andExpect(status().isUnprocessableContent())
        .andExpect(jsonPath("$.code").value("INVALID_WORKFLOW"));
    assertThat(store.objects()).hasSize(1);
    assertThat(
            jdbc.sql("SELECT COUNT(*) FROM workflow_hub.workflow_comparisons")
                .query(Long.class)
                .single())
        .isZero();
  }

  @Test
  void registersAMinorOnAnOlderLineAndUsesTheHighestMajorLineForTheNextMajor() throws Exception {
    Version v1 = upload();
    Version v11 = register(v1, "MINOR", "v1.1");
    Version v2 = register(v11, "MAJOR", "v2");
    Version v12 = register(v11, "MINOR", "v1.2");

    mvc.perform(get(WORKFLOWS + "/{workflowId}", v1.workflowId()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.data.latestVersion.versionId").value(v12.versionId().toString()))
        .andExpect(jsonPath("$.data.latestVersion.versionLabel").value("v1.2"));
    register(v2, "MAJOR", "v3");
    assertThat(versionLabels(v1)).containsExactlyInAnyOrder("v1", "v1.1", "v2", "v1.2", "v3");
  }

  @Test
  void comparesAgainstADownloadDisabledBaseAndStoresTheExactCandidateBytes() throws Exception {
    Version v1 = upload();
    mvc.perform(
            patch(VERSION_PATH + "/download-availability", v1.workflowId(), v1.versionId())
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"downloadEnabled\":false}")
                .with(user(OWNER)))
        .andExpect(status().isOk());

    Version v11 = register(v1, "MINOR", "v1.1");

    mvc.perform(
            get(VERSION_PATH + "/download", v11.workflowId(), v11.versionId()).with(user(OWNER)))
        .andExpect(status().isOk())
        .andExpect(content().bytes(CANDIDATE));
    mvc.perform(get(VERSION_PATH + "/download", v1.workflowId(), v1.versionId()).with(user(OWNER)))
        .andExpect(status().isForbidden())
        .andExpect(jsonPath("$.code").value("VERSION_DOWNLOAD_DISABLED"));
  }

  @ParameterizedTest
  @CsvSource({"MINOR,v1.1", "MAJOR,v2"})
  void oneConcurrentRegistrationWinsOnTheSameLine(String updateType, String label)
      throws Exception {
    Version v1 = upload();
    UUID first = createComparison(v1);
    UUID second = createComparison(v1);

    List<MvcResult> results =
        race(
            registration(v1, first, updateType, "race-a").with(user(OWNER)),
            registration(v1, second, updateType, "race-b").with(user(OWNER)));

    assertThat(results)
        .extracting(result -> result.getResponse().getStatus())
        .containsExactlyInAnyOrder(201, 409);
    MvcResult winner =
        results.stream()
            .filter(result -> result.getResponse().getStatus() == 201)
            .findFirst()
            .orElseThrow();
    MvcResult loser =
        results.stream()
            .filter(result -> result.getResponse().getStatus() == 409)
            .findFirst()
            .orElseThrow();
    jsonPath("$.data.workflowId").value(v1.workflowId().toString()).match(winner);
    jsonPath("$.data.versionLabel").value(label).match(winner);
    jsonPath("$.code").value("LATEST_VERSION_CHANGED").match(loser);
    jsonPath("$.details.latestVersion.versionId")
        .value(idFrom(winner, "versionId").toString())
        .match(loser);
    jsonPath("$.details.latestVersion.versionLabel").value(label).match(loser);
    jsonPath("$.details.latestVersion.createdAt").isNotEmpty().match(loser);
    assertThat(versionLabels(v1)).containsExactlyInAnyOrder("v1", label);
  }

  @Test
  void concurrentMinorRegistrationsOnDifferentLinesBothSucceed() throws Exception {
    Version v1 = upload();
    Version v2 = register(v1, "MAJOR", "v2");
    UUID first = createComparison(v1);
    UUID second = createComparison(v2);

    List<MvcResult> results =
        race(
            registration(v1, first, "MINOR", "v1-minor").with(user(OWNER)),
            registration(v2, second, "MINOR", "v2-minor").with(user(OWNER)));

    status().isCreated().match(results.get(0));
    jsonPath("$.data.versionLabel").value("v1.1").match(results.get(0));
    status().isCreated().match(results.get(1));
    jsonPath("$.data.versionLabel").value("v2.1").match(results.get(1));
    assertThat(versionLabels(v1)).containsExactlyInAnyOrder("v1", "v2", "v1.1", "v2.1");
  }

  @Test
  void concurrentIdenticalRequestsReplayTheCreatedVersionEvenAfterExpiry() throws Exception {
    Version v1 = upload();
    UUID comparisonId = createComparison(v1);
    UUID differentComparison = createComparison(v1);
    String key = "same-key";

    List<MvcResult> results =
        race(
            registration(v1, comparisonId, "MINOR", key).with(user(OWNER)),
            registration(v1, comparisonId, "MINOR", key).with(user(OWNER)));

    status().isCreated().match(results.get(0));
    status().isCreated().match(results.get(1));
    assertThat(results.get(1).getResponse().getContentAsString())
        .isEqualTo(results.get(0).getResponse().getContentAsString());
    expire(comparisonId);
    clearInvocations(store);

    mvc.perform(registration(v1, comparisonId, "MINOR", key).with(user(OWNER)))
        .andExpect(status().isCreated())
        .andExpect(content().json(results.get(0).getResponse().getContentAsString()));
    mvc.perform(registration(v1, comparisonId, "MAJOR", key).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_REUSED"));
    mvc.perform(registration(v1, differentComparison, "MINOR", key).with(user(OWNER)))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.code").value("IDEMPOTENCY_KEY_REUSED"));
    verifyNoInteractions(store);
    assertThat(versionLabels(v1)).containsExactlyInAnyOrder("v1", "v1.1");
  }

  @Test
  void replaysWhenAnIdenticalRequestCommitsBeforeTheStagedFileReadFails() throws Exception {
    Version v1 = upload();
    UUID comparisonId = createComparison(v1);
    String key = "same-key-during-expiry";
    String stagedKey = "workflows/comparisons/" + comparisonId + ".json";
    CountDownLatch reading = new CountDownLatch(1);
    CountDownLatch resumeRead = new CountDownLatch(1);
    AtomicBoolean readStarted = new AtomicBoolean();
    doAnswer(
            (invocation) -> {
              if (readStarted.compareAndSet(false, true)) {
                reading.countDown();
                if (!resumeRead.await(15, TimeUnit.SECONDS)) {
                  throw new IllegalStateException("Staged file read was not resumed");
                }
              }
              return invocation.callRealMethod();
            })
        .when(store)
        .get(stagedKey);

    var pool = Executors.newSingleThreadExecutor();
    try {
      var delayed =
          pool.submit(
              () ->
                  mvc.perform(registration(v1, comparisonId, "MINOR", key).with(user(OWNER)))
                      .andReturn());
      assertThat(reading.await(5, TimeUnit.SECONDS)).isTrue();
      var committed =
          mvc.perform(registration(v1, comparisonId, "MINOR", key).with(user(OWNER)))
              .andExpect(status().isCreated())
              .andReturn();
      expire(comparisonId);
      store.delete(stagedKey);
      resumeRead.countDown();

      var replayed = delayed.get(15, TimeUnit.SECONDS);
      status().isCreated().match(replayed);
      content().json(committed.getResponse().getContentAsString()).match(replayed);
      assertThat(versionLabels(v1)).containsExactlyInAnyOrder("v1", "v1.1");
    } finally {
      resumeRead.countDown();
      pool.shutdownNow();
    }
  }

  @Test
  void rejectsAnExpiredComparisonBeforeAccessingStorage() throws Exception {
    Version v1 = upload();
    UUID comparisonId = createComparison(v1);
    expire(comparisonId);
    clearInvocations(store);

    mvc.perform(registration(v1, comparisonId, "MINOR", "first-attempt").with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("COMPARISON_NOT_FOUND"));

    verifyNoInteractions(store);
    assertThat(versionLabels(v1)).containsExactly("v1");
  }

  @Test
  void retriesRegistrationWithTheSameKeyAfterAnObjectWriteFails() throws Exception {
    Version v1 = upload();
    UUID comparisonId = createComparison(v1);
    store.failPuts = true;

    mvc.perform(registration(v1, comparisonId, "MINOR", "retry-put").with(user(OWNER)))
        .andExpect(status().isServiceUnavailable())
        .andExpect(jsonPath("$.code").value("STORAGE_UNAVAILABLE"));
    assertThat(versionLabels(v1)).containsExactly("v1");
    store.failPuts = false;

    mvc.perform(registration(v1, comparisonId, "MINOR", "retry-put").with(user(OWNER)))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.versionLabel").value("v1.1"));
    assertThat(versionLabels(v1)).containsExactlyInAnyOrder("v1", "v1.1");
  }

  @Test
  void rejectsUnauthenticatedOrOutOfScopeComparisonRequestsBeforeAccessingStorage()
      throws Exception {
    Version v1 = upload();
    Version unrelated = upload();
    Version wrongBase = new Version(v1.workflowId(), unrelated.versionId());
    clearInvocations(store);

    mvc.perform(comparison(v1)).andExpect(status().isUnauthorized());
    mvc.perform(comparison(v1).with(user(OTHER_USER))).andExpect(status().isNotFound());
    mvc.perform(comparison(wrongBase).with(user(OWNER))).andExpect(status().isNotFound());

    verifyNoInteractions(store);
  }

  @Test
  void rejectsUnauthenticatedOrOutOfScopeRegistrationsBeforeAccessingStorage() throws Exception {
    Version v1 = upload();
    Version unrelated = upload();
    UUID comparisonId = createComparison(v1);
    clearInvocations(store);

    mvc.perform(registration(v1, comparisonId, "MINOR", "anonymous"))
        .andExpect(status().isUnauthorized());
    mvc.perform(registration(v1, comparisonId, "MINOR", "foreign").with(user(OTHER_USER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("WORKFLOW_NOT_FOUND"));
    mvc.perform(registration(unrelated, comparisonId, "MINOR", "wrong-workflow").with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("COMPARISON_NOT_FOUND"));
    mvc.perform(registration(v1, UUID.randomUUID(), "MINOR", "unknown").with(user(OWNER)))
        .andExpect(status().isNotFound())
        .andExpect(jsonPath("$.code").value("COMPARISON_NOT_FOUND"));

    verifyNoInteractions(store);
    assertThat(versionLabels(v1)).containsExactly("v1");
    assertThat(versionLabels(unrelated)).containsExactly("v1");
  }

  private List<MvcResult> race(
      MockHttpServletRequestBuilder first, MockHttpServletRequestBuilder second) throws Exception {
    CountDownLatch ready = new CountDownLatch(2);
    CountDownLatch start = new CountDownLatch(1);
    var pool = Executors.newFixedThreadPool(2);
    try {
      var requests =
          List.of(first, second).stream()
              .map(
                  request ->
                      pool.submit(
                          () -> {
                            ready.countDown();
                            if (!start.await(5, TimeUnit.SECONDS)) {
                              throw new IllegalStateException("Registration race did not start");
                            }
                            return mvc.perform(request).andReturn();
                          }))
              .toList();
      assertThat(ready.await(5, TimeUnit.SECONDS)).isTrue();
      start.countDown();
      return List.of(
          requests.get(0).get(15, TimeUnit.SECONDS), requests.get(1).get(15, TimeUnit.SECONDS));
    } finally {
      pool.shutdownNow();
    }
  }

  private void expire(UUID comparisonId) {
    jdbc.sql(
            "UPDATE workflow_hub.workflow_comparisons SET expires_at = now() - interval '1 second' WHERE id = :id")
        .param("id", comparisonId)
        .update();
  }

  private List<String> versionLabels(Version version) {
    return jdbc.sql("SELECT version FROM workflow_hub.workflow_versions WHERE workflow_id = :id")
        .param("id", version.workflowId())
        .query(String.class)
        .list();
  }

  private Version register(Version base, String updateType, String label) throws Exception {
    UUID comparisonId = createComparison(base);
    MvcResult result =
        mvc.perform(
                registration(base, comparisonId, updateType, UUID.randomUUID().toString())
                    .with(user(OWNER)))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.data.workflowId").value(base.workflowId().toString()))
            .andExpect(jsonPath("$.data.versionLabel").value(label))
            .andReturn();
    return versionFrom(result);
  }

  private UUID createComparison(Version base) throws Exception {
    return idFrom(
        mvc.perform(comparison(base).with(user(OWNER))).andExpect(status().isOk()).andReturn(),
        "comparisonId");
  }

  private Version upload() throws Exception {
    MvcResult result =
        mvc.perform(
                multipart(WORKFLOWS)
                    .file(file(BASE))
                    .header(IDEMPOTENCY_KEY, UUID.randomUUID().toString())
                    .with(user(OWNER)))
            .andExpect(status().isCreated())
            .andReturn();
    return versionFrom(result);
  }

  private static Version versionFrom(MvcResult result) throws Exception {
    return new Version(idFrom(result, "workflowId"), idFrom(result, "versionId"));
  }

  private static UUID idFrom(MvcResult result, String field) throws Exception {
    String value = JsonPath.read(result.getResponse().getContentAsString(), "$.data." + field);
    return UUID.fromString(value);
  }

  private static MockMultipartHttpServletRequestBuilder comparison(Version base) {
    return multipart(COMPARISONS, base.workflowId(), base.versionId()).file(file(CANDIDATE));
  }

  private static MockHttpServletRequestBuilder registration(
      Version version, UUID comparisonId, String updateType, String key) {
    return post(VERSIONS, version.workflowId())
        .header(IDEMPOTENCY_KEY, key)
        .contentType(MediaType.APPLICATION_JSON)
        .content(
            """
                 {"comparisonId":"%s","updateType":"%s"}
                 """
                .formatted(comparisonId, updateType));
  }

  private static MockMultipartFile file(byte[] bytes) {
    return new MockMultipartFile("file", "synthetic.json", MediaType.APPLICATION_JSON_VALUE, bytes);
  }

  private static RequestPostProcessor user(String subject) {
    return jwt().jwt(token -> token.subject(subject));
  }

  private record Version(UUID workflowId, UUID versionId) {}
}
