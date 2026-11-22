package dev.workflowhub.workflow.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.multipart;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.jayway.jsonpath.JsonPath;
import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.service.WorkflowUploadService.UploadResult;
import dev.workflowhub.workflow.service.WorkflowVersionService;
import dev.workflowhub.workflow.service.WorkflowVersionService.UpdateType;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.mock.web.MockMultipartFile;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMultipartHttpServletRequestBuilder;
import org.springframework.transaction.CannotCreateTransactionException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionStatus;
import org.springframework.transaction.support.TransactionCallback;
import org.springframework.transaction.support.TransactionTemplate;

/** 커밋은 됐는데 응답만 유실된 경우, 이미 커밋된 행이 가리키는 S3 객체를 지우면 안 된다. */
@SpringBootTest
@AutoConfigureMockMvc
@Import({
  PostgresTestConfiguration.class,
  WorkflowUploadAmbiguousCommitTests.StoreConfiguration.class
})
class WorkflowUploadAmbiguousCommitTests {
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
  @Autowired WorkflowVersionService versions;
  @MockitoSpyBean TransactionTemplate transactions;
  @Autowired PlatformTransactionManager transactionManager;

  @BeforeEach
  void clean() {
    jdbc.sql("DELETE FROM workflow_hub.idempotency_keys").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_comparisons").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_versions").update();
    jdbc.sql("DELETE FROM workflow_hub.workflows").update();
    store.reset();
  }

  @Test
  void keepsTheObjectAndReturns201WhenTheCommitWasActuallyApplied() throws Exception {
    doAnswer(
            invocation -> {
              invocation.callRealMethod();
              throw new IllegalStateException("simulated lost commit acknowledgement");
            })
        .when(transactions)
        .executeWithoutResult(any());

    mvc.perform(
            multipart("/api/workflows")
                .file(
                    new MockMultipartFile(
                        "file",
                        "w.json",
                        "application/json",
                        "{\"name\":\"n\",\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}"
                            .getBytes(StandardCharsets.UTF_8)))
                .header("Idempotency-Key", "key-ambiguous")
                .with(jwt().jwt(token -> token.subject("u"))))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.versionLabel").value("v1"));

    String objectKey =
        jdbc.sql("SELECT s3_object_key FROM workflow_hub.workflow_versions")
            .query(String.class)
            .single();
    assertThat(store.objects()).containsOnlyKeys(objectKey);
  }

  @Test
  void keepsTheObjectWhenTheCommitFailedAndCannotBeConfirmed() throws Exception {
    // 본문은 실행하되 롤백시킨 뒤 커밋 실패처럼 예외를 던진다. 행이 없어서 확인에 실패한다.
    doAnswer(
            invocation -> {
              Consumer<TransactionStatus> body = invocation.getArgument(0);
              new TransactionTemplate(transactionManager)
                  .executeWithoutResult(
                      status -> {
                        body.accept(status);
                        status.setRollbackOnly();
                      });
              throw new IllegalStateException("simulated commit failure");
            })
        .when(transactions)
        .executeWithoutResult(any());

    mvc.perform(upload("key-unconfirmed")).andExpect(status().isInternalServerError());

    assertThat(jdbc.sql("SELECT count(*) FROM workflow_hub.workflows").query(Long.class).single())
        .isZero();
    // 이후 커밋됐을 수 있으므로 객체를 지우지 않는다. 남은 객체는 로그의 키로 정리한다.
    assertThat(store.objects()).hasSize(1);
  }

  @Test
  void deletesTheObjectWhenTheTransactionCouldNotEvenStart() throws Exception {
    doThrow(new CannotCreateTransactionException("simulated pool exhaustion"))
        .when(transactions)
        .executeWithoutResult(any());

    mvc.perform(upload("key-no-tx")).andExpect(status().isInternalServerError());

    assertThat(store.objects()).isEmpty();
  }

  @Test
  void discardsTheUncommittedVersionObjectWhenAnotherRequestWonTheSameKey() throws Exception {
    var initial =
        mvc.perform(upload("initial")).andExpect(status().isCreated()).andReturn().getResponse();
    String workflowId = JsonPath.read(initial.getContentAsString(), "$.data.workflowId");
    String versionId = JsonPath.read(initial.getContentAsString(), "$.data.versionId");
    var comparison =
        mvc.perform(
                multipart(
                        "/api/workflows/{workflowId}/versions/{versionId}/comparisons",
                        workflowId,
                        versionId)
                    .file(workflowFile())
                    .with(jwt().jwt(token -> token.subject("u"))))
            .andExpect(status().isOk())
            .andReturn()
            .getResponse();
    UUID comparisonId =
        UUID.fromString(JsonPath.read(comparison.getContentAsString(), "$.data.comparisonId"));
    String key = "same-version-key";
    var winner = new AtomicReference<UploadResult>();

    doAnswer(
            invocation -> {
              TransactionCallback<?> body = invocation.getArgument(0);
              new TransactionTemplate(transactionManager)
                  .executeWithoutResult(
                      status -> {
                        body.doInTransaction(status);
                        status.setRollbackOnly();
                      });
              winner.set(versions.register("u", workflowId, key, comparisonId, UpdateType.MINOR));
              throw new IllegalStateException("simulated commit failure after another request won");
            })
        .doCallRealMethod()
        .when(transactions)
        .execute(any());

    mvc.perform(
            post("/api/workflows/{workflowId}/versions", workflowId)
                .contentType(MediaType.APPLICATION_JSON)
                .content(
                    """
                    {"comparisonId":"%s","updateType":"MINOR"}
                    """
                        .formatted(comparisonId))
                .header("Idempotency-Key", key)
                .with(jwt().jwt(token -> token.subject("u"))))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.data.versionId").value(winner.get().versionId().toString()));

    var versionKeys =
        jdbc.sql("SELECT s3_object_key FROM workflow_hub.workflow_versions")
            .query(String.class)
            .list();
    assertThat(versionKeys).hasSize(2);
    assertThat(store.objects())
        .hasSize(3)
        .containsKey("workflows/comparisons/" + comparisonId + ".json")
        .containsKeys(versionKeys.toArray(String[]::new));
  }

  private MockMultipartHttpServletRequestBuilder upload(String key) {
    return multipart("/api/workflows")
        .file(workflowFile())
        .header("Idempotency-Key", key)
        .with(jwt().jwt(token -> token.subject("u")));
  }

  private MockMultipartFile workflowFile() {
    return new MockMultipartFile(
        "file",
        "w.json",
        "application/json",
        "{\"name\":\"n\",\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}"
            .getBytes(StandardCharsets.UTF_8));
  }
}
