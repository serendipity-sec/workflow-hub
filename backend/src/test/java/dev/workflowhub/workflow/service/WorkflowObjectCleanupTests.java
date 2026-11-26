package dev.workflowhub.workflow.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.nio.charset.StandardCharsets;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;

/** 합성 파일과 인메모리 저장소로 실패·재시작·재시도를 확인한다. 실제 S3의 동작은 검증하지 못한다. */
@SpringBootTest
@Import({PostgresTestConfiguration.class, WorkflowObjectCleanupTests.StoreConfiguration.class})
class WorkflowObjectCleanupTests {
  private static final byte[] WORKFLOW =
      "{\"name\":\"n\",\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}"
          .getBytes(StandardCharsets.UTF_8);

  @TestConfiguration(proxyBeanMethods = false)
  static class StoreConfiguration {
    @Bean
    @Primary
    InMemoryWorkflowObjectStore inMemoryStore() {
      return new InMemoryWorkflowObjectStore();
    }
  }

  @Autowired JdbcClient jdbc;
  @Autowired InMemoryWorkflowObjectStore store;
  @Autowired WorkflowObjectCleanup cleanup;
  @Autowired org.springframework.transaction.PlatformTransactionManager transactionManager;
  @Autowired WorkflowUploadService uploads;

  @BeforeEach
  void clean() {
    jdbc.sql("DELETE FROM workflow_hub.pending_objects").update();
    jdbc.sql("DELETE FROM workflow_hub.idempotency_keys").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_comparisons").update();
    jdbc.sql("DELETE FROM workflow_hub.workflow_versions").update();
    jdbc.sql("DELETE FROM workflow_hub.workflows").update();
    store.reset();
  }

  @Test
  void successfulUploadLeavesNoPendingRecord() {
    var result = uploads.upload("u", "key-ok", "T", WORKFLOW);

    assertThat(pendingKeys()).isEmpty();
    assertThat(store.objects()).hasSize(1);
    assertThat(result.versionLabel()).isEqualTo("v1");
  }

  @Test
  void keepsRecordAndObjectOfARequestThatMayStillBeInProgress() {
    String key = objectKey();
    cleanup.record(key);
    store.put(key, WORKFLOW);

    cleanup.cleanDue();

    assertThat(store.objects()).containsKey(key);
    assertThat(pendingKeys()).containsExactly(key);
  }

  @Test
  void deletesAnUnreferencedObjectAfterTheGracePeriodEvenAfterARestart() {
    // 재시작은 기록만 DB에 남고 메모리 상태가 없는 상황이다. 객체가 올라갔는지 알 필요가 없다.
    String stored = objectKey();
    String neverStored = objectKey();
    cleanup.record(stored);
    store.put(stored, WORKFLOW);
    cleanup.record(neverStored);
    markDue(stored);
    markDue(neverStored);

    cleanup.cleanDue();

    assertThat(store.objects()).isEmpty();
    assertThat(pendingKeys()).isEmpty();
  }

  @Test
  void keepsTheObjectOfACommittedVersionWhoseCommitResultWasLost() {
    // 커밋은 적용됐지만 요청이 결과를 확인하지 못해 기록이 남은 상황을 만든다.
    String key = objectKey();
    insertVersionReferencing(key);
    cleanup.record(key);
    store.put(key, WORKFLOW);
    markDue(key);

    cleanup.cleanDue();

    assertThat(store.objects()).containsKey(key);
    assertThat(pendingKeys()).isEmpty();
  }

  @Test
  void retriesWhenTheObjectDeletionFailsTemporarily() {
    String key = objectKey();
    cleanup.record(key);
    store.put(key, WORKFLOW);
    markDue(key);

    store.failDeletes = true;
    cleanup.cleanDue();

    assertThat(store.objects()).containsKey(key);
    assertThat(pendingKeys()).containsExactly(key);

    // 실패 직후에는 재시도 간격이 지나기 전이라 다시 집지 않는다.
    store.failDeletes = false;
    cleanup.cleanDue();
    assertThat(store.objects()).containsKey(key);

    markDue(key);
    cleanup.cleanDue();

    assertThat(store.objects()).isEmpty();
    assertThat(pendingKeys()).isEmpty();
  }

  @Test
  void failedDeletionAfterADatabaseFailureIsRetriedLater() {
    store.failDeletes = true;
    // 소유자가 공백이면 DB 제약에 걸려 S3 저장 뒤에 기록이 실패한다.
    assertThatThrownBy(() -> uploads.upload(" ", "key-db", "T", WORKFLOW))
        .isInstanceOf(RuntimeException.class);
    assertThat(store.objects()).hasSize(1);
    assertThat(pendingKeys()).hasSize(1);

    store.failDeletes = false;
    String key = pendingKeys().get(0);
    markDue(key);
    cleanup.cleanDue();

    assertThat(store.objects()).isEmpty();
    assertThat(pendingKeys()).isEmpty();
  }

  @Test
  void keepsTheRecordAfterAStorageFailureBecauseTheWriteMayCompleteLater() {
    store.failPuts = true;

    assertThatThrownBy(() -> uploads.upload("u", "key-put", "T", WORKFLOW))
        .isInstanceOf(WorkflowUploadException.class);

    assertThat(pendingKeys()).hasSize(1);
    assertThat(store.objects()).isEmpty();
  }

  @Test
  void refusesToCommitAVersionWhoseObjectWasAlreadyCleanedUp() {
    // 저장은 끝났지만 커밋 전에 정리 작업이 대기 시간을 넘겨 객체를 지운 상황이다.
    store.afterPut =
        () -> {
          jdbc.sql(
                  "UPDATE workflow_hub.pending_objects SET cleanup_after = clock_timestamp() - interval '1 second'")
              .update();
          cleanup.cleanDue();
        };

    assertThatThrownBy(() -> uploads.upload("u", "key-late", "T", WORKFLOW))
        .isInstanceOfSatisfying(
            WorkflowUploadException.class,
            error -> assertThat(error.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));

    // 삭제된 파일을 가리키는 버전은 만들어지지 않는다.
    assertThat(jdbc.sql("SELECT count(*) FROM workflow_hub.workflows").query(Long.class).single())
        .isZero();
    assertThat(store.objects()).isEmpty();
    assertThat(pendingKeys()).isEmpty();
  }

  @Test
  void refusesToCommitAnObjectWhoseDeletionStartedEvenIfTheDeleteFailed() {
    // S3가 삭제를 적용했는데 응답이 유실돼 실패로 보이는 경우, 요청이 같은 객체로 커밋하면 안 된다.
    String key = objectKey();
    cleanup.record(key);
    store.put(key, WORKFLOW);
    markDue(key);
    store.failDeletes = true;
    cleanup.cleanDue();
    assertThat(pendingKeys()).containsExactly(key);

    assertThatThrownBy(
            () ->
                new org.springframework.transaction.support.TransactionTemplate(transactionManager)
                    .executeWithoutResult(status -> cleanup.releaseForCommit(key)))
        .isInstanceOfSatisfying(
            WorkflowUploadException.class,
            error -> assertThat(error.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));

    store.failDeletes = false;
    markDue(key);
    cleanup.cleanDue();
    assertThat(store.objects()).isEmpty();
    assertThat(pendingKeys()).isEmpty();
  }

  @Test
  void doesNotTouchObjectsWithoutARecord() {
    store.put("workflows/untracked/object.json", WORKFLOW);

    cleanup.cleanDue();

    assertThat(store.objects()).containsKey("workflows/untracked/object.json");
  }

  private String objectKey() {
    return "workflows/" + UUID.randomUUID() + "/" + UUID.randomUUID() + ".json";
  }

  private java.util.List<String> pendingKeys() {
    return jdbc.sql("SELECT object_key FROM workflow_hub.pending_objects ORDER BY object_key")
        .query(String.class)
        .list();
  }

  private void markDue(String key) {
    jdbc.sql(
            """
            UPDATE workflow_hub.pending_objects
            SET cleanup_after = clock_timestamp() - interval '1 second'
            WHERE object_key = :key
            """)
        .param("key", key)
        .update();
  }

  private void insertVersionReferencing(String key) {
    UUID workflow =
        jdbc.sql(
                """
                INSERT INTO workflow_hub.workflows (owner_id, title)
                VALUES ('test-owner', 'Fixture') RETURNING id
                """)
            .query(UUID.class)
            .single();
    jdbc.sql(
            """
            INSERT INTO workflow_hub.workflow_versions (workflow_id, version, s3_object_key)
            VALUES (:workflowId, 'v1', :key)
            """)
        .param("workflowId", workflow)
        .param("key", key)
        .update();
  }
}
