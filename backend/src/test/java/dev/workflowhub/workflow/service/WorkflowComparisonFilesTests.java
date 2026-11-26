package dev.workflowhub.workflow.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.workflowhub.PostgresTestConfiguration;
import dev.workflowhub.workflow.storage.InMemoryWorkflowObjectStore;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Import(PostgresTestConfiguration.class)
@Transactional
class WorkflowComparisonFilesTests {
  @Autowired JdbcClient jdbc;

  @Test
  void retriesExpiredObjectDeletionAndLeavesActiveComparisonsAndVersions() {
    var store = new InMemoryWorkflowObjectStore();
    var files = new WorkflowComparisonFiles(jdbc, store);
    UUID base = insertBase();
    var expired = files.stage(base, new byte[] {1});
    var active = files.stage(base, new byte[] {2});
    store.put("workflows/fixtures/v1.json", new byte[] {3});
    markDue(expired.id());

    store.failDeletes = true;
    files.cleanExpired();
    assertThat(pending(expired.id())).isTrue();
    assertThat(files.read(expired.id())).containsExactly(1);

    store.failDeletes = false;
    files.cleanExpired();
    assertThat(pending(expired.id())).isTrue();
    markDue(expired.id());
    files.cleanExpired();

    assertThat(pending(expired.id())).isFalse();
    assertThat(store.objects())
        .doesNotContainKey("workflows/comparisons/" + expired.id() + ".json");
    assertThat(files.read(active.id())).containsExactly(2);
    assertThat(store.get("workflows/fixtures/v1.json")).containsExactly(3);
  }

  @Test
  void retainsCleanupRecordWhenUploadMayHaveCompletedAfterAnError() {
    var store =
        new InMemoryWorkflowObjectStore() {
          @Override
          public void put(String key, byte[] content) {
            super.put(key, content);
            throw new IllegalStateException("simulated lost acknowledgement");
          }
        };
    var files = new WorkflowComparisonFiles(jdbc, store);
    UUID base = insertBase();

    assertThatThrownBy(() -> files.stage(base, new byte[] {1}))
        .isInstanceOfSatisfying(
            WorkflowUploadException.class,
            error -> assertThat(error.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE));
    UUID comparisonId =
        jdbc.sql(
                """
                SELECT id FROM workflow_hub.workflow_comparisons
                WHERE base_version_id = :base
                  AND expires_at <= statement_timestamp()
                  AND cleanup_after > statement_timestamp()
                """)
            .param("base", base)
            .query(UUID.class)
            .single();
    assertThat(files.read(comparisonId)).containsExactly(1);
    markDue(comparisonId);
    files.cleanExpired();

    assertThat(pending(comparisonId)).isFalse();
    assertThat(store.objects()).isEmpty();
  }

  private UUID insertBase() {
    UUID workflow =
        jdbc.sql(
                """
                INSERT INTO workflow_hub.workflows (owner_id, title)
                VALUES ('test-owner', 'Fixture') RETURNING id
                """)
            .query(UUID.class)
            .single();
    return jdbc.sql(
            """
            INSERT INTO workflow_hub.workflow_versions (workflow_id, version, s3_object_key)
            VALUES (:workflowId, 'v1', 'workflows/fixtures/v1.json') RETURNING id
            """)
        .param("workflowId", workflow)
        .query(UUID.class)
        .single();
  }

  private void markDue(UUID id) {
    jdbc.sql(
            """
            UPDATE workflow_hub.workflow_comparisons
            SET expires_at = statement_timestamp() - interval '1 second',
                cleanup_after = statement_timestamp() - interval '1 second'
            WHERE id = :id
            """)
        .param("id", id)
        .update();
  }

  private boolean pending(UUID id) {
    return jdbc.sql(
            "SELECT EXISTS (SELECT 1 FROM workflow_hub.workflow_comparisons WHERE id = :id)")
        .param("id", id)
        .query(Boolean.class)
        .single();
  }
}
