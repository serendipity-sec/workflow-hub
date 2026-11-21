package dev.workflowhub.workflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.workflowhub.PostgresTestConfiguration;
import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest
@Import(PostgresTestConfiguration.class)
@Transactional
class WorkflowMigrationTests {
  @Autowired JdbcClient jdbc;

  @Test
  void storesWorkflowAndVersionMetadataAfterStartupMigration() {
    UUID workflowId = insertWorkflow("Workflow A");
    insertVersion(workflowId, "v1", "fixtures/a/v1.json");

    assertThat(
            jdbc.sql("SELECT owner_id, title FROM workflow_hub.workflows WHERE id = :id")
                .param("id", workflowId)
                .query()
                .singleRow())
        .containsEntry("owner_id", "test-user")
        .containsEntry("title", "Workflow A");

    StoredVersion version =
        jdbc.sql(
                """
            SELECT s3_object_key, created_at
            FROM workflow_hub.workflow_versions
            WHERE workflow_id = :id AND version = 'v1'
            """)
            .param("id", workflowId)
            .query(
                (rs, row) ->
                    new StoredVersion(
                        rs.getString("s3_object_key"),
                        rs.getObject("created_at", OffsetDateTime.class)))
            .single();
    assertThat(version.objectKey()).isEqualTo("fixtures/a/v1.json");
    assertThat(version.createdAt()).isNotNull();
  }

  @Test
  void allowsDifferentVersionsWithinAWorkflowAndTheSameVersionAcrossWorkflows() {
    UUID first = insertWorkflow("Workflow A");
    UUID second = insertWorkflow("Workflow B");

    insertVersion(first, "v1", "fixtures/a/v1.json");
    insertVersion(first, "v1.1", "fixtures/a/v1.1.json");
    insertVersion(first, "v2", "fixtures/a/v2.json");
    insertVersion(second, "v1", "fixtures/b/v1.json");

    assertThat(versionsFor(first)).containsExactly("v1", "v1.1", "v2");
    assertThat(versionsFor(second)).containsExactly("v1");
  }

  @Test
  void rejectsDuplicateVersionInTheSameWorkflow() {
    UUID workflowId = insertWorkflow("Workflow A");
    insertVersion(workflowId, "v1", "fixtures/a/v1.json");

    assertThatThrownBy(() -> insertVersion(workflowId, "v1", "fixtures/a/other.json"))
        .rootCause()
        .isInstanceOfSatisfying(
            SQLException.class, error -> assertThat(error.getSQLState()).isEqualTo("23505"));
  }

  @Test
  void rejectsVersionForMissingWorkflow() {
    assertThatThrownBy(() -> insertVersion(UUID.randomUUID(), "v1", "fixtures/missing/v1.json"))
        .rootCause()
        .isInstanceOfSatisfying(
            SQLException.class, error -> assertThat(error.getSQLState()).isEqualTo("23503"));
  }

  private UUID insertWorkflow(String title) {
    return jdbc.sql(
            """
        INSERT INTO workflow_hub.workflows (owner_id, title)
        VALUES ('test-user', :title)
        RETURNING id
        """)
        .param("title", title)
        .query(UUID.class)
        .single();
  }

  private void insertVersion(UUID workflowId, String version, String objectKey) {
    jdbc.sql(
            """
        INSERT INTO workflow_hub.workflow_versions (workflow_id, version, s3_object_key)
        VALUES (:workflowId, :version, :objectKey)
        """)
        .param("workflowId", workflowId)
        .param("version", version)
        .param("objectKey", objectKey)
        .update();
  }

  private List<String> versionsFor(UUID workflowId) {
    return jdbc.sql(
            """
        SELECT version FROM workflow_hub.workflow_versions
        WHERE workflow_id = :id
        ORDER BY version
        """)
        .param("id", workflowId)
        .query(String.class)
        .list();
  }

  private record StoredVersion(String objectKey, OffsetDateTime createdAt) {}
}
