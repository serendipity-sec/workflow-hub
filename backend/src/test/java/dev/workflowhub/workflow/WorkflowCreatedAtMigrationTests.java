package dev.workflowhub.workflow;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.sql.SQLException;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.jdbc.datasource.DriverManagerDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

class WorkflowCreatedAtMigrationTests {
  @Test
  void upgradesExistingRowsFromV2AndDoesNotReapplyOnRestart() {
    try (var postgres = new PostgreSQLContainer("postgres:17-alpine")) {
      postgres.start();
      flyway(postgres, "2").migrate();
      var jdbc =
          JdbcClient.create(
              new DriverManagerDataSource(
                  postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword()));
      UUID workflowId = UUID.randomUUID();
      jdbc.sql(
              "INSERT INTO workflow_hub.workflows (id, owner_id, title) VALUES (:id, 'test-owner', 'Migration fixture')")
          .param("id", workflowId)
          .update();
      jdbc.sql(
              """
              INSERT INTO workflow_hub.workflow_versions
                  (workflow_id, version, s3_object_key, created_at)
              VALUES (:id, 'v1', 'fixtures/first.json', '2026-10-20T01:00:00Z'),
                     (:id, 'v1.1', 'fixtures/second.json', '2026-10-21T01:00:00Z')
              """)
          .param("id", workflowId)
          .update();

      var current = flyway(postgres, null);
      assertThat(current.migrate().migrationsExecuted).isEqualTo(4);
      assertThat(
              jdbc.sql("SELECT created_at FROM workflow_hub.workflows WHERE id = :id")
                  .param("id", workflowId)
                  .query(OffsetDateTime.class)
                  .single())
          .isEqualTo(OffsetDateTime.parse("2026-10-20T01:00:00Z"));
      assertThat(current.info().current().getScript())
          .isEqualTo("V6__add_workflow_version_file_identity.sql");
      // 기존 버전의 해시·크기는 알 수 없으므로 미확인(NULL)으로 남고 기존 행은 그대로 유지된다.
      assertThat(
              jdbc.sql(
                      """
                      SELECT version, s3_object_key, content_sha256, size_bytes
                      FROM workflow_hub.workflow_versions
                      WHERE workflow_id = :id ORDER BY version
                      """)
                  .param("id", workflowId)
                  .query()
                  .listOfRows())
          .extracting("version", "s3_object_key", "content_sha256", "size_bytes")
          .containsExactly(
              org.assertj.core.groups.Tuple.tuple("v1", "fixtures/first.json", null, null),
              org.assertj.core.groups.Tuple.tuple("v1.1", "fixtures/second.json", null, null));
      assertThat(
              jdbc.sql(
                      """
                      SELECT download_enabled
                      FROM workflow_hub.workflow_versions
                      WHERE workflow_id = :id
                      """)
                  .param("id", workflowId)
                  .query(Boolean.class)
                  .list())
          .containsExactly(true, true);
      assertThat(current.migrate().migrationsExecuted).isZero();

      assertThat(
              jdbc.sql(
                      """
              INSERT INTO workflow_hub.workflows (owner_id, title)
              VALUES ('test-owner', 'New fixture') RETURNING created_at
              """)
                  .query(OffsetDateTime.class)
                  .single())
          .isNotNull();
      assertThatThrownBy(
              () ->
                  jdbc.sql(
                          """
              INSERT INTO workflow_hub.workflows (owner_id, title, created_at)
              VALUES ('test-owner', 'Invalid fixture', NULL)
              """)
                      .update())
          .rootCause()
          .isInstanceOfSatisfying(
              SQLException.class, error -> assertThat(error.getSQLState()).isEqualTo("23502"));
    }
  }

  private Flyway flyway(PostgreSQLContainer postgres, String target) {
    var config =
        Flyway.configure()
            .dataSource(postgres.getJdbcUrl(), postgres.getUsername(), postgres.getPassword())
            .defaultSchema("workflow_hub")
            .schemas("workflow_hub");
    if (target != null) {
      config.target(target);
    }
    return config.load();
  }
}
