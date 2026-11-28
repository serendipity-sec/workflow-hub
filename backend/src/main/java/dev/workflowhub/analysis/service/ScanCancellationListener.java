package dev.workflowhub.analysis.service;

import dev.workflowhub.common.events.WorkflowDeletionEvent;
import java.time.OffsetDateTime;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Component;

/**
 * 워크플로·버전 삭제 트랜잭션 안에서 진행 중(queued/running)인 보안 검사를 함께 cancelled로 전환한다.
 *
 * <p>WorkerTaskService·ScanLeaseRecovery와 같은 잠금 순서(analysis_jobs -> analysis_job_attempts ->
 * scan_runs)를 지켜 AB-BA 교착을 막는다.
 */
@Component
public class ScanCancellationListener {
  private static final Logger log = LoggerFactory.getLogger(ScanCancellationListener.class);
  private final JdbcClient jdbc;

  public ScanCancellationListener(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  @EventListener
  public void onWorkflowDeleted(WorkflowDeletionEvent.WorkflowDeleted event) {
    int cancelled = cancelForWorkflow(event.workflowId(), event.deletedAt());
    if (cancelled > 0) {
      log.info(
          "event=analysis.scan.cancelled_on_workflow_delete workflowId={} count={}",
          event.workflowId(),
          cancelled);
    }
  }

  @EventListener
  public void onWorkflowVersionDeleted(WorkflowDeletionEvent.WorkflowVersionDeleted event) {
    int cancelled = cancelForVersion(event.versionId(), event.deletedAt());
    if (cancelled > 0) {
      log.info(
          "event=analysis.scan.cancelled_on_version_delete workflowId={} versionId={} count={}",
          event.workflowId(),
          event.versionId(),
          cancelled);
    }
  }

  private int cancelForVersion(UUID versionId, OffsetDateTime now) {
    jdbc.sql(
            """
            WITH locked AS (
                SELECT id
                FROM workflow_hub.analysis_jobs
                WHERE workflow_version_id = :versionId
                  AND status IN ('queued', 'running')
                ORDER BY id
                FOR UPDATE
            )
            UPDATE workflow_hub.analysis_jobs j
            SET status = 'cancelled', lease_expires_at = NULL, updated_at = :now
            FROM locked
            WHERE j.id = locked.id
            """)
        .param("now", now)
        .param("versionId", versionId)
        .update();
    jdbc.sql(
            """
            UPDATE workflow_hub.analysis_job_attempts a
            SET status = 'cancelled', lease_expires_at = NULL, finished_at = :now
            FROM workflow_hub.analysis_jobs j
            WHERE a.job_id = j.id
              AND j.workflow_version_id = :versionId
              AND a.status IN ('queued', 'running')
            """)
        .param("now", now)
        .param("versionId", versionId)
        .update();
    return jdbc.sql(
            """
            UPDATE workflow_hub.scan_runs
            SET execution_status = 'cancelled', analysis_coverage = 'unknown', finished_at = :now
            WHERE workflow_version_id = :versionId
              AND execution_status IN ('queued', 'running')
            """)
        .param("now", now)
        .param("versionId", versionId)
        .update();
  }

  private int cancelForWorkflow(UUID workflowId, OffsetDateTime now) {
    jdbc.sql(
            """
            WITH locked AS (
                SELECT j.id
                FROM workflow_hub.analysis_jobs j
                JOIN workflow_hub.scan_runs s ON s.id = j.scan_run_id
                WHERE s.workflow_id = :workflowId
                  AND j.status IN ('queued', 'running')
                ORDER BY j.id
                FOR UPDATE OF j
            )
            UPDATE workflow_hub.analysis_jobs j
            SET status = 'cancelled', lease_expires_at = NULL, updated_at = :now
            FROM locked
            WHERE j.id = locked.id
            """)
        .param("now", now)
        .param("workflowId", workflowId)
        .update();
    jdbc.sql(
            """
            UPDATE workflow_hub.analysis_job_attempts a
            SET status = 'cancelled', lease_expires_at = NULL, finished_at = :now
            FROM workflow_hub.analysis_jobs j
            JOIN workflow_hub.scan_runs s ON s.id = j.scan_run_id
            WHERE a.job_id = j.id
              AND s.workflow_id = :workflowId
              AND a.status IN ('queued', 'running')
            """)
        .param("now", now)
        .param("workflowId", workflowId)
        .update();
    return jdbc.sql(
            """
            UPDATE workflow_hub.scan_runs
            SET execution_status = 'cancelled', analysis_coverage = 'unknown', finished_at = :now
            WHERE workflow_id = :workflowId
              AND execution_status IN ('queued', 'running')
            """)
        .param("now", now)
        .param("workflowId", workflowId)
        .update();
  }
}
