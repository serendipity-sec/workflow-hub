package dev.workflowhub.analysis.service;

import dev.workflowhub.analysis.queue.ScanDispatchRejectedException;
import dev.workflowhub.analysis.queue.ScanTaskMessage;
import dev.workflowhub.analysis.queue.ScanTaskQueue;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;

/**
 * 보안 검사 작업을 SQS에 발행하고 발행 성공을 시도 행(dispatched_at)에 기록한다.
 *
 * <p>발행에 실패해도 시도 상태는 바꾸지 않는다. 발행이 확인되지 않은 queued 시도는 {@link ScanLeaseRecovery}가 재발행 간격 뒤 같은
 * attemptId로 다시 발행하고, 대기 제한 시간이 지나면 다음 시도로 넘기거나 timed_out으로 마감한다.
 */
@Service
public class ScanTaskDispatcher {
  private static final Logger log = LoggerFactory.getLogger(ScanTaskDispatcher.class);
  private static final int CONFIRM_ATTEMPTS = 2;

  private final ScanTaskQueue queue;
  private final JdbcClient jdbc;

  public ScanTaskDispatcher(ScanTaskQueue queue, JdbcClient jdbc) {
    this.queue = queue;
    this.jdbc = jdbc;
  }

  /** 발행 결과. REJECTED는 메시지가 들어가지 않았음이 확실한 거부, UNKNOWN은 메시지가 이미 큐에 있을 수 있는 실패다. */
  public enum Outcome {
    SENT,
    REJECTED,
    UNKNOWN
  }

  /** 호출하는 쪽의 트랜잭션 밖에서 호출한다. */
  public Outcome dispatch(ScanTaskMessage message, String source) {
    try {
      queue.enqueue(message);
    } catch (RuntimeException e) {
      Outcome outcome =
          e instanceof ScanDispatchRejectedException ? Outcome.REJECTED : Outcome.UNKNOWN;
      log.error(
          "event=analysis.dispatch.failed source={} outcome={} taskId={} scanRunId={} attemptId={} attemptNumber={}",
          source,
          outcome,
          message.taskId(),
          message.scanRunId(),
          message.attemptId(),
          message.attemptNumber(),
          e);
      return outcome;
    }
    // 발행은 성공했다. 기록이 남지 않으면 회수기가 같은 시도를 한 번 더 발행할 수 있어(워커의 두 번째 다운로드는 409)
    // 일시적인 DB 오류에 대비해 한 번 더 기록한다.
    for (int attempt = 1; attempt <= CONFIRM_ATTEMPTS; attempt++) {
      try {
        confirm(message);
        return Outcome.SENT;
      } catch (RuntimeException e) {
        log.error(
            "event=analysis.dispatch.confirm_failed source={} taskId={} attemptId={} confirmAttempt={}",
            source,
            message.taskId(),
            message.attemptId(),
            attempt,
            e);
      }
    }
    return Outcome.SENT;
  }

  private void confirm(ScanTaskMessage message) {
    jdbc.sql(
            """
            UPDATE workflow_hub.analysis_job_attempts
            SET dispatched_at = clock_timestamp()
            WHERE id = :attemptId AND dispatched_at IS NULL
            """)
        .param("attemptId", message.attemptId())
        .update();
  }
}
