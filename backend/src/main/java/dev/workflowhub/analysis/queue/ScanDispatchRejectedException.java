package dev.workflowhub.analysis.queue;

/**
 * 큐가 발행 요청을 명확히 거부해 메시지가 들어가지 않았음이 확실할 때 던진다. 그 밖의 예외(시간 초과·연결 끊김 등)는 메시지가 이미 큐에 들어갔을 수 있는 결과 불명
 * 실패로 취급한다.
 */
public class ScanDispatchRejectedException extends RuntimeException {
  public ScanDispatchRejectedException(String message, Throwable cause) {
    super(message, cause);
  }
}
