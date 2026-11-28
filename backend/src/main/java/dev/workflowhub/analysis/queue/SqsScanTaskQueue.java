package dev.workflowhub.analysis.queue;

import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import tools.jackson.databind.json.JsonMapper;

/** AWS SQS로 보안 검사 작업 메시지를 발행한다. 큐 URL이 비어 있으면 기동 시 실패한다. */
public class SqsScanTaskQueue implements ScanTaskQueue {
  private final SqsClient sqs;
  private final String queueUrl;
  private final JsonMapper mapper;

  public SqsScanTaskQueue(SqsClient sqs, String queueUrl, JsonMapper mapper) {
    if (queueUrl == null || queueUrl.isBlank()) {
      throw new IllegalArgumentException("SCAN_QUEUE_URL must be set");
    }
    this.sqs = sqs;
    this.queueUrl = queueUrl;
    this.mapper = mapper;
  }

  @Override
  public void enqueue(ScanTaskMessage message) {
    String body = mapper.writeValueAsString(message);
    try {
      sqs.sendMessage(SendMessageRequest.builder().queueUrl(queueUrl).messageBody(body).build());
    } catch (AwsServiceException e) {
      // 4xx(권한·큐 없음·스로틀링·요청 오류)는 SQS가 요청을 받아들이지 않은 응답이다. SDK가 이 호출 안에서 재시도했다면 앞선 시도가 시간 초과
      // 뒤 메시지를 넣었을 수 있으므로 첫 시도의 4xx만 명확한 거부로 본다. 5xx와 클라이언트 측 실패(시간 초과·연결 끊김)도 결과 불명이다.
      Integer attempts = e.numAttempts();
      if (e.statusCode() >= 400 && e.statusCode() < 500 && attempts != null && attempts == 1) {
        throw new ScanDispatchRejectedException("SQS rejected the scan task message", e);
      }
      throw e;
    }
  }
}
