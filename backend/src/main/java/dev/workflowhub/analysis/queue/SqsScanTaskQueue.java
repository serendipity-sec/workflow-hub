package dev.workflowhub.analysis.queue;

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
    sqs.sendMessage(SendMessageRequest.builder().queueUrl(queueUrl).messageBody(body).build());
  }
}
