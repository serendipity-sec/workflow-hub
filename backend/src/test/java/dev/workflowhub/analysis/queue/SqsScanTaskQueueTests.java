package dev.workflowhub.analysis.queue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.core.exception.ApiCallTimeoutException;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SqsException;
import tools.jackson.databind.json.JsonMapper;

class SqsScanTaskQueueTests {
  private final JsonMapper mapper = JsonMapper.builder().build();

  @Test
  void requiresQueueUrlAtStartup() {
    SqsClient sqs = mock(SqsClient.class);
    assertThatThrownBy(() -> new SqsScanTaskQueue(sqs, "", mapper))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("SCAN_QUEUE_URL");
    assertThatThrownBy(() -> new SqsScanTaskQueue(sqs, "   ", mapper))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void sendsSerializedScanTaskMessageToConfiguredQueue() {
    SqsClient sqs = mock(SqsClient.class);
    var queue = new SqsScanTaskQueue(sqs, "https://sqs.example/queue", mapper);
    var message =
        new ScanTaskMessage(
            "1.0.0",
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "a".repeat(64),
            512,
            1,
            3,
            Instant.parse("2026-11-29T00:10:00Z"));

    queue.enqueue(message);

    var captor = ArgumentCaptor.forClass(SendMessageRequest.class);
    verify(sqs).sendMessage(captor.capture());
    assertThat(captor.getValue().queueUrl()).isEqualTo("https://sqs.example/queue");
    assertThat(captor.getValue().messageBody()).contains(message.taskId().toString());
    assertThat(captor.getValue().messageBody()).contains(message.inputSha256());
  }

  @Test
  void reportsOnlyClientErrorResponsesAsDefiniteRejections() {
    var message =
        new ScanTaskMessage(
            "1.0.0",
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            UUID.randomUUID(),
            "a".repeat(64),
            512,
            1,
            3,
            Instant.parse("2026-11-29T00:10:00Z"));

    SqsClient denied = mock(SqsClient.class);
    when(denied.sendMessage(any(SendMessageRequest.class)))
        .thenThrow(SqsException.builder().statusCode(403).message("denied").numAttempts(1).build());
    assertThatThrownBy(
            () -> new SqsScanTaskQueue(denied, "https://sqs.example/q", mapper).enqueue(message))
        .isInstanceOf(ScanDispatchRejectedException.class);

    // SDK가 재시도한 뒤의 4xx는 앞선 시도가 메시지를 넣었을 수 있으므로 결과 불명이다.
    SqsClient throttledAfterRetry = mock(SqsClient.class);
    when(throttledAfterRetry.sendMessage(any(SendMessageRequest.class)))
        .thenThrow(
            SqsException.builder().statusCode(400).message("throttled").numAttempts(3).build());
    assertThatThrownBy(
            () ->
                new SqsScanTaskQueue(throttledAfterRetry, "https://sqs.example/q", mapper)
                    .enqueue(message))
        .isInstanceOf(SqsException.class)
        .isNotInstanceOf(ScanDispatchRejectedException.class);

    // 시도 횟수를 알 수 없으면 거부로 단정하지 않는다.
    SqsClient unknownAttempts = mock(SqsClient.class);
    when(unknownAttempts.sendMessage(any(SendMessageRequest.class)))
        .thenThrow(SqsException.builder().statusCode(403).message("denied").build());
    assertThatThrownBy(
            () ->
                new SqsScanTaskQueue(unknownAttempts, "https://sqs.example/q", mapper)
                    .enqueue(message))
        .isInstanceOf(SqsException.class)
        .isNotInstanceOf(ScanDispatchRejectedException.class);

    SqsClient serverError = mock(SqsClient.class);
    when(serverError.sendMessage(any(SendMessageRequest.class)))
        .thenThrow(SqsException.builder().statusCode(500).message("internal").build());
    assertThatThrownBy(
            () ->
                new SqsScanTaskQueue(serverError, "https://sqs.example/q", mapper).enqueue(message))
        .isInstanceOf(SqsException.class)
        .isNotInstanceOf(ScanDispatchRejectedException.class);

    SqsClient timeout = mock(SqsClient.class);
    when(timeout.sendMessage(any(SendMessageRequest.class)))
        .thenThrow(ApiCallTimeoutException.builder().message("timeout").build());
    assertThatThrownBy(
            () -> new SqsScanTaskQueue(timeout, "https://sqs.example/q", mapper).enqueue(message))
        .isInstanceOf(ApiCallTimeoutException.class);
  }
}
