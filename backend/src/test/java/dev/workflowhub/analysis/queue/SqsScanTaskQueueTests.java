package dev.workflowhub.analysis.queue;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
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
}
