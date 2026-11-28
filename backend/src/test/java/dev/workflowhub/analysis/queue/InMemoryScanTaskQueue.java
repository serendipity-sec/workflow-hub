package dev.workflowhub.analysis.queue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** 테스트용 SQS 작업 큐 대역. 실제 AWS SQS 동작은 검증하지 못한다. */
public class InMemoryScanTaskQueue implements ScanTaskQueue {
  private final List<ScanTaskMessage> messages = new CopyOnWriteArrayList<>();
  public volatile boolean failEnqueue;

  @Override
  public void enqueue(ScanTaskMessage message) {
    if (failEnqueue) {
      throw new IllegalStateException("simulated SQS dispatch failure");
    }
    messages.add(message);
  }

  public List<ScanTaskMessage> messages() {
    return List.copyOf(messages);
  }

  public ScanTaskMessage lastMessage() {
    return messages.getLast();
  }

  public void reset() {
    messages.clear();
    failEnqueue = false;
  }
}
