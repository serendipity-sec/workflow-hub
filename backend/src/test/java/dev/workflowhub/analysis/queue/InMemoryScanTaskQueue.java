package dev.workflowhub.analysis.queue;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/** 테스트용 SQS 작업 큐 대역. 실제 AWS SQS 동작은 검증하지 못한다. */
public class InMemoryScanTaskQueue implements ScanTaskQueue {
  private final List<ScanTaskMessage> messages = new CopyOnWriteArrayList<>();
  public volatile boolean failEnqueue;

  /** 다음 enqueue 시작 시 한 번만 실행한다. 발행 응답을 기다리는 사이 다른 작업이 끼어드는 상황을 만든다. */
  public volatile Runnable beforeEnqueue;

  @Override
  public void enqueue(ScanTaskMessage message) {
    Runnable hook = beforeEnqueue;
    beforeEnqueue = null;
    if (hook != null) {
      hook.run();
    }
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
    beforeEnqueue = null;
  }
}
