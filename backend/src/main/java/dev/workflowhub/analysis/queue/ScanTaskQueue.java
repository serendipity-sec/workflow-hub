package dev.workflowhub.analysis.queue;

/** 보안 검사 작업 메시지 발행 포트. 운영에서는 SQS 어댑터를 쓰고 테스트에서는 인메모리 대역을 쓴다. */
public interface ScanTaskQueue {
  void enqueue(ScanTaskMessage message);
}
