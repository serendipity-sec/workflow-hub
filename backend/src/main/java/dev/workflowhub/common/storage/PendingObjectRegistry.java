package dev.workflowhub.common.storage;

/**
 * S3에 쓰기 전에 남기는 정리 대상 기록(pending_objects) 계약. 여러 도메인이 같은 보호 규칙으로 비공개 객체를 저장할 때 쓴다.
 *
 * <p>기록은 S3에 쓰기 전에 요청 트랜잭션과 따로 커밋하고, 객체를 가리키는 행을 저장하는 트랜잭션 안에서 해제한다. 해제하지 못한 기록의 객체는 정리 작업이 참조 여부를
 * 확인한 뒤 지운다.
 */
public interface PendingObjectRegistry {
  /** S3에 쓰기 전에 호출한다. 요청 트랜잭션과 따로 커밋해야 롤백·재시작 뒤에도 남는다. */
  void recordPendingObject(String objectKey);

  /** 객체 참조를 저장하는 트랜잭션 안에서 호출한다. 정리 작업이 이미 삭제를 시작했거나 기록이 없으면 false다. */
  boolean releasePendingObject(String objectKey);

  /** 어떤 행도 참조하지 않는 것이 확인된 객체를 즉시 지운다. 실패하면 기록을 남겨 정리 작업이 이어받는다. 예외를 던지지 않는다. */
  void discardPendingObject(String objectKey);
}
