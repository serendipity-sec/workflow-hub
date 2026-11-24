package dev.workflowhub.workflow.storage;

import java.util.OptionalLong;

/** 원본 워크플로 파일의 비공개 저장소. 저장한 객체는 덮어쓰지 않는다. */
public interface WorkflowObjectStore {
  /** 새 키로 저장한다. 같은 키가 있으면 덮어쓰지 말고 실패해야 한다. */
  void put(String key, byte[] content);

  byte[] get(String key);

  /**
   * 객체 크기(바이트)를 본문을 읽지 않고 확인한다. 객체가 없으면 빈 값이다. 확인하지 못하면(권한·네트워크 오류 포함) 예외를 던진다. 없다는 답은 복구를 거절하는
   * 근거로만 쓰이며, 호출하는 쪽은 그 답으로 행을 바꾸지 않는다.
   */
  OptionalLong size(String key);

  /** 객체를 완전히 삭제한다. 어떤 버전도 참조하지 않는 객체이거나 삭제 기한이 지난 버전의 객체를 정리할 때만 쓴다. */
  void delete(String key);
}
