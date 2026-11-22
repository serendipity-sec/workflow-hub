package dev.workflowhub.workflow.storage;

/** 원본 워크플로 파일의 비공개 저장소. 저장한 객체는 덮어쓰지 않는다. */
public interface WorkflowObjectStore {
  /** 새 키로 저장한다. 같은 키가 있으면 덮어쓰지 말고 실패해야 한다. */
  void put(String key, byte[] content);

  /** 객체를 완전히 삭제한다. 어떤 버전도 참조하지 않는 객체를 정리할 때만 쓴다. */
  void delete(String key);
}
