package dev.workflowhub.workflow.storage;

import java.util.Map;
import java.util.OptionalLong;
import java.util.concurrent.ConcurrentHashMap;

/** 테스트용 S3 대역. 실제 S3의 동작은 검증하지 못한다. */
public class InMemoryWorkflowObjectStore implements WorkflowObjectStore {
  private final Map<String, byte[]> objects = new ConcurrentHashMap<>();
  public volatile boolean failPuts;
  public volatile boolean failDeletes;
  public volatile boolean failSizes;

  /** put이 끝난 직후 실행한다. 저장과 커밋 사이에 다른 작업이 끼어드는 상황을 만든다. */
  public volatile Runnable afterPut;

  @Override
  public void put(String key, byte[] content) {
    if (failPuts) {
      throw new IllegalStateException("simulated put failure");
    }
    if (objects.putIfAbsent(key, content.clone()) != null) {
      throw new IllegalStateException("object already exists");
    }
    Runnable hook = afterPut;
    if (hook != null) {
      hook.run();
    }
  }

  @Override
  public byte[] get(String key) {
    byte[] content = objects.get(key);
    if (content == null) {
      throw new IllegalStateException("object does not exist");
    }
    return content.clone();
  }

  @Override
  public OptionalLong size(String key) {
    if (failSizes) {
      throw new IllegalStateException("simulated size failure");
    }
    byte[] content = objects.get(key);
    return content == null ? OptionalLong.empty() : OptionalLong.of(content.length);
  }

  @Override
  public void delete(String key) {
    if (failDeletes) {
      throw new IllegalStateException("simulated delete failure");
    }
    objects.remove(key);
  }

  public Map<String, byte[]> objects() {
    return objects;
  }

  public void reset() {
    objects.clear();
    failPuts = false;
    failDeletes = false;
    failSizes = false;
    afterPut = null;
  }
}
