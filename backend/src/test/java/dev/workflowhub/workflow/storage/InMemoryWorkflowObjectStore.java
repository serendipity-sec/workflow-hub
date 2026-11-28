package dev.workflowhub.workflow.storage;

import java.util.Map;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/** 테스트용 S3 대역. 실제 S3의 동작은 검증하지 못한다. */
public class InMemoryWorkflowObjectStore implements WorkflowObjectStore {
  private final Map<String, byte[]> objects = new ConcurrentHashMap<>();
  public volatile boolean failPuts;
  public volatile boolean failDeletes;
  public volatile boolean failSizes;

  /** 이 키의 삭제만 실패시킨다. */
  public final Set<String> failDeleteKeys = ConcurrentHashMap.newKeySet();

  /** delete 호출 횟수(실패 포함). */
  public final AtomicInteger deleteCalls = new AtomicInteger();

  /** size가 끝난 직후 한 번만 실행한다. 복구가 S3를 확인하는 사이 다른 요청이 끼어드는 상황을 만든다. */
  public volatile Runnable afterSize;

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
    OptionalLong size = content == null ? OptionalLong.empty() : OptionalLong.of(content.length);
    Runnable hook = afterSize;
    afterSize = null;
    if (hook != null) {
      hook.run();
    }
    return size;
  }

  @Override
  public void delete(String key) {
    deleteCalls.incrementAndGet();
    if (failDeletes || failDeleteKeys.contains(key)) {
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
    failDeleteKeys.clear();
    deleteCalls.set(0);
    afterSize = null;
    afterPut = null;
  }
}
