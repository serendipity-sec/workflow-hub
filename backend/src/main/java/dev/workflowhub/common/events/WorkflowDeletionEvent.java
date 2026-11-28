package dev.workflowhub.common.events;

import java.time.OffsetDateTime;
import java.util.UUID;

/** 워크플로·버전 삭제 트랜잭션 안에서 다른 도메인(보안 검사 등)이 함께 정리할 수 있도록 발행하는 도메인 이벤트. */
public sealed interface WorkflowDeletionEvent {
  UUID workflowId();

  OffsetDateTime deletedAt();

  record WorkflowDeleted(UUID workflowId, OffsetDateTime deletedAt)
      implements WorkflowDeletionEvent {}

  record WorkflowVersionDeleted(UUID workflowId, UUID versionId, OffsetDateTime deletedAt)
      implements WorkflowDeletionEvent {}
}
