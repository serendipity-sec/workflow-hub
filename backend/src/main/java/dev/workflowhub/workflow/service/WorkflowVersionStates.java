package dev.workflowhub.workflow.service;

/** 삭제한 버전의 상태 판정을 한곳에 둔다. 목록 조회와 복구가 같은 규칙을 써야 목록에 보이는 항목을 복구가 거절하지 않는다. */
final class WorkflowVersionStates {
  private WorkflowVersionStates() {}

  /**
   * 삭제된 뒤 복구 기간 안에 있고 원본 정리가 시작되지 않은 workflow_versions 행의 조건식. 컬럼마다 alias를 붙여 workflows의 같은 이름
   * 컬럼(deleted_at)과 섞이지 않게 한다. 시각은 문장 시작 시각으로 고정해 한 쿼리 안의 여러 조건이 같은 기준을 쓴다. DB 상태만 보는 복구 후보 조건이므로
   * 저장소에 원본이 있는지는 확인하지 않으며, 복구 요청이 그것을 확인해 거절할 수 있다.
   */
  static String restorable(String alias) {
    return "%1$s.deleted_at IS NOT NULL AND %1$s.purged_at IS NULL".formatted(alias)
        + " AND %1$s.delete_started_at IS NULL AND %1$s.delete_after > statement_timestamp()"
            .formatted(alias);
  }
}
