package dev.workflowhub.workflow.service;

/**
 * 업로드·비교가 받아들이는 n8n JSON의 구조 한도. 한도에 도달한 입력은 통과하고 초과한 입력만 거절한다.
 *
 * <p>깊이는 루트 객체를 1로 센 배열·객체 중첩 수, 노드 수는 {@code nodes} 배열 길이, 연결 수는 {@code connections} 아래 대상
 * 항목({@code {"node":...}})의 총 개수다. 값은 환경 변수로 바꾸며 기본값의 근거는 docs/INPUT_LIMITS.md에 있다.
 */
public record WorkflowLimits(int maxDepth, int maxNodes, int maxConnections) {
  /**
   * 연결이 하나라도 있는 워크플로의 문서 깊이(루트, connections, 소스 노드, main 배열, 출력 배열, 대상 객체). 이보다 낮은 깊이 한도는 연결이 있는 모든
   * 파일을 거절한다.
   */
  static final int MIN_DEPTH = 6;

  public static final WorkflowLimits DEFAULTS = new WorkflowLimits(64, 300, 1500);

  /** 잘못된 값은 시작 단계에서 실패시켜, 배포 뒤 사용자 요청에서야 알게 되는 일을 막는다. */
  public WorkflowLimits {
    if (maxDepth < MIN_DEPTH) {
      throw new IllegalArgumentException(
          "WORKFLOW_MAX_DEPTH must be at least "
              + MIN_DEPTH
              + " because a workflow with a connection is at least that deep");
    }
    requirePositive("WORKFLOW_MAX_NODES", maxNodes);
    requirePositive("WORKFLOW_MAX_CONNECTIONS", maxConnections);
  }

  private static void requirePositive(String setting, int value) {
    if (value < 1) {
      throw new IllegalArgumentException(setting + " must be a positive integer");
    }
  }
}
