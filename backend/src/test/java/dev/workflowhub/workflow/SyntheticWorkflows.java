package dev.workflowhub.workflow;

import java.nio.charset.StandardCharsets;

/** 규모 한도를 확인하는 테스트용 합성 n8n JSON. 실제 워크플로는 쓰지 않는다. */
public final class SyntheticWorkflows {
  private SyntheticWorkflows() {}

  /**
   * 노드 {@code nodes}개, 연결 {@code connections}개, 문서 깊이 {@code depth}인 워크플로.
   *
   * <p>문서 깊이는 루트 객체(1), nodes 배열(2), 노드 객체(3)에 첫 노드 parameters의 중첩이 더해진 값이라 depth는 4 이상이어야 한다. 연결은
   * 모두 첫 노드에서 첫 노드로 향하는 대상 항목으로 채운다. 연결이 하나라도 있으면 그 구조(루트, connections, 소스 노드, main 배열, 출력 배열, 대상
   * 객체)만으로 문서 깊이가 6이 되므로, 실제 깊이는 depth와 6 중 큰 값이다.
   */
  public static String json(int nodes, int connections, int depth) {
    var json = new StringBuilder("{\"name\":\"Synthetic\",\"nodes\":[");
    for (int i = 0; i < nodes; i++) {
      if (i > 0) {
        json.append(',');
      }
      json.append("{\"name\":\"N").append(i).append("\",\"type\":\"t\"");
      if (i == 0) {
        json.append(",\"parameters\":").append(nested(depth - 3));
      }
      json.append('}');
    }
    json.append("],\"connections\":{");
    if (connections > 0) {
      json.append("\"N0\":{\"main\":[[");
      for (int i = 0; i < connections; i++) {
        if (i > 0) {
          json.append(',');
        }
        json.append("{\"node\":\"N0\",\"type\":\"main\",\"index\":0}");
      }
      json.append("]]}");
    }
    return json.append("}}").toString();
  }

  public static byte[] bytes(int nodes, int connections, int depth) {
    return json(nodes, connections, depth).getBytes(StandardCharsets.UTF_8);
  }

  /** levels개 객체가 중첩된 값. */
  private static String nested(int levels) {
    return "{\"a\":".repeat(levels - 1) + "{}" + "}".repeat(levels - 1);
  }
}
