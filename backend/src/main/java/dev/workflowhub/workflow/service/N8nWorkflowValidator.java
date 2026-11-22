package dev.workflowhub.workflow.service;

import java.util.HashSet;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** n8n 내보내기 JSON의 구조만 검사한다. 노드·표현식은 실행하지 않고, 내용을 로그나 오류 메시지에 싣지 않는다. */
@Component
public class N8nWorkflowValidator {
  private final JsonMapper mapper =
      JsonMapper.builder()
          .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
          .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
          .build();

  public N8nWorkflow validate(byte[] content) {
    JsonNode root;
    try {
      root = mapper.readTree(content);
    } catch (JacksonException e) {
      throw invalid("File is not valid JSON");
    }
    if (root == null || !root.isObject()) {
      throw invalid("Workflow must be a JSON object");
    }

    JsonNode nodes = root.get("nodes");
    if (nodes == null || !nodes.isArray() || nodes.isEmpty()) {
      throw invalid("Workflow must have a non-empty nodes array");
    }
    Set<String> nodeNames = new HashSet<>();
    for (JsonNode node : nodes) {
      if (!node.isObject()
          || !isNonBlankText(node.get("name"))
          || !isNonBlankText(node.get("type"))) {
        throw invalid("Every node must have a text name and type");
      }
      if (!nodeNames.add(node.get("name").stringValue())) {
        throw invalid("Node names must be unique");
      }
    }

    JsonNode connections = root.get("connections");
    if (connections == null || !connections.isObject()) {
      throw invalid("Workflow must have a connections object");
    }
    for (var source : connections.properties()) {
      if (!nodeNames.contains(source.getKey())) {
        throw invalid("Connections must reference existing nodes");
      }
      validateConnectionTypes(source.getValue(), nodeNames);
    }

    JsonNode name = root.get("name");
    return new N8nWorkflow(name != null && name.isString() ? name.stringValue() : null);
  }

  private static void validateConnectionTypes(JsonNode byType, Set<String> nodeNames) {
    if (!byType.isObject()) {
      throw invalid("Connections must reference existing nodes");
    }
    for (JsonNode outputs : byType.values()) {
      if (!outputs.isArray()) {
        throw invalid("Connections must reference existing nodes");
      }
      for (JsonNode targets : outputs) {
        if (targets.isNull()) {
          continue; // n8n은 연결이 없는 출력을 null로 기록한다.
        }
        if (!targets.isArray()) {
          throw invalid("Connections must reference existing nodes");
        }
        for (JsonNode target : targets) {
          JsonNode node = target.isObject() ? target.get("node") : null;
          if (!isNonBlankText(node) || !nodeNames.contains(node.stringValue())) {
            throw invalid("Connections must reference existing nodes");
          }
        }
      }
    }
  }

  private static boolean isNonBlankText(JsonNode value) {
    return value != null && value.isString() && !value.stringValue().isBlank();
  }

  private static WorkflowUploadException invalid(String message) {
    return new WorkflowUploadException(
        HttpStatus.UNPROCESSABLE_CONTENT, "INVALID_WORKFLOW", message);
  }

  /** 검증을 통과한 워크플로에서 서비스가 쓰는 값. name은 없을 수 있다. */
  public record N8nWorkflow(String name) {}
}
