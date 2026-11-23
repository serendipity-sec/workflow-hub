package dev.workflowhub.workflow.service;

import java.util.HashSet;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.StreamReadConstraints;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.exc.StreamConstraintsException;
import tools.jackson.core.json.JsonFactory;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * n8n 내보내기 JSON의 구조와 규모 한도를 검사한다. 노드·표현식은 실행하지 않고, 내용을 로그나 오류 메시지에 싣지 않는다.
 *
 * <p>최초 업로드와 버전 비교가 모두 이 검사를 지나므로 한도는 여기서만 적용한다.
 */
@Component
public class N8nWorkflowValidator {
  static final String LIMIT_EXCEEDED = "WORKFLOW_LIMIT_EXCEEDED";

  private final WorkflowLimits limits;
  private final JsonMapper mapper;

  public N8nWorkflowValidator(WorkflowLimits limits) {
    this.limits = limits;
    // 깊이는 트리를 만든 뒤가 아니라 파싱 중에 끊어야 깊은 입력이 자원을 쓰기 전에 거절된다.
    var constraints = StreamReadConstraints.builder().maxNestingDepth(limits.maxDepth()).build();
    this.mapper =
        JsonMapper.builder(JsonFactory.builder().streamReadConstraints(constraints).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();
  }

  public N8nWorkflow validate(byte[] content) {
    JsonNode name = parse(content).get("name");
    return new N8nWorkflow(name != null && name.isString() ? name.stringValue() : null);
  }

  JsonNode parse(byte[] content) {
    JsonNode root;
    try {
      root = mapper.readTree(content);
    } catch (StreamConstraintsException e) {
      // 문자열·이름 길이 같은 다른 제약도 같은 예외를 던지고 Jackson은 종류를 구분하는 타입을 주지 않는다.
      // 예외 문구에 기대지 않도록 실패한 경우에만 바이트의 괄호 깊이를 직접 세어 깊이 초과를 가린다.
      if (maxBracketDepth(content) > limits.maxDepth()) {
        throw limitExceeded("Workflow nesting depth exceeds the limit (" + limits.maxDepth() + ")");
      }
      throw invalid("File is not valid JSON");
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
    if (nodes.size() > limits.maxNodes()) {
      throw limitExceeded("Workflow node count exceeds the limit (" + limits.maxNodes() + ")");
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
    long connectionCount = 0;
    for (var source : connections.properties()) {
      if (!nodeNames.contains(source.getKey())) {
        throw invalid("Connections must reference existing nodes");
      }
      connectionCount += validateConnectionTypes(source.getValue(), nodeNames);
      if (connectionCount > limits.maxConnections()) {
        throw limitExceeded(
            "Workflow connection count exceeds the limit (" + limits.maxConnections() + ")");
      }
    }

    return root;
  }

  /** 대상 항목({@code {"node":...}}) 수를 돌려준다. 연결이 없는 null 출력은 세지 않는다. */
  private static int validateConnectionTypes(JsonNode byType, Set<String> nodeNames) {
    if (!byType.isObject()) {
      throw invalid("Connections must reference existing nodes");
    }
    int count = 0;
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
          count++;
        }
      }
    }
    return count;
  }

  /** 문자열 밖의 중괄호와 대괄호를 센 최대 중첩 깊이. UTF-8에서 따옴표와 역슬래시는 여러 바이트 문자의 일부가 될 수 없어 바이트 단위로 세어도 안전하다. */
  private static int maxBracketDepth(byte[] content) {
    int depth = 0;
    int max = 0;
    boolean inString = false;
    boolean escaped = false;
    for (byte b : content) {
      if (inString) {
        if (escaped) {
          escaped = false;
        } else if (b == '\\') {
          escaped = true;
        } else if (b == '"') {
          inString = false;
        }
      } else if (b == '"') {
        inString = true;
      } else if (b == '{' || b == '[') {
        max = Math.max(max, ++depth);
      } else if (b == '}' || b == ']') {
        depth--;
      }
    }
    return max;
  }

  private static boolean isNonBlankText(JsonNode value) {
    return value != null && value.isString() && !value.stringValue().isBlank();
  }

  private static WorkflowUploadException invalid(String message) {
    return new WorkflowUploadException(
        HttpStatus.UNPROCESSABLE_CONTENT, "INVALID_WORKFLOW", message);
  }

  /** 메시지에는 초과한 한도의 종류와 값만 싣고, 입력 내용은 싣지 않는다. */
  private static WorkflowUploadException limitExceeded(String message) {
    return new WorkflowUploadException(HttpStatus.UNPROCESSABLE_CONTENT, LIMIT_EXCEEDED, message);
  }

  /** 검증을 통과한 워크플로에서 서비스가 쓰는 값. name은 없을 수 있다. */
  public record N8nWorkflow(String name) {}
}
