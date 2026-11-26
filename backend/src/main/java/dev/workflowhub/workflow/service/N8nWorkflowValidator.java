package dev.workflowhub.workflow.service;

import java.util.HashSet;
import java.util.Set;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.JsonToken;
import tools.jackson.core.ObjectReadContext;
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
  // 깊이 초과를 가리는 용도로만 쓰는 파서 공장. 본 파싱과 같은 인코딩 감지를 쓰되 깊이 제약만 푼다.
  private final JsonFactory depthProbe;

  public N8nWorkflowValidator(WorkflowLimits limits) {
    this.limits = limits;
    // 깊이는 트리를 만든 뒤가 아니라 파싱 중에 끊어야 깊은 입력이 자원을 쓰기 전에 거절된다.
    var constraints = StreamReadConstraints.builder().maxNestingDepth(limits.maxDepth()).build();
    this.mapper =
        JsonMapper.builder(JsonFactory.builder().streamReadConstraints(constraints).build())
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .build();
    this.depthProbe =
        JsonFactory.builder()
            .streamReadConstraints(
                StreamReadConstraints.builder().maxNestingDepth(Integer.MAX_VALUE).build())
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
      // 예외 문구에 기대지 않도록 실패한 경우에만 토큰을 따라가며 깊이 초과를 가린다.
      if (exceedsDepthLimit(content)) {
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

  /**
   * 토큰을 따라가며 중첩이 깊이 한도를 넘는지 본다. 원문 바이트를 직접 세지 않고 파서로 읽으므로 본 파싱과 같은 인코딩(UTF-8·UTF-16·UTF-32 자동 감지)으로
   * 해석하며, 문자열 안의 괄호와 이스케이프도 파서가 처리한다. 한도를 넘는 순간 멈추고, 그 전에 입력이 깨지면 깊이 초과가 아니다.
   */
  private boolean exceedsDepthLimit(byte[] content) {
    int depth = 0;
    try (JsonParser parser = depthProbe.createParser(ObjectReadContext.empty(), content)) {
      for (JsonToken token = parser.nextToken(); token != null; token = parser.nextToken()) {
        if (token.isStructStart()) {
          if (++depth > limits.maxDepth()) {
            return true;
          }
        } else if (token.isStructEnd()) {
          depth--;
        }
      }
    } catch (JacksonException e) {
      // 깊이에 닿기 전에 입력이 깨졌다.
    }
    return false;
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
