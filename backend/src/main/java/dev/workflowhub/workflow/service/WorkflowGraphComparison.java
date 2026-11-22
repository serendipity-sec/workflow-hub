package dev.workflowhub.workflow.service;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.function.Supplier;
import org.springframework.stereotype.Component;
import tools.jackson.databind.JsonNode;

@Component
public class WorkflowGraphComparison {
  private static final List<String> NODE_FIELDS =
      List.of(
          "name",
          "type",
          "typeVersion",
          "disabled",
          "credentials",
          "executeOnce",
          "alwaysOutputData",
          "retryOnFail",
          "maxTries",
          "waitBetweenTries",
          "onError",
          "continueOnFail",
          "webhookId");
  private static final String HTTP_REQUEST = "n8n-nodes-base.httpRequest";
  private static final Map<String, List<String>> PARAMETER_FIELDS =
      Map.of(
          HTTP_REQUEST,
          List.of(
              "method",
              "url",
              "authentication",
              "sendQuery",
              "queryParameters",
              "sendHeaders",
              "headerParameters",
              "jsonHeaders",
              "sendBody",
              "bodyParameters",
              "jsonBody",
              "options"),
          "n8n-nodes-base.slack",
          List.of("text", "blocksUi", "attachments"),
          "n8n-nodes-base.code",
          List.of("jsCode", "pythonCode"));
  private static final Set<String> HTTP_METHODS =
      Set.of("DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT");

  private final N8nWorkflowValidator validator;

  public WorkflowGraphComparison(N8nWorkflowValidator validator) {
    this.validator = validator;
  }

  public Result compare(byte[] base, byte[] candidate) {
    return compare(() -> base, candidate);
  }

  /** 수정본을 먼저 검증해, 잘못된 입력이 기준 파일 읽기(저장소 접근)를 일으키지 않게 한다. */
  public Result compare(Supplier<byte[]> base, byte[] candidate) {
    JsonNode candidateTree = validator.parse(candidate);
    JsonNode baseTree = validator.parse(base.get());

    Map<String, JsonNode> baseByName = nodesByName(baseTree);
    Map<String, JsonNode> candidateByName = nodesByName(candidateTree);
    Map<String, String> baseIds = uniqueIdsByName(baseByName);
    Map<String, String> candidateIds = uniqueIdsByName(candidateByName);
    Map<String, String> matchedNames =
        matchNodes(baseByName, candidateByName, baseIds, candidateIds);
    Map<String, String> baseGraphIds = new HashMap<>();
    Map<String, String> candidateGraphIds = new HashMap<>();
    List<Change> changes = new ArrayList<>();

    int nextNode = 1;
    for (String baseName : baseByName.keySet()) {
      String graphId = "n" + nextNode++;
      baseGraphIds.put(baseName, graphId);
      String candidateName = matchedNames.get(baseName);
      if (candidateName == null) {
        changes.add(new Change(ChangeKind.NODE_REMOVED, graphId, List.of()));
        continue;
      }
      candidateGraphIds.put(candidateName, graphId);
      List<FieldChange> fields =
          fieldChanges(baseByName.get(baseName), candidateByName.get(candidateName));
      if (!fields.isEmpty()) {
        changes.add(new Change(ChangeKind.NODE_MODIFIED, graphId, fields));
      }
    }
    for (String candidateName : candidateByName.keySet()) {
      if (!candidateGraphIds.containsKey(candidateName)) {
        String graphId = "n" + nextNode++;
        candidateGraphIds.put(candidateName, graphId);
        changes.add(new Change(ChangeKind.NODE_ADDED, graphId, List.of()));
      }
    }

    List<EdgeKey> baseEdges = edges(baseTree, baseGraphIds);
    List<EdgeKey> candidateEdges = edges(candidateTree, candidateGraphIds);
    List<Connection> baseConnections = new ArrayList<>();
    List<Connection> candidateConnections = new ArrayList<>();
    Map<EdgeKey, Deque<String>> availableIds = new HashMap<>();

    int nextEdge = 1;
    for (EdgeKey edge : baseEdges) {
      String id = "e" + nextEdge++;
      baseConnections.add(edge.connection(id));
      availableIds.computeIfAbsent(edge, ignored -> new ArrayDeque<>()).addLast(id);
    }
    Set<String> retainedEdges = new HashSet<>();
    for (EdgeKey edge : candidateEdges) {
      Deque<String> available = availableIds.get(edge);
      String matchedId = available == null ? null : available.pollFirst();
      if (matchedId == null) {
        String newId = "e" + nextEdge++;
        candidateConnections.add(edge.connection(newId));
        changes.add(new Change(ChangeKind.CONNECTION_ADDED, newId, List.of()));
      } else {
        candidateConnections.add(edge.connection(matchedId));
        retainedEdges.add(matchedId);
      }
    }
    for (Connection connection : baseConnections) {
      if (!retainedEdges.contains(connection.id())) {
        changes.add(new Change(ChangeKind.CONNECTION_REMOVED, connection.id(), List.of()));
      }
    }

    Graphs graphs =
        new Graphs(
            new Graph(graphNodes(baseByName, baseGraphIds), List.copyOf(baseConnections)),
            new Graph(
                graphNodes(candidateByName, candidateGraphIds), List.copyOf(candidateConnections)));
    return new Result(summarize(changes), graphs, List.copyOf(changes));
  }

  private static Map<String, JsonNode> nodesByName(JsonNode tree) {
    Map<String, JsonNode> byName = new LinkedHashMap<>();
    for (JsonNode node : tree.get("nodes")) {
      byName.put(node.get("name").stringValue(), node);
    }
    return byName;
  }

  private static Map<String, String> uniqueIdsByName(Map<String, JsonNode> nodes) {
    Map<String, String> byName = new HashMap<>();
    Set<String> seen = new HashSet<>();
    Set<String> duplicates = new HashSet<>();
    nodes.forEach(
        (name, node) -> {
          String id = nonBlankText(node.get("id"));
          if (id != null) {
            byName.put(name, id);
            if (!seen.add(id)) {
              duplicates.add(id);
            }
          }
        });
    byName.values().removeAll(duplicates);
    return byName;
  }

  private static Map<String, String> matchNodes(
      Map<String, JsonNode> baseByName,
      Map<String, JsonNode> candidateByName,
      Map<String, String> baseIds,
      Map<String, String> candidateIds) {
    Map<String, String> candidateNamesById = new HashMap<>();
    candidateIds.forEach((name, id) -> candidateNamesById.put(id, name));
    Map<String, String> matches = new HashMap<>();
    Set<String> matchedCandidates = new HashSet<>();

    baseIds.forEach(
        (baseName, id) -> {
          String candidateName = candidateNamesById.get(id);
          if (candidateName != null) {
            matches.put(baseName, candidateName);
            matchedCandidates.add(candidateName);
          }
        });
    for (String name : baseByName.keySet()) {
      if (!matches.containsKey(name)
          && !matchedCandidates.contains(name)
          && candidateByName.containsKey(name)
          && (!baseIds.containsKey(name) || !candidateIds.containsKey(name))) {
        matches.put(name, name);
      }
    }
    return matches;
  }

  private static List<Node> graphNodes(Map<String, JsonNode> byName, Map<String, String> ids) {
    List<Node> nodes = new ArrayList<>();
    byName.forEach(
        (name, node) ->
            nodes.add(
                new Node(
                    ids.get(name),
                    name,
                    node.get("type").stringValue(),
                    position(node.get("position")))));
    return List.copyOf(nodes);
  }

  private static Position position(JsonNode value) {
    if (value == null
        || !value.isArray()
        || value.size() != 2
        || !value.get(0).isNumber()
        || !value.get(1).isNumber()) {
      return null;
    }
    double x = value.get(0).doubleValue();
    double y = value.get(1).doubleValue();
    return Double.isFinite(x) && Double.isFinite(y) ? new Position(x, y) : null;
  }

  private static List<EdgeKey> edges(JsonNode tree, Map<String, String> graphIds) {
    List<EdgeKey> edges = new ArrayList<>();
    for (var source : tree.get("connections").properties()) {
      for (var byType : source.getValue().properties()) {
        JsonNode outputs = byType.getValue();
        for (int outputIndex = 0; outputIndex < outputs.size(); outputIndex++) {
          for (JsonNode target : outputs.get(outputIndex)) {
            JsonNode index = target.get("index");
            Integer inputIndex =
                index != null
                        && index.isIntegralNumber()
                        && index.canConvertToInt()
                        && index.intValue() >= 0
                    ? index.intValue()
                    : null;
            edges.add(
                new EdgeKey(
                    graphIds.get(source.getKey()),
                    graphIds.get(target.get("node").stringValue()),
                    byType.getKey(),
                    outputIndex,
                    nonBlankText(target.get("type")),
                    inputIndex));
          }
        }
      }
    }
    return edges;
  }

  private static List<FieldChange> fieldChanges(JsonNode base, JsonNode candidate) {
    List<FieldChange> fields = new ArrayList<>();
    for (String key : NODE_FIELDS) {
      JsonNode before = base.get(key);
      JsonNode after = candidate.get(key);
      if (!Objects.equals(before, after)) {
        if (key.equals("disabled")) {
          fields.add(new FieldChange("/disabled", booleanValue(before), booleanValue(after)));
        } else {
          fields.add(new FieldChange("/" + key, null, null));
        }
      }
    }
    compareParameters(base, candidate, fields);
    return List.copyOf(fields);
  }

  private static void compareParameters(
      JsonNode base, JsonNode candidate, List<FieldChange> fields) {
    JsonNode before = base.path("parameters");
    JsonNode after = candidate.path("parameters");
    if (before.equals(after)) {
      return;
    }
    String nodeType = base.get("type").stringValue();
    if (!nodeType.equals(candidate.get("type").stringValue())
        || !before.isObject()
        || !after.isObject()) {
      fields.add(new FieldChange("/parameters", null, null));
      return;
    }
    List<String> knownFields = PARAMETER_FIELDS.getOrDefault(nodeType, List.of());
    for (String key : knownFields) {
      JsonNode beforeValue = before.get(key);
      JsonNode afterValue = after.get(key);
      if (!Objects.equals(beforeValue, afterValue)) {
        fields.add(
            new FieldChange(
                "/parameters/" + key,
                visibleParameterValue(nodeType, key, beforeValue),
                visibleParameterValue(nodeType, key, afterValue)));
      }
    }
    // 사용자 정의 키는 값과 마찬가지로 민감할 수 있어 상위 경로만 기록한다.
    if (hasOtherParameterChanges(before, after, knownFields)
        || hasOtherParameterChanges(after, before, knownFields)) {
      fields.add(new FieldChange("/parameters", null, null));
    }
  }

  private static Object visibleParameterValue(String nodeType, String key, JsonNode value) {
    if (!HTTP_REQUEST.equals(nodeType)) {
      return null;
    }
    return switch (key) {
      case "method" -> safeHttpMethod(value);
      case "sendQuery", "sendHeaders", "sendBody" -> booleanValue(value);
      default -> null;
    };
  }

  private static boolean hasOtherParameterChanges(
      JsonNode before, JsonNode after, List<String> knownFields) {
    return before.properties().stream()
        .anyMatch(
            field ->
                !knownFields.contains(field.getKey())
                    && !Objects.equals(field.getValue(), after.get(field.getKey())));
  }

  private static Boolean booleanValue(JsonNode value) {
    return value != null && value.isBoolean() ? value.booleanValue() : null;
  }

  private static String safeHttpMethod(JsonNode value) {
    String method = nonBlankText(value);
    return method != null && HTTP_METHODS.contains(method) ? method : null;
  }

  private static String nonBlankText(JsonNode value) {
    return value != null && value.isString() && !value.stringValue().isBlank()
        ? value.stringValue()
        : null;
  }

  private static Summary summarize(List<Change> changes) {
    Map<ChangeKind, Integer> counts = new EnumMap<>(ChangeKind.class);
    for (Change change : changes) {
      counts.merge(change.kind(), 1, Integer::sum);
    }
    return new Summary(
        counts.getOrDefault(ChangeKind.NODE_ADDED, 0),
        counts.getOrDefault(ChangeKind.NODE_REMOVED, 0),
        counts.getOrDefault(ChangeKind.NODE_MODIFIED, 0),
        counts.getOrDefault(ChangeKind.CONNECTION_ADDED, 0),
        counts.getOrDefault(ChangeKind.CONNECTION_REMOVED, 0));
  }

  private record EdgeKey(
      String sourceId,
      String targetId,
      String sourceType,
      int outputIndex,
      String targetType,
      Integer inputIndex) {
    Connection connection(String id) {
      return new Connection(
          id, sourceId, targetId, sourceType, outputIndex, targetType, inputIndex);
    }
  }

  public record Result(Summary summary, Graphs graphs, List<Change> changes) {}

  public record Summary(
      int nodesAdded,
      int nodesRemoved,
      int nodesModified,
      int connectionsAdded,
      int connectionsRemoved) {}

  public record Graphs(Graph base, Graph candidate) {}

  public record Graph(List<Node> nodes, List<Connection> connections) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Node(String id, String label, String type, Position position) {}

  public record Position(double x, double y) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record Connection(
      String id,
      String sourceId,
      String targetId,
      String sourceType,
      int outputIndex,
      String targetType,
      Integer inputIndex) {}

  public enum ChangeKind {
    NODE_ADDED,
    NODE_REMOVED,
    NODE_MODIFIED,
    CONNECTION_ADDED,
    CONNECTION_REMOVED
  }

  public record Change(ChangeKind kind, String targetId, List<FieldChange> fields) {}

  @JsonInclude(JsonInclude.Include.NON_NULL)
  public record FieldChange(String path, Object before, Object after) {}
}
