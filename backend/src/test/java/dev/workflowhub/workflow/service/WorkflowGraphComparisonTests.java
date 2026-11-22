package dev.workflowhub.workflow.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.workflowhub.workflow.service.WorkflowGraphComparison.ChangeKind;
import dev.workflowhub.workflow.service.WorkflowGraphComparison.FieldChange;
import dev.workflowhub.workflow.service.WorkflowGraphComparison.Node;
import dev.workflowhub.workflow.service.WorkflowGraphComparison.Summary;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import tools.jackson.databind.json.JsonMapper;

class WorkflowGraphComparisonTests {
  private final WorkflowGraphComparison comparison =
      new WorkflowGraphComparison(new N8nWorkflowValidator());

  @Test
  void keepsConnectionsAcrossRenamesAndReportsBranchAndPortChanges() {
    var result =
        compare(
            """
            {"nodes":[{"name":"Switch","id":"stable","type":"t","position":[2,-10.5]},
                      {"name":"Target","type":"t"}],
             "connections":{"Switch":{"main":[null,[{"node":"Target","type":"aux","index":2}]],
               "aux":[[{"node":"Target","type":"aux","index":0}]]}}}
            """,
            """
            {"nodes":[{"name":"Target","type":"t"},
                      {"name":"Renamed","id":"stable","type":"t","position":[2,9]}],
             "connections":{"Renamed":{"main":[null,[{"node":"Target","type":"aux","index":2}]],
               "aux":[[{"node":"Target","type":"main","index":1}]]}}}
            """);

    assertThat(result.summary()).isEqualTo(new Summary(0, 0, 1, 1, 1));
    var baseNode = result.graphs().base().nodes().getFirst();
    assertThat(baseNode.position().y()).isEqualTo(-10.5);
    assertThat(result.graphs().candidate().nodes().getLast().id()).isEqualTo(baseNode.id());

    var baseConnection = result.graphs().base().connections().getFirst();
    assertThat(baseConnection.sourceId()).isEqualTo(baseNode.id());
    assertThat(baseConnection.sourceType()).isEqualTo("main");
    assertThat(baseConnection.outputIndex()).isEqualTo(1);
    assertThat(baseConnection.targetType()).isEqualTo("aux");
    assertThat(baseConnection.inputIndex()).isEqualTo(2);
    assertThat(result.graphs().candidate().connections().getFirst()).isEqualTo(baseConnection);
    assertThat(result.changes())
        .anySatisfy(
            change -> {
              assertThat(change.kind()).isEqualTo(ChangeKind.NODE_MODIFIED);
              assertThat(change.targetId()).isEqualTo(baseNode.id());
              assertThat(change.fields()).containsExactly(new FieldChange("/name", null, null));
            });
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        """
        {"main":[null,[{"node":"A","type":"main","index":0}]]}
        """,
        """
        {"aux":[[{"node":"A","type":"main","index":0}]]}
        """,
        """
        {"main":[[{"node":"A","type":"aux","index":0}]]}
        """,
        """
        {"main":[[{"node":"A","type":"main","index":1}]]}
        """
      })
  void treatsEachConnectionTypeAndPortAsPartOfTheEdgeIdentity(String candidateEdges) {
    String workflow =
        """
        {"nodes":[{"name":"A","type":"t"}],"connections":{"A":%s}}
        """;
    var result =
        compare(
            workflow.formatted(
                """
                {"main":[[{"node":"A","type":"main","index":0}]]}
                """),
            workflow.formatted(candidateEdges));

    assertThat(result.summary()).isEqualTo(new Summary(0, 0, 0, 1, 1));
    assertThat(result.graphs().base().connections().getFirst().id())
        .isNotEqualTo(result.graphs().candidate().connections().getFirst().id());
  }

  @Test
  void appliesIdMatchesBeforeNameFallbackAndTreatsDistinctUsableIdsAsReplacements() {
    var result =
        compare(
            """
            {"nodes":[{"name":"Fallback","type":"t"},{"name":"Old","id":"stable","type":"t"},
                      {"name":"Duplicate","id":"dupe","type":"t"},
                      {"name":"DuplicateSister","id":"dupe","type":"t"},
                      {"name":"Replaced","id":"before","type":"t"}],"connections":{}}
            """,
            """
            {"nodes":[{"name":"Fallback","id":"stable","type":"t"},
                      {"name":"Duplicate","id":"dupe","type":"t"},
                      {"name":"DuplicateSister","id":" ","type":"t"},
                      {"name":"Replaced","id":"after","type":"t"}],"connections":{}}
            """);

    assertThat(result.summary()).isEqualTo(new Summary(1, 2, 1, 0, 0));
    var before = result.graphs().base().nodes();
    var after = result.graphs().candidate().nodes();
    assertThat(after)
        .extracting(Node::id)
        .containsExactly(
            before.get(1).id(),
            before.get(2).id(),
            before.get(3).id(),
            result.changes().stream()
                .filter(change -> change.kind() == ChangeKind.NODE_ADDED)
                .findFirst()
                .orElseThrow()
                .targetId());
    assertThat(after.getLast().id()).isNotEqualTo(before.getLast().id());
  }

  @Test
  void reportsSafeSettingPathsWithoutSerializingPrivateValuesOrDynamicKeys() {
    var result =
        compare(
            """
            {"nodes":[{"name":"HTTP","type":"n8n-nodes-base.httpRequest","disabled":false,
                 "parameters":{"method":"GET","url":"synthetic-private-url-one","privateKeyOne":1},
                 "credentials":{"privateCredentialOne":{"id":"synthetic-private-id-one"}}}],
             "connections":{}}
            """,
            """
            {"nodes":[{"name":"HTTP","type":"n8n-nodes-base.httpRequest","disabled":true,
                 "parameters":{"method":"POST","url":"synthetic-private-url-two","privateKeyTwo":2},
                 "credentials":{"privateCredentialTwo":{"id":"synthetic-private-id-two"}}}],
             "connections":{}}
            """);

    assertThat(result.summary()).isEqualTo(new Summary(0, 0, 1, 0, 0));
    assertThat(result.changes().getFirst().fields())
        .containsExactlyInAnyOrder(
            new FieldChange("/disabled", false, true),
            new FieldChange("/parameters/method", "GET", "POST"),
            new FieldChange("/parameters/url", null, null),
            new FieldChange("/parameters", null, null),
            new FieldChange("/credentials", null, null));

    var payload = JsonMapper.builder().build().writeValueAsString(result);
    assertThat(payload).doesNotContain("synthetic-private", "privateKey", "privateCredential");
  }

  @Test
  void doesNotReturnEnumLikeValuesForUnrelatedNodeTypes() {
    var result =
        compare(
            """
            {"nodes":[{"name":"Node","type":"t","parameters":{"method":"GET"}}],"connections":{}}
            """,
            """
            {"nodes":[{"name":"Node","type":"t","parameters":{"method":"POST"}}],"connections":{}}
            """);

    assertThat(result.changes().getFirst().fields())
        .containsExactly(new FieldChange("/parameters", null, null));
  }

  @ParameterizedTest
  @CsvSource({
    "n8n-nodes-base.slack, text",
    "n8n-nodes-base.slack, blocksUi",
    "n8n-nodes-base.slack, attachments",
    "n8n-nodes-base.code, jsCode",
    "n8n-nodes-base.code, pythonCode"
  })
  void identifiesKnownMessageAndCodeSettingsWithoutTheirValues(String type, String field) {
    String workflow =
        """
        {"nodes":[{"name":"Node","type":"%s",
                    "parameters":{"%s":"synthetic-private-%s","unknown-%s":1}}],"connections":{}}
        """;
    var result =
        compare(
            workflow.formatted(type, field, "base", "base"),
            workflow.formatted(type, field, "candidate", "candidate"));

    assertThat(result.changes().getFirst().fields())
        .containsExactly(
            new FieldChange("/parameters/" + field, null, null),
            new FieldChange("/parameters", null, null));
    assertThat(JsonMapper.builder().build().writeValueAsString(result))
        .doesNotContain("synthetic-private", "unknown-");
  }

  @Test
  void reportsOnlyStrictBooleanValuesForHttpSwitchesAndHidesJsonHeaders() {
    String workflow =
        """
        {"nodes":[{"name":"HTTP","type":"n8n-nodes-base.httpRequest","parameters":%s}],
         "connections":{}}
        """;
    var result =
        compare(
            workflow.formatted(
                """
                {"sendQuery":false,"sendHeaders":true,"sendBody":"synthetic-private-value",
                 "jsonHeaders":"synthetic-private-base"}
                """),
            workflow.formatted(
                """
                {"sendQuery":true,"sendHeaders":false,"sendBody":true,
                 "jsonHeaders":"synthetic-private-candidate"}
                """));

    assertThat(result.changes().getFirst().fields())
        .containsExactlyInAnyOrder(
            new FieldChange("/parameters/sendQuery", false, true),
            new FieldChange("/parameters/sendHeaders", true, false),
            new FieldChange("/parameters/sendBody", null, true),
            new FieldChange("/parameters/jsonHeaders", null, null));
    assertThat(JsonMapper.builder().build().writeValueAsString(result))
        .doesNotContain("synthetic-private");
  }

  @Test
  void omitsInvalidBooleanAndMethodValuesFromTheResponse() {
    var result =
        compare(
            """
            {"nodes":[{"name":"HTTP","type":"n8n-nodes-base.httpRequest",
                 "disabled":"synthetic-private-setting-one","parameters":{"method":"GET"}}],
             "connections":{}}
            """,
            """
            {"nodes":[{"name":"HTTP","type":"n8n-nodes-base.httpRequest",
                 "disabled":true,"parameters":{"method":"synthetic-private-setting-two"}}],
             "connections":{}}
            """);

    var output =
        JsonMapper.builder().build().valueToTree(result).get("changes").get(0).get("fields");
    assertThat(output.get(0).has("before")).isFalse();
    assertThat(output.get(0).get("after").booleanValue()).isTrue();
    assertThat(output.get(1).get("before").stringValue()).isEqualTo("GET");
    assertThat(output.get(1).has("after")).isFalse();
    assertThat(output.toString()).doesNotContain("synthetic-private-setting");
  }

  @Test
  void handlesLegacyEdgeMetadataAndCountsDuplicateConnectionsSeparately() {
    var result =
        compare(
            """
            {"nodes":[{"name":"Legacy","type":"t","position":[1,"invalid"]}],
             "connections":{"Legacy":{"main":[[{"node":"Legacy"}, {"node":"Legacy"}]]}}}
            """,
            """
            {"nodes":[{"name":"Legacy","type":"t","position":[1,2]}],
             "connections":{"Legacy":{"main":[[{"node":"Legacy","type":false,"index":-1}]]}}}
            """);

    assertThat(result.summary()).isEqualTo(new Summary(0, 0, 0, 0, 1));
    assertThat(result.graphs().base().nodes().getFirst().position()).isNull();
    assertThat(result.graphs().candidate().connections().getFirst())
        .isEqualTo(result.graphs().base().connections().getFirst())
        .satisfies(
            connection -> {
              assertThat(connection.targetType()).isNull();
              assertThat(connection.inputIndex()).isNull();
            });
    assertThat(result.changes().getFirst().targetId())
        .isEqualTo(result.graphs().base().connections().getLast().id());
  }

  @Test
  void appliesUploadValidationToBothInputs() {
    String valid =
        """
        {"nodes":[{"name":"A","type":"t"}],"connections":{}}
        """;
    String invalid =
        """
        {"nodes":[{"name":"A","type":"t"}],"connections":{"A":{"main":[[{"node":"Missing"}]]}}}
        """;

    assertThatThrownBy(() -> compare(valid, invalid)).isInstanceOf(WorkflowUploadException.class);
    assertThatThrownBy(() -> compare(invalid, valid)).isInstanceOf(WorkflowUploadException.class);
  }

  @ParameterizedTest
  @ValueSource(strings = {"notes", "notesInFlow"})
  void reportsOnlyThePathWhenNodeNoteSettingsChange(String field) {
    String base = "{\"name\":\"A\",\"type\":\"t\",\"%s\":%s}";
    String before = field.equals("notes") ? "\"synthetic-private-note-one\"" : "false";
    String after = field.equals("notes") ? "\"synthetic-private-note-two\"" : "true";

    var result =
        compare(
            "{\"nodes\":[" + base.formatted(field, before) + "],\"connections\":{}}",
            "{\"nodes\":[" + base.formatted(field, after) + "],\"connections\":{}}");

    assertThat(result.summary()).isEqualTo(new Summary(0, 0, 1, 0, 0));
    assertThat(result.changes().getFirst().fields())
        .containsExactly(new FieldChange("/" + field, null, null));
    assertThat(JsonMapper.builder().build().writeValueAsString(result))
        .doesNotContain("synthetic-private");
  }

  private WorkflowGraphComparison.Result compare(String base, String candidate) {
    return comparison.compare(
        base.getBytes(StandardCharsets.UTF_8), candidate.getBytes(StandardCharsets.UTF_8));
  }
}
