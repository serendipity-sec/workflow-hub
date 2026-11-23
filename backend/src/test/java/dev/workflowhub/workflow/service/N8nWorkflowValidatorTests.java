package dev.workflowhub.workflow.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import dev.workflowhub.workflow.SyntheticWorkflows;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.assertj.core.api.AbstractThrowableAssert;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;

class N8nWorkflowValidatorTests {
  private final N8nWorkflowValidator validator = new N8nWorkflowValidator(WorkflowLimits.DEFAULTS);

  @Test
  void acceptsTheSyntheticContractExample() throws Exception {
    byte[] example =
        Files.readAllBytes(Path.of("src/test/resources/samples/minimal-workflow.json"));

    assertThat(validator.validate(example).name()).isEqualTo("Synthetic manual workflow");
  }

  @Test
  void acceptsConnectionsWithNullOutputsAndUnknownTopLevelFields() {
    String json =
        """
        {"nodes":[{"name":"A","type":"t"},{"name":"B","type":"t"}],
         "connections":{"A":{"main":[null,[{"node":"B","type":"main","index":0}]]}},
         "pinData":{},"meta":{"instanceId":"synthetic"},"extra":1}
        """;

    assertThat(validator.validate(bytes(json)).name()).isNull();
  }

  @ParameterizedTest
  @ValueSource(
      strings = {
        "",
        "not json",
        "[]",
        "\"text\"",
        "{}",
        "{\"nodes\":[],\"connections\":{}}",
        "{\"nodes\":{},\"connections\":{}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}]}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":[]}",
        "{\"nodes\":[{\"name\":\"A\"}],\"connections\":{}}",
        "{\"nodes\":[{\"type\":\"t\"}],\"connections\":{}}",
        "{\"nodes\":[{\"name\":\" \",\"type\":\"t\"}],\"connections\":{}}",
        "{\"nodes\":[\"A\"],\"connections\":{}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"},{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{\"Missing\":{\"main\":[]}}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{\"A\":{\"main\":[[{\"node\":\"Missing\"}]]}}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{\"A\":{\"main\":[[{}]]}}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{\"A\":[]}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{},\"connections\":{}}",
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}} trailing"
      })
  void rejectsInvalidWorkflows(String json) {
    assertThatThrownBy(() -> validator.validate(bytes(json)))
        .isInstanceOfSatisfying(
            WorkflowUploadException.class,
            e -> {
              assertThat(e.status()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
              assertThat(e.code()).isEqualTo("INVALID_WORKFLOW");
              // 오류 메시지에 업로드 내용이 섞이면 안 된다.
              assertThat(e.getMessage()).doesNotContain("trailing", "Missing");
            });
  }

  @Test
  void defaultLimitsAreDepth64Nodes300AndConnections1500() {
    assertThat(WorkflowLimits.DEFAULTS).isEqualTo(new WorkflowLimits(64, 300, 1500));
  }

  @Test
  void acceptsAFileExactlyAtEveryDefaultLimit() {
    String json = SyntheticWorkflows.json(300, 1500, 64);

    assertThat(validator.validate(bytes(json)).name()).isEqualTo("Synthetic");
  }

  @ParameterizedTest
  @CsvSource({
    "301, 1, 4, node count exceeds the limit (300)",
    "1, 1501, 4, connection count exceeds the limit (1500)",
    "1, 0, 65, nesting depth exceeds the limit (64)"
  })
  void rejectsAFileOneOverEachDefaultLimit(
      int nodes, int connections, int depth, String expectedMessage) {
    assertLimitExceeded(
            () -> validator.validate(bytes(SyntheticWorkflows.json(nodes, connections, depth))))
        .hasMessageContaining(expectedMessage);
  }

  @Test
  void usesTheConfiguredLimitsInsteadOfTheDefaults() {
    // 연결이 있는 워크플로의 문서 깊이는 구조상 6 이상이므로 깊이 한도는 그보다 크게 둔다.
    var small = new N8nWorkflowValidator(new WorkflowLimits(8, 2, 3));

    assertThat(small.validate(bytes(SyntheticWorkflows.json(2, 3, 8))).name())
        .isEqualTo("Synthetic");
    assertLimitExceeded(() -> small.validate(bytes(SyntheticWorkflows.json(3, 0, 4))))
        .hasMessageContaining("node count exceeds the limit (2)");
    assertLimitExceeded(() -> small.validate(bytes(SyntheticWorkflows.json(2, 4, 4))))
        .hasMessageContaining("connection count exceeds the limit (3)");
    assertLimitExceeded(() -> small.validate(bytes(SyntheticWorkflows.json(2, 0, 9))))
        .hasMessageContaining("nesting depth exceeds the limit (8)");
  }

  @Test
  void doesNotCountNullOutputsAsConnections() {
    var oneConnection = new N8nWorkflowValidator(new WorkflowLimits(64, 300, 1));
    String json =
        """
        {"nodes":[{"name":"A","type":"t"},{"name":"B","type":"t"}],
         "connections":{"A":{"main":[null,null,[{"node":"B","type":"main","index":0}],null]}}}
        """;

    oneConnection.validate(bytes(json));
  }

  @Test
  void rejectsAVeryDeepFileWhileParsingInsteadOfFailingWithAStackOverflow() {
    String json = "{\"a\":".repeat(100_000);

    assertLimitExceeded(() -> validator.validate(bytes(json)))
        .hasMessageContaining("nesting depth exceeds the limit (64)");
  }

  @Test
  void aStructuralErrorIsStillInvalidWorkflowNotALimitError() {
    // 한도 검사를 추가해도 구조 오류의 코드는 바뀌지 않는다.
    assertThatThrownBy(() -> validator.validate(bytes("{\"nodes\":[],\"connections\":{}}")))
        .isInstanceOfSatisfying(
            WorkflowUploadException.class, e -> assertThat(e.code()).isEqualTo("INVALID_WORKFLOW"));
  }

  @Test
  void limitErrorMessagesNeverContainTheFileContent() {
    var one = new N8nWorkflowValidator(new WorkflowLimits(64, 1, 1));
    String json =
        """
        {"nodes":[{"name":"secret-token-abc123","type":"t"},{"name":"other-secret","type":"t"}],
         "connections":{}}
        """;

    assertLimitExceeded(() -> one.validate(bytes(json)))
        .satisfies(e -> assertThat(e.getMessage()).doesNotContain("secret", "abc123"));
  }

  @ParameterizedTest
  @ValueSource(ints = {1, 5})
  void rejectsADepthLimitShallowerThanAnyWorkflowWithAConnection(int depth) {
    assertThatThrownBy(() -> new WorkflowLimits(depth, 300, 1500))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_MAX_DEPTH must be at least 6");
  }

  @Test
  void theShallowestAllowedDepthLimitStillAcceptsAWorkflowWithAConnection() {
    var shallowest = new N8nWorkflowValidator(new WorkflowLimits(6, 300, 1500));

    shallowest.validate(bytes(SyntheticWorkflows.json(1, 1, 6)));
    assertLimitExceeded(() -> shallowest.validate(bytes(SyntheticWorkflows.json(1, 1, 7))))
        .hasMessageContaining("nesting depth exceeds the limit (6)");
  }

  @Test
  void aPropertyNameOverTheParserLengthLimitIsInvalidJsonNotADepthError() {
    // Jackson은 깊이 외의 제약도 같은 예외로 알린다. 깊이가 한도 안이면 깊이 오류로 분류하면 안 된다.
    String json =
        "{\""
            + "a".repeat(60_000)
            + "\":1,\"nodes\":[{\"name\":\"A\",\"type\":\"t\"}],\"connections\":{}}";

    assertThatThrownBy(() -> validator.validate(bytes(json)))
        .isInstanceOfSatisfying(
            WorkflowUploadException.class, e -> assertThat(e.code()).isEqualTo("INVALID_WORKFLOW"));
  }

  @Test
  void bracketsInsideStringsDoNotCountAsDepth() {
    // 문자열 안의 괄호와 이스케이프된 따옴표는 깊이에 영향을 주지 않는다.
    String json =
        "{\"nodes\":[{\"name\":\"A\",\"type\":\"t\",\"parameters\":{\"text\":\""
            + "[[[[[[[[[[{{{{{{{{{{\\\"[[[[[[[[[[".repeat(20)
            + "\"}}],\"connections\":{}}";

    validator.validate(bytes(json));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, -1})
  void rejectsNonPositiveLimitsAtStartup(int value) {
    assertThatThrownBy(() -> new WorkflowLimits(value, 300, 1500))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_MAX_DEPTH");
    assertThatThrownBy(() -> new WorkflowLimits(64, value, 1500))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_MAX_NODES");
    assertThatThrownBy(() -> new WorkflowLimits(64, 300, value))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("WORKFLOW_MAX_CONNECTIONS");
  }

  private static AbstractThrowableAssert<?, ? extends Throwable> assertLimitExceeded(
      ThrowingCallable call) {
    return assertThatThrownBy(call)
        .isInstanceOfSatisfying(
            WorkflowUploadException.class,
            e -> {
              assertThat(e.status()).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
              assertThat(e.code()).isEqualTo("WORKFLOW_LIMIT_EXCEEDED");
            });
  }

  private static byte[] bytes(String json) {
    return json.getBytes(StandardCharsets.UTF_8);
  }
}
