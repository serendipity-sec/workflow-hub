package dev.workflowhub.workflow.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;

class N8nWorkflowValidatorTests {
  private final N8nWorkflowValidator validator = new N8nWorkflowValidator();

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

  private static byte[] bytes(String json) {
    return json.getBytes(StandardCharsets.UTF_8);
  }
}
