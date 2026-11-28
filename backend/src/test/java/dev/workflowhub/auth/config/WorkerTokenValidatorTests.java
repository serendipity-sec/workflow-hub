package dev.workflowhub.auth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;

class WorkerTokenValidatorTests {
  @Test
  void rejectsMissingOrBlankConfigurationAtStartup() {
    assertThatThrownBy(() -> new WorkerTokenValidator(null))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new WorkerTokenValidator("   "))
        .isInstanceOf(IllegalArgumentException.class);
    assertThatThrownBy(() -> new WorkerTokenValidator(", , "))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void matchesAnyConfiguredActiveTokenForRotationAndRejectsOthers() {
    WorkerTokenValidator validator = new WorkerTokenValidator("token-v1, token-v2 ,token-v1");

    assertThat(validator.matches("token-v1")).isTrue();
    assertThat(validator.matches("token-v2")).isTrue();
    assertThat(validator.matches("token-v3")).isFalse();
    assertThat(validator.matches("token-v1 ")).isFalse();
    assertThat(validator.matches("")).isFalse();
    assertThat(validator.matches(null)).isFalse();
    assertThat(validator.matches("eyJhbGciOiJSUzI1NiJ9.payload.sig")).isFalse();
  }
}
