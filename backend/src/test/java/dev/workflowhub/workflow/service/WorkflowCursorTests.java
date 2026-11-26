package dev.workflowhub.workflow.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpStatus;

class WorkflowCursorTests {
  @Test
  void preservesMicrosecondsAndUuidInAUrlSafeToken() {
    WorkflowCursor cursor =
        new WorkflowCursor(
            Instant.parse("2026-11-22T09:00:00.123456Z"),
            UUID.fromString("ffffffff-ffff-ffff-ffff-ffffffffffff"));

    String token = cursor.encode();

    assertThat(token).matches("[A-Za-z0-9_-]+");
    assertThat(WorkflowCursor.decode(token)).isEqualTo(cursor);
  }

  @Test
  void rejectsNonCanonicalAndNonUrlSafeBase64() {
    // 마지막 문자의 미사용 비트가 0이 아니어도 Base64 디코더는 동일한 바이트를 반환한다.
    assertInvalidCursor("A".repeat(37) + "B");
    assertInvalidCursor("/" + "A".repeat(37));
  }

  @ParameterizedTest
  @ValueSource(ints = {0, 37, 39, 4096})
  void rejectsWrongTokenLengths(int length) {
    assertInvalidCursor("A".repeat(length));
  }

  @ParameterizedTest
  @CsvSource({"-210866803201, 0", "9224318016000, 0", "0, -1", "0, 1000000"})
  void rejectsTimestampOutsidePostgresRange(long epochSeconds, int micros) {
    byte[] payload =
        ByteBuffer.allocate(28).putLong(epochSeconds).putInt(micros).putLong(0).putLong(0).array();
    assertInvalidCursor(Base64.getUrlEncoder().withoutPadding().encodeToString(payload));
  }

  private static void assertInvalidCursor(String token) {
    assertThatThrownBy(() -> WorkflowCursor.decode(token))
        .isInstanceOfSatisfying(
            WorkflowQueryException.class,
            e -> {
              assertThat(e.status()).isEqualTo(HttpStatus.BAD_REQUEST);
              assertThat(e.code()).isEqualTo("INVALID_CURSOR");
            });
  }
}
