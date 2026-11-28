package dev.workflowhub.analysis.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

class ScanCursorTests {
  @Test
  void roundTripsValidCursor() {
    var cursor = new ScanCursor(Instant.parse("2026-11-29T00:10:00.123456Z"), UUID.randomUUID());
    String encoded = cursor.encode();
    assertThat(ScanCursor.decode(encoded)).isEqualTo(cursor);
  }

  @Test
  void rejectsInvalidCursorTokens() {
    assertThat(ScanCursor.decode(null)).isNull();
    assertThatThrownBy(() -> ScanCursor.decode("not-a-cursor"))
        .isInstanceOf(ScanException.class)
        .extracting(e -> ((ScanException) e).code())
        .isEqualTo("INVALID_CURSOR");
  }
}
