package dev.workflowhub.analysis.service;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

record ScanCursor(Instant createdAt, UUID id) {
  private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder DECODER = Base64.getUrlDecoder();
  private static final int BYTE_LENGTH = Long.BYTES * 3 + Integer.BYTES;
  private static final int TOKEN_LENGTH = (BYTE_LENGTH * 8 + 5) / 6;
  private static final long FIRST_TIMESTAMP_SECOND =
      Instant.parse("-4713-11-24T00:00:00Z").getEpochSecond();
  private static final long EXCLUSIVE_END_TIMESTAMP_SECOND =
      Instant.parse("+294277-01-01T00:00:00Z").getEpochSecond();

  static ScanCursor decode(String token) {
    if (token == null) {
      return null;
    }
    if (token.length() != TOKEN_LENGTH) {
      throw ScanException.invalidCursor();
    }
    byte[] payload;
    try {
      payload = DECODER.decode(token);
    } catch (IllegalArgumentException e) {
      throw ScanException.invalidCursor();
    }
    if (payload.length != BYTE_LENGTH || !ENCODER.encodeToString(payload).equals(token)) {
      throw ScanException.invalidCursor();
    }
    ByteBuffer buffer = ByteBuffer.wrap(payload);
    long seconds = buffer.getLong();
    int micros = buffer.getInt();
    if (seconds < FIRST_TIMESTAMP_SECOND
        || seconds >= EXCLUSIVE_END_TIMESTAMP_SECOND
        || micros < 0
        || micros >= 1_000_000) {
      throw ScanException.invalidCursor();
    }
    return new ScanCursor(
        Instant.ofEpochSecond(seconds, micros * 1_000L),
        new UUID(buffer.getLong(), buffer.getLong()));
  }

  String encode() {
    ByteBuffer buffer = ByteBuffer.allocate(BYTE_LENGTH);
    buffer.putLong(createdAt.getEpochSecond());
    buffer.putInt(createdAt.getNano() / 1_000);
    buffer.putLong(id.getMostSignificantBits());
    buffer.putLong(id.getLeastSignificantBits());
    return ENCODER.encodeToString(buffer.array());
  }
}
