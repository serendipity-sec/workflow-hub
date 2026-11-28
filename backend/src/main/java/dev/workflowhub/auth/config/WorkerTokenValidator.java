package dev.workflowhub.auth.config;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

/** 워커 내부 API(/internal/worker/v1/**)용 서비스 전용 Bearer 토큰 검증기. 키 회전을 위해 복수 활성 토큰을 허용한다. */
public class WorkerTokenValidator {
  private final List<byte[]> activeTokenHashes;

  public WorkerTokenValidator(String rawTokens) {
    List<String> tokens =
        rawTokens == null
            ? List.of()
            : Arrays.stream(rawTokens.split(","))
                .map(String::trim)
                .filter(token -> !token.isEmpty())
                .distinct()
                .toList();
    if (tokens.isEmpty()) {
      throw new IllegalArgumentException(
          "WORKER_API_TOKENS must contain at least one non-blank token");
    }
    this.activeTokenHashes = tokens.stream().map(WorkerTokenValidator::sha256).toList();
  }

  /** 토큰 길이·위치에 따른 시간 차이를 줄이기 위해 모든 활성 토큰 해시를 상수 시간으로 비교한다. */
  public boolean matches(String candidate) {
    if (candidate == null || candidate.isBlank()) {
      return false;
    }
    byte[] candidateHash = sha256(candidate);
    boolean matched = false;
    for (byte[] expected : activeTokenHashes) {
      matched |= MessageDigest.isEqual(expected, candidateHash);
    }
    return matched;
  }

  private static byte[] sha256(String value) {
    try {
      return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
