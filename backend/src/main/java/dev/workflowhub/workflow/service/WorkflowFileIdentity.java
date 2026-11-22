package dev.workflowhub.workflow.service;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** S3에 저장하는 원본 바이트의 SHA-256(소문자 hex)과 크기. 클라이언트 값이나 S3 ETag는 쓰지 않는다. */
record WorkflowFileIdentity(String sha256, long sizeBytes) {
  /** 저장소에 넘기는 바로 그 배열로 계산해야 저장한 바이트와 기록이 어긋나지 않는다. */
  static WorkflowFileIdentity of(byte[] file) {
    try {
      return new WorkflowFileIdentity(
          HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(file)), file.length);
    } catch (NoSuchAlgorithmException e) {
      throw new IllegalStateException(e);
    }
  }
}
