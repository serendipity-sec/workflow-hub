package dev.workflowhub.common.api;

import org.springframework.boot.servlet.autoconfigure.MultipartProperties;
import org.springframework.stereotype.Component;

/** 413 응답의 안내 문구. 상한 자체는 서블릿의 spring.servlet.multipart.max-file-size 한 곳에서만 정한다. */
@Component
public class UploadLimit {
  private static final long MIB = 1024 * 1024;
  private final long maxFileBytes;

  UploadLimit(MultipartProperties multipart) {
    this.maxFileBytes = multipart.getMaxFileSize().toBytes();
  }

  /** 파일 하나가 상한을 넘었을 때와 요청 전체가 상한을 넘었을 때 모두 쓰는 메시지다. */
  public String tooLargeMessage() {
    if (maxFileBytes < 0) {
      return "Upload exceeds the size limit";
    }
    String limit = maxFileBytes % MIB == 0 ? maxFileBytes / MIB + " MiB" : maxFileBytes + " bytes";
    return "Upload exceeds the size limit (" + limit + " per file)";
  }
}
