package dev.workflowhub.common.logging;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * 요청마다 추적 ID를 정해 로그(MDC)와 응답 헤더에 넣고, 요청 한 줄 로그를 남긴다. 보안 필터보다 먼저 실행되어 401 응답도 같은 ID를 갖는다. 헤더 값, 쿼리
 * 문자열, 본문은 기록하지 않는다.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestIdFilter extends OncePerRequestFilter {
  public static final String HEADER = "X-Request-Id";
  public static final String MDC_KEY = "requestId";
  // 로그 위조를 막기 위해 안전한 문자만 받는다.
  private static final Pattern VALID_ID = Pattern.compile("[A-Za-z0-9_-]{8,64}");
  private static final Logger log = LoggerFactory.getLogger(RequestIdFilter.class);

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain chain)
      throws ServletException, IOException {
    String incoming = request.getHeader(HEADER);
    String requestId =
        incoming != null && VALID_ID.matcher(incoming).matches()
            ? incoming
            : UUID.randomUUID().toString();
    MDC.put(MDC_KEY, requestId);
    response.setHeader(HEADER, requestId);
    long start = System.nanoTime();
    try {
      chain.doFilter(request, response);
    } finally {
      long millis = (System.nanoTime() - start) / 1_000_000;
      String path = request.getRequestURI();
      if (path.equals("/api/health")) {
        log.debug(
            "event=http.request method={} path={} status={} durationMs={}",
            request.getMethod(),
            path,
            response.getStatus(),
            millis);
      } else {
        log.info(
            "event=http.request method={} path={} status={} durationMs={}",
            request.getMethod(),
            path,
            response.getStatus(),
            millis);
      }
      MDC.remove(MDC_KEY);
    }
  }
}
