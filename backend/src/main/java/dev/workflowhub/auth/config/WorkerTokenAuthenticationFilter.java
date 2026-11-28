package dev.workflowhub.auth.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

/** /internal/** 경로에서 사용자 JWT와 분리된 서비스 전용 Bearer 토큰만 인증한다. */
class WorkerTokenAuthenticationFilter extends OncePerRequestFilter {
  private static final String BEARER_SCHEME = "Bearer";
  private final WorkerTokenValidator validator;

  WorkerTokenAuthenticationFilter(WorkerTokenValidator validator) {
    this.validator = validator;
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {
    String token = bearerToken(request.getHeader(HttpHeaders.AUTHORIZATION));
    if (token != null && validator.matches(token)) {
      var authentication =
          UsernamePasswordAuthenticationToken.authenticated(
              "worker", null, List.of(new SimpleGrantedAuthority("ROLE_WORKER")));
      SecurityContextHolder.getContext().setAuthentication(authentication);
    }
    filterChain.doFilter(request, response);
  }

  /**
   * RFC 9110 credentials 형식(auth-scheme 1*SP token)에서 토큰을 꺼낸다. 인증 스킴은 대소문자를 구분하지 않고, 구분 공백은 하나 이상
   * 허용한다. 토큰 자체는 바꾸지 않으며, 형식 검증은 {@link WorkerTokenValidator#matches}가 한다.
   */
  static String bearerToken(String header) {
    if (header == null
        || header.length() <= BEARER_SCHEME.length()
        || !header.regionMatches(true, 0, BEARER_SCHEME, 0, BEARER_SCHEME.length())
        || header.charAt(BEARER_SCHEME.length()) != ' ') {
      return null;
    }
    int start = BEARER_SCHEME.length();
    while (start < header.length() && header.charAt(start) == ' ') {
      start++;
    }
    return start == header.length() ? null : header.substring(start);
  }
}
