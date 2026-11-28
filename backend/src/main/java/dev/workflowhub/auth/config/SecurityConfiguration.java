package dev.workflowhub.auth.config;

import dev.workflowhub.common.api.ApiErrorWriter;
import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {
  @Bean
  WorkerTokenValidator workerTokenValidator(
      @Value("${app.analysis.worker-tokens}") String workerTokens) {
    return new WorkerTokenValidator(workerTokens);
  }

  @Bean
  JwtDecoder jwtDecoder(
      @Value("${app.auth.issuer}") String issuer,
      @Value("${app.auth.jwk-set-uri}") String jwks,
      @Value("${app.auth.audience}") String audience) {
    NimbusJwtDecoder decoder =
        NimbusJwtDecoder.withJwkSetUri(jwks)
            .jwsAlgorithms(
                algorithms -> {
                  algorithms.add(SignatureAlgorithm.ES256);
                  algorithms.add(SignatureAlgorithm.RS256);
                })
            .build();
    decoder.setJwtValidator(TokenValidators.create(issuer, audience));
    return decoder;
  }

  /** 워커 내부 API는 사용자 Supabase JWT와 완전히 분리된 서비스 전용 Bearer 토큰만 허용한다. */
  @Bean
  @Order(1)
  SecurityFilterChain workerSecurityFilterChain(
      HttpSecurity http, ApiErrorWriter errors, WorkerTokenValidator workerTokens)
      throws Exception {
    return http.securityMatcher("/internal/**")
        .csrf(csrf -> csrf.disable())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .requestCache(cache -> cache.disable())
        .addFilterBefore(
            new WorkerTokenAuthenticationFilter(workerTokens), AnonymousAuthenticationFilter.class)
        .authorizeHttpRequests(auth -> auth.anyRequest().hasRole("WORKER"))
        .exceptionHandling(
            handling ->
                handling
                    .authenticationEntryPoint(
                        (request, response, exception) -> {
                          response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                          errors.write(
                              response,
                              401,
                              "WORKER_UNAUTHORIZED",
                              "Invalid or missing worker service token");
                        })
                    .accessDeniedHandler(
                        (request, response, exception) ->
                            errors.write(
                                response, 403, "WORKER_FORBIDDEN", "Worker access denied")))
        .build();
  }

  @Bean
  @Order(2)
  SecurityFilterChain securityFilterChain(
      HttpSecurity http, ApiErrorWriter errors, @Value("${app.docs.enabled}") boolean docsEnabled)
      throws Exception {
    return http
        // 쿠키 인증을 쓰지 않고 Bearer 헤더만 받으므로 CSRF를 끈다.
        .csrf(csrf -> csrf.disable())
        .cors(Customizer.withDefaults())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .requestCache(cache -> cache.disable())
        .authorizeHttpRequests(
            auth -> {
              auth.requestMatchers("/api/health").permitAll();
              if (docsEnabled) {
                // 개발 환경 전용. 설정이 꺼져 있으면 이 경로는 인증을 요구한다.
                auth.requestMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html")
                    .permitAll();
              }
              auth.anyRequest().authenticated();
            })
        .oauth2ResourceServer(
            oauth ->
                oauth
                    .jwt(Customizer.withDefaults())
                    .authenticationEntryPoint(
                        (request, response, exception) -> {
                          response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                          errors.write(response, 401, "UNAUTHORIZED", "Authentication required");
                        }))
        .exceptionHandling(
            handling ->
                handling.accessDeniedHandler(
                    (request, response, exception) ->
                        errors.write(response, 403, "FORBIDDEN", "Access denied")))
        .build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(
      @Value("${app.cors.allowed-origins}") String origins) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.stream(origins.split(",")).map(String::trim).toList());
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(
        List.of("Authorization", "Content-Type", "Idempotency-Key", "X-Request-Id"));
    // 브라우저가 오류 보고용으로 추적 ID를 읽을 수 있게 한다.
    config.setExposedHeaders(List.of("X-Request-Id"));
    config.setAllowCredentials(false);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
  }
}
