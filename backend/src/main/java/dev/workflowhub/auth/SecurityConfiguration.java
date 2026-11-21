package dev.workflowhub.auth;

import java.util.Arrays;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@Configuration
public class SecurityConfiguration {
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

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
        // API accepts bearer headers only, never authentication cookies.
        .csrf(csrf -> csrf.disable())
        .cors(Customizer.withDefaults())
        .sessionManagement(
            session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
        .requestCache(cache -> cache.disable())
        .authorizeHttpRequests(
            auth -> auth.requestMatchers("/api/health").permitAll().anyRequest().authenticated())
        .oauth2ResourceServer(
            oauth ->
                oauth
                    .jwt(Customizer.withDefaults())
                    .authenticationEntryPoint(
                        (request, response, exception) -> {
                          response.setStatus(401);
                          response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
                          response.setContentType("application/json");
                          response
                              .getWriter()
                              .write(
                                  "{\"code\":\"UNAUTHORIZED\",\"message\":\"Authentication required\"}");
                        }))
        .exceptionHandling(
            errors ->
                errors.accessDeniedHandler(
                    (request, response, exception) -> {
                      response.setStatus(403);
                      response.setContentType("application/json");
                      response
                          .getWriter()
                          .write("{\"code\":\"FORBIDDEN\",\"message\":\"Access denied\"}");
                    }))
        .build();
  }

  @Bean
  CorsConfigurationSource corsConfigurationSource(
      @Value("${app.cors.allowed-origins}") String origins) {
    CorsConfiguration config = new CorsConfiguration();
    config.setAllowedOrigins(Arrays.stream(origins.split(",")).map(String::trim).toList());
    config.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
    config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
    config.setAllowCredentials(false);
    UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
    source.registerCorsConfiguration("/api/**", config);
    return source;
  }
}
