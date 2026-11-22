package dev.workflowhub.auth.config;

import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtValidators;

final class TokenValidators {
  private TokenValidators() {}

  static OAuth2TokenValidator<Jwt> create(String issuer, String audience) {
    return new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefaultWithIssuer(issuer),
        jwt -> {
          if (jwt.getAudience() == null
              || !jwt.getAudience().contains(audience)
              || !"authenticated".equals(jwt.getClaimAsString("role"))
              || jwt.getSubject() == null
              || jwt.getSubject().isBlank()
              || jwt.getExpiresAt() == null) {
            return OAuth2TokenValidatorResult.failure(
                new OAuth2Error(
                    "invalid_token", "Required token claims are missing or invalid", null));
          }
          return OAuth2TokenValidatorResult.success();
        });
  }
}
