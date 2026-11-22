package dev.workflowhub.auth;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

class TokenValidatorsTests {
  private final String issuer = "https://project.supabase.co/auth/v1";

  private Jwt.Builder token() {
    return Jwt.withTokenValue("test-only")
        .header("alg", "ES256")
        .issuer(issuer)
        .subject("user-123")
        .claim("role", "authenticated")
        .audience(List.of("authenticated"))
        .issuedAt(Instant.now().minusSeconds(60))
        .expiresAt(Instant.now().plusSeconds(300));
  }

  @Test
  void acceptsExpectedClaims() {
    assertThat(
            TokenValidators.create(issuer, "authenticated").validate(token().build()).hasErrors())
        .isFalse();
  }

  @Test
  void rejectsWrongIssuerAudienceMissingSubjectAndExpiredTokens() {
    for (Jwt invalid :
        List.of(
            token().issuer("https://other.example").build(),
            token().audience(List.of("other")).build(),
            token().claims(claims -> claims.remove("sub")).build(),
            token().subject(" ").build(),
            token().claim("role", "service_role").build(),
            token().claim("role", "anon").build(),
            token().claims(claims -> claims.remove("role")).build(),
            token()
                .expiresAt(Instant.now().minusSeconds(120))
                .issuedAt(Instant.now().minusSeconds(300))
                .build(),
            token().claims(claims -> claims.remove("exp")).build())) {
      assertThat(TokenValidators.create(issuer, "authenticated").validate(invalid).hasErrors())
          .isTrue();
    }
  }
}
