package dev.workflowhub.auth.config;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.JwtException;

class TokenDecoderTests {
  @Test
  void productionDecoderValidatesJwksSignatureAndUserClaims() throws Exception {
    RSAKey trusted = new RSAKeyGenerator(2048).keyID("test-key").generate();
    RSAKey untrusted = new RSAKeyGenerator(2048).keyID("test-key").generate();
    HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
    byte[] publicKeys =
        new JWKSet(trusted.toPublicJWK()).toString().getBytes(StandardCharsets.UTF_8);
    server.createContext(
        "/jwks",
        exchange -> {
          exchange.getResponseHeaders().set("Content-Type", "application/json");
          exchange.sendResponseHeaders(200, publicKeys.length);
          try (var body = exchange.getResponseBody()) {
            body.write(publicKeys);
          }
        });
    server.start();
    try {
      String issuer = "http://127.0.0.1:" + server.getAddress().getPort();
      var decoder =
          new SecurityConfiguration().jwtDecoder(issuer, issuer + "/jwks", "authenticated");
      assertThat(decoder.decode(signed(trusted, issuer, "authenticated")).getSubject())
          .isEqualTo("user-123");
      assertThatThrownBy(() -> decoder.decode(signed(untrusted, issuer, "authenticated")))
          .isInstanceOf(JwtException.class);
      assertThatThrownBy(() -> decoder.decode(signed(trusted, issuer, "service_role")))
          .isInstanceOf(JwtException.class);
    } finally {
      server.stop(0);
    }
  }

  private String signed(RSAKey key, String issuer, String role) throws Exception {
    var claims =
        new JWTClaimsSet.Builder()
            .issuer(issuer)
            .subject("user-123")
            .audience("authenticated")
            .claim("role", role)
            .issueTime(Date.from(Instant.now().minusSeconds(5)))
            .expirationTime(Date.from(Instant.now().plusSeconds(300)))
            .build();
    var jwt =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256)
                .keyID("test-key")
                .type(JOSEObjectType.JWT)
                .build(),
            claims);
    jwt.sign(new RSASSASigner(key));
    return jwt.serialize();
  }
}
