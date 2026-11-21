package dev.workflowhub.auth;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IdentityController {
  @GetMapping("/api/me")
  public Identity me(@AuthenticationPrincipal Jwt jwt) {
    return new Identity(jwt.getSubject());
  }

  public record Identity(String id) {}
}
