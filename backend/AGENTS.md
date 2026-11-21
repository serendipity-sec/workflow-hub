# Backend harness

Read root AGENTS.md and contracts/openapi.yaml first. Work inside backend unless a contract change is coordinated.

- Java 25, Spring Boot 4.0.10, Gradle wrapper only. Package by domain (`auth`, `health`, future `workflow`, `revision`), not global controller/service folders.
- Windows: `./gradlew.bat bootRun`; Linux/macOS: `./gradlew bootRun`.
- Verify: `./gradlew spotlessCheck test bootJar` (use gradlew.bat on Windows). Format: `./gradlew spotlessApply`.
- Google Java Format is authoritative. No hand-maintained conflicting Java style rules.
- Supabase issues and rotates tokens. This API validates bearer access tokens via asymmetric JWKS, issuer, audience, expiry and subject. Never issue a second JWT or accept refresh tokens as API credentials.
- No server login sessions or authentication cookies. CSRF is disabled only because this API accepts bearer headers; revisit if cookies become credentials.
- CORS origins are explicit. Do not use wildcard origins for convenience.
- Identity comes from verified subject, never a client-supplied owner ID. Future workflow queries must enforce owner/shared visibility and revision ownership.
- Supabase Postgres and S3 business persistence are not implemented yet. Do not imply otherwise in reports. Original JSON must never be executed or logged.
- No production credentials needed for tests. MockMvc JWT tests cover endpoint behavior; validator unit tests cover claims. Real Google callback/JWKS/RTR integration needs an actual configured Supabase project.
- Update API contract with endpoint changes, add meaningful authorization/error tests, report exact checks and limitations.
