package dev.workflowhub.common.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Swagger UI용 문서 정보. API 명세의 기준은 컨트롤러 어노테이션이다. */
@Configuration
public class OpenApiConfiguration {
  public static final String BEARER = "bearerAuth";
  public static final String WORKER_BEARER = "workerBearerAuth";

  @Bean
  OpenAPI workflowHubOpenApi() {
    return new OpenAPI()
        .info(
            new Info()
                .title("Workflow Hub API")
                .version("0.1.0")
                .description(
                    "사용자 API는 Supabase 액세스 토큰(Bearer), 워커 내부 API(/internal/worker/v1/**)는 서비스 전용 Bearer 토큰으로 호출한다. 문서는 개발 환경에서만 노출한다."))
        .components(
            new Components()
                .addSecuritySchemes(
                    BEARER,
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT"))
                .addSecuritySchemes(
                    WORKER_BEARER,
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .description("워커 전용 서비스 Bearer 토큰(복수 활성 토큰 회전 지원)")))
        .addSecurityItem(new SecurityRequirement().addList(BEARER));
  }
}
