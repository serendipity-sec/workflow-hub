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
  static final String BEARER = "bearerAuth";

  @Bean
  OpenAPI workflowHubOpenApi() {
    return new OpenAPI()
        .info(
            new Info()
                .title("Workflow Hub API")
                .version("0.1.0")
                .description("Supabase 사용자 액세스 토큰(Bearer)으로 호출한다. 문서는 개발 환경에서만 노출한다."))
        .components(
            new Components()
                .addSecuritySchemes(
                    BEARER,
                    new SecurityScheme()
                        .type(SecurityScheme.Type.HTTP)
                        .scheme("bearer")
                        .bearerFormat("JWT")))
        .addSecurityItem(new SecurityRequirement().addList(BEARER));
  }
}
