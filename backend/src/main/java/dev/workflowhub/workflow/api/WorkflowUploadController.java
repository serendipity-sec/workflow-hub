package dev.workflowhub.workflow.api;

import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.workflow.service.WorkflowUploadException;
import dev.workflowhub.workflow.service.WorkflowUploadService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.io.IOException;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@Tag(name = "workflows", description = "워크플로 등록")
public class WorkflowUploadController {
  private final WorkflowUploadService uploads;

  public WorkflowUploadController(WorkflowUploadService uploads) {
    this.uploads = uploads;
  }

  // 소유자는 항상 검증된 토큰의 subject다. 요청에 담긴 owner 값은 읽지 않는다.
  @PostMapping(path = "/api/workflows", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(
      summary = "n8n 워크플로 JSON 최초 등록",
      description =
          """
          n8n에서 내보낸 JSON 파일 하나를 새 비공개 워크플로의 v1으로 등록한다.
          같은 Idempotency-Key와 같은 입력으로 재시도하면 최초 201 본문을 그대로 받는다.

          curl 예시:
          ```
          curl -X POST http://localhost:8080/api/workflows \\
            -H "Authorization: Bearer $TOKEN" \\
            -H "Idempotency-Key: $(uuidgen)" \\
            -F "title=주문 접수 Slack 알림" \\
            -F "file=@backend/src/test/resources/samples/minimal-workflow.json;type=application/json"
          ```
          """)
  @ApiResponses({
    @ApiResponse(
        responseCode = "201",
        description = "워크플로와 v1이 생성되었다",
        content =
            @Content(
                schema = @Schema(implementation = UploadResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{"workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",\
                            "versionId":"5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33","versionLabel":"v1"}}
                            """))),
    @ApiResponse(
        responseCode = "400",
        description =
            "Idempotency-Key 누락·형식 오류(IDEMPOTENCY_KEY_*), file 파트 누락(FILE_REQUIRED), 깨진 multipart 본문(BAD_REQUEST)",
        content =
            @Content(
                schema = @Schema(implementation = ApiError.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"code":"IDEMPOTENCY_KEY_REQUIRED","message":"Idempotency-Key header is required","requestId":"3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11"}
                            """))),
    @ApiResponse(
        responseCode = "401",
        description = "토큰이 없거나 유효하지 않다",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = "같은 Idempotency-Key로 다른 제목이나 파일을 보냈다. 이 판단은 파일 유효성 검사보다 먼저 이루어진다",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "413",
        description = "파일이 크기 상한(기본 5 MiB, spring.servlet.multipart.max-file-size)을 넘는다",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "422",
        description =
            "유효한 n8n 워크플로가 아니거나(INVALID_WORKFLOW) 제목을 쓸 수 없다(TITLE_REQUIRED, TITLE_TOO_LONG, TITLE_INVALID)",
        content =
            @Content(
                schema = @Schema(implementation = ApiError.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"code":"INVALID_WORKFLOW","message":"Workflow must have a non-empty nodes array","requestId":"3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11"}
                            """))),
    @ApiResponse(
        responseCode = "500",
        description = "예상하지 못한 서버 오류. 응답의 requestId로 서버 로그를 찾는다",
        content =
            @Content(
                schema = @Schema(implementation = ApiError.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"code":"INTERNAL_ERROR","message":"Unexpected server error","requestId":"3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11"}
                            """))),
    @ApiResponse(
        responseCode = "503",
        description =
            "파일 저장에 실패했거나, 저장한 파일이 등록 전에 정리되어 커밋하지 못했다(STORAGE_UNAVAILABLE). 아무것도 생성되지 않았으니 같은 키로 재시도한다",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ResponseEntity<UploadResponse> upload(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @RequestHeader(name = "Idempotency-Key", required = false)
          @Parameter(
              required = true,
              description = "요청마다 새로 만드는 고유 키(UUID 권장, 1~255자 ASCII)",
              example = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
          String idempotencyKey,
      @RequestParam(name = "title", required = false)
          @Parameter(
              description = "표시 이름(최대 200자). 비우면 JSON의 name을 쓴다",
              schema = @Schema(maxLength = 200),
              example = "주문 접수 Slack 알림")
          String title,
      @RequestParam("file") @Parameter(description = "n8n 워크플로 JSON 파일 하나(기본 최대 5 MiB)")
          MultipartFile file) {
    byte[] content;
    try {
      content = file.getBytes();
    } catch (IOException e) {
      throw new WorkflowUploadException(
          HttpStatus.BAD_REQUEST, "FILE_UNREADABLE", "Could not read the uploaded file");
    }
    var result = uploads.upload(jwt.getSubject(), idempotencyKey, title, content);
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(
            new UploadResponse(
                new UploadData(result.workflowId(), result.versionId(), result.versionLabel())));
  }

  public record UploadResponse(UploadData data) {}

  public record UploadData(
      @Schema(example = "0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10") UUID workflowId,
      @Schema(example = "5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33") UUID versionId,
      @Schema(example = "v1") String versionLabel) {}
}
