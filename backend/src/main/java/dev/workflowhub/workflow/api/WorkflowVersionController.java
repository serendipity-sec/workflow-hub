package dev.workflowhub.workflow.api;

import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.workflow.api.WorkflowUploadController.UploadData;
import dev.workflowhub.workflow.api.WorkflowUploadController.UploadResponse;
import dev.workflowhub.workflow.service.WorkflowGraphComparison.Change;
import dev.workflowhub.workflow.service.WorkflowGraphComparison.Graphs;
import dev.workflowhub.workflow.service.WorkflowGraphComparison.Summary;
import dev.workflowhub.workflow.service.WorkflowUploadException;
import dev.workflowhub.workflow.service.WorkflowVersionService;
import dev.workflowhub.workflow.service.WorkflowVersionService.LatestVersionChanged;
import dev.workflowhub.workflow.service.WorkflowVersionService.UpdateType;
import dev.workflowhub.workflow.service.WorkflowVersionService.VersionReference;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartHttpServletRequest;

@RestController
@RequestMapping(
    path = "/api/workflows/{workflowId}/versions",
    produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "workflows")
public class WorkflowVersionController {
  private static final Logger log = LoggerFactory.getLogger(WorkflowVersionController.class);
  private static final String UNAUTHORIZED = "토큰이 없거나 유효하지 않다";
  private static final String SERVER_ERROR = "예상하지 못한 서버 오류. 응답의 requestId로 서버 로그를 찾는다";
  private final WorkflowVersionService versions;

  public WorkflowVersionController(WorkflowVersionService versions) {
    this.versions = versions;
  }

  @PostMapping(path = "/{versionId}/comparisons", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
  @Operation(
      summary = "기준 버전과 n8n 수정본 비교",
      requestBody =
          @io.swagger.v3.oas.annotations.parameters.RequestBody(
              required = true,
              content =
                  @Content(
                      mediaType = MediaType.MULTIPART_FORM_DATA_VALUE,
                      schema = @Schema(implementation = ComparisonRequest.class))),
      description =
          """
          같은 메이저 계열의 번호가 가장 높은 소유 버전과 수정한 JSON 파일 하나를 비교한다.
          다운로드가 중지된 버전도 비교 기준으로 쓸 수 있다. 응답의 comparisonId는 24시간 동안 등록에 사용할 수 있다.
          """)
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "양쪽 그래프와 변경 내역을 계산했다",
        content = @Content(schema = @Schema(implementation = ComparisonResponse.class))),
    @ApiResponse(
        responseCode = "400",
        description =
            "파일 파트가 없거나 file 하나가 아니다, 또는 깨진 multipart 본문(INVALID_FILE_COUNT, FILE_UNREADABLE, BAD_REQUEST)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = "이 워크플로에 속한 소유 버전을 찾을 수 없다(WORKFLOW_VERSION_NOT_FOUND)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = "같은 메이저 계열에 더 높은 버전이 있다(LATEST_VERSION_CHANGED)",
        content = @Content(schema = @Schema(implementation = ConflictResponse.class))),
    @ApiResponse(
        responseCode = "413",
        description = "수정본 파일이 크기 상한(기본 5 MiB)을 넘는다(FILE_TOO_LARGE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "415",
        description = "요청 형식은 multipart/form-data여야 한다",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "422",
        description = "유효한 n8n 워크플로 JSON이 아니다(INVALID_WORKFLOW)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description = "기준 파일을 읽거나 비교 파일을 저장할 수 없다(STORAGE_UNAVAILABLE)",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ComparisonResponse compare(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId") @Parameter(schema = @Schema(format = "uuid")) String workflowId,
      @PathVariable("versionId") @Parameter(schema = @Schema(format = "uuid")) String versionId,
      @Parameter(hidden = true) MultipartHttpServletRequest request) {
    // file 외 이름의 파일 파트까지 포함해 전체 파일 파트가 정확히 file 하나여야 한다.
    var all = request.getMultiFileMap();
    var named = all.get("file");
    int total = all.values().stream().mapToInt(List::size).sum();
    if (total != 1 || named == null) {
      throw new WorkflowUploadException(
          HttpStatus.BAD_REQUEST, "INVALID_FILE_COUNT", "Exactly one file part is required");
    }
    byte[] bytes;
    try {
      bytes = named.get(0).getBytes();
    } catch (IOException e) {
      throw new WorkflowUploadException(
          HttpStatus.BAD_REQUEST, "FILE_UNREADABLE", "Could not read the uploaded file");
    }
    var result = versions.compare(jwt.getSubject(), workflowId, versionId, bytes);
    return new ComparisonResponse(
        new ComparisonData(
            result.comparisonId(),
            result.baseVersion(),
            result.expiresAt(),
            result.diff().summary(),
            result.diff().graphs(),
            result.diff().changes()));
  }

  @PostMapping(consumes = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "비교한 JSON을 새 버전으로 등록",
      description =
          """
          MINOR는 선택한 메이저 계열의 최신 버전에서 올린다. MAJOR는 가장 높은 메이저 계열의 최신 버전에서 올린다.
          같은 Idempotency-Key와 입력으로 성공한 요청을 재시도하면 비교가 만료된 뒤에도 최초 201을 반환한다.
          """)
  @ApiResponses({
    @ApiResponse(
        responseCode = "201",
        description = "비교한 원본으로 새 버전을 등록했다",
        content =
            @Content(
                schema = @Schema(implementation = UploadResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{"workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",\
                            "versionId":"5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33","versionLabel":"v1.2"}}
                            """))),
    @ApiResponse(
        responseCode = "400",
        description = "Idempotency-Key나 JSON 등록 입력이 누락되었거나 유효하지 않다",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = "소유 워크플로가 없거나 비교가 없거나 만료되었다(WORKFLOW_NOT_FOUND, COMPARISON_NOT_FOUND)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description =
            "등록 기준이 바뀌었다(LATEST_VERSION_CHANGED). 같은 키를 다른 입력에 썼을 때는 IDEMPOTENCY_KEY_REUSED를 반환한다",
        content = @Content(schema = @Schema(anyOf = {ApiError.class, ConflictResponse.class}))),
    @ApiResponse(
        responseCode = "415",
        description = "요청 형식은 application/json이어야 한다",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description =
            "비교 파일을 읽거나 등록 파일을 저장할 수 없다. 저장한 등록 파일이 커밋 전에 정리된 경우도 같다(STORAGE_UNAVAILABLE). 이 요청으로는 버전이 만들어지지 않았으니 같은 Idempotency-Key로 재시도한다",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ResponseEntity<UploadResponse> register(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId") @Parameter(schema = @Schema(format = "uuid")) String workflowId,
      @RequestHeader(name = "Idempotency-Key", required = false)
          @Parameter(
              required = true,
              description = "요청마다 새로 만드는 고유 키(UUID 권장, 1~255자 ASCII)",
              example = "7c9e6679-7425-40de-944b-e07fc1f90ae7")
          String key,
      @RequestBody RegistrationRequest request) {
    var result =
        versions.register(
            jwt.getSubject(), workflowId, key, request.comparisonId(), request.parseUpdateType());
    return ResponseEntity.status(HttpStatus.CREATED)
        .body(
            new UploadResponse(
                new UploadData(result.workflowId(), result.versionId(), result.versionLabel())));
  }

  @ExceptionHandler(LatestVersionChanged.class)
  ResponseEntity<ConflictResponse> latestVersionChanged(LatestVersionChanged e) {
    log.warn("event=workflow.version.rejected status=409 code={}", e.code());
    ApiError error = ApiError.of(e.code(), e.getMessage());
    return ResponseEntity.status(HttpStatus.CONFLICT)
        .body(
            new ConflictResponse(
                error.code(),
                error.message(),
                error.requestId(),
                new ConflictDetails(e.latestVersion())));
  }

  @Schema(requiredProperties = {"comparisonId", "updateType"})
  public record RegistrationRequest(
      UUID comparisonId, @Schema(allowableValues = {"MINOR", "MAJOR"}) String updateType) {
    private UpdateType parseUpdateType() {
      if (comparisonId != null) {
        if ("MINOR".equals(updateType)) {
          return UpdateType.MINOR;
        }
        if ("MAJOR".equals(updateType)) {
          return UpdateType.MAJOR;
        }
      }
      throw new WorkflowUploadException(
          HttpStatus.BAD_REQUEST,
          "INVALID_VERSION_REQUEST",
          "comparisonId and updateType (MINOR or MAJOR) are required");
    }
  }

  @Schema(requiredProperties = {"file"})
  public record ComparisonRequest(
      @Schema(format = "binary", description = "n8n 워크플로 JSON 파일 하나(기본 최대 5 MiB)") String file) {}

  public record ComparisonResponse(ComparisonData data) {}

  public record ComparisonData(
      UUID comparisonId,
      VersionReference baseVersion,
      Instant expiresAt,
      Summary summary,
      Graphs graphs,
      List<Change> changes) {}

  public record ConflictResponse(
      String code, String message, String requestId, ConflictDetails details) {}

  public record ConflictDetails(VersionReference latestVersion) {}
}
