package dev.workflowhub.analysis.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.workflowhub.analysis.service.ScanException;
import dev.workflowhub.analysis.service.ScanModels.ScanError;
import dev.workflowhub.analysis.service.ScanModels.ScanLlm;
import dev.workflowhub.analysis.service.ScanModels.ScanPolicy;
import dev.workflowhub.analysis.service.ScanModels.ScanReportView;
import dev.workflowhub.analysis.service.ScanModels.ScanRunView;
import dev.workflowhub.analysis.service.ScanModels.ScanSummary;
import dev.workflowhub.analysis.service.ScanModels.ScanVersions;
import dev.workflowhub.analysis.service.ScanService;
import dev.workflowhub.common.api.ApiError;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "analysis")
public class ScanController {
  private static final String WORKFLOW_ID = "0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10";
  private static final String VERSION_ID = "5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33";
  private static final String SCAN_RUN_ID = "9f8e7d6c-5b4a-4321-9876-543210fedcba";
  private static final String SHA256 =
      "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0";
  private static final String TIMESTAMP = "2026-11-29T00:10:00Z";
  private static final String UNAUTHORIZED = "토큰이 없거나 유효하지 않다(UNAUTHORIZED)";
  private static final String VERSION_NOT_FOUND =
      "요청한 소유 워크플로 버전을 찾을 수 없다(WORKFLOW_VERSION_NOT_FOUND)";
  private static final String SCAN_NOT_FOUND = "요청한 소유 보안 검사 실행을 찾을 수 없다(SCAN_RUN_NOT_FOUND)";
  private static final String SERVER_ERROR = "예상하지 못한 서버 오류. 응답의 requestId로 서버 로그를 찾는다";

  private final ScanService scans;

  public ScanController(ScanService scans) {
    this.scans = scans;
  }

  @PostMapping("/api/workflows/{workflowId}/versions/{versionId}/scans")
  @Operation(
      summary = "워크플로 버전 보안 검사 요청",
      description =
          "소유한 워크플로 버전의 비동기 보안 검사를 요청하고 SQS 작업을 발행한다. 같은 버전에 이미 진행 중인 검사가 있거나 해시가 없으면 409, 파일이 검사 파일 크기 한도(SCAN_MAX_FILE_BYTES, 기본 262144바이트 = 256 KiB)를 초과하면 422로 거절한다. 같은 Idempotency-Key 재전송은 최초 요청의 첫 발행이 확인된 뒤에만 같은 scanRunId로 202를 돌려주고, 확인 전에는 503 SCAN_DISPATCH_UNAVAILABLE을 돌려준다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "202",
        description = "보안 검사 작업을 수락해 큐에 발행했다(또는 동일 Idempotency-Key 재시도)",
        content =
            @Content(
                schema = @Schema(implementation = ScanRunResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{
                              "scanRunId":"9f8e7d6c-5b4a-4321-9876-543210fedcba",
                              "workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",
                              "workflowVersionId":"5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33",
                              "versionLabel":"v1",
                              "inputSha256":"a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
                              "versions":null,
                              "executionStatus":"queued",
                              "analysisCoverage":"unknown",
                              "policy":{"evaluationStatus":"not_applicable","decision":null,"advisoryDecision":null},
                              "publicationStatus":"private",
                              "llm":{"status":"not_requested"},
                              "summary":null,
                              "reportAvailable":false,
                              "error":null,
                              "createdAt":"2026-11-29T00:10:00Z",
                              "startedAt":null,
                              "finishedAt":null
                            }}
                            """))),
    @ApiResponse(
        responseCode = "400",
        description = "Idempotency-Key 형식이 잘못됐다(INVALID_IDEMPOTENCY_KEY)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = VERSION_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description =
            "해시 누락(VERSION_HASH_UNAVAILABLE), 진행 중 검사 중복(SCAN_ALREADY_IN_PROGRESS, details에 scanRunId·executionStatus 포함), 또는 멱등성 키 충돌(IDEMPOTENCY_KEY_CONFLICT)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "422",
        description =
            "원본 파일 크기가 검사 파일 크기 한도(SCAN_MAX_FILE_BYTES, 기본 262144바이트 = 256 KiB)를 초과한다(SCAN_FILE_TOO_LARGE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description =
            "작업 큐(SQS) 발행에 일시적으로 실패했거나, 같은 Idempotency-Key의 최초 요청이 아직 발행을 확인하지 못했다(SCAN_DISPATCH_UNAVAILABLE). 같은 키로 다시 시도한다",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ResponseEntity<ScanRunResponse> requestScan(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(
              description = "검사할 버전 ID",
              schema = @Schema(format = "uuid"),
              example = VERSION_ID)
          String versionId,
      @RequestHeader(name = "Idempotency-Key", required = false)
          @Parameter(
              description = "네트워크 재시도 시 동일 검사 실행을 돌려받기 위한 선택적 멱등성 키(1~128자)",
              example = "scan-req-0001")
          String idempotencyKey) {
    ScanRunView run = scans.requestScan(jwt.getSubject(), workflowId, versionId, idempotencyKey);
    return ResponseEntity.status(HttpStatus.ACCEPTED)
        .body(new ScanRunResponse(ScanRunData.from(run)));
  }

  @GetMapping("/api/workflows/{workflowId}/versions/{versionId}/scans")
  @Operation(
      summary = "버전별 보안 검사 이력 목록 조회",
      description = "소유한 워크플로 버전의 보안 검사 실행 이력을 최신순 커서 페이지네이션으로 조회한다. DB의 상태·요약만 반환한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "보안 검사 이력 목록을 조회했다",
        content = @Content(schema = @Schema(implementation = ScanListResponse.class))),
    @ApiResponse(
        responseCode = "400",
        description = "limit 범위 오류(INVALID_LIMIT) 또는 잘못된 cursor(INVALID_CURSOR)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = VERSION_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ScanListResponse listScans(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(description = "버전 ID", schema = @Schema(format = "uuid"), example = VERSION_ID)
          String versionId,
      @RequestParam(name = "limit", required = false)
          @Parameter(
              description = "한 페이지에서 조회할 최대 항목 수",
              schema =
                  @Schema(
                      type = "integer",
                      format = "int32",
                      minimum = "1",
                      maximum = "100",
                      defaultValue = "20"))
          String limit,
      @RequestParam(name = "cursor", required = false)
          @Parameter(description = "다음 페이지를 요청할 때 이전 응답의 nextCursor 값을 그대로 사용한다")
          String cursor) {
    var page = scans.listScans(jwt.getSubject(), workflowId, versionId, parseLimit(limit), cursor);
    var items = page.items().stream().map(ScanRunData::from).toList();
    return new ScanListResponse(new ScanListData(items, page.nextCursor()));
  }

  @GetMapping("/api/workflows/{workflowId}/versions/{versionId}/scans/latest")
  @Operation(
      summary = "버전의 최신 보안 검사 상태·요약 단건 조회",
      description =
          "소유한 워크플로 버전의 가장 최근 보안 검사 상태와 요약(DB 저장 정보)을 조회한다. 아직 검사 이력이 없는 살아 있는 버전이면 200 OK와 data: null을 반환한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "최신 보안 검사 상태·요약(검사 이력이 없으면 data: null)",
        content = @Content(schema = @Schema(implementation = LatestScanResponse.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = VERSION_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public LatestScanResponse getLatestScan(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(description = "버전 ID", schema = @Schema(format = "uuid"), example = VERSION_ID)
          String versionId) {
    var latest = scans.getLatestScan(jwt.getSubject(), workflowId, versionId);
    return new LatestScanResponse(latest.map(ScanRunData::from).orElse(null));
  }

  @GetMapping("/api/workflows/{workflowId}/versions/{versionId}/scans/{scanRunId}")
  @Operation(
      summary = "보안 검사 상태·요약 단건 조회 (폴링 대상)",
      description =
          "지정한 보안 검사 실행의 4축 상태, 버전·해시, 요약(summary), 오류 정보를 DB에서 조회한다. 상세 serviceReport는 reportAvailable=true일 때 GET .../report로 지연 조회한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "보안 검사 상태·요약을 조회했다",
        content = @Content(schema = @Schema(implementation = ScanRunResponse.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = SCAN_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ScanRunResponse getScan(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(description = "버전 ID", schema = @Schema(format = "uuid"), example = VERSION_ID)
          String versionId,
      @PathVariable("scanRunId")
          @Parameter(
              description = "보안 검사 실행 ID",
              schema = @Schema(format = "uuid"),
              example = SCAN_RUN_ID)
          String scanRunId) {
    return new ScanRunResponse(
        ScanRunData.from(scans.getScan(jwt.getSubject(), workflowId, versionId, scanRunId)));
  }

  @GetMapping("/api/workflows/{workflowId}/versions/{versionId}/scans/{scanRunId}/report")
  @Operation(
      summary = "완료된 보안 검사의 상세 리포트(serviceReport) 조회",
      description =
          "소유권을 검증한 뒤 비공개 S3에 저장된 serviceReport 원문 JSON을 읽어 반환한다. S3 키나 직접 URL은 브라우저에 노출하지 않는다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "완료된 보안 검사의 serviceReport 상세를 반환했다",
        content = @Content(schema = @Schema(implementation = ScanReportResponse.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = SCAN_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = "검사가 아직 완료되지 않았거나 리포트가 없다(SCAN_REPORT_NOT_AVAILABLE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description = "비공개 S3에서 리포트를 읽을 수 없다(STORAGE_UNAVAILABLE)",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ScanReportResponse getScanReport(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(description = "버전 ID", schema = @Schema(format = "uuid"), example = VERSION_ID)
          String versionId,
      @PathVariable("scanRunId")
          @Parameter(
              description = "보안 검사 실행 ID",
              schema = @Schema(format = "uuid"),
              example = SCAN_RUN_ID)
          String scanRunId) {
    ScanReportView report = scans.getScanReport(jwt.getSubject(), workflowId, versionId, scanRunId);
    return new ScanReportResponse(ScanReportData.from(report));
  }

  private static Integer parseLimit(String limit) {
    if (limit == null) {
      return null;
    }
    try {
      return Integer.valueOf(limit);
    } catch (NumberFormatException e) {
      throw ScanException.invalidLimit();
    }
  }

  @Schema(requiredProperties = "data")
  public record ScanRunResponse(ScanRunData data) {}

  @Schema(requiredProperties = "data")
  public record LatestScanResponse(
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "최신 보안 검사 실행 정보. 검사 이력이 없으면 null",
              types = {"object", "null"},
              schemaResolution = Schema.SchemaResolution.INLINE)
          ScanRunData data) {}

  @Schema(requiredProperties = "data")
  public record ScanListResponse(ScanListData data) {}

  @Schema(requiredProperties = {"items", "nextCursor"})
  public record ScanListData(
      List<ScanRunData> items,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "다음 페이지에 사용할 커서. 마지막 페이지에서는 null",
              types = {"string", "null"})
          String nextCursor) {}

  @Schema(requiredProperties = "data")
  public record ScanReportResponse(ScanReportData data) {}

  @Schema(
      requiredProperties = {
        "scanRunId",
        "workflowId",
        "workflowVersionId",
        "versionLabel",
        "inputSha256",
        "versions",
        "serviceReport"
      })
  public record ScanReportData(
      @Schema(example = SCAN_RUN_ID) UUID scanRunId,
      @Schema(example = WORKFLOW_ID) UUID workflowId,
      @Schema(example = VERSION_ID) UUID workflowVersionId,
      @Schema(example = "v1") String versionLabel,
      @Schema(example = SHA256) String inputSha256,
      @JsonInclude(JsonInclude.Include.ALWAYS) ScanVersions versions,
      @Schema(description = "워커가 생성한 화면 표시용 정제 한국어 리포트(serviceReport)") JsonNode serviceReport) {
    private static ScanReportData from(ScanReportView view) {
      return new ScanReportData(
          view.scanRunId(),
          view.workflowId(),
          view.workflowVersionId(),
          view.versionLabel(),
          view.inputSha256(),
          view.versions(),
          view.serviceReport());
    }
  }

  @Schema(
      requiredProperties = {
        "scanRunId",
        "workflowId",
        "workflowVersionId",
        "versionLabel",
        "inputSha256",
        "versions",
        "executionStatus",
        "analysisCoverage",
        "policy",
        "publicationStatus",
        "llm",
        "summary",
        "reportAvailable",
        "error",
        "createdAt",
        "startedAt",
        "finishedAt"
      })
  public record ScanRunData(
      @Schema(example = SCAN_RUN_ID) UUID scanRunId,
      @Schema(example = WORKFLOW_ID) UUID workflowId,
      @Schema(example = VERSION_ID) UUID workflowVersionId,
      @Schema(example = "v1") String versionLabel,
      @Schema(example = SHA256) String inputSha256,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "결과 계약·엔진·규칙 버전. 워커가 결과를 제출하기 전(queued·running·cancelled 등)에는 null",
              types = {"object", "null"},
              schemaResolution = Schema.SchemaResolution.INLINE)
          ScanVersions versions,
      @Schema(
              description = "검사 실행 상태",
              allowableValues = {
                "queued",
                "running",
                "completed",
                "failed",
                "timed_out",
                "cancelled"
              },
              example = "queued")
          String executionStatus,
      @Schema(
              description = "지원 프로파일 기준 분석 범위",
              allowableValues = {"checked", "partial", "unsupported", "unknown"},
              example = "unknown")
          String analysisCoverage,
      ScanPolicy policy,
      @Schema(
              description = "공개 상태",
              allowableValues = {"private", "submitted", "published", "withdrawn"},
              example = "private")
          String publicationStatus,
      ScanLlm llm,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "화면 기본 구성용 요약. completed가 아니면 null",
              types = {"object", "null"},
              schemaResolution = Schema.SchemaResolution.INLINE)
          ScanSummary summary,
      @Schema(description = "true이면 GET .../scans/{scanRunId}/report로 상세 serviceReport를 조회할 수 있다")
          boolean reportAvailable,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "failed·timed_out 오류 정보. 그 밖의 상태에서는 null",
              types = {"object", "null"},
              schemaResolution = Schema.SchemaResolution.INLINE)
          ScanError error,
      @Schema(example = TIMESTAMP) Instant createdAt,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "워커가 처음 파일을 받은 시각. 시작 전에는 null",
              types = {"string", "null"},
              format = "date-time")
          Instant startedAt,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "종료 상태가 된 시각. 종료 전에는 null",
              types = {"string", "null"},
              format = "date-time")
          Instant finishedAt) {
    private static ScanRunData from(ScanRunView view) {
      return new ScanRunData(
          view.scanRunId(),
          view.workflowId(),
          view.workflowVersionId(),
          view.versionLabel(),
          view.inputSha256(),
          view.versions(),
          view.executionStatus(),
          view.analysisCoverage(),
          view.policy(),
          view.publicationStatus(),
          view.llm(),
          view.summary(),
          view.reportAvailable(),
          view.error(),
          view.createdAt(),
          view.startedAt(),
          view.finishedAt());
    }
  }
}
