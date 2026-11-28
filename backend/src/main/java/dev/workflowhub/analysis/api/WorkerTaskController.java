package dev.workflowhub.analysis.api;

import dev.workflowhub.analysis.service.ScanException;
import dev.workflowhub.analysis.service.ScanModels.HeartbeatResult;
import dev.workflowhub.analysis.service.ScanModels.ResultSubmission;
import dev.workflowhub.analysis.service.ScanModels.WorkerFileDownload;
import dev.workflowhub.analysis.service.WorkerTaskService;
import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.common.config.OpenApiConfiguration;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.headers.Header;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/internal/worker/v1/tasks/{taskId}/attempts/{attemptId}")
@Tag(name = "worker-internal")
@SecurityRequirement(name = OpenApiConfiguration.WORKER_BEARER)
public class WorkerTaskController {
  private static final String TASK_ID = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
  private static final String ATTEMPT_ID = "11111111-2222-4333-8444-555555555555";
  private static final String WORKER_AUTH_ERROR = "유효하지 않은 워커 서비스 토큰(WORKER_UNAUTHORIZED)";
  private static final String WORKER_FORBIDDEN = "워커 권한이 없는 주체(WORKER_FORBIDDEN)";
  private static final String ATTEMPT_NOT_FOUND = "존재하지 않는 작업 또는 시도(TASK_ATTEMPT_NOT_FOUND)";
  private static final String ATTEMPT_EXPIRED = "임대가 만료됐거나 새 시도로 대체된 시도(ATTEMPT_EXPIRED)";
  private static final String SERVER_ERROR = "예상하지 못한 서버 오류. 응답의 requestId로 서버 로그를 찾는다";

  private final WorkerTaskService workerTasks;

  public WorkerTaskController(WorkerTaskService workerTasks) {
    this.workerTasks = workerTasks;
  }

  @GetMapping(value = "/file", produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "워커용 원본 워크플로 다운로드 및 실행 시작",
      description =
          "queued 시도를 running으로 원자적 전환하고 임대(SCAN_LEASE_DURATION, 기본 60초)를 발급한 뒤 S3 원본 JSON 바이트를 반환한다. 임대 길이는 설정에 따라 다르므로 워커는 응답의 X-Lease-Expires-At을 기준으로 판단한다. 상태를 바꾸므로 HEAD 요청은 405 METHOD_NOT_ALLOWED로 거절한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "원본 워크플로 JSON 바이트와 해시·임대 만료 시각 헤더",
        headers = {
          @Header(
              name = "X-Input-Sha256",
              description = "서버가 기록한 원본 바이트의 SHA-256(소문자 hex 64자)",
              schema = @Schema(type = "string")),
          @Header(
              name = "X-Lease-Expires-At",
              description = "발급된 임대 만료 시각(UTC ISO-8601). 워커는 이 값을 임대 기준으로 쓴다",
              schema = @Schema(type = "string", format = "date-time"))
        },
        content =
            @Content(
                mediaType = MediaType.APPLICATION_JSON_VALUE,
                schema = @Schema(type = "string", format = "binary"))),
    @ApiResponse(
        responseCode = "401",
        description = WORKER_AUTH_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "403",
        description = WORKER_FORBIDDEN,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = ATTEMPT_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = "취소된 작업(TASK_CANCELLED) 또는 실행 불가 상태(TASK_NOT_RUNNABLE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "410",
        description = ATTEMPT_EXPIRED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description = "S3 원본 읽기 일시 실패(STORAGE_UNAVAILABLE)",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ResponseEntity<byte[]> fetchFile(
      @PathVariable("taskId")
          @Parameter(description = "작업 ID", schema = @Schema(format = "uuid"), example = TASK_ID)
          String taskId,
      @PathVariable("attemptId")
          @Parameter(description = "시도 ID", schema = @Schema(format = "uuid"), example = ATTEMPT_ID)
          String attemptId) {
    WorkerFileDownload download = workerTasks.fetchFile(taskId, attemptId);
    return ResponseEntity.ok()
        .contentType(MediaType.APPLICATION_JSON)
        .header("X-Input-Sha256", download.inputSha256())
        .header("X-Lease-Expires-At", download.leaseExpiresAt().toString())
        .body(download.content());
  }

  /** Spring MVC는 GET 매핑을 HEAD에도 적용한다. HEAD로 시도가 시작되면 워커가 본문을 받지 못하므로 상태를 바꾸지 않고 거절한다. */
  @RequestMapping(value = "/file", method = RequestMethod.HEAD)
  @Operation(hidden = true)
  public void rejectFileHead() throws HttpRequestMethodNotSupportedException {
    throw new HttpRequestMethodNotSupportedException("HEAD", List.of("GET"));
  }

  @PostMapping(value = "/heartbeat", produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "워커 시도 임대 연장",
      description =
          "실행 중인 유효 시도의 임대를 서버 시각 기준으로 임대 길이(SCAN_LEASE_DURATION, 기본 60초)만큼 연장한다. 워커는 응답의 leaseExpiresAt을 기준으로 다음 heartbeat 시점을 정한다. 409/410을 받으면 워커는 즉시 분석을 중단해야 한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "임대를 연장했다",
        content = @Content(schema = @Schema(implementation = HeartbeatResponse.class))),
    @ApiResponse(
        responseCode = "401",
        description = WORKER_AUTH_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "403",
        description = WORKER_FORBIDDEN,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = ATTEMPT_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = "취소된 작업(TASK_CANCELLED) 또는 실행 중이 아닌 시도(ATTEMPT_NOT_ACTIVE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "410",
        description = ATTEMPT_EXPIRED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public HeartbeatResponse heartbeat(
      @PathVariable("taskId")
          @Parameter(description = "작업 ID", schema = @Schema(format = "uuid"), example = TASK_ID)
          String taskId,
      @PathVariable("attemptId")
          @Parameter(description = "시도 ID", schema = @Schema(format = "uuid"), example = ATTEMPT_ID)
          String attemptId) {
    HeartbeatResult result = workerTasks.heartbeat(taskId, attemptId);
    return new HeartbeatResponse(
        new HeartbeatData(result.taskId(), result.attemptId(), result.leaseExpiresAt()));
  }

  @PutMapping(
      value = "/result",
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "워커 검사 결과 제출",
      description =
          "Idempotency-Key(원본 요청 본문 SHA-256)와 시도·임대·버전·해시 일치를 검증한 뒤 결과를 저장한다. 완료 결과의 serviceReport와 assessment 원문은 비공개 S3에 저장한다.",
      requestBody =
          @io.swagger.v3.oas.annotations.parameters.RequestBody(
              required = true,
              description =
                  "워커 검사 결과 JSON 본문(공백 없는 직렬화 권장, 최대 크기 SCAN_MAX_RESULT_BYTES, 기본 6291456바이트 = 6 MiB). outcome이 completed이면 inspection, failed·timed_out이면 error가 필수다. 서버는 원본 바이트로 Idempotency-Key를 검증하므로 문서에 없는 추가 필드도 그대로 해시에 포함된다",
              content =
                  @Content(
                      mediaType = MediaType.APPLICATION_JSON_VALUE,
                      schema =
                          @Schema(
                              oneOf = {
                                WorkerResultSchemas.CompletedResult.class,
                                WorkerResultSchemas.FailedResult.class
                              }))))
  @ApiResponses({
    @ApiResponse(
        responseCode = "201",
        description = "최초 결과 수락·저장 완료",
        content = @Content(schema = @Schema(implementation = ResultSubmissionResponse.class))),
    @ApiResponse(
        responseCode = "200",
        description = "이미 수락한 동일 제출(Idempotency-Key 일치)의 멱등 재전송",
        content = @Content(schema = @Schema(implementation = ResultSubmissionResponse.class))),
    @ApiResponse(
        responseCode = "400",
        description = "Idempotency-Key 누락·불일치 또는 잘못된 JSON(BAD_REQUEST)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = WORKER_AUTH_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "403",
        description = WORKER_FORBIDDEN,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = ATTEMPT_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description =
            "식별자·해시 불일치(RESULT_IDENTITY_MISMATCH), 다른 본문 재제출(IDEMPOTENCY_KEY_CONFLICT), 취소됨(TASK_CANCELLED), 또는 실행 중이 아님(ATTEMPT_NOT_ACTIVE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "410",
        description = ATTEMPT_EXPIRED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "413",
        description = "결과 본문이 최대 크기(SCAN_MAX_RESULT_BYTES, 기본 6 MiB)를 초과함(PAYLOAD_TOO_LARGE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "415",
        description = "Content-Type이 application/json이 아님(UNSUPPORTED_MEDIA_TYPE)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "422",
        description = "결과 스키마 위반(INVALID_RESULT)",
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description = "결과 저장소 일시 오류(STORAGE_UNAVAILABLE)",
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public ResponseEntity<ResultSubmissionResponse> submitResult(
      @PathVariable("taskId")
          @Parameter(description = "작업 ID", schema = @Schema(format = "uuid"), example = TASK_ID)
          String taskId,
      @PathVariable("attemptId")
          @Parameter(description = "시도 ID", schema = @Schema(format = "uuid"), example = ATTEMPT_ID)
          String attemptId,
      @RequestHeader(name = "Idempotency-Key", required = false)
          @Parameter(description = "요청 본문 원본 바이트의 SHA-256(소문자 hex 64자)", required = true)
          String idempotencyKey,
      HttpServletRequest request)
      throws IOException {
    byte[] rawBody = readBoundedBody(request, workerTasks.maxResultBytes());
    ResultSubmission submission =
        workerTasks.submitResult(taskId, attemptId, idempotencyKey, rawBody);
    HttpStatus status = submission.created() ? HttpStatus.CREATED : HttpStatus.OK;
    return ResponseEntity.status(status)
        .body(
            new ResultSubmissionResponse(
                new ResultSubmissionData(
                    submission.scanRunId(),
                    submission.executionStatus(),
                    submission.analysisCoverage())));
  }

  private static byte[] readBoundedBody(HttpServletRequest request, long maxBytes)
      throws IOException {
    long contentLength = request.getContentLengthLong();
    if (contentLength > maxBytes) {
      throw ScanException.resultTooLarge(maxBytes);
    }
    try (InputStream in = request.getInputStream();
        ByteArrayOutputStream out = new ByteArrayOutputStream()) {
      byte[] buffer = new byte[8192];
      long total = 0;
      int read;
      while ((read = in.read(buffer)) != -1) {
        total += read;
        if (total > maxBytes) {
          throw ScanException.resultTooLarge(maxBytes);
        }
        out.write(buffer, 0, read);
      }
      return out.toByteArray();
    }
  }

  @Schema(requiredProperties = "data")
  public record HeartbeatResponse(HeartbeatData data) {}

  @Schema(requiredProperties = {"taskId", "attemptId", "leaseExpiresAt"})
  public record HeartbeatData(UUID taskId, UUID attemptId, Instant leaseExpiresAt) {}

  @Schema(requiredProperties = "data")
  public record ResultSubmissionResponse(ResultSubmissionData data) {}

  @Schema(requiredProperties = {"scanRunId", "executionStatus", "analysisCoverage"})
  public record ResultSubmissionData(
      UUID scanRunId, String executionStatus, String analysisCoverage) {}
}
