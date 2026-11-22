package dev.workflowhub.workflow.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.workflow.service.WorkflowQueryException;
import dev.workflowhub.workflow.service.WorkflowQueryService;
import dev.workflowhub.workflow.service.WorkflowQueryService.VersionItem;
import dev.workflowhub.workflow.service.WorkflowQueryService.WorkflowItem;
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
import org.springframework.http.MediaType;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(produces = MediaType.APPLICATION_JSON_VALUE)
@Tag(name = "workflows")
public class WorkflowQueryController {
  private static final String WORKFLOW_ID = "0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10";
  private static final String VERSION_ID = "5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33";
  private static final String TITLE = "주문 접수 Slack 알림";
  private static final String REGISTERED_AT = "2026-11-22T04:15:30Z";
  private static final String CURSOR_PARAMETER = "다음 페이지를 요청할 때 같은 목록의 nextCursor 값을 그대로 사용한다";
  private static final String END_CURSOR = "다음 페이지에 사용할 값. 마지막 페이지에서는 null";
  private static final String LATEST_VERSION = "가장 최근에 등록한 버전. 등록된 버전이 없으면 null";
  private static final String BAD_PAGINATION =
      "limit이 정수 범위를 벗어나거나(INVALID_LIMIT), cursor가 유효하지 않다(INVALID_CURSOR)";
  private static final String UNAUTHORIZED = "토큰이 없거나 유효하지 않다";
  private static final String NOT_FOUND = "요청한 ID의 소유 워크플로를 찾을 수 없다(WORKFLOW_NOT_FOUND)";
  private static final String SERVER_ERROR = "예상하지 못한 서버 오류. 응답의 requestId로 서버 로그를 찾는다";
  private final WorkflowQueryService queries;

  public WorkflowQueryController(WorkflowQueryService queries) {
    this.queries = queries;
  }

  @GetMapping("/api/me/workflows")
  @Operation(summary = "내 워크플로 목록", description = "로그인 사용자가 소유한 워크플로를 최근 등록순으로 조회한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "워크플로 목록을 조회했다",
        content =
            @Content(
                schema = @Schema(implementation = WorkflowListResponse.class),
                examples =
                    @ExampleObject(
                        name = "빈 목록",
                        value =
                            """
                    {"data":{"items":[],"nextCursor":null}}
                    """))),
    @ApiResponse(
        responseCode = "400",
        description = BAD_PAGINATION,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public WorkflowListResponse listWorkflows(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
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
      @RequestParam(name = "cursor", required = false) @Parameter(description = CURSOR_PARAMETER)
          String cursor) {
    var page = queries.listWorkflows(jwt.getSubject(), parseLimit(limit), cursor);
    var items = page.items().stream().map(WorkflowSummary::from).toList();
    return new WorkflowListResponse(new WorkflowListData(items, page.nextCursor()));
  }

  @GetMapping("/api/workflows/{workflowId}")
  @Operation(summary = "내 워크플로 상세와 최신 버전")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "워크플로 상세를 조회했다",
        content =
            @Content(
                schema = @Schema(implementation = WorkflowDetailResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{
                              "workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",
                              "title":"주문 접수 Slack 알림",
                              "createdAt":"2026-11-22T04:15:30Z",
                              "latestVersion":{
                                "versionId":"5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33",
                                "versionLabel":"v1",
                                "createdAt":"2026-11-22T04:15:30Z"
                              }
                            }}
                            """))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public WorkflowDetailResponse getWorkflow(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId) {
    var workflow = queries.getWorkflow(jwt.getSubject(), workflowId);
    return new WorkflowDetailResponse(
        new WorkflowDetailData(
            workflow.workflowId(),
            workflow.title(),
            VersionMetadata.from(workflow.latestVersion()),
            workflow.createdAt()));
  }

  @GetMapping("/api/workflows/{workflowId}/versions")
  @Operation(summary = "내 워크플로 버전 목록", description = "내가 소유한 워크플로의 버전을 최근 등록순으로 조회한다.")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "버전 목록을 조회했다",
        content =
            @Content(
                schema = @Schema(implementation = VersionListResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{"items":[{
                              "versionId":"5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33",
                              "versionLabel":"v1",
                              "createdAt":"2026-11-22T04:15:30Z"
                            }],"nextCursor":null}}
                            """))),
    @ApiResponse(
        responseCode = "400",
        description = BAD_PAGINATION,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public VersionListResponse listVersions(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
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
      @RequestParam(name = "cursor", required = false) @Parameter(description = CURSOR_PARAMETER)
          String cursor) {
    var page = queries.listVersions(jwt.getSubject(), workflowId, parseLimit(limit), cursor);
    var items = page.items().stream().map(VersionMetadata::from).toList();
    return new VersionListResponse(new VersionListData(items, page.nextCursor()));
  }

  private static Integer parseLimit(String limit) {
    if (limit == null) {
      return null;
    }
    try {
      return Integer.valueOf(limit);
    } catch (NumberFormatException e) {
      throw WorkflowQueryException.invalidLimit();
    }
  }

  @Schema(requiredProperties = "data")
  public record WorkflowListResponse(WorkflowListData data) {}

  @Schema(requiredProperties = "data")
  public record WorkflowDetailResponse(WorkflowDetailData data) {}

  @Schema(requiredProperties = "data")
  public record VersionListResponse(VersionListData data) {}

  @Schema(requiredProperties = {"items", "nextCursor"})
  public record WorkflowListData(
      List<WorkflowSummary> items,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = END_CURSOR,
              types = {"string", "null"})
          String nextCursor) {}

  @Schema(requiredProperties = {"items", "nextCursor"})
  public record VersionListData(
      List<VersionMetadata> items,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = END_CURSOR,
              types = {"string", "null"})
          String nextCursor) {}

  @Schema(requiredProperties = {"workflowId", "title", "latestVersion"})
  public record WorkflowSummary(
      @Schema(example = WORKFLOW_ID) UUID workflowId,
      @Schema(example = TITLE) String title,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = LATEST_VERSION,
              types = {"object", "null"},
              schemaResolution = Schema.SchemaResolution.INLINE)
          VersionMetadata latestVersion) {
    private static WorkflowSummary from(WorkflowItem item) {
      return new WorkflowSummary(
          item.workflowId(), item.title(), VersionMetadata.from(item.latestVersion()));
    }
  }

  @Schema(requiredProperties = {"workflowId", "title", "latestVersion", "createdAt"})
  public record WorkflowDetailData(
      @Schema(example = WORKFLOW_ID) UUID workflowId,
      @Schema(example = TITLE) String title,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = LATEST_VERSION,
              types = {"object", "null"},
              schemaResolution = Schema.SchemaResolution.INLINE)
          VersionMetadata latestVersion,
      @Schema(example = REGISTERED_AT) Instant createdAt) {}

  @Schema(requiredProperties = {"versionId", "versionLabel", "createdAt"})
  public record VersionMetadata(
      @Schema(example = VERSION_ID) UUID versionId,
      @Schema(example = "v1") String versionLabel,
      @Schema(example = REGISTERED_AT) Instant createdAt) {
    private static VersionMetadata from(VersionItem item) {
      return item == null
          ? null
          : new VersionMetadata(item.versionId(), item.versionLabel(), item.createdAt());
    }
  }
}
