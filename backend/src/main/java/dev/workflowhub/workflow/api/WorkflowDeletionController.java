package dev.workflowhub.workflow.api;

import com.fasterxml.jackson.annotation.JsonInclude;
import dev.workflowhub.common.api.ApiError;
import dev.workflowhub.workflow.service.WorkflowDeletionService;
import dev.workflowhub.workflow.service.WorkflowDeletionService.Deletion;
import dev.workflowhub.workflow.service.WorkflowDeletionService.Restoration;
import dev.workflowhub.workflow.service.WorkflowQueryException;
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
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/** 소유자의 버전·워크플로 삭제와 복구(#37). 삭제하면 즉시 조회·다운로드에서 제외되고, 복구 기간이 지나면 원본이 지워진다. */
@RestController
@Tag(name = "workflows")
public class WorkflowDeletionController {
  private static final String WORKFLOW_ID = "0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10";
  private static final String VERSION_ID = "5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33";
  private static final String DELETED_AT = "2026-11-22T04:15:30Z";
  private static final String RESTORE_UNTIL = "2026-11-29T04:15:30Z";
  private static final String UNAUTHORIZED = "토큰이 없거나 유효하지 않다";
  private static final String VERSION_NOT_FOUND_BASE =
      "요청한 소유 워크플로 버전을 찾을 수 없다(WORKFLOW_VERSION_NOT_FOUND).";
  private static final String WORKFLOW_NOT_FOUND_BASE = "요청한 소유 워크플로를 찾을 수 없다(WORKFLOW_NOT_FOUND).";
  private static final String VERSION_NOT_FOUND =
      VERSION_NOT_FOUND_BASE + " 이미 삭제했거나 원본이 지워진 버전도 같다";
  private static final String WORKFLOW_NOT_FOUND =
      WORKFLOW_NOT_FOUND_BASE + " 이미 삭제했거나 원본이 지워진 워크플로도 같다";
  private static final String RESTORE_VERSION_NOT_FOUND =
      VERSION_NOT_FOUND_BASE
          + " 소유하지 않았거나 없는 버전이거나 원본 정리가 끝난 버전이다. 복구 기간 안의 삭제된 버전은 해당하지 않으며, 복구 기간이 끝났어도 정리 전이면 409다";
  private static final String RESTORE_WORKFLOW_NOT_FOUND =
      WORKFLOW_NOT_FOUND_BASE
          + " 소유하지 않았거나 없는 워크플로이거나 모든 원본의 정리가 끝난 워크플로이다. 복구 기간 안의 삭제된 워크플로는 해당하지 않으며, 복구 기간이 끝났어도 정리 전이면 409다";
  private static final String NOT_DELETED = "삭제 상태가 아니다(NOT_DELETED)";
  private static final String RESTORE_UNAVAILABLE =
      "복구할 수 없다(RESTORE_UNAVAILABLE). 복구 기간이 끝났거나 원본 삭제가 시작됐거나 원본 파일이 더 이상 없다";
  private static final String STORAGE_UNAVAILABLE =
      "원본 파일의 존재를 저장소에서 확인할 수 없다(STORAGE_UNAVAILABLE). 아무것도 바뀌지 않았으므로 다시 시도한다";
  private static final String SERVER_ERROR = "예상하지 못한 서버 오류. 응답의 requestId로 서버 로그를 찾는다";
  private final WorkflowDeletionService deletion;

  public WorkflowDeletionController(WorkflowDeletionService deletion) {
    this.deletion = deletion;
  }

  @DeleteMapping(
      path = "/api/workflows/{workflowId}/versions/{versionId}",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "내 워크플로 버전 삭제",
      description =
          """
          선택한 버전을 삭제한다. 삭제를 수락하는 즉시 조회·다운로드·비교에서 제외되고, 같은 번호는 다시 쓰지 않는다. \
          원본은 restoreUntil(기본 7일 뒤)까지 보관하며 그 안에는 복구할 수 있고, 이후 S3 원본을 지운다. \
          살아 있는 버전이 이 하나뿐이면 워크플로 전체를 삭제하고 workflowDeleted가 true다. \
          allowWorkflowDelete=false를 보내면 그 경우 아무것도 바꾸지 않고 409 LAST_VERSION_REMAINING으로 거절한다. \
          "버전만 삭제"로 확인한 화면은 이 값을 보내, 그사이 다른 탭·기기에서 나머지 버전이 지워졌을 때 \
          워크플로 전체를 지우지 않고 사용자에게 다시 묻는다. \
          같은 요청을 다시 보내면 이미 삭제된 버전이므로 404다.""")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "버전을 삭제했다. workflowDeleted가 true이면 마지막 버전이라 워크플로 전체가 삭제됐다",
        content =
            @Content(
                schema = @Schema(implementation = DeletionResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{
                              "workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",
                              "versionId":"5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33",
                              "workflowDeleted":false,
                              "deletedAt":"2026-11-22T04:15:30Z",
                              "restoreUntil":"2026-11-29T04:15:30Z"
                            }}
                            """))),
    @ApiResponse(
        responseCode = "400",
        description = "allowWorkflowDelete가 true나 false가 아니다. 빈 값도 해당한다(BAD_REQUEST). 아무것도 바뀌지 않았다",
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
            "allowWorkflowDelete=false인데 살아 있는 마지막 버전이다(LAST_VERSION_REMAINING). 아무것도 바뀌지 않았다",
        content =
            @Content(
                schema = @Schema(implementation = ApiError.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"code":"LAST_VERSION_REMAINING","message":"This is the last version; deleting it would delete the workflow","requestId":"3f1c0f5e-52a8-4d2b-9a43-6b2f6f8f0c11"}
                            """))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public DeletionResponse deleteVersion(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(
              description = "삭제할 버전 ID",
              schema = @Schema(format = "uuid"),
              example = VERSION_ID)
          String versionId,
      @RequestParam(name = "allowWorkflowDelete", required = false)
          @Parameter(
              description =
                  "마지막 버전일 때 워크플로 전체 삭제를 허용할지. false이면 그 경우 409로 거절한다. 생략하면 true(기존 동작). 값은 true 또는 false만 받는다",
              schema = @Schema(type = "boolean", defaultValue = "true"))
          String allowWorkflowDelete) {
    return DeletionResponse.of(
        deletion.deleteVersion(
            jwt.getSubject(),
            workflowId,
            versionId,
            parseAllowWorkflowDelete(allowWorkflowDelete)));
  }

  /**
   * 생략하면 기존 동작(true)이다. 빈 값이나 1·yes처럼 Spring이 참으로 바꾸는 값은 거절한다. 기본값이 더 많이 지우는 쪽이라, 값을 채우지 못한 요청이
   * 워크플로 전체 삭제로 처리되지 않게 하기 위해서다.
   */
  private static boolean parseAllowWorkflowDelete(String value) {
    if (value == null) {
      return true;
    }
    return switch (value) {
      case "true" -> true;
      case "false" -> false;
      default -> throw WorkflowQueryException.invalidAllowWorkflowDelete();
    };
  }

  @DeleteMapping(path = "/api/workflows/{workflowId}", produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "내 워크플로 전체 삭제",
      description =
          """
          워크플로와 아직 삭제하지 않은 모든 버전을 삭제한다. 이미 개별 삭제한 버전은 자기 복구 기간을 그대로 유지한다. \
          삭제를 수락하는 즉시 조회·다운로드·비교에서 제외되고, 원본은 restoreUntil(기본 7일 뒤)까지 보관한 뒤 지운다.""")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "워크플로를 삭제했다. versionId는 null이다",
        content =
            @Content(
                schema = @Schema(implementation = DeletionResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{
                              "workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",
                              "versionId":null,
                              "workflowDeleted":true,
                              "deletedAt":"2026-11-22T04:15:30Z",
                              "restoreUntil":"2026-11-29T04:15:30Z"
                            }}
                            """))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = WORKFLOW_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public DeletionResponse deleteWorkflow(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "삭제할 워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId) {
    return DeletionResponse.of(deletion.deleteWorkflow(jwt.getSubject(), workflowId));
  }

  @PostMapping(
      path = "/api/workflows/{workflowId}/versions/{versionId}/restore",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "삭제한 버전 복구",
      description =
          """
          복구 기간 안의 삭제된 버전을 되살린다. S3에 원본이 남아 있는지 확인한 뒤에만 복구한다. \
          삭제된 워크플로의 버전이면 그 버전과 워크플로를 함께 되살리고(workflowRestored가 true), \
          같이 삭제된 다른 버전은 삭제 상태로 남는다. 삭제된 버전 목록은 버전 목록의 includeDeleted로 조회한다.""")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "버전을 복구했다",
        content =
            @Content(
                schema = @Schema(implementation = RestoreResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{
                              "workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",
                              "workflowRestored":false,
                              "restoredVersionIds":["5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33"],
                              "unavailableVersionIds":[]
                            }}
                            """))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = RESTORE_VERSION_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = NOT_DELETED + " 또는 " + RESTORE_UNAVAILABLE,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description = STORAGE_UNAVAILABLE,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public RestoreResponse restoreVersion(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId,
      @PathVariable("versionId")
          @Parameter(
              description = "복구할 버전 ID",
              schema = @Schema(format = "uuid"),
              example = VERSION_ID)
          String versionId) {
    return RestoreResponse.of(deletion.restoreVersion(jwt.getSubject(), workflowId, versionId));
  }

  @PostMapping(
      path = "/api/workflows/{workflowId}/restore",
      produces = MediaType.APPLICATION_JSON_VALUE)
  @Operation(
      summary = "삭제한 워크플로 복구",
      description =
          """
          워크플로를 삭제할 때 함께 삭제된 버전 중 복구 기간 안에 있고 S3 원본이 남아 있는 버전을 되살린다. \
          그 전에 개별 삭제한 버전은 되살리지 않으며 각자 기간 안에서 따로 복구한다. \
          원본이 사라졌거나 복구할 수 없는 버전은 unavailableVersionIds에 담고, 되살릴 수 있는 버전이 하나도 없으면 409다.""")
  @ApiResponses({
    @ApiResponse(
        responseCode = "200",
        description = "워크플로를 복구했다. 일부 버전만 복구됐으면 나머지는 unavailableVersionIds에 있다",
        content =
            @Content(
                schema = @Schema(implementation = RestoreResponse.class),
                examples =
                    @ExampleObject(
                        value =
                            """
                            {"data":{
                              "workflowId":"0b6a8d7e-2f4c-4e0a-9a43-1d1f5c3e7a10",
                              "workflowRestored":true,
                              "restoredVersionIds":["5d2f7c1a-8b3e-4c6d-a1f0-9e4b2c7d8a33"],
                              "unavailableVersionIds":[]
                            }}
                            """))),
    @ApiResponse(
        responseCode = "401",
        description = UNAUTHORIZED,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "404",
        description = RESTORE_WORKFLOW_NOT_FOUND,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "409",
        description = NOT_DELETED + " 또는 " + RESTORE_UNAVAILABLE,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "500",
        description = SERVER_ERROR,
        content = @Content(schema = @Schema(implementation = ApiError.class))),
    @ApiResponse(
        responseCode = "503",
        description = STORAGE_UNAVAILABLE,
        content = @Content(schema = @Schema(implementation = ApiError.class)))
  })
  public RestoreResponse restoreWorkflow(
      @AuthenticationPrincipal @Parameter(hidden = true) Jwt jwt,
      @PathVariable("workflowId")
          @Parameter(
              description = "복구할 워크플로 ID",
              schema = @Schema(format = "uuid"),
              example = WORKFLOW_ID)
          String workflowId) {
    return RestoreResponse.of(deletion.restoreWorkflow(jwt.getSubject(), workflowId));
  }

  @Schema(requiredProperties = "data")
  public record DeletionResponse(DeletionData data) {
    private static DeletionResponse of(Deletion result) {
      return new DeletionResponse(
          new DeletionData(
              result.workflowId(),
              result.versionId(),
              result.workflowDeleted(),
              result.deletedAt(),
              result.restoreUntil()));
    }
  }

  @Schema(requiredProperties = "data")
  public record RestoreResponse(RestoreData data) {
    private static RestoreResponse of(Restoration result) {
      return new RestoreResponse(
          new RestoreData(
              result.workflowId(),
              result.workflowRestored(),
              result.restoredVersionIds(),
              result.unavailableVersionIds()));
    }
  }

  @Schema(
      requiredProperties = {
        "workflowId",
        "versionId",
        "workflowDeleted",
        "deletedAt",
        "restoreUntil"
      })
  public record DeletionData(
      @Schema(example = WORKFLOW_ID) UUID workflowId,
      @JsonInclude(JsonInclude.Include.ALWAYS)
          @Schema(
              description = "삭제를 요청한 버전 ID. 워크플로 전체를 삭제한 요청에서는 null",
              example = VERSION_ID,
              types = {"string", "null"},
              format = "uuid")
          UUID versionId,
      @Schema(description = "워크플로 전체가 삭제됐으면 true", example = "false") boolean workflowDeleted,
      @Schema(example = DELETED_AT) Instant deletedAt,
      @Schema(description = "이 시각까지 복구할 수 있다. 이후 원본을 지운다", example = RESTORE_UNTIL)
          Instant restoreUntil) {}

  @Schema(
      requiredProperties = {
        "workflowId",
        "workflowRestored",
        "restoredVersionIds",
        "unavailableVersionIds"
      })
  public record RestoreData(
      @Schema(example = WORKFLOW_ID) UUID workflowId,
      @Schema(description = "삭제 상태였던 워크플로를 이번 요청으로 되살렸으면 true", example = "true")
          boolean workflowRestored,
      @Schema(description = "이번 요청으로 되살린 버전 ID") List<UUID> restoredVersionIds,
      @Schema(description = "함께 삭제됐지만 복구하지 못한 버전 ID(원본 없음 등). 버전 복구에서는 항상 비어 있다")
          List<UUID> unavailableVersionIds) {}
}
