import { createHash } from "node:crypto";
import { z } from "zod";
import { assessmentReportSchema } from "./assessment-contract.js";
import type { FileAssessment } from "./assessment-contract.js";
import { categories, staticLocationSchema } from "./static-contract.js";
import type { Category, Finding, StaticLocation } from "./static-contract.js";

export const serviceReportLimits = {
  itemsPerGroup: 256,
  bytes: 3 * 1024 * 1024,
} as const;
const hash = z.string().regex(/^[a-f0-9]{64}$/);
const count = z.int().nonnegative();
const text = z.string().min(1).max(512);
const groups = [
  "findings",
  "observations",
  "analysisGaps",
  "environmentChecks",
  "scopeNotes",
] as const;
type DiagnosticGroup = "analysisGaps" | "environmentChecks" | "scopeNotes";
const categoryNames: Record<Category, string> = {
  secrets: "비밀정보",
  pii: "개인정보",
  request_auth: "요청자 검증",
  egress: "외부 전송",
  ssrf: "요청 목적지",
  sql: "SQL 입력",
  code_execution: "명령·코드 실행",
  transport: "통신 설정",
  output: "응답·로그",
  dependencies: "의존성과 권한",
};
const actions: Record<Category, string> = {
  secrets:
    "실제 키인지 확인하고 노출된 키는 폐기·교체하세요. 파일에는 자격 증명 참조를 사용하세요.",
  pii: "업무에 필요한 개인정보만 남기고 고정 예시 데이터와 전송·출력 필드를 검토하세요.",
  request_auth:
    "요청자를 확인하는 인증과 권한 검사를 구성하고 허용·거부 사례를 확인하세요.",
  egress:
    "수신 대상과 업무 목적을 확인하고 필요한 데이터만 허용된 곳에 보내세요.",
  ssrf: "허용한 요청 origin을 고정하고 DNS·리다이렉트·내부망 접근 제한을 확인하세요.",
  sql: "SQL 구조와 식별자를 고정하고 외부 입력은 값 매개변수로 바인딩하세요.",
  code_execution:
    "외부 입력을 명령 문자열에 합치지 말고 실행 기능과 운영 권한을 제한하세요.",
  transport:
    "인증서 검증과 암호화된 통신을 사용하고 URL에서 인증정보를 제거하세요.",
  output:
    "응답·메시지·로그에는 필요한 필드만 포함하고 열람 대상과 보존 기간을 확인하세요.",
  dependencies:
    "실제 설치 패키지와 하위 워크플로, 파일·SSH·도구의 실행 권한을 확인하세요.",
};

type DiagnosticDescription = {
  group: DiagnosticGroup;
  title: string;
  explanation: string;
  action: string;
};
const diagnosticDescriptions = new Map<string, DiagnosticDescription>();
function describe(
  codes: readonly string[],
  group: DiagnosticGroup,
  title: string,
  explanation: string,
  action: string,
): void {
  for (const code of codes)
    diagnosticDescriptions.set(code, { group, title, explanation, action });
}
describe(
  [
    "runtime_evidence_missing",
    "database_runtime_schema_and_permissions_unverified",
    "database_match_columns_and_effect_unverified",
    "database_filter_and_result_scope_unverified",
    "database_deletion_scope_unverified",
    "filesystem_permissions_and_path_scope_unverified",
    "remote_host_permissions_and_directory_unverified",
    "ai_runtime_invocation_and_permissions_unverified",
    "model_tool_query_and_execution_unverified",
  ],
  "environmentChecks",
  "실제 실행 권한 확인",
  "JSON 설정만으로 실제 DB·파일·SSH·도구 권한과 실행 영향을 확인할 수 없습니다.",
  "운영자가 실행 계정의 최소 권한과 접근 범위를 확인하세요. 비밀키를 제출할 필요는 없습니다.",
);
describe(
  [
    "dns_redirect_and_network_access_unverified",
    "destination_access_unverified",
    "redirect_destination_unverified",
    "provider_endpoint_from_credentials_unverified",
    "ai_model_endpoint_from_credentials_unverified",
  ],
  "environmentChecks",
  "실제 통신 대상 확인",
  "최종 목적지·DNS·리다이렉트·네트워크 접근은 실행 환경에 따라 달라집니다.",
  "허용 도메인과 내부망 접근 제한을 운영 환경에서 확인하세요.",
);
describe(
  [
    "trusted_policy_transfer_unresolved",
    "ai_model_transfer_policy_unresolved",
    "model_processing_and_retention_unverified",
    "recipient_identity_unresolved",
    "response_recipient_authorization_unverified",
    "instance_workflow_link_included",
  ],
  "environmentChecks",
  "수신자와 데이터 사용 정책 확인",
  "전송·응답 설정은 보이지만 수신자의 권한과 해당 데이터 사용의 허용 여부는 확인되지 않았습니다.",
  "수신 대상, 외부 AI 사용, 데이터 보존·공유 범위가 업무 정책에 맞는지 확인하세요.",
);
describe(
  [
    "transferred_data_sensitivity_unverified",
    "response_data_sensitivity_unverified",
    "read_response_classification_unverified",
    "sheet_headers_runtime_unverified",
    "sheet_empty_header_fallback_possible",
    "ai_model_invocation_and_output_unverified",
    "model_tool_invocation_unverified",
    "trigger_payload_schema_unverified",
  ],
  "environmentChecks",
  "실제 입력·응답 데이터 확인",
  "외부 서비스 응답, 시트 헤더, 모델 출력과 실제 도구 선택은 JSON 정의에 포함되지 않습니다.",
  "실제 사용 전에 데이터 구조와 전송 범위를 확인하고 필요하면 익명화한 구조 정보로 다시 검토하세요.",
);
describe(
  [
    "nlp_english_model_profile",
    "nlp_language_outside_profile",
    "nlp_metadata_formats_only",
    "nlp_program_formats_only",
    "nlp_template_literal_text_only",
    "nlp_json_string_values_only",
    "nlp_technical_entity_filtered",
    "nlp_chunked_text_profile",
  ],
  "scopeNotes",
  "개인정보 탐지의 지원 범위",
  "개인정보 검사는 지원 형식과 영어 문맥 모델을 사용합니다. 한국어 이름·주소와 모든 문맥을 포괄하지 않습니다.",
  "이 범위를 확인하고 민감한 자료를 배포할 때 사람이 한 번 더 검토하세요. 탐지 0건은 개인정보 부재를 보증하지 않습니다.",
);
describe(
  [
    "python_static_profile_limited",
    "model_attack_resistance_and_value_flow_unverified",
  ],
  "scopeNotes",
  "정적 검사로 확인하는 범위",
  "워크플로·코드·AI 모델을 실행하지 않았으며 실제 실행 결과나 모델의 공격 저항성을 시험한 결과가 아닙니다.",
  "결과를 정적 검토 근거로 사용하고 운영 환경의 실행 보증으로 사용하지 마세요.",
);
describe(
  [
    "code_ast_profile_limit",
    "code_source_observation_limit",
    "code_source_size_limit",
    "code_token_observation_incomplete",
    "code_transfer_budget_exceeded",
    "code_value_shape_limit",
    "constant_inference_size_limit",
    "database_mapping_limit",
    "definition_diagnostic_limit",
    "definition_finding_limit",
    "definition_origin_limit",
    "flow_budget_exceeded",
    "native_field_size_limit",
    "native_input_scope_limit",
    "native_total_text_limit",
    "native_finding_limit",
    "python_ast_limit",
    "python_alias_analysis_limit",
  ],
  "analysisGaps",
  "검사 처리 한도에 도달",
  "일부 경로·필드·코드가 검사 시간·크기·복잡도 한도 안에서 분석되지 못했습니다.",
  "표시된 위치를 수동 검토하거나 업무 의미를 유지해 나눈 정의로 재검사하세요. 누락 부분을 정상으로 계산하지 않습니다.",
);
describe(
  [
    "code_parse_unavailable",
    "expression_parse_unavailable",
    "python_parse_unavailable",
    "nlp_json_text_unresolved",
    "native_python_source_missing",
    "required_send_field_missing",
    "binary_payload_unavailable",
  ],
  "analysisGaps",
  "분석에 필요한 정의가 불완전함",
  "파싱할 수 없는 코드나 누락된 필드·바이너리 내용 때문에 해당 부분을 확인하지 못했습니다.",
  "정의의 형식과 누락된 파일을 확인하고 수정한 정확한 파일로 다시 검사하세요.",
);
describe(
  [
    "code_alias_mutation_unresolved",
    "code_bounded_flow_partial",
    "code_closure_capture_unresolved",
    "code_effects_partially_analyzed",
    "code_language_unresolved",
    "code_logging_and_sensitivity_partially_analyzed",
    "code_logging_semantics_partial",
    "code_loop_carried_state_unverified",
    "code_loop_summary_partial",
    "code_mapping_unsupported",
    "code_object_mutation_unresolved",
    "code_source_binding_unresolved",
    "code_source_observations_only",
    "code_statement_profile_unresolved",
    "code_try_state_unresolved",
    "javascript_control_flow_partial",
    "javascript_profile_unsupported",
    "javascript_semantics_partially_analyzed",
    "unsupported_code_language",
    "unsupported_log_code_profile",
    "python_wildcard_import_unresolved",
    "python_dynamic_import_unresolved",
  ],
  "analysisGaps",
  "코드 흐름의 일부가 미지원",
  "코드의 변경 효과·함수·반복·외부 호출을 끝까지 해석하지 못했습니다. 관측한 입력과 민감 후보는 유지됩니다.",
  "해당 코드의 입력·출력과 부작용을 검토하세요. LLM 설명도 별도 검증 없이 안전 판정으로 사용하지 않습니다.",
);
describe(
  [
    "sql_input_flow_partially_analyzed",
    "sql_parameter_binding_unresolved",
    "sql_parameter_mapping_data_dependent",
    "sql_parse_unsupported",
    "sql_query_structure_unresolved",
    "unsupported_database_operation",
    "database_operation_profile_unsupported",
    "database_mapping_unresolved",
    "database_input_provenance_unresolved",
  ],
  "analysisGaps",
  "SQL 또는 DB 작업의 일부가 미지원",
  "동적으로 구성된 SQL·바인딩·매핑이나 지원하지 않는 DB 작업의 의미를 완전히 확인하지 못했습니다.",
  "쿼리 구조와 값 바인딩을 확인하고 입력이 SQL 구조나 작업 범위를 바꾸지 않는지 검토하세요.",
);
describe(
  [
    "ai_connection_contract_unresolved",
    "ai_context_connection_unresolved",
    "ai_node_semantics_unreviewed",
    "ai_prompt_expression_partial",
    "non_main_connection_semantics_unreviewed",
    "partial_workflow_topology",
    "direct_reference_unconnected",
    "merge_item_alignment_unverified",
    "nonstandard_execution_semantics",
    "node_execution_semantics_unresolved",
    "branch_guard_semantics_unresolved",
    "switch_fallback_selector_unresolved",
    "switch_options_unresolved",
    "subworkflow_argument_and_return_flow_unresolved",
    "trigger_input_connection_unresolved",
    "service_output_port_unresolved",
  ],
  "analysisGaps",
  "연결·분기·하위 흐름의 일부가 미확인",
  "연결 방향·분기 보호·항목 대응 또는 하위 워크플로 입출력을 완전히 확인하지 못했습니다.",
  "해당 연결과 보호 조건을 검토하고 필요한 하위 워크플로 정의를 함께 제공하세요.",
);
describe(
  [
    "opaque_node_effects",
    "node_transform_unsupported",
    "field_projection_partial",
    "input_provenance_unresolved",
    "payload_provenance_unresolved",
    "recipient_provenance_unresolved",
    "http_destination_provenance_unresolved",
    "http_resource_provenance_unresolved",
    "command_input_flow_partially_analyzed",
    "command_input_origin_unresolved",
    "transport_url_unresolved",
    "object_expression_unsupported",
    "expression_semantics_unsupported",
    "expression_syntax_unsupported",
    "builtin_capability_profile_unreviewed",
    "unsupported_node_version",
    "unsupported_send_operation",
    "message_reply_markup_unverified",
  ],
  "analysisGaps",
  "값이 전달되는 경로의 일부가 미지원",
  "노드 변환·표현식·버전 또는 외부 응답의 의미를 정확히 해석하지 못해 일부 값의 출처가 미확인입니다.",
  "표시된 노드의 실제 설정과 입출력 구조를 검토하세요. 미확인 출처를 신뢰된 값으로 간주하지 않습니다.",
);
describe(
  [
    "collection_cardinality_unverified",
    "code_collection_cardinality_unverified",
    "aggregate_options_unresolved",
    "aggregate_fields_unresolved",
    "aggregate_excluded_unknown_fields",
    "aggregate_mode_unresolved",
    "aggregate_dotted_key_resolution_unverified",
    "aggregate_array_property_unresolved",
    "aggregate_flatten_shape_unverified",
  ],
  "analysisGaps",
  "배열·집계 결과의 일부가 미확인",
  "항목 개수·집계 필드·중첩 배열의 형태를 완전히 확인하지 못했습니다. 알려진 원본 출처와 민감 후보는 유지됩니다.",
  "집계 전후의 필드와 항목 대응을 검토하세요. 미확인 배열 항목을 없거나 안전한 값으로 간주하지 않습니다.",
);
describe(
  [
    "native_tool_unavailable",
    "native_failed",
    "native_timeout",
    "native_cancelled",
    "native_output_limit",
    "native_invalid_report",
    "native_invalid_input",
    "native_model_or_dependency_unavailable",
    "nlp_field_analysis_failed",
    "python_analysis_failed",
  ],
  "analysisGaps",
  "검사 도구가 일부 작업을 완료하지 못함",
  "도구 실행·모델 준비·시간·응답 오류로 일부 검사가 누락되었습니다.",
  "워커의 도구와 실행 환경을 복구하고 다시 검사하세요. 누락된 검사를 통과로 표시하지 않습니다.",
);
const unknownDiagnostic: DiagnosticDescription = {
  group: "analysisGaps",
  title: "추가 분석이 필요한 항목",
  explanation:
    "현재 설명 사전에 없는 분석 한계가 보고되었습니다. 원본 결과의 근거 식별자로 확인할 수 있습니다.",
  action:
    "원본 검사 결과의 해당 근거를 검토하세요. 미등록 사유를 무시하거나 단순 환경 안내로 바꾸지 않습니다.",
};

const safeKeys = new Set([
  "nodes",
  "parameters",
  "credentials",
  "settings",
  "connections",
  "pinData",
  "notes",
  "authentication",
  "httpMethod",
  "responseMode",
  "responseData",
  "responseBody",
  "respondWith",
  "options",
  "conditions",
  "combinator",
  "leftValue",
  "rightValue",
  "operator",
  "type",
  "operation",
  "resource",
  "query",
  "queryReplacement",
  "url",
  "method",
  "headerParameters",
  "headers",
  "headersJson",
  "jsonHeaders",
  "bodyParameters",
  "body",
  "jsonBody",
  "queryParameters",
  "allowUnauthorizedCerts",
  "ignoreResponseCode",
  "redirect",
  "redirects",
  "followRedirects",
  "maxRedirects",
  "proxy",
  "timeout",
  "rejectUnauthorized",
  "ssl",
  "tls",
  "command",
  "jsCode",
  "pythonCode",
  "functionCode",
  "language",
  "mode",
  "source",
  "workflowId",
  "workflowJson",
  "workflowInputs",
  "fileSelector",
  "filePath",
  "fileName",
  "fromEmail",
  "toEmail",
  "toRecipients",
  "subject",
  "text",
  "html",
  "channel",
  "channelId",
  "chatId",
  "message",
  "value",
  "values",
  "assignments",
  "name",
  "path",
]);
function displayLocation(location: StaticLocation): StaticLocation {
  const parts = location.pointer.split("/").slice(1);
  const safe: string[] = [];
  for (const part of parts) {
    if (!safeKeys.has(part) && !/^(0|[1-9][0-9]{0,5})$/.test(part)) break;
    safe.push(part);
  }
  return {
    nodeKey: location.nodeKey,
    pointer: safe.length ? `/${safe.join("/")}` : "",
  };
}
const referenceSchema = z.strictObject({
  analysisKey: hash.nullable(),
  inputSha256: hash,
  kind: z.enum(["finding", "diagnostic", "file", "subworkflow"]),
  id: hash,
});
const findingCardSchema = z.strictObject({
  id: hash,
  reference: referenceSchema,
  location: staticLocationSchema,
  category: z.enum(categories),
  severity: z.enum(["info", "low", "medium", "high"]),
  claim: z.enum(["configuration", "candidate", "supported_path"]),
  title: text,
  explanation: text,
  action: text,
  evidence: z
    .array(
      z.strictObject({ location: staticLocationSchema, explanation: text }),
    )
    .min(1)
    .max(32),
  omittedEvidence: count,
  remediation: z
    .array(
      z.strictObject({
        id: hash,
        automatic: z.boolean(),
        label: text,
        conditions: z.array(text).min(1).max(4),
        requiresRecheck: z.literal(true),
        behaviorPreserved: z.literal("not_verified"),
      }),
    )
    .max(16),
  omittedRemediation: count,
});
const diagnosticCardSchema = z.strictObject({
  id: hash,
  reference: referenceSchema,
  location: staticLocationSchema,
  code: z.string().regex(/^[a-z][a-z0-9_]{0,79}$/),
  title: text,
  explanation: text,
  action: text,
});
const functionsSchema = z.strictObject({
  analysisKey: hash,
  inputSha256: hash,
  depth: count,
  summaryAvailable: z.boolean(),
  nodeCount: count,
  activeNodeCount: count,
  declaredCapabilities: z.array(text).max(24),
  explanation: text,
  businessPurpose: z.literal("not_verified"),
  policyDecision: z.enum(["allow", "review", "block", "inconclusive"]),
  publicationStatus: z.enum([
    "eligible_for_service_review",
    "hold",
    "rejected",
  ]),
});
const countsSchema = z.strictObject({
  findings: count,
  observations: count,
  analysisGaps: count,
  environmentChecks: count,
  scopeNotes: count,
});
export const serviceReportSchema = z
  .strictObject({
    serviceReportVersion: z.literal("1.0.0"),
    inputSha256: hash,
    engineVersion: z.string().regex(/^\d+\.\d+\.\d+$/),
    assessmentStatus: z.enum(["analyzed", "partial", "unsupported", "error"]),
    executionStatus: z.enum(["completed", "completed_with_errors", "failed"]),
    analysisStatus: z.enum(["complete", "review_required", "failed"]),
    staticCoverageStatus: z.enum([
      "within_supported_profile",
      "gaps_present",
      "not_evaluated",
    ]),
    workflowExecution: z.literal("not_run"),
    decision: z.enum(["allow", "review", "block", "inconclusive"]),
    publication: z.literal("requires_service_authorization"),
    vulnerabilityCount: z.literal("not_established"),
    headline: text,
    explanation: text,
    functions: z.array(functionsSchema).max(9),
    findings: z.array(findingCardSchema).max(serviceReportLimits.itemsPerGroup),
    observations: z
      .array(findingCardSchema)
      .max(serviceReportLimits.itemsPerGroup),
    analysisGaps: z
      .array(diagnosticCardSchema)
      .max(serviceReportLimits.itemsPerGroup),
    environmentChecks: z
      .array(diagnosticCardSchema)
      .max(serviceReportLimits.itemsPerGroup),
    scopeNotes: z
      .array(diagnosticCardSchema)
      .max(serviceReportLimits.itemsPerGroup),
    counts: countsSchema,
    omitted: countsSchema,
    truncated: z.boolean(),
  })
  .refine(
    (report) => {
      if (Buffer.byteLength(JSON.stringify(report)) > serviceReportLimits.bytes)
        return false;
      if (
        !groups.every(
          (group) =>
            report.counts[group] ===
            report[group].length + report.omitted[group],
        )
      )
        return false;
      if (
        report.truncated !== groups.some((group) => report.omitted[group] > 0)
      )
        return false;
      if (
        report.findings.some((item) => item.severity === "info") ||
        report.observations.some((item) => item.severity !== "info")
      )
        return false;
      if (
        report.analysisStatus !==
        (report.assessmentStatus === "error"
          ? "failed"
          : report.assessmentStatus === "analyzed"
            ? "complete"
            : "review_required")
      )
        return false;
      if (
        report.staticCoverageStatus !==
        (report.assessmentStatus === "error"
          ? "not_evaluated"
          : report.counts.analysisGaps
            ? "gaps_present"
            : "within_supported_profile")
      )
        return false;
      if (
        (report.assessmentStatus === "error") !==
        (report.executionStatus === "failed")
      )
        return false;
      if (
        report.assessmentStatus === "error"
          ? report.functions.length !== 0
          : report.functions[0]?.inputSha256 !== report.inputSha256
      )
        return false;
      const files = new Map(
        report.functions.map((file) => [file.analysisKey, file.inputSha256]),
      );
      if (files.size !== report.functions.length) return false;
      if (
        groups.some((group) =>
          report[group].some(({ reference }) =>
            reference.analysisKey === null
              ? report.assessmentStatus !== "error" ||
                reference.inputSha256 !== report.inputSha256
              : files.get(reference.analysisKey) !== reference.inputSha256,
          ),
        )
      )
        return false;
      if (
        report.assessmentStatus === "analyzed" &&
        (report.executionStatus !== "completed" ||
          report.counts.analysisGaps > 0)
      )
        return false;
      return groups.every(
        (group) =>
          new Set(report[group].map((item) => item.id)).size ===
          report[group].length,
      );
    },
    { message: "Inconsistent service report" },
  );
export type ServiceReport = z.infer<typeof serviceReportSchema>;
const digest = (parts: unknown[]) =>
  createHash("sha256").update(JSON.stringify(parts)).digest("hex");
const emptyCounts = () => ({
  findings: 0,
  observations: 0,
  analysisGaps: 0,
  environmentChecks: 0,
  scopeNotes: 0,
});

const evidenceDescriptions: Record<string, string> = {
  tls_certificate_validation_disabled: "인증서 검증을 끄는 설정이 있습니다.",
  plaintext_http_url: "암호화되지 않은 HTTP 주소가 설정되어 있습니다.",
  url_contains_authentication_material:
    "URL에 인증정보를 포함한 설정이 있습니다.",
  webhook_authentication_none: "Webhook 인증이 없음으로 설정되어 있습니다.",
  webhook_authentication_default_none:
    "Webhook 인증이 생략되어 기본 인증 없음 설정을 사용합니다.",
  webhook_authentication_configured:
    "Webhook에 인증 방식이 선언되어 있습니다. 실제 집행은 별도 확인 대상입니다.",
  dynamic_sql_text: "SQL 문자열에 동적인 값이 포함되어 있습니다.",
  nlp_person_candidate: "지원하는 문맥 모델에서 사람 이름 후보를 찾았습니다.",
  nlp_location_candidate: "지원하는 문맥 모델에서 위치·주소 후보를 찾았습니다.",
  nlp_email_candidate: "이메일 형식의 개인정보 후보를 찾았습니다.",
  nlp_phone_candidate: "전화번호 형식의 개인정보 후보를 찾았습니다.",
  nlp_payment_card_candidate: "결제 카드 형식의 개인정보 후보를 찾았습니다.",
  nlp_ip_address_candidate: "IP 주소 형식의 데이터 후보를 찾았습니다.",
};
const remediationNames: Record<string, string> = {
  enable_tls_verification: "인증서 검증 켜기",
  bind_postgres_lookup_value: "Postgres 조회 값을 매개변수로 바인딩하기",
  bind_postgres_lookup_values:
    "Postgres 조회의 입력값을 쿼리 매개변수로 분리하기",
  rotate_exposed_secret: "노출된 키 교체와 참조 사용",
  minimize_personal_data: "개인정보 최소화",
  configure_request_authentication: "요청 인증 구성",
  restrict_egress_destination: "전송 대상과 데이터 제한",
  constrain_request_origin: "요청 origin 제한",
  review_sql_binding: "SQL 값 바인딩 검토",
  remove_dynamic_command: "외부 입력 명령 결합 제거",
  review_transport_configuration: "통신 설정 검토",
  minimize_output_data: "응답·로그 데이터 최소화",
  review_dependency_and_permissions: "의존성과 권한 검토",
};
const capabilityNames: Record<string, string> = {
  webhook: "웹 요청으로 시작",
  schedule: "일정에 따라 시작",
  manual: "수동 시작",
  email: "이메일 읽기·전송 기능",
  http: "외부 HTTP 요청 기능",
  database: "DB 조회·변경 기능",
  condition: "조건 분기",
  mapping: "데이터 변환",
  merge: "데이터 병합",
  code: "코드 처리 기능",
  command: "시스템 명령 기능",
  ssh: "원격 SSH 기능",
  file: "파일 접근 기능",
  message: "메시지 처리 기능",
  document: "문서·시트 처리 기능",
  ai: "AI 모델·도구 기능",
  subworkflow: "하위 워크플로 기능",
  response: "요청에 응답",
  note: "메모",
  unknown: "미확인 노드 기능",
};
function findingCard(
  file: FileAssessment,
  finding: Finding,
): z.infer<typeof findingCardSchema> {
  const categoryName = categoryNames[finding.category];
  const observation = finding.severity === "info";
  const plans = observation
    ? []
    : file.remediation.filter((plan) => plan.findingIds.includes(finding.id));
  const explanation = observation
    ? `${categoryName} 관련 설정·기능을 관찰했습니다. 이 기록 자체는 취약점 판정이 아닙니다.`
    : finding.claim === "supported_path"
      ? `${categoryName}에 영향을 주는 입력 경로를 지원하는 정적 분석 범위에서 확인했습니다. 실제 실행·악용 여부는 검증하지 않았습니다.`
      : finding.claim === "configuration"
        ? `${categoryName}에서 검토가 필요한 설정을 확인했습니다. 실제 운영의 영향은 사용 조건과 함께 확인해야 합니다.`
        : `${categoryName}의 위험 후보를 찾았습니다. 실제 값과 사용 조건을 확인하기 전에는 확정된 취약점으로 계산하지 않습니다.`;
  return {
    id: digest([file.analysisKey, "finding", finding.id]),
    reference: {
      analysisKey: file.analysisKey,
      inputSha256: file.inputSha256,
      kind: "finding",
      id: finding.id,
    },
    location: displayLocation(finding.location),
    category: finding.category,
    severity: finding.severity,
    claim: finding.claim,
    title: `${categoryName} ${observation ? "관찰" : "검토"}`,
    explanation,
    action: observation
      ? "업무에 필요한 기능인지 확인하고 관련 위험 후보와 사용 조건을 함께 확인하세요."
      : actions[finding.category],
    evidence: finding.evidence.slice(0, 32).map((item) => ({
      location: displayLocation(item.location),
      explanation:
        evidenceDescriptions[item.code] ??
        `${categoryName} 검사기가 이 위치를 근거로 기록했습니다. 원본 결과의 근거 식별자로 세부 코드를 확인할 수 있습니다.`,
    })),
    omittedEvidence: Math.max(0, finding.evidence.length - 32),
    remediation: plans.slice(0, 16).map((plan) => ({
      id: plan.id,
      automatic: plan.automatic,
      label: remediationNames[plan.kind] ?? "수정 계획 검토",
      conditions: [
        "계획에 기록된 원본 파일 해시와 현재 파일이 일치해야 합니다.",
        plan.automatic
          ? "해당 노드의 버전·설정·표현식이 수정기가 지원하는 조건을 만족해야 합니다. 적용 시 다시 검증합니다."
          : "사람이 실제 사용 조건을 확인한 뒤 수정해야 합니다.",
        "수정본을 새 파일로 재검사하고 정상 업무 기능은 별도로 확인해야 합니다.",
      ],
      requiresRecheck: true,
      behaviorPreserved: "not_verified",
    })),
    omittedRemediation: Math.max(0, plans.length - 16),
  };
}

/** A deterministic presentation layer. This does not change scanner coverage or authorize publication. */
export function buildServiceReport(input: unknown): ServiceReport {
  const report = assessmentReportSchema.parse(input);
  const output: ServiceReport = {
    serviceReportVersion: "1.0.0",
    inputSha256: report.inputSha256,
    engineVersion: report.engineVersion,
    assessmentStatus: report.status,
    executionStatus: report.status === "error" ? "failed" : "completed",
    analysisStatus:
      report.status === "error"
        ? "failed"
        : report.status === "analyzed"
          ? "complete"
          : "review_required",
    staticCoverageStatus:
      report.status === "error" ? "not_evaluated" : "within_supported_profile",
    workflowExecution: "not_run",
    decision: report.status === "error" ? "inconclusive" : report.decision,
    publication: "requires_service_authorization",
    vulnerabilityCount: "not_established",
    headline:
      report.status === "error"
        ? "검사를 완료하지 못했습니다"
        : "정적 검사 결과를 확인하세요",
    explanation:
      report.status === "error"
        ? "입력 또는 검사 실행 오류가 발생했습니다. 이 결과를 안전 판정으로 사용하지 마세요."
        : "발견한 위험 후보, 확인한 기능, 분석하지 못한 위치와 사용 전 확인할 조건을 나누어 제공합니다. 워크플로는 실행하지 않았습니다.",
    functions: [],
    findings: [],
    observations: [],
    analysisGaps: [],
    environmentChecks: [],
    scopeNotes: [],
    counts: emptyCounts(),
    omitted: emptyCounts(),
    truncated: false,
  };
  const seen = new Set<string>();
  const addDiagnostic = (
    group: DiagnosticGroup,
    card: z.infer<typeof diagnosticCardSchema>,
  ) => {
    const key = `${group}:${card.id}`;
    if (seen.has(key)) return;
    seen.add(key);
    output.counts[group]++;
    if (output[group].length < serviceReportLimits.itemsPerGroup)
      output[group].push(card);
    else output.omitted[group]++;
  };
  const addFileError = (
    file: FileAssessment | undefined,
    message: string,
    code: string,
  ) => {
    const id = digest([file?.analysisKey ?? report.inputSha256, code]);
    addDiagnostic("analysisGaps", {
      id,
      reference: {
        analysisKey: file?.analysisKey ?? null,
        inputSha256: file?.inputSha256 ?? report.inputSha256,
        kind: "file",
        id,
      },
      location: { nodeKey: null, pointer: "" },
      code,
      title: "검사 실행 오류",
      explanation: message,
      action:
        "입력과 워커 실행 환경을 확인한 뒤 다시 검사하세요. 실패한 항목은 통과로 처리하지 않습니다.",
    });
  };
  if (report.status === "error") {
    addFileError(
      undefined,
      "입력 또는 격리된 검사 실행을 완료하지 못했습니다. 원본 보고서의 오류 코드를 확인하세요.",
      "assessment_failed",
    );
    return serviceReportSchema.parse(output);
  }
  for (const file of report.files) {
    const summary = file.functionSummary;
    const activeNodes = summary?.nodes.filter((node) => !node.disabled) ?? [];
    const capabilities = [
      ...new Set(
        activeNodes.map(
          (node) => capabilityNames[node.kind] ?? capabilityNames.unknown!,
        ),
      ),
    ];
    output.functions.push({
      analysisKey: file.analysisKey,
      inputSha256: file.inputSha256,
      depth: file.depth,
      summaryAvailable: summary !== undefined,
      nodeCount: summary?.nodes.length ?? 0,
      activeNodeCount: activeNodes.length,
      declaredCapabilities: capabilities,
      explanation: summary
        ? `활성 노드 ${activeNodes.length}개에서 선언된 기능: ${capabilities.length ? capabilities.join(", ") : "없음"}. 실제 업무 목적과 실행 순서는 별도 확인 대상입니다.`
        : "이 버전의 보고서에는 기능 구조 요약이 없습니다. 원본 정의를 확인하세요.",
      businessPurpose: "not_verified",
      policyDecision: file.policy.decision,
      publicationStatus: file.policy.publication.status,
    });
    if (file.base.status === "error") {
      output.executionStatus = "completed_with_errors";
      addFileError(
        file,
        "이 파일의 기본 정적 검사가 실패했습니다. 다른 파일이나 확장 검사의 결과만으로 전체 통과를 판단하지 마세요.",
        "file_analysis_failed",
      );
    }
    if (
      file.tools.gitleaks.status === "error" ||
      file.tools.native.modes.some((mode) => mode.status === "error")
    ) {
      output.executionStatus = "completed_with_errors";
      addFileError(
        file,
        "이 파일에서 하나 이상의 검사 도구가 실패하여 해당 검사 범위가 누락되었습니다.",
        "inspection_tool_failed",
      );
    }
    const rules = [
      ...(file.base.status === "error" ? [] : file.base.rules),
      ...file.extensionRules,
    ];
    for (const rule of rules) {
      for (const finding of rule.findings) {
        const group = finding.severity === "info" ? "observations" : "findings";
        const card = findingCard(file, finding);
        if (seen.has(card.id)) continue;
        seen.add(card.id);
        output.counts[group]++;
        if (output[group].length < serviceReportLimits.itemsPerGroup)
          output[group].push(card);
        else output.omitted[group]++;
      }
      for (const diagnostic of rule.diagnostics) {
        const description =
          diagnosticDescriptions.get(diagnostic.code) ?? unknownDiagnostic;
        addDiagnostic(description.group, {
          id: digest([file.analysisKey, "diagnostic", diagnostic.id]),
          reference: {
            analysisKey: file.analysisKey,
            inputSha256: file.inputSha256,
            kind: "diagnostic",
            id: diagnostic.id,
          },
          location: displayLocation(diagnostic.location),
          code: diagnosticDescriptions.has(diagnostic.code)
            ? diagnostic.code
            : "unrecognized_diagnostic",
          title: description.title,
          explanation: description.explanation,
          action: description.action,
        });
      }
    }
  }
  for (const link of report.subworkflows) {
    if (link.status === "disabled" || link.status === "definition_analyzed")
      continue;
    const parent = report.files.find(
      (file) => file.analysisKey === link.parentAnalysisKey,
    )!;
    const id = digest([link.parentAnalysisKey, link.caller, link.status]);
    addDiagnostic("analysisGaps", {
      id,
      reference: {
        analysisKey: parent.analysisKey,
        inputSha256: parent.inputSha256,
        kind: "subworkflow",
        id,
      },
      location: displayLocation(link.caller),
      code: "subworkflow_definition_unresolved",
      title: "하위 워크플로를 검사하지 못함",
      explanation:
        "하위 정의가 없거나 유효하지 않거나 순환·검사 한도에 도달해 호출 대상 전체를 확인하지 못했습니다.",
      action:
        "정확한 하위 워크플로 정의와 파일 해시를 확인해 함께 재검사하세요. 누락된 자식을 안전하다고 간주하지 않습니다.",
    });
  }
  if (output.counts.analysisGaps) output.staticCoverageStatus = "gaps_present";
  // Korean explanations can expand a bounded input report substantially.
  // Every omitted card remains in counts; the assessment is authoritative.
  let outputBytes = Buffer.byteLength(JSON.stringify(output));
  const byteTarget = serviceReportLimits.bytes - 4096;
  for (const group of [
    "observations",
    "scopeNotes",
    "environmentChecks",
    "findings",
    "analysisGaps",
  ] as const) {
    while (outputBytes > byteTarget && output[group].length > 0) {
      const removed = output[group].pop()!;
      outputBytes -= Buffer.byteLength(JSON.stringify(removed));
      output.omitted[group]++;
    }
  }
  output.truncated = groups.some((group) => output.omitted[group] > 0);
  output.headline =
    output.executionStatus === "completed_with_errors"
      ? "검사 도구 오류와 남은 확인 항목이 있습니다"
      : output.counts.analysisGaps
        ? "검사 결과와 분석하지 못한 위치를 확인하세요"
        : output.counts.findings
          ? "검토할 위험 후보와 사용 조건이 있습니다"
          : "지원 범위의 검사 결과와 사용 조건을 확인하세요";
  return serviceReportSchema.parse(output);
}
