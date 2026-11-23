export const causeKinds = [
  "environment_evidence",
  "definition_input",
  "analyzer_extension",
  "mixed_provenance",
  "scope_boundary",
  "unclassified",
] as const;
export type CauseKind = (typeof causeKinds)[number];
export type Cause = {
  kind: CauseKind;
  scopeOnly: boolean;
  explanation: string;
  nextStep: string;
};
const causes = new Map<string, Cause>();
function register(codes: string, cause: Cause): void {
  for (const code of codes.trim().split(/\s+/)) {
    if (causes.has(code)) throw new Error(`Duplicate coverage cause: ${code}`);
    causes.set(code, cause);
  }
}
register(
  `runtime_evidence_missing database_runtime_schema_and_permissions_unverified
   filesystem_permissions_and_path_scope_unverified remote_host_permissions_and_directory_unverified
   ai_runtime_invocation_and_permissions_unverified model_tool_query_and_execution_unverified
   ai_tool_approval_and_access_unverified ai_approval_evidence_missing
   ai_code_tool_sandbox_and_effects_unverified authentication_credential_reference_missing`,
  {
    kind: "environment_evidence",
    scopeOnly: false,
    explanation:
      "실제 실행 계정·파일·DB·SSH·AI 도구의 권한과 승인 근거가 필요합니다.",
    nextStep:
      "사용 전에 실행 계정의 최소 권한과 승인 절차를 확인하세요. 서비스가 비밀키나 환경 자료 입력을 요구하는 항목은 아닙니다.",
  },
);
register(
  `dns_redirect_and_network_access_unverified destination_access_unverified
   redirect_destination_unverified provider_endpoint_from_credentials_unverified
   ai_model_endpoint_from_credentials_unverified`,
  {
    kind: "environment_evidence",
    scopeOnly: false,
    explanation:
      "실제 목적지·DNS·리다이렉트·네트워크 접근은 JSON만으로 확정할 수 없습니다.",
    nextStep: "배포 환경에서 최종 목적지와 허용 네트워크 범위를 확인하세요.",
  },
);
register(
  `model_processing_and_retention_unverified response_recipient_authorization_unverified
   instance_workflow_link_included transfer_policy_not_configured ai_model_transfer_policy_not_configured
   error_storage_visibility_unverified ai_vector_transfer_policy_not_configured
   ai_vector_store_endpoint_and_access_unverified ai_embedding_endpoint_from_credentials_unverified`,
  {
    kind: "environment_evidence",
    scopeOnly: false,
    explanation:
      "실제 데이터의 수신·공유·보존을 허용하는 업무 정책이 확인되지 않았습니다.",
    nextStep:
      "수신 대상, 데이터 종류, 외부 AI 사용과 보존 범위를 운영 정책에 맞춰 확인하세요.",
  },
);
register(
  `external_node_package_evidence_missing installed_package_version_and_content_missing`,
  {
    kind: "environment_evidence",
    scopeOnly: false,
    explanation:
      "실제로 설치된 외부 노드 패키지의 버전과 내용이 제공되지 않았습니다.",
    nextStep:
      "사용 전에 설치된 외부 노드의 출처·정확한 버전·업데이트 상태를 확인하세요. JSON에 없는 실제 설치 내용을 검사했다고 보증하지 않습니다.",
  },
);
register(
  `trigger_payload_schema_unverified trigger_runtime_data_unverified service_response_shape_unverified
   read_response_classification_unverified sheet_headers_runtime_unverified sheet_empty_header_fallback_possible
   ai_memory_content_and_session_isolation_unverified ai_memory_context_content_unverified
   ai_retrieved_content_and_access_unverified ai_retrieved_context_content_unverified
   ai_model_invocation_and_output_unverified model_invocation_and_output_unverified
   ai_model_selection_and_fallback_unverified ai_generation_output_unverified
   ai_output_parser_retry_model_content_unverified ai_tool_arguments_and_result_unverified
   ai_tool_or_context_result_unverified ai_generated_argument_or_retry_content_unverified
   ai_prompt_influence_on_tool_selection_unverified model_tool_invocation_unverified
   ai_model_context_sensitivity_unverified
   automatic_mapping_selection_unverified ai_document_binary_content_unverified ai_binary_prompt_content_unverified
   ai_vector_query_and_results_unverified ai_vector_runtime_operations_unverified`,
  {
    kind: "environment_evidence",
    scopeOnly: false,
    explanation:
      "외부 입력·응답·검색 자료·메모리·모델의 실제 출력은 정의에 포함되지 않습니다.",
    nextStep:
      "익명화한 입력·응답 구조와 데이터 분류를 확인하세요. 모델의 미래 출력은 정적 검사로 보장하지 않습니다.",
  },
);
register(
  `subworkflow_content_not_provided subworkflow_definition_not_supplied
   binary_payload_unavailable binary_body_content_unverified
   required_send_field_missing ai_required_model_connection_missing ai_required_output_parser_missing
   remote_working_directory_unavailable error_payload_unavailable
   ai_required_embedding_connection_missing ai_required_document_connection_missing
   ai_document_binary_input_missing ai_required_vector_store_connection_missing
   ai_required_retriever_connection_missing ai_required_fallback_model_missing ai_binary_prompt_input_missing
   input_not_connected`,
  {
    kind: "definition_input",
    scopeOnly: false,
    explanation:
      "하위 정의·연결·필수 필드·별도 파일 등 분석할 입력이 빠졌습니다. 실제 팀 API 연결과는 별개입니다.",
    nextStep:
      "표시된 설정·연결 오류를 수정하고 재검사하세요. 참조된 하위 정의나 별도 파일의 내부는 검사되지 않았으며 보안 확인이 필요합니다.",
  },
);
register(
  `nlp_english_model_profile nlp_metadata_formats_only nlp_program_formats_only
   nlp_template_literal_text_only nlp_json_string_values_only nlp_technical_entity_filtered nlp_chunked_text_profile
   python_static_profile_limited code_bounded_flow_partial ai_disabled_node_not_invoked
   javascript_semantics_partially_analyzed code_logging_semantics_partial code_logging_and_sensitivity_partially_analyzed`,
  {
    kind: "scope_boundary",
    scopeOnly: true,
    explanation:
      "지원하는 언어·텍스트·정적 해석 범위를 알리는 진단입니다. 이것만으로 구현 오류나 취약점이라는 뜻은 아닙니다.",
    nextStep:
      "지원 범위를 결과와 함께 표시하세요. 한국어 문맥 탐지와 실제 실행 보증은 이 결과에서 제공하지 않습니다.",
  },
);
register(`model_attack_resistance_and_value_flow_unverified`, {
  kind: "scope_boundary",
  scopeOnly: false,
  explanation:
    "모델의 공격 저항성과 실행 중 값의 흐름은 정적 분석만으로 입증되지 않습니다.",
  nextStep:
    "정의에서 관측한 경로와 모델의 실제 행동 검증을 구분하세요. LLM 설명을 안전성 증거로 승격하지 않습니다.",
});
register(
  `payload_provenance_unresolved input_provenance_unresolved recipient_provenance_unresolved
   field_projection_partial transferred_data_sensitivity_unverified response_data_sensitivity_unverified
   http_destination_provenance_unresolved http_resource_provenance_unresolved transport_url_unresolved
   destination_locator_unresolved recipient_identity_unresolved command_input_origin_unresolved
   local_file_path_provenance_unresolved database_input_provenance_unresolved
   resource_mapping_schema_unresolved
   json_parse_shape_unverified code_collection_shape_unverified code_collection_cardinality_unverified
   collection_cardinality_unverified string_split_cardinality_unverified code_collection_index_unverified
   code_branch_field_optional code_spread_shape_unverified code_array_spread_shape_unverified
   merge_item_alignment_unverified record_match_selection_unverified ai_prompt_value_unresolved
   sql_parameter_mapping_data_dependent direct_reference_unconnected code_language_unresolved code_identifier_unresolved
   code_await_result_unverified code_flatmap_shape_unverified code_collection_empty_or_unavailable code_builtin_result_unverified
   ai_tool_example_derived_schema_content_unverified error_payload_provenance_unresolved
   error_payload_json_unverified error_payload_object_unverified
   binary_provenance_unresolved binary_source_field_unresolved binary_assignment_selection_unresolved
   ai_document_options_unresolved ai_document_metadata_unresolved ai_document_selector_unresolved
   ai_vector_query_input_unresolved ai_document_provenance_unresolved ai_vector_transfer_policy_unresolved
   ai_lookup_tool_destination_unresolved`,
  {
    kind: "mixed_provenance",
    scopeOnly: false,
    explanation:
      "앞선 변환의 미지원과 실제 입력 구조 부족이 모두 가능한 미확정 값입니다. 이 진단 코드만으로 원인을 단정할 수 없습니다.",
    nextStep:
      "같은 노드와 상위 경로의 근거를 함께 확인하세요. 먼저 변환 해석을 보완하고 남는 실제 구조·데이터 분류만 확인하세요.",
  },
);
register(
  `opaque_node_effects expression_semantics_unsupported node_transform_unsupported
   partial_workflow_topology nonstandard_execution_semantics javascript_control_flow_partial
   ai_node_profile_unreviewed builtin_capability_profile_unreviewed node_execution_semantics_unresolved
   code_effects_partially_analyzed ai_node_semantics_unreviewed non_main_connection_semantics_unreviewed
   ai_prompt_expression_partial code_statement_profile_unresolved code_source_observations_only
   code_item_mode_unresolved ai_connection_contract_unresolved ai_context_connection_unresolved
   code_exception_value_unverified code_try_state_unresolved code_call_effect_unresolved
   object_expression_unsupported unsupported_node_version
   branch_type_validation_unresolved command_input_flow_partially_analyzed ai_model_request_expression_partial
   ai_model_request_profile_unreviewed unsupported_code_language
   sql_query_structure_unresolved sql_parameter_binding_unresolved unsupported_send_operation
   code_loop_summary_partial code_expression_profile_unresolved code_closure_capture_unresolved
   branch_guard_disjunction unsupported_expression ai_subnode_expression_item_binding_unverified
   code_object_mutation_unresolved javascript_profile_unsupported
   unsupported_log_code_profile message_reply_markup_unverified code_assignment_target_unresolved
   cyclic_dataflow service_output_port_unresolved code_return_shape_unresolved code_callback_mutation_unresolved
   sql_input_flow_partially_analyzed code_dynamic_index_unresolved
   code_function_profile_unresolved unsupported_error_output_profile unsupported_error_output_mode
   binary_provenance_cycle binary_conversion_profile_unresolved binary_error_output_unresolved
   ai_vector_profile_unreviewed ai_embedding_connection_unresolved ai_document_connection_unresolved
   ai_document_selection_unresolved ai_document_binary_selection_unresolved ai_document_splitter_unresolved
   ai_vector_query_connection_unresolved ai_vector_update_profile_unreviewed ai_vector_reranker_unreviewed
   ai_lookup_tool_request_content_unverified binary_pinned_output_unverified
   binary_connection_unresolved ai_chat_message_type_unresolved binary_expression_effects_unresolved
   code_loop_carried_state_unverified`,
  {
    kind: "analyzer_extension",
    scopeOnly: false,
    explanation:
      "현재 검사기가 처리하지 못하는 구문·노드·실행 방식이 남아 있습니다.",
    nextStep:
      "공식 노드 동작과 AST를 근거로 지원 프로필을 확장하고 양성·음성·미지원 회귀 사례로 검증하세요. 모든 동작의 완전 해석을 약속하지 않습니다.",
  },
);
register(
  `flow_budget_exceeded constant_inference_size_limit native_input_scope_limit
   code_ast_profile_limit code_source_observation_limit code_source_size_limit code_token_observation_incomplete
   code_transfer_budget_exceeded code_value_shape_limit database_mapping_limit definition_diagnostic_limit
   definition_finding_limit definition_origin_limit native_field_size_limit native_total_text_limit native_finding_limit
   python_ast_limit python_alias_analysis_limit error_payload_analysis_limit
   binary_provenance_limit ai_document_analysis_limit javascript_ast_limit log_argument_limit flow_alternative_limit`,
  {
    kind: "analyzer_extension",
    scopeOnly: false,
    explanation:
      "검사 처리량·크기·복잡도 한도 때문에 일부 분석이 생략됐습니다.",
    nextStep:
      "누락 위치를 유지하면서 캐시·요약·예산 배분을 개선하고 자원 한도 회귀 검사를 수행하세요. 한도만 무제한으로 늘리지 않습니다.",
  },
);
register(
  `code_parse_unavailable expression_parse_unavailable expression_syntax_unsupported python_parse_unavailable nlp_json_text_unresolved`,
  {
    kind: "mixed_provenance",
    scopeOnly: false,
    explanation:
      "입력 구문 오류와 파서의 미지원 구문을 추가로 구별해야 합니다.",
    nextStep:
      "원문을 로컬에서 공식 구문·파서와 대조해 입력 수정 또는 파서 지원 확장을 결정하세요.",
  },
);
register(`nlp_language_outside_profile`, {
  kind: "scope_boundary",
  scopeOnly: false,
  explanation:
    "입력에서 현재 개인정보 문맥 모델이 지원하지 않는 언어를 관측했습니다.",
  nextStep:
    "해당 입력은 지원 범위 밖으로 표시하고 사람이 검토하세요. 형식 탐지만으로 개인정보 부재를 판단하지 않습니다.",
});
register(
  `trusted_policy_transfer_unresolved ai_model_transfer_policy_unresolved`,
  {
    kind: "mixed_provenance",
    scopeOnly: false,
    explanation:
      "업무 정책이 없거나, 목적지·데이터 분류를 해석하지 못해 제공된 정책을 적용하지 못한 상태입니다.",
    nextStep:
      "먼저 목적지·데이터 출처 해석을 확인하고 실제로 부족한 수신·공유 정책 근거를 운영자에게 확인하세요.",
  },
);
const unknownCause: Cause = {
  kind: "unclassified",
  scopeOnly: false,
  explanation: "이 진단의 해결 조건을 아직 분류하지 않았습니다.",
  nextStep:
    "원래 진단을 검토해 분류 규칙과 검증 사례를 추가하세요. 환경 탓이나 정상 상태로 자동 분류하지 않습니다.",
};
export const classifyCoverageCause = (code: string): Cause => ({
  ...(causes.get(code) ?? unknownCause),
});
