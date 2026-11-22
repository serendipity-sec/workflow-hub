import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { assessmentReportSchema } from "../dist/assessment-contract.js";

assert.ok(
  process.argv[2] && process.argv[3] && process.argv[4],
  "Usage: node validation/audit-public-coverage.mjs <before-dir> <after-dir> <output>",
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const groups = {
  external_context: new Set([
    "database_runtime_schema_and_permissions_unverified",
    "database_match_columns_and_effect_unverified",
    "database_deletion_scope_unverified",
    "database_filter_and_result_scope_unverified",
    "filesystem_permissions_and_path_scope_unverified",
    "remote_host_permissions_and_directory_unverified",
    "dns_redirect_and_network_access_unverified",
    "sheet_headers_runtime_unverified",
    "sheet_empty_header_fallback_possible",
    "ai_runtime_invocation_and_permissions_unverified",
    "ai_model_invocation_and_output_unverified",
    "ai_model_transfer_policy_unresolved",
    "ai_model_endpoint_from_credentials_unverified",
    "model_tool_invocation_unverified",
    "model_tool_query_and_execution_unverified",
    "runtime_evidence_missing",
    "trusted_policy_transfer_unresolved",
    "response_recipient_authorization_unverified",
    "destination_access_unverified",
    "provider_endpoint_from_credentials_unverified",
    "model_processing_and_retention_unverified",
    "recipient_identity_unresolved",
    "instance_workflow_link_included",
    "redirect_destination_unverified",
    "read_response_classification_unverified",
    "transferred_data_sensitivity_unverified",
    "response_data_sensitivity_unverified",
  ]),
  declared_analysis_limit: new Set([
    "nlp_english_model_profile",
    "nlp_metadata_formats_only",
    "nlp_template_literal_text_only",
    "nlp_program_formats_only",
    "nlp_json_string_values_only",
    "nlp_technical_entity_filtered",
    "nlp_chunked_text_profile",
    "python_static_profile_limited",
    "model_attack_resistance_and_value_flow_unverified",
  ]),
  unavailable_definition_data: new Set([
    "binary_payload_unavailable",
    "required_send_field_missing",
  ]),
  processing_limit: new Set([
    "code_ast_profile_limit",
    "code_source_size_limit",
    "code_source_observation_limit",
    "code_token_observation_incomplete",
    "code_value_shape_limit",
    "code_transfer_budget_exceeded",
    "constant_inference_size_limit",
    "definition_origin_limit",
    "definition_diagnostic_limit",
    "definition_finding_limit",
    "database_mapping_limit",
    "native_field_size_limit",
    "flow_budget_exceeded",
    "native_total_text_limit",
    "native_input_scope_limit",
    "expression_parse_unavailable",
    "code_parse_unavailable",
  ]),
  unsupported_static_semantics: new Set([
    "code_source_observations_only",
    "code_source_binding_unresolved",
    "code_bounded_flow_partial",
    "code_statement_profile_unresolved",
    "code_effects_partially_analyzed",
    "code_closure_capture_unresolved",
    "code_alias_mutation_unresolved",
    "code_object_mutation_unresolved",
    "code_try_state_unresolved",
    "code_loop_carried_state_unverified",
    "code_loop_summary_partial",
    "sql_query_structure_unresolved",
    "database_mapping_unresolved",
    "database_input_provenance_unresolved",
    "http_resource_provenance_unresolved",
    "http_destination_provenance_unresolved",
    "ai_connection_contract_unresolved",
    "ai_context_connection_unresolved",
    "ai_prompt_expression_partial",
    "opaque_node_effects",
    "builtin_capability_profile_unreviewed",
    "unsupported_node_version",
    "node_transform_unsupported",
    "code_mapping_unsupported",
    "expression_semantics_unsupported",
    "expression_syntax_unsupported",
    "object_expression_unsupported",
    "node_execution_semantics_unresolved",
    "nonstandard_execution_semantics",
    "branch_guard_semantics_unresolved",
    "partial_workflow_topology",
    "non_main_connection_semantics_unreviewed",
    "ai_node_semantics_unreviewed",
    "input_provenance_unresolved",
    "payload_provenance_unresolved",
    "field_projection_partial",
    "switch_fallback_selector_unresolved",
    "switch_options_unresolved",
    "recipient_provenance_unresolved",
    "command_input_origin_unresolved",
    "command_input_flow_partially_analyzed",
    "direct_reference_unconnected",
    "code_logging_and_sensitivity_partially_analyzed",
    "code_logging_semantics_partial",
    "javascript_semantics_partially_analyzed",
    "javascript_control_flow_partial",
    "javascript_profile_unsupported",
    "unsupported_code_language",
    "code_language_unresolved",
    "unsupported_log_code_profile",
    "merge_item_alignment_unverified",
    "sql_parse_unsupported",
    "sql_input_flow_partially_analyzed",
    "sql_parameter_mapping_data_dependent",
    "sql_parameter_binding_unresolved",
    "unsupported_database_operation",
    "database_operation_profile_unsupported",
    "unsupported_send_operation",
    "message_reply_markup_unverified",
    "transport_url_unresolved",
  ]),
};
const groupOf = (code) =>
  Object.entries(groups).find(([, codes]) => codes.has(code))?.[0] ??
  "unclassified";
const count = (values) => {
  const counts = new Map();
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1);
  return Object.fromEntries([...counts].sort(([a], [b]) => a.localeCompare(b)));
};

async function audit(directory) {
  const manifestBytes = await readFile(join(directory, "downloads.json"));
  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  assert.ok(Array.isArray(manifest.samples) && manifest.samples.length === 15);
  assert.equal(new Set(manifest.samples.map(({ id }) => id)).size, 15);
  const samples = [];
  for (const sample of manifest.samples) {
    assert.ok(Number.isSafeInteger(sample.id) && sample.id > 0);
    const bytes = await readFile(join(directory, `${sample.id}.workflow.json`));
    assert.equal(hash(bytes), sample.sha256);
    assert.equal(bytes.length, sample.bytes);
    const reportBytes = await readFile(
      join(directory, `${sample.id}.assessment.json`),
    );
    const report = assessmentReportSchema.parse(JSON.parse(reportBytes));
    assert.equal(report.inputSha256, sample.sha256);
    assert.equal(report.execution, "not_run");
    assert.notEqual(report.status, "error");
    assert.equal(report.boundary.kind, "docker");
    const rules = report.files.flatMap((file) => [
      ...file.base.rules,
      ...file.extensionRules,
    ]);
    const diagnostics = [];
    const gaps = [];
    for (const rule of rules) {
      const incomplete = rule.coverage.filter((entry) =>
        ["partial", "unsupported"].includes(entry.status),
      );
      if (!incomplete.length) continue;
      const ids = new Set(incomplete.flatMap((entry) => entry.diagnosticIds));
      const codes = rule.diagnostics
        .filter((entry) => ids.has(entry.id))
        .map((entry) => entry.code);
      assert.ok(codes.length, "Incomplete coverage must retain an explanation");
      diagnostics.push(...codes);
      gaps.push({
        ruleId: rule.ruleId,
        coverage: count(incomplete.map((entry) => entry.status)),
        diagnosticCodes: count(codes),
      });
    }
    const tools = report.files.flatMap((file) => [
      file.tools.gitleaks,
      ...file.tools.native.modes,
    ]);
    samples.push({
      id: sample.id,
      sourceUrl: sample.source,
      inputSha256: sample.sha256,
      reportSha256: hash(reportBytes),
      engineVersion: report.engineVersion,
      image: `sha256:${report.boundary.imageSha256}`,
      status: report.status,
      toolInvocations: tools.length,
      toolErrors: tools.filter((tool) => tool.status !== "completed").length,
      coverage: count(
        rules.flatMap((rule) => rule.coverage.map((c) => c.status)),
      ),
      reasonGroups: count(diagnostics.map(groupOf)),
      findings: count(
        rules.flatMap((rule) => rule.findings.map((f) => f.severity)),
      ),
      gaps,
    });
  }
  const diagnosticCounts = {};
  const affectedSamples = {};
  for (const sample of samples) {
    const present = new Set();
    for (const gap of sample.gaps)
      for (const [code, amount] of Object.entries(gap.diagnosticCodes)) {
        diagnosticCounts[code] = (diagnosticCounts[code] ?? 0) + amount;
        present.add(code);
      }
    for (const code of present)
      affectedSamples[code] = (affectedSamples[code] ?? 0) + 1;
  }
  return {
    manifestSha256: hash(manifestBytes),
    summary: {
      samples: samples.length,
      statuses: count(samples.map((sample) => sample.status)),
      toolInvocations: samples.reduce((sum, s) => sum + s.toolInvocations, 0),
      toolErrors: samples.reduce((sum, s) => sum + s.toolErrors, 0),
      diagnosticCounts,
      affectedSamples,
    },
    samples,
  };
}

const before = await audit(resolve(process.argv[2]));
const after = await audit(resolve(process.argv[3]));
assert.equal(before.manifestSha256, after.manifestSha256);
assert.deepEqual(
  before.samples.map(({ id, inputSha256 }) => ({ id, inputSha256 })),
  after.samples.map(({ id, inputSha256 }) => ({ id, inputSha256 })),
);
const diagnosticDelta = Object.fromEntries(
  [
    ...new Set([
      ...Object.keys(before.summary.diagnosticCounts),
      ...Object.keys(after.summary.diagnosticCounts),
    ]),
  ]
    .sort()
    .map((code) => [
      code,
      (after.summary.diagnosticCounts[code] ?? 0) -
        (before.summary.diagnosticCounts[code] ?? 0),
    ]),
);
const output = {
  outcome: "passed",
  scope: "same_frozen_public_definitions_before_after",
  workflowExecution: "not_run",
  generalAccuracy: "not_measured",
  interpretation: [
    "diagnostic_occurrences_include_multiple_rule_scopes_not_independent_risks",
    "external_context_is_not_equivalent_to_team_api_unavailability",
    "reduced_gap_counts_do_not_prove_risk_resolution_or_complete_analysis",
    "model_and_environment_limits_remain_visible",
  ],
  groupCodes: Object.fromEntries(
    Object.entries(groups).map(([name, codes]) => [name, [...codes].sort()]),
  ),
  before,
  after,
  diagnosticDelta,
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
};
const target = resolve(process.argv[4]);
await mkdir(dirname(target), { recursive: true });
await writeFile(target, JSON.stringify(output, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({
    outcome: output.outcome,
    before: before.summary.statuses,
    after: after.summary.statuses,
    diagnosticDelta,
  }) + "\n",
);
