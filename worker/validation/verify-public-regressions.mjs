import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { assessmentReportSchema } from "../dist/assessment-contract.js";
import { createContext } from "../dist/static-context.js";
import { buildValueFlow } from "../dist/value-flow.js";

assert.ok(process.argv[2], "Supply the frozen public input/report directory");
assert.match(
  process.env.WORKER_ASSESSMENT_IMAGE ?? "",
  /^sha256:[a-f0-9]{64}$/,
);
const directory = resolve(process.argv[2]);
const hash = (value) => createHash("sha256").update(value).digest("hex");
const manifest = JSON.parse(
  await readFile(join(directory, "downloads.json"), "utf8"),
);
const reports = new Map(),
  contexts = new Map();
for (const sample of manifest.samples) {
  assert.ok(Number.isSafeInteger(sample.id) && sample.id > 0);
  const input = await readFile(join(directory, `${sample.id}.workflow.json`));
  assert.equal(hash(input), sample.sha256);
  const report = assessmentReportSchema.parse(
    JSON.parse(
      await readFile(join(directory, `${sample.id}.assessment.json`), "utf8"),
    ),
  );
  assert.notEqual(report.status, "error");
  assert.equal(report.inputSha256, sample.sha256);
  assert.equal(report.engineVersion, "0.7.0");
  assert.equal(report.boundary.kind, "docker");
  assert.equal(
    `sha256:${report.boundary.imageSha256}`,
    process.env.WORKER_ASSESSMENT_IMAGE,
  );
  reports.set(sample.id, report);
  contexts.set(sample.id, createContext(input));
}
const findings = (id) =>
  reports
    .get(id)
    .files.flatMap((file) => [...file.base.rules, ...file.extensionRules])
    .flatMap((rule) => rule.findings);
const rule = (id, ruleId) =>
  reports
    .get(id)
    .files[0].extensionRules.find((rule) => rule.ruleId === ruleId);
const codes = (finding) => finding.evidence.map((evidence) => evidence.code);
const checks = [];
function check(code, condition) {
  assert.ok(condition, code);
  checks.push(code);
}

check(
  "idless_official_template_accepted",
  reports
    .get(7622)
    .files[0].functionSummary.nodes.every(
      (node) => node.identity === "name_derived",
    ),
);
check(
  "postgres_2_4_input_path_detected",
  findings(10111).some(
    (finding) =>
      finding.category === "sql" && finding.claim === "supported_path",
  ),
);
check(
  "postgres_string_parameter_channel_observed",
  rule(16081, "N8N_ADVANCED_SQL").findings.some((finding) =>
    codes(finding).includes("sql_value_parameter_channel_configured"),
  ),
);
check(
  "postgres_string_mapping_stays_unverified",
  rule(16081, "N8N_ADVANCED_SQL").diagnostics.some(
    (diagnostic) => diagnostic.code === "sql_parameter_mapping_data_dependent",
  ),
);
check(
  "complex_sql_casts_parse",
  !rule(20541, "N8N_ADVANCED_SQL").diagnostics.some(
    (diagnostic) => diagnostic.code === "sql_parse_unsupported",
  ),
);
check(
  "complex_sql_binding_observed",
  rule(20541, "N8N_ADVANCED_SQL").findings.some((finding) =>
    codes(finding).includes("sql_value_binding_configured"),
  ),
);
const fixedCommands = contexts
  .get(11007)
  .nodes.filter(
    (node) =>
      node.type === "n8n-nodes-base.executeCommand" &&
      typeof node.parameters.command === "string" &&
      node.parameters.command.startsWith("=") &&
      !node.parameters.command.includes("{{"),
  );
check("constant_command_control_exists", fixedCommands.length > 0);
check(
  "constant_command_has_no_dynamic_candidate",
  fixedCommands.every(
    (node) =>
      !rule(11007, "N8N_ADVANCED_EXECUTION").findings.some(
        (finding) =>
          finding.location.nodeKey === node.key &&
          codes(finding).includes("command_dynamic_value_candidate"),
      ),
  ),
);
check(
  "external_command_input_candidate_retained",
  rule(11007, "N8N_ADVANCED_EXECUTION").findings.some((finding) =>
    codes(finding).includes("command_external_value_candidate"),
  ),
);
// Both actual title branches are statically modeled; the separately transmitted
// body must retain its personal-data possibility and partial provenance.
const mailContext = contexts.get(15403);
const mailFlow = buildValueFlow(mailContext);
for (const index of [14, 27]) {
  const title = mailFlow.output(mailContext.nodes[index].key, "docTitle");
  check(
    `summary_${index}_title_is_public`,
    title.status === "resolved" && title.sensitivity === "public_literal",
  );
}
const subject = mailFlow.resolve(
  mailContext.nodes[19].key,
  mailContext.nodes[19].parameters.subject,
);
check(
  "whole_subject_is_public",
  subject.status === "resolved" && subject.sensitivity === "public_literal",
);
check(
  "constant_subject_has_no_personal_transfer_candidate",
  !rule(15403, "N8N_EXTENDED_OUTBOUND_DATA").findings.some(
    (finding) =>
      finding.location.pointer === "/nodes/19/parameters/subject" &&
      codes(finding).includes("personal_data_candidate_transferred"),
  ),
);
check(
  "actual_message_personal_candidate_retained",
  rule(15403, "N8N_EXTENDED_OUTBOUND_DATA").findings.some(
    (finding) =>
      finding.location.pointer === "/nodes/19/parameters/message" &&
      codes(finding).includes("personal_data_candidate_transferred"),
  ),
);
check(
  "populated_summary_mapping_supported",
  !rule(15403, "N8N_VALUE_FLOW_COVERAGE").diagnostics.some(
    (d) =>
      d.location.pointer === "/nodes/14/parameters" &&
      d.code === "code_mapping_unsupported",
  ),
);
check(
  "if_2_3_pass_through_supported",
  !rule(15403, "N8N_VALUE_FLOW_COVERAGE").diagnostics.some(
    (d) =>
      d.location.pointer === "/nodes/18/parameters" &&
      d.code === "node_transform_unsupported",
  ),
);
for (const [id, context] of contexts) {
  const base = reports
    .get(id)
    .files[0].base.rules.find(
      (r) => r.ruleId === "N8N_DEPENDENCY_CAPABILITIES",
    );
  for (const node of context.nodes.filter(
    (n) => n.type === "n8n-nodes-base.stickyNote" && n.typeVersion === 1,
  ))
    assert.ok(
      !base.diagnostics.some(
        (d) =>
          d.location.nodeKey === node.key &&
          d.code === "builtin_capability_profile_unreviewed",
      ),
    );
}
checks.push("reviewed_sticky_notes_not_unreviewed_capabilities");
for (const [id, kind, operation] of [
  [6216, "emailSend", null],
  [11007, "telegram", "sendDocument"],
]) {
  const selected = contexts
    .get(id)
    .nodes.filter(
      (n) =>
        n.type === "n8n-nodes-base." + kind &&
        (operation === null || n.parameters.operation === operation),
    );
  check(`${id}_connector_control_exists`, selected.length > 0);
  check(
    `${id}_known_send_profile_supported`,
    selected.every(
      (node) =>
        !rule(id, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
          (d) =>
            d.location.nodeKey === node.key &&
            ["unsupported_node_version", "unsupported_send_operation"].includes(
              d.code,
            ),
        ),
    ),
  );
}
check(
  "binary_attachment_content_stays_unavailable",
  rule(11007, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
    (d) => d.code === "binary_payload_unavailable",
  ),
);
check(
  "optional_telegram_keyboard_not_required_input",
  !rule(10476, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
    (d) => d.code === "required_send_field_missing",
  ) &&
    rule(10476, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
      (d) => d.code === "message_reply_markup_unverified",
    ),
);
const longText = reports
  .get(3314)
  .files[0].tools.native.modes.find((m) => m.mode === "nlp");
check(
  "long_program_scanned_in_bounded_chunks",
  longText.diagnostics.some((d) => d.code === "nlp_chunked_text_profile"),
);
check(
  "long_program_not_skipped_at_old_field_limit",
  !longText.diagnostics.some((d) => d.code === "native_field_size_limit"),
);
for (const id of [20541, 14034, 3314, 11007])
  check(
    `${id}_spurious_budget_exhaustion_removed`,
    !rule(id, "N8N_VALUE_FLOW_COVERAGE").diagnostics.some(
      (d) => d.code === "flow_budget_exceeded",
    ),
  );
check(
  "runtime_context_still_explicit",
  [...reports.values()].every((report) =>
    report.files[0].extensionRules.some(
      (r) =>
        r.ruleId === "CONTEXT_RUNTIME_EVIDENCE" &&
        r.diagnostics.some((d) => d.code === "runtime_evidence_missing"),
    ),
  ),
);
for (const [id, index, label] of [
  [18521, 20, "notion"],
  [15403, 13, "gemini"],
  [15403, 17, "docs_update"],
  [15403, 23, "whatsapp"],
]) {
  check(
    `${label}_transfer_fields_inspected`,
    rule(id, "N8N_EXTENDED_OUTBOUND_DATA").findings.some((finding) =>
      finding.location.pointer.startsWith(`/nodes/${index}/parameters/`),
    ),
  );
}
const documentTitle = mailFlow.resolve(
  mailContext.nodes[16].key,
  mailContext.nodes[16].parameters.title,
);
check(
  "docs_create_title_is_public_after_mapping_fix",
  documentTitle.status === "resolved" &&
    documentTitle.sensitivity === "public_literal" &&
    !rule(15403, "N8N_EXTENDED_OUTBOUND_DATA").findings.some(
      (finding) =>
        finding.location.pointer === "/nodes/16/parameters/title" &&
        codes(finding).includes("personal_data_candidate_transferred"),
    ),
);
check(
  "docs_create_profile_keeps_access_and_policy_gaps",
  ["destination_access_unverified", "trusted_policy_transfer_unresolved"].every(
    (code) =>
      rule(15403, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
        (diagnostic) =>
          diagnostic.location.pointer === "/nodes/16/parameters" &&
          diagnostic.code === code,
      ),
  ),
);
check(
  "ner_structural_metadata_false_positives_removed",
  [...reports].every(([id, report]) =>
    report.files[0].tools.native.modes
      .find((mode) => mode.mode === "nlp")
      .findings.every(
        (finding) =>
          !["nlp_person_candidate", "nlp_location_candidate"].includes(
            finding.code,
          ) ||
          !/^\/nodes\/\d+\/(?:id|name|type|typeVersion)$/.test(
            contexts.get(id).fields[finding.fieldIndex].pointer,
          ),
      ),
  ),
);
check(
  "informational_observations_have_no_correction_plans",
  [...reports.values()].every((report) =>
    report.files.every((file) =>
      file.remediation.every((plan) =>
        plan.findingIds.every(
          (id) => !file.findingPresentation.observations.includes(id),
        ),
      ),
    ),
  ),
);
for (const id of [2490, 18521]) {
  const outbound = rule(id, "N8N_EXTENDED_OUTBOUND_DATA");
  check(
    `${id}_table_operation_capability_observed`,
    outbound.findings.some((f) =>
      codes(f).some((code) =>
        ["outbound_send_capability", "external_read_capability"].includes(code),
      ),
    ),
  );
  check(
    `${id}_table_runtime_and_policy_gaps_retained`,
    outbound.diagnostics.some(
      (d) => d.code === "trusted_policy_transfer_unresolved",
    ),
  );
}
check(
  "sheets_runtime_headers_not_assumed",
  rule(18521, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
    (d) => d.code === "sheet_headers_runtime_unverified",
  ),
);
for (const id of [7622, 7643])
  check(
    `${id}_reversed_ai_connection_not_auto_repaired`,
    rule(id, "N8N_AI_CONNECTION_CONTRACTS").diagnostics.some(
      (d) => d.code === "ai_connection_contract_unresolved",
    ),
  );
check(
  "reviewed_ai_prompt_model_transfer_has_explicit_execution_gap",
  [...reports.keys()].some((id) =>
    rule(id, "N8N_AI_PROMPT_DATA").diagnostics.some(
      (d) => d.code === "ai_model_invocation_and_output_unverified",
    ),
  ),
);
check(
  "structured_postgres_default_insert_is_observed",
  rule(10111, "N8N_DATABASE_OPERATIONS").findings.some((f) =>
    codes(f).includes("database_insert_capability"),
  ),
);
check(
  "known_builtin_capability_inventory_covers_fixed_samples",
  [...reports.values()].every(
    (report) =>
      !report.files[0].base.rules
        .find((r) => r.ruleId === "N8N_DEPENDENCY_CAPABILITIES")
        .diagnostics.some(
          (d) => d.code === "builtin_capability_profile_unreviewed",
        ),
  ),
);
check(
  "dynamic_sql_structure_stays_explicit",
  rule(20459, "N8N_ADVANCED_SQL").diagnostics.some(
    (d) => d.code === "sql_query_structure_unresolved",
  ),
);
check(
  "read_response_fields_not_promoted_to_known_personal_data",
  rule(7643, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
    (d) => d.code === "read_response_classification_unverified",
  ),
);
check(
  "local_or_remote_file_content_stays_unavailable",
  rule(11007, "N8N_FILE_OPERATION_PATHS").diagnostics.some(
    (d) => d.code === "binary_payload_unavailable",
  ),
);

const openAiNode = contexts
  .get(10476)
  .nodes.find(
    (node) =>
      node.type === "@n8n/n8n-nodes-langchain.openAi" && node.typeVersion === 2,
  );
check("openai_responses_fixed_public_control_exists", Boolean(openAiNode));
check(
  "openai_responses_default_profile_is_supported",
  !rule(10476, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
    (d) =>
      d.location.nodeKey === openAiNode.key &&
      [
        "unsupported_node_version",
        "unsupported_send_operation",
        "unsupported_connector_resource",
      ].includes(d.code),
  ),
);
check(
  "openai_endpoint_still_requires_credential_context",
  rule(10476, "N8N_EXTENDED_OUTBOUND_DATA").diagnostics.some(
    (d) =>
      d.location.nodeKey === openAiNode.key &&
      d.code === "provider_endpoint_from_credentials_unverified",
  ),
);

const output = {
  // These assertions concern the fixed definitions, not operational safety.
  outcome: "passed",
  scope: "previously_documented_public_regressions",
  workflowExecution: "not_run",
  generalAccuracy: "not_measured",
  knownLimitations: [
    "remaining_unmodeled_code_data_and_runtime_context",
    "english_ner_context_sensitive",
  ],
  image: process.env.WORKER_ASSESSMENT_IMAGE,
  assertions: checks,
  inputs: manifest.samples.map(({ id, sha256 }) => ({ id, sha256 })),
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
};
const target = resolve(
  process.argv[3] ?? "evidence-local/public-regression-results.json",
);
await mkdir(dirname(target), { recursive: true });
await writeFile(target, JSON.stringify(output, null, 2) + "\n");
process.stdout.write(
  JSON.stringify({ outcome: output.outcome, assertions: checks.length }) + "\n",
);
