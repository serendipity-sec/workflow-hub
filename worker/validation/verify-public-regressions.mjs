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
  assert.equal(report.engineVersion, "0.4.0");
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
// The supported empty-summary Code branch is distinct from the downstream
// subject: a second unsupported Code branch and IF 2.3 also reach that subject.
// Do not extend one branch's constant result into a whole-path proof.
const mailContext = contexts.get(15403);
const emptyTitle = buildValueFlow(mailContext).output(
  mailContext.nodes[27].key,
  "docTitle",
);
check(
  "supported_empty_summary_title_is_public",
  emptyTitle.status === "resolved" &&
    emptyTitle.sensitivity === "public_literal",
);
const unresolvedMailFlow = rule(15403, "N8N_VALUE_FLOW_COVERAGE").diagnostics;
check(
  "populated_summary_code_remains_explicitly_unsupported",
  unresolvedMailFlow.some(
    (diagnostic) =>
      diagnostic.location.pointer === "/nodes/14/parameters" &&
      diagnostic.code === "code_mapping_unsupported",
  ),
);
check(
  "downstream_if_version_remains_explicitly_unsupported",
  unresolvedMailFlow.some(
    (diagnostic) =>
      diagnostic.location.pointer === "/nodes/18/parameters" &&
      diagnostic.code === "node_transform_unsupported",
  ),
);
check(
  "mixed_subject_is_candidate_not_proven_transfer",
  rule(15403, "N8N_EXTENDED_OUTBOUND_DATA").findings.some(
    (finding) =>
      finding.location.pointer === "/nodes/19/parameters/subject" &&
      finding.claim === "candidate" &&
      codes(finding).includes("personal_data_candidate_transferred"),
  ),
);
for (const [id, index, label] of [
  [18521, 20, "notion"],
  [15403, 13, "gemini"],
  [15403, 16, "docs_create"],
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
const output = {
  outcome: "passed",
  scope: "previously_documented_public_regressions",
  workflowExecution: "not_run",
  generalAccuracy: "not_measured",
  knownLimitations: [
    "public_15403_subject_overapproximation_after_unsupported_code_and_if",
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
