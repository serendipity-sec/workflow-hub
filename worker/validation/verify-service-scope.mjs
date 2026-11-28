import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { join, dirname, resolve } from "node:path";
import { assessmentReportSchema } from "../dist/contracts/assessment-contract.js";
import { presentInspection } from "../dist/service/inspection.js";
import { buildCoverageExplanation } from "../dist/service/coverage-causes.js";

const [target, ...directories] = process.argv.slice(2);
assert.ok(
  target && directories.length === 2,
  "Supply output and both frozen public directories",
);
const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const reports = new Map();
const inputs = [];
const assertions = [];
const check = (name, condition) => {
  assert.ok(condition, name);
  assertions.push(name);
};
for (const directory of directories) {
  const manifest = JSON.parse(
    await readFile(join(directory, "downloads.json"), "utf8"),
  );
  assert.ok(manifest.samples.length > 0 && !manifest.failures?.length);
  for (const sample of manifest.samples) {
    assert.ok(
      Number.isSafeInteger(sample.id) &&
        sample.id > 0 &&
        !reports.has(sample.id),
    );
    const bytes = await readFile(join(directory, `${sample.id}.workflow.json`));
    assert.equal(hash(bytes), sample.sha256);
    const raw = await readFile(join(directory, `${sample.id}.assessment.json`));
    const report = assessmentReportSchema.parse(JSON.parse(raw));
    assert.notEqual(report.status, "error");
    assert.equal(report.engineVersion, "0.9.0");
    assert.equal(report.inputSha256, sample.sha256);
    assert.equal(report.boundary.kind, "docker");
    assert.equal(
      `sha256:${report.boundary.imageSha256}`,
      process.env.WORKER_ASSESSMENT_IMAGE,
    );
    reports.set(sample.id, report);
    inputs.push({
      id: sample.id,
      inputSha256: sample.sha256,
      assessmentSha256: hash(raw),
    });
    const inspection = await presentInspection(report);
    const service = inspection.serviceReport;
    const explanation = buildCoverageExplanation(report);
    assert.deepEqual(inspection.assessment, report);
    check(
      `${sample.id}_initial_service_scope_and_precautions`,
      service.serviceReportVersion === "1.1.0" &&
        service.serviceScope.environmentInput === "not_requested" &&
        service.serviceScope.piiScope ===
          "existing_detectors_context_completeness_excluded" &&
        service.assessmentStatus === report.status &&
        service.decision === report.decision,
    );
    check(
      `${sample.id}_all_diagnostic_causes_classified`,
      explanation.counts.unclassified === 0 && !explanation.truncated,
    );
    check(
      `${sample.id}_critical_candidates_and_gaps_require_review`,
      (service.serviceScope.highRiskFindingCount === 0 &&
        service.counts.analysisGaps === 0) ||
        service.serviceScope.securityReviewRequired,
    );
  }
}
assert.equal(reports.size, 25);
const rule = (id, name) =>
  reports
    .get(id)
    .files[0].extensionRules.find((entry) => entry.ruleId === name);
const codes = (entry) =>
  entry.findings.flatMap((finding) =>
    finding.evidence.map((evidence) => evidence.code),
  );
for (const id of [10077, 11807]) {
  const vector = rule(id, "N8N_AI_VECTOR_DATA");
  check(
    `${id}_document_embedding_path_is_inspected`,
    codes(vector).some((code) => code.startsWith("ai_document_to_embedding_")),
  );
  check(
    `${id}_document_storage_path_is_inspected`,
    codes(vector).some((code) =>
      code.startsWith("ai_document_to_vector_store_"),
    ),
  );
  check(
    `${id}_actual_vector_data_and_access_remain_unverified`,
    vector.diagnostics.some(
      (diagnostic) =>
        diagnostic.code === "ai_vector_runtime_operations_unverified",
    ) &&
      vector.diagnostics.some(
        (diagnostic) =>
          diagnostic.code === "ai_vector_store_endpoint_and_access_unverified",
      ),
  );
}
for (const id of [7622, 7643])
  check(
    `${id}_reversed_required_model_edges_stay_unresolved`,
    rule(id, "N8N_AI_CONNECTION_CONTRACTS").diagnostics.some(
      (entry) => entry.code === "ai_connection_contract_unresolved",
    ) &&
      rule(id, "N8N_AI_CONNECTION_CONTRACTS").diagnostics.some(
        (entry) => entry.code === "ai_required_model_connection_missing",
      ),
  );
for (const id of [10077, 8573])
  check(
    `${id}_reviewed_retriever_memory_and_fallback_contracts`,
    !rule(id, "N8N_AI_PROMPT_DATA").diagnostics.some(
      (entry) => entry.code === "ai_context_connection_unresolved",
    ),
  );
check(
  "referenced_child_is_still_not_inspected",
  reports.get(8573).subworkflows.some((entry) => entry.status === "unresolved"),
);
const output = {
  outcome: "passed",
  engineVersion: "0.9.0",
  image: process.env.WORKER_ASSESSMENT_IMAGE,
  scope: "fixed_public_service_scope_and_new_static_path_regressions",
  workflowExecution: "not_run",
  actualTeamApiIntegration: "not_run",
  generalAccuracy: "not_measured",
  assertions,
  inputs,
  verificationScriptSha256: hash(await readFile(new URL(import.meta.url))),
};
await mkdir(dirname(resolve(target)), { recursive: true });
await writeFile(resolve(target), JSON.stringify(output, null, 2) + "\n");
console.log(
  JSON.stringify({
    outcome: output.outcome,
    samples: reports.size,
    assertions: assertions.length,
  }),
);
